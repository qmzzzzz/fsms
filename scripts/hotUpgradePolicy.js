/**
 * 热升级判据（scripts/hotUpgrade.js 的纯逻辑层）
 *
 * 分层理由与 deployPolicy.js 相同：这里的每一条判据都要能在毫秒级被直接断言
 * （该不该拒绝这个镜像、当前哪一色在接流量、readyz 算不算过），而「执行」
 * 只能靠子进程桩观测。挤在一起时，体积棘轮会先逼注释被删。
 *
 * 本模块零副作用：不读 process.env、不碰文件系统、不打印、不退出。
 *
 * 为什么这些判据值得单独成文件——每一条都对应一种「升级看起来成功、实际没成」的形态：
 *   · 镜像没有 digest 而是浮动 tag ⇒ 你以为在升到 sha-abc，registry 可能给了别的
 *     （tag 可被覆盖），审计里记的版本与线上跑的不是一回事；
 *   · upstream 里两行都未注释 ⇒ nginx 轮询，两色混跑，用户看到自相矛盾的页面；
 *   · 只看 /health 200 就切流 ⇒ 进程活着但 Mongo 事务能力已丢，切完才开始报错；
 *   · readyz 用 200 单独判定 ⇒ 某些反代会把 503 改写成 200 的登录页。
 */

'use strict';

/** 数据面端口 ↔ 颜色。改这里必须同步 deployment/nginx.conf.example 的 upstream 块 */
const COLOR_BY_PORT = { 3000: 'blue', 3001: 'green' };
const PORT_BY_COLOR = { blue: 3000, green: 3001 };

/** 只看 `sha256:` 后的 64 位小写十六进制——registry 的 digest 就是这个形状 */
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/**
 * 解析镜像引用，**必须**是 digest 钉扎形态：`registry/repo@sha256:<64hex>`。
 *
 * 拒绝浮动 tag 的理由不是洁癖：升级器是最高危入口，「能指定镜像」等于
 * 「能指定跑什么代码」。tag 可以被覆盖、可以被指向任意层，而 digest 不会变。
 * 审计里记 digest 才有意义；记 tag 只能证明「当时请求的是这个名字」。
 *
 * @param {string} ref
 * @returns {{ ref: string, repository: string, digest: string }}
 */
function parseImageRef(ref) {
  if (typeof ref !== 'string' || ref.trim() === '') {
    throw new Error('镜像引用为空：必须形如 registry/repo@sha256:<64位十六进制>');
  }
  const value = ref.trim();
  const at = value.lastIndexOf('@');
  if (at <= 0) {
    // 典型误用：`ghcr.io/org/fsms:v1.2.3` 或 `ghcr.io/org/fsms:latest`
    throw new Error(
      `镜像必须用 digest 钉扎，不接受 tag：${value}\n` +
        '  正确形态：ghcr.io/<org>/<repo>@sha256:<64位十六进制>\n' +
        '  tag 可被覆盖，无法证明线上跑的就是审计里记的那一版。'
    );
  }
  const repository = value.slice(0, at);
  const digest = value.slice(at + 1);
  if (!DIGEST_RE.test(digest)) {
    throw new Error(`digest 格式非法（应为 sha256: + 64 位小写十六进制）：${digest}`);
  }
  if (!/^[a-z0-9][a-z0-9._\-/:]*$/i.test(repository) || repository.includes('//')) {
    throw new Error(`镜像仓库名非法：${repository}`);
  }
  return { ref: value, repository, digest };
}

/**
 * 白名单校验：仓库必须落在允许前缀内。
 *
 * 空白名单 = 全拒（fail-closed），而不是全放行。升级器的默认状态必须是
 * 「不知道能拉什么 ⇒ 什么都不拉」；否则忘配白名单就等于把「指定任意镜像」
 * 这个能力开放出去，而它等价于 RCE。
 *
 * @param {{ repository: string }} parsed parseImageRef 的产物
 * @param {string[]} allowlist 仓库前缀，如 ['ghcr.io/qmzzzzz/']
 */
function assertImageAllowed(parsed, allowlist) {
  const list = (Array.isArray(allowlist) ? allowlist : [])
    .map((s) => String(s || '').trim())
    .filter(Boolean);
  if (list.length === 0) {
    throw new Error(
      '镜像白名单为空（HOT_UPGRADE_REGISTRY_ALLOWLIST 未配置）：拒绝升级。\n' +
        '  空白名单按「全部拒绝」处理——升级器默认不得接受任意镜像。'
    );
  }
  const repo = parsed.repository;
  const matched = list.some((prefix) => {
    // 前缀必须落在路径分隔符上：`ghcr.io/org/fs` 不得匹配 `ghcr.io/org/fsms-evil`
    const normalized = prefix.endsWith('/') ? prefix : `${prefix}/`;
    return repo === prefix || repo.startsWith(normalized);
  });
  if (!matched) {
    throw new Error(
      `镜像仓库不在白名单内：${repo}\n  允许：${list.join(', ')}\n` +
        '  若确需放行，请显式修改 HOT_UPGRADE_REGISTRY_ALLOWLIST 并留痕。'
    );
  }
  return true;
}

/** 取文本的主导行尾：Windows checkout 出来的文件是 CRLF，回写时必须原样保留 */
function detectEol(text) {
  const crlf = (text.match(/\r\n/g) || []).length;
  const lf = (text.match(/(?<!\r)\n/g) || []).length;
  return crlf > lf ? '\r\n' : '\n';
}

/** 定位 `upstream fsms_app {` 到配对的 `}`，返回 [startLine, endLine]（含） */
function findUpstreamBlock(lines) {
  const start = lines.findIndex((line) => /^\s*upstream\s+fsms_app\s*\{/.test(line));
  if (start < 0) {
    throw new Error(
      '在 nginx 配置里找不到 `upstream fsms_app {` 块。\n' +
        '  蓝绿切流依赖它，找不到时**不得**猜测目标地址（猜错等于把流量打到空端口）。\n' +
        '  请先按 deployment/nginx.conf.example 的 upstream 段改造实际配置。'
    );
  }
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\s*\}/.test(lines[i])) return [start, i];
  }
  throw new Error('`upstream fsms_app` 块没有配对的 `}`：配置已被破坏，拒绝继续。');
}

/** 单行 server 指令：可选注释前缀 + server + 地址 + 分号 + 行尾注释 */
const SERVER_LINE_RE = /^(\s*)(#\s*)?server\s+([^\s;]+)\s*;(.*)$/;

/** 从 `127.0.0.1:3001` 这类地址里取端口 */
function portOf(address) {
  const m = /:(\d+)$/.exec(address);
  return m ? Number(m[1]) : null;
}

/**
 * 读出当前承接流量的是哪一色。
 *
 * 不变量：块内**有且只有一行**未注释的 server。
 *   · 0 行 ⇒ 配置已坏（nginx 会 502），不猜，直接报错；
 *   · 2 行 ⇒ nginx 会轮询，两色混跑，这是比 502 更危险的状态（能跑、但语义错乱）。
 */
function parseActiveUpstream(conf) {
  const lines = String(conf).split(/\r?\n/);
  const [start, end] = findUpstreamBlock(lines);

  const active = [];
  const declared = [];
  for (let i = start + 1; i < end; i += 1) {
    const m = SERVER_LINE_RE.exec(lines[i]);
    if (!m) continue;
    const address = m[3];
    const port = portOf(address);
    declared.push({ line: i, port, address, commented: Boolean(m[2]) });
    if (!m[2]) active.push({ line: i, port, address });
  }

  if (active.length !== 1) {
    throw new Error(
      `upstream fsms_app 内有 ${active.length} 行未注释的 server（必须恰好 1 行）。\n` +
        (active.length === 0
          ? '  0 行 ⇒ nginx 无可用后端，所有请求 502。\n'
          : '  多于 1 行 ⇒ nginx 会轮询，两个版本混跑，用户会看到自相矛盾的页面。\n') +
        '  请先修好 upstream 块再升级。'
    );
  }

  const { port } = active[0];
  const color = COLOR_BY_PORT[port];
  if (!color) {
    throw new Error(
      `upstream 的活动端口 ${port} 不是已知色（${Object.keys(COLOR_BY_PORT).join(' / ')}）。\n` +
        '  端口与颜色的对应关系在 scripts/hotUpgradePolicy.js 的 COLOR_BY_PORT。'
    );
  }
  return { color, port, declared };
}

/**
 * 把 upstream 切到目标色，返回新配置文本。
 *
 * 只改块内 server 行的注释状态，不动其它任何字节——切流配置一旦被"顺手整理"，
 * 排查问题时无法区分「我改的」与「工具改的」。
 *
 * 幂等：对已处于目标状态的文本再调用一次，输出与输入逐字节相同。
 * 这一点很重要——脚本失败重试时不会把文件改成第三种形态。
 */
function renderUpstream(conf, targetColor) {
  const targetPort = PORT_BY_COLOR[targetColor];
  if (!targetPort) {
    throw new Error(`未知目标色：${targetColor}（可选 ${Object.keys(PORT_BY_COLOR).join(' / ')}）`);
  }
  const text = String(conf);
  const eol = detectEol(text);
  // 逐行剥掉行尾 \r 再按主导行尾统一回写。
  //
  // 不剥会出真事故：`(.*)$` 里的 `.` 不匹配 \r，于是「\r 残留 + 行尾注释」的
  // server 行整条匹配失败——表现是「明明有 server 行，却一个都没匹配到」，
  // 然后报出与真实原因无关的「没有该端口的 server 行」。实测于 2026-10-30：
  // 对已含 CRLF 的文本再做一次 `\n → \r\n` 替换就得到 `\r\r\n`，正是这个形态。
  // 代价：行尾混用的文件会被统一成主导风格；配置文件由本脚本整体重写，可接受。
  const lines = text.split(/\r?\n/).map((line) => line.replace(/\r$/, ''));
  const [start, end] = findUpstreamBlock(lines);

  // 先确认目标端口存在，再动手改。
  // 顺序反过来会先注释掉唯一的活动行，得到「一行都不剩」的配置——自检能拦住，
  // 但报出来的是「0 行未注释」，指向的是症状而不是原因。
  const ports = [];
  for (let i = start + 1; i < end; i += 1) {
    const m = SERVER_LINE_RE.exec(lines[i]);
    if (m) ports.push(portOf(m[3]));
  }
  if (!ports.includes(targetPort)) {
    throw new Error(
      `upstream 块里没有端口 ${targetPort} 的 server 行：无法切到 ${targetColor}。\n` +
        `  块内已声明：${ports.join(', ') || '（无）'}\n` +
        '  说明配置与脚本的端口约定不一致，拒绝写入半成品配置。'
    );
  }

  let touched = false;
  for (let i = start + 1; i < end; i += 1) {
    const m = SERVER_LINE_RE.exec(lines[i]);
    if (!m) continue;
    const [, indent, hash, address, tail] = m;
    const port = portOf(address);
    if (port === targetPort) {
      // 目标色：必须未注释
      lines[i] = `${indent}server ${address};${tail}`;
      touched = true;
    } else if (!hash) {
      // 非目标色：必须注释掉，且保留原有缩进与行尾注释
      lines[i] = `${indent}# server ${address};${tail}`;
      touched = true;
    }
  }

  if (!touched) {
    throw new Error(
      `切到 ${targetColor} 时没有任何 server 行需要改写：配置形态与预期不符，拒绝继续。`
    );
  }

  // 写完必须自检：切流后仍要满足「恰好一行未注释」，否则这次写入是坏的
  const result = lines.join(eol);
  parseActiveUpstream(result);
  return result;
}

/**
 * readyz 判定。
 *
 * 只认 `200 + status === 'ready'`：
 *   · 单看 200 不够——某些反代/兜底页会把 503 改写成 200 的 HTML；
 *   · 单看 body 不够——进程能返回 ready 但 HTTP 层已是 503 说明中间有东西在拦。
 * 二者同时满足才算过。
 */
function evaluateReadyz(httpStatus, body) {
  if (httpStatus !== 200) {
    return { ok: false, reason: `HTTP ${httpStatus}` };
  }
  if (!body || typeof body !== 'object') {
    return { ok: false, reason: '响应不是 JSON 对象（可能被反代改写成了 HTML）' };
  }
  if (body.status !== 'ready') {
    const checks = body.checks && typeof body.checks === 'object' ? body.checks : {};
    const detail = Object.entries(checks)
      .filter(([, v]) => v !== 'ok')
      .map(([k, v]) => `${k}=${v}`)
      .join(',');
    return { ok: false, reason: `status=${body.status}${detail ? ` (${detail})` : ''}` };
  }
  return { ok: true, reason: 'ready' };
}

/** 默认参数。数值都取「宁可多等一会儿」的一侧：切流过早的代价远大于多等 1 分钟 */
const DEFAULT_OPTIONS = {
  readyzTimeoutSec: 180,
  observeSec: 300,
  readyzIntervalSec: 3,
};

const FLAGS = [
  'image',
  'nginx-conf',
  'readyz-timeout',
  'observe-seconds',
  'apply',
  'dry-run',
  'help',
];

/**
 * 解析命令行。
 *
 * 刻意不引入参数解析库：本脚本要在生产机上跑，依赖越少越好；
 * 且未知参数必须**报错**而不是忽略——`--dryrun`（少一个连字符）被忽略时，
 * 脚本会真的去改生产配置，这是最不该静默的一类失误。
 */
function parseArgs(argv = []) {
  const opts = {
    ...DEFAULT_OPTIONS,
    apply: false,
    dryRun: false,
    help: false,
    image: '',
    nginxConf: '',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (!raw.startsWith('--')) throw new Error(`无法识别的参数：${raw}`);
    const [name, inlineValue] = raw.slice(2).split('=');
    if (!FLAGS.includes(name)) {
      throw new Error(`未知参数：--${name}（可用：${FLAGS.map((f) => `--${f}`).join(', ')}）`);
    }
    const takeValue = () => {
      if (inlineValue !== undefined) return inlineValue;
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new Error(`--${name} 需要一个值`);
      }
      i += 1;
      return next;
    };
    if (name === 'dry-run') opts.dryRun = true;
    else if (name === 'apply') opts.apply = true;
    else if (name === 'help') opts.help = true;
    else if (name === 'image') opts.image = takeValue();
    else if (name === 'nginx-conf') opts.nginxConf = takeValue();
    else if (name === 'readyz-timeout') opts.readyzTimeoutSec = parsePositiveInt(takeValue(), name);
    else if (name === 'observe-seconds')
      opts.observeSec = parsePositiveInt(takeValue(), name, true);
  }
  return opts;
}

/** 正整数解析；allowZero 用于 --observe-seconds 0（跳过观察期，仅限演练） */
function parsePositiveInt(value, name, allowZero = false) {
  const n = Number(value);
  const min = allowZero ? 0 : 1;
  if (!Number.isInteger(n) || n < min) {
    throw new Error(`--${name} 需要 ${min} 以上的整数，收到：${value}`);
  }
  return n;
}

module.exports = {
  COLOR_BY_PORT,
  PORT_BY_COLOR,
  DEFAULT_OPTIONS,
  parseImageRef,
  assertImageAllowed,
  parseActiveUpstream,
  renderUpstream,
  evaluateReadyz,
  parseArgs,
  detectEol,
};
