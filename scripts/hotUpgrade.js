#!/usr/bin/env node
/**
 * 蓝绿升级（单机 docker-compose 拓扑，零停机）
 *
 * 一次升级的完整动作，顺序不可调换：
 *   1. 备份（失败即中止，此时还没动任何东西）
 *   2. 起备色容器（新镜像）
 *   3. 等备色 /readyz 变绿——不是 /health：后者只证明进程活着，
 *      而「升级后 Mongo 事务能力丢了」正是这类系统最常见的静默故障
 *   4. 跑迁移（用**新版本**的代码跑；失败就停在备色，旧色继续服务）
 *   5. nginx -t 通过后 reload 切流
 *   6. 观察窗口内持续探备色，异常则切回
 *   7. 停旧色（保留容器，不 rm——后续回滚还能 start 回来）
 *
 * 失败分支自带现场抓取（2026-11-02，参考 a033/LANSEC 的「die 前 dump」）：就绪门控
 * 与观察窗口判负时，先把目标色容器日志尾巴收进留痕与任务说明，再收尾——省掉运维
 * 「还得再上一次机器看根因」那一步（边界见 captureTargetLogs 的注释）。
 *
 * 默认是演练：不加 `--apply` 只打印计划并以 2 退出。
 * 这是刻意的——把「真的改生产」做成一个必须显式输入的动词，
 * 而不是某个参数的默认值。
 *
 * 刻意不做的事：
 *   · 不自动发现新版本（自动升级 + 迁移 = 半夜静默炸库）；
 *   · 不做 down 迁移（回滚只回代码不回数据，靠 expand/contract 保证不需要逆）；
 *   · 不在升级期间轮换密钥（那会让所有用户掉线、历史审计链验签失败）。
 *
 * 用法：
 *   node scripts/hotUpgrade.js --image ghcr.io/org/fsms@sha256:<64hex> --nginx-conf /etc/nginx/nginx.conf
 *   node scripts/hotUpgrade.js --image ... --apply
 *
 * 供宿主机代理调用时，镜像引用可走 `HOT_UPGRADE_IMAGE`（不进 argv），
 * 并用 `--status-file` 把进度回写给应用侧轮询（见 scripts/hotUpgradeAgent.js）。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const policy = require('./hotUpgradePolicy');
const { createStatusSink } = require('./hotUpgradeStatusSink');

const ROOT = path.resolve(__dirname, '..');
const COMPOSE_FILE = process.env.HOT_UPGRADE_COMPOSE_FILE || path.join(ROOT, 'docker-compose.yml');
const NGINX_BIN = process.env.HOT_UPGRADE_NGINX_BIN || 'nginx';
/** 实际部署里 nginx 主配置的位置；容器化 nginx 或自编译路径不同时用 --nginx-conf 覆盖 */
const DEFAULT_NGINX_CONF = process.env.HOT_UPGRADE_NGINX_CONF || '/etc/nginx/nginx.conf';

/**
 * 单次 /readyz 探测的超时。
 *
 * 没有超时的 fetch 会让「容器已接受连接但不回包」变成永久挂起：没有超时就没有失败，
 * 没有失败就没有回滚——最坏形态是流量已经切走、脚本永远停在观察窗口里不返回，
 * systemd 只能等 TimeoutStartSec(2h) 才把它杀掉。
 */
const PROBE_TIMEOUT_MS = 5000;

/**
 * 失败分支的现场抓取上限（口径见 captureTargetLogs）。
 *
 * 参考同族系统 a033/LANSEC install.sh 的做法：每次 die 之前都 dump status + journalctl；
 * 本脚本的对应物是「目标色容器日志尾巴」——readyz / 观察窗口只给一句判据，
 * 根因（栈、连接错误、迁移报错）在容器自己的日志里。
 */
const LOG_TAIL_LINES = 80;
const LOG_TAIL_MAX_CHARS = 64 * 1024;
const LOG_STATUS_SNIPPET_MAX_CHARS = 1500;
const LOG_CAPTURE_TIMEOUT_MS = 10 * 1000;
const LOG_CAPTURE_MAX_BUFFER = 1024 * 1024;

/** 颜色 ↔ compose 服务名 / 镜像变量。与 policy 的 PORT_BY_COLOR 必须一致 */
const SERVICE_BY_COLOR = { blue: 'app', green: 'app-green' };
const IMAGE_ENV_BY_COLOR = { blue: 'APP_IMAGE', green: 'APP_IMAGE_NEXT' };

/** --tail 的取值先固化为字符串常量：argv 每个元素都必须是字符串，且不让类型转换出现在命令构造里 */
const LOG_TAIL_ARG = String(LOG_TAIL_LINES);
/** 允许出现在 logs 命令里的服务名（构建期封闭的两个枚举值；白名单是刻意的，见 captureTargetLogs） */
const LOG_TARGET_SERVICES = [SERVICE_BY_COLOR.blue, SERVICE_BY_COLOR.green];

const log = (msg) => process.stdout.write(`[hot-upgrade] ${msg}\n`);

/** 状态回写（供应用侧轮询）。宿主代理预置 id 等字段，见 hotUpgradeStatusSink.js */
let statusSink = null;

const fail = (msg, outcome = 'failed') => {
  if (statusSink) statusSink.finish('failed', { outcome, message: msg });
  process.stderr.write(`[hot-upgrade] 中止：${msg}\n`);
  process.exit(1);
};

/** 子进程一律继承 stdio：升级过程要能被人看见，而不是跑完才给结论 */
function run(file, args, extraEnv = {}) {
  execFileSync(file, args, {
    cwd: ROOT,
    stdio: 'inherit',
    env: { ...process.env, ...extraEnv },
  });
}

/**
 * compose 前缀：显式 -f，避免命令受 cwd 影响（cwd 决定项目名，项目名决定卷）。
 *
 * `--profile green` 必须常驻：app-green 在 compose 里挂在 profile 下，不加它时
 * `run/stop app-green` 会报 no such service（`up` 那一处原先单独加过，于是迁移与停容器
 * 两个动作仍然会踩空——升级到了迁移步才失败，看上去像「镜像有问题」）。
 */
const compose = (...args) => ['compose', '-f', COMPOSE_FILE, '--profile', 'green', ...args];

/**
 * 原子写配置：先写临时文件再 rename。
 *
 * 直接 writeFileSync 覆盖时，进程若在写到一半被杀，nginx 配置会变成半截文本——
 * 下一次 reload 直接失败，且现场看起来像「脚本把配置写坏了」。rename 在同分区是原子的。
 */
function writeConfAtomically(file, text, mode = 0o644) {
  const tmp = `${file}.hot-upgrade.tmp`;
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeFileSync(fd, text, 'utf8');
    // 先 fsync 再 rename：rename 只是换名字，不保证内容已经落盘
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
}

/** 探一次 readyz；返回 { ok, reason }。网络错误/超时都算不 ok，不吞、不抛 */
async function probeReadyz(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/readyz`, {
      headers: { Accept: 'application/json' },
      // 必须带超时：挂住的容器（连接建立但永不回包）会让升级永久卡在这一步。
      // 超时一律按「未就绪」返回，绝不向上抛出未捕获异常。
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const body = await res.json().catch(() => null);
    return policy.evaluateReadyz(res.status, body);
  } catch (err) {
    const reason = isTimeoutError(err)
      ? `探测超时（${PROBE_TIMEOUT_MS}ms 内无响应）：按未就绪处理`
      : `连接失败：${err.message}`;
    return { ok: false, reason };
  }
}

/** AbortSignal.timeout 的中止在各 Node 版本里表现为不同错误名/码，这里统一识别 */
const TIMEOUT_ERRORS = new Set(['TimeoutError', 'AbortError', 'ABORT_ERR', 'UND_ERR_ABORTED']);
const isTimeoutError = (err) =>
  Boolean(err) && (TIMEOUT_ERRORS.has(err.name) || TIMEOUT_ERRORS.has(err.code));

/** 轮询到超时；返回最后一次结果（调用方决定要不要因此中止） */
async function waitReadyz(port, timeoutSec, intervalSec) {
  const deadline = Date.now() + timeoutSec * 1000;
  let last = { ok: false, reason: '未开始探测' };
  while (Date.now() < deadline) {
    last = await probeReadyz(port);
    if (last.ok) return last;
    log(`  备色尚未就绪（${last.reason}），${intervalSec}s 后重试`);
    await new Promise((r) => setTimeout(r, intervalSec * 1000));
  }
  return last;
}

/** 观察窗口：持续探，任何一次不 ok 即判定失败 */
async function observe(port, observeSec, intervalSec) {
  const deadline = Date.now() + observeSec * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, intervalSec * 1000));
    const result = await probeReadyz(port);
    if (!result.ok) return result;
  }
  return { ok: true, reason: '观察期内持续就绪' };
}

/**
 * 把 upstream 切到指定色并 reload——**事务式**：任一步失败都写回原配置并重新自检。
 *
 * 顺序固定：备份原文件 → 写候选 → nginx -t → reload。
 * 只在 nginx -t 失败时回滚是不够的：reload 也会失败（证书/端口/权限/其它 include 出错时
 * -t 通过而 reload 失败），那时文件里留着候选配置，宿主 nginx 的下一次 reload/重启
 * 就会带着一份「脚本以为已经回滚了」的坏配置起来。
 */
function switchTraffic(confPath, targetColor) {
  const original = fs.readFileSync(confPath, 'utf8');
  const next = policy.renderUpstream(original, targetColor);
  const originalMode = fs.statSync(confPath).mode & 0o777;

  if (next === original) {
    log(`upstream 已在 ${targetColor}，无需改配置`);
    run(NGINX_BIN, ['-t']);
    run(NGINX_BIN, ['-s', 'reload']);
    return original;
  }

  // 1. 备份原文件。后缀刻意不带 .conf：避免被 `include /etc/nginx/*.conf` 之类的
  //    通配当成一份配置加载进去（那会得到一个「备份文件把 nginx 弄坏」的怪现场）。
  const backupFile = `${confPath}.hot-upgrade-orig.bak`;
  try {
    writeConfAtomically(backupFile, original, originalMode);
  } catch (err) {
    // 此刻还没动任何配置，报错就说清这一点：不需要回滚
    throw new Error(`备份原配置失败（配置未被改动）：${err.message}`);
  }

  // 2. 写候选
  writeConfAtomically(confPath, next, originalMode);

  /** 写回原配置并重新自检；返回一句话说清「回滚了没有、校验过没有」 */
  const rollback = (stage) => {
    try {
      writeConfAtomically(confPath, original, originalMode);
      run(NGINX_BIN, ['-t']);
      return `已回滚原配置（${stage}；回滚后 nginx -t 通过）`;
    } catch (_) {
      // 最坏情况：写回失败或写回后仍自检不过。绝不能含糊地说「已回滚」——
      // 运维要据此决定是手工恢复备份文件还是先停流量。
      return (
        `回滚未完成（${stage}）：原配置未能写回，或写回后 nginx -t 仍不通过（原因见宿主 journal）。` +
        `原配置备份在同一目录下的 ${path.basename(backupFile)}，请立即人工处理`
      );
    }
  };

  // 3. 校验候选
  try {
    run(NGINX_BIN, ['-t']);
  } catch (_) {
    throw new Error(`nginx -t 未通过（原因见宿主 journal）；${rollback('候选配置自检失败')}`);
  }

  // 4. 切流
  try {
    run(NGINX_BIN, ['-s', 'reload']);
  } catch (_) {
    throw new Error(`nginx -s reload 失败（原因见宿主 journal）；${rollback('reload 失败')}`);
  }
  return original;
}

/** 留痕：每次升级写一份本地记录（审计链之外的第二份证据，便于事后复盘） */
function recordState(state) {
  const dir = path.join(ROOT, 'logs');
  try {
    fs.mkdirSync(dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const file = path.join(dir, `hot-upgrade-${stamp}.json`);
    // 显式 0600：这份记录含镜像 digest 与宿主 nginx 路径，不该被同机其它用户读到
    fs.writeFileSync(file, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
    log(`状态记录：${file}`);
  } catch (err) {
    // 记录失败不阻断升级本身，但要说出来——否则「有留痕」是假的
    process.stderr.write(`[hot-upgrade] 警告：状态记录写入失败（${err.message}）\n`);
  }
}

/**
 * 切流 + 观察 + 失败回滚。
 *
 * 单独成函数不只是为了行数：这是本脚本唯一「已经把流量挪走」的阶段，
 * 它的每条失败分支都必须说清「此刻流量在哪一色、旧色还在不在」——
 * 集中在一处，才不会出现「回滚失败却提示已回滚」这种更坏的信息错误。
 */
async function switchAndVerify({ confPath, active, target, targetPort, opts, state, step }) {
  step('switch-traffic', `${active.color} -> ${target}`);
  try {
    switchTraffic(confPath, target);
  } catch (err) {
    recordState({ ...state, outcome: 'aborted_switch_failed', reason: err.message });
    fail(`切流失败：${err.message}`, 'aborted_switch_failed');
  }

  step('observe', `${opts.observeSec}s`);
  const observed = await observe(targetPort, opts.observeSec, 5);
  if (observed.ok) return;

  step('rollback', `切回 ${active.color}`);
  // 观察期判负 = 新色「能启动但不稳定」：根因在它的日志里，且必须赶在下面的 stop
  // 之前抓（回滚失败分支也一样抓——那是最需要现场的一支）。
  const targetLogs = captureTargetLogs(target);
  try {
    switchTraffic(confPath, active.color);
  } catch (err) {
    // 最坏情况：流量可能还在新色，旧色也还在跑。必须把现场原样说清楚，
    // 而不是含糊地报「回滚失败」——运维要据此决定是手工切回还是直接停新色。
    recordState({
      ...state,
      outcome: 'rollback_failed',
      reason: err.message,
      targetLogsTail: targetLogs,
    });
    const msg =
      `回滚切流失败（${err.message}）。当前流量可能仍在新色，` +
      `旧色容器 ${SERVICE_BY_COLOR[active.color]} 仍在运行。请立即人工确认。`;
    // 这一支的文案必须保持紧急且短（下一步动作是人工上机确认流量），
    // 日志只进留痕 targetLogsTail，不追加到任务说明里稀释结论。
    fail(msg, 'rollback_failed');
  }
  recordState({
    ...state,
    outcome: 'rolled_back',
    reason: observed.reason,
    targetLogsTail: targetLogs,
  });
  // 回滚成功才停新色：此刻流量已确认在旧色。不停的话，一个有问题的版本会继续占着
  // 3001 端口跑到下一次升级，谁也不知道它还在（也可能自己重启、连同一个库）。
  // 只有回滚**失败**的分支不能停——那时流量可能还在新色，停了就是全站 502。
  try {
    run('docker', compose('stop', SERVICE_BY_COLOR[target]));
  } catch (err) {
    log(`回滚已生效，但停新色容器失败：${err.message}（请人工确认 ${SERVICE_BY_COLOR[target]}）`);
  }
  fail(
    `观察期未通过（${observed.reason}），已切回 ${active.color}。${logAppendix(targetLogs)}`,
    'rolled_back'
  );
}

/**
 * 尽力停掉某个颜色的容器；失败只记一行日志（收尾路径不许把主结论覆盖成异常）。
 * @param {'blue'|'green'} color
 * @param {string} why 失败时说明这是哪一步的清理
 */
function stopQuietly(color, why) {
  try {
    run('docker', compose('stop', SERVICE_BY_COLOR[color]));
  } catch (err) {
    log(`${why}：停容器失败（${err.message}），请人工确认 ${SERVICE_BY_COLOR[color]}`);
  }
}

/**
 * 把抓到的日志裁成可回写 status 的短片段（纯函数，供测试直接断言）。
 *
 * 只有**真正发生截断**时才做行边界调整：从截断点之后的第一处换行起步——
 * 半行开头不完整，留着只会让人误以为日志缺了行。未超上限的输入原样保留
 * （只 trim 首尾），行结构不动。
 */
function buildLogSnippet(rawLogs, maxChars = LOG_STATUS_SNIPPET_MAX_CHARS) {
  if (typeof rawLogs !== 'string') return '';
  const trimmed = rawLogs.trim();
  if (trimmed === '') return '';
  if (trimmed.length <= maxChars) return trimmed;
  const clipped = trimmed.slice(-maxChars);
  const firstNewline = clipped.indexOf('\n');
  return (firstNewline >= 0 ? clipped.slice(firstNewline + 1) : clipped).trim();
}

/** 失败文案的日志附录：没抓到日志时一个字节都不加（不留「日志如下：无」这种空话） */
function logAppendix(rawLogs) {
  const snippet = buildLogSnippet(rawLogs);
  if (!snippet) return '';
  return `\n目标色容器日志末尾（代理抓取原文，未本地化，截断保留）：\n${snippet}`;
}

/**
 * 抓目标色容器的日志尾巴（失败分支专用）。
 *
 * 与 run() 的 stdio 继承不同：这份输出要进留痕与 status 的任务说明，走管道捕获。
 * execFileSync 的 timeout 会收掉卡住的 docker（守护进程半死时最像「命令正常」）。
 * 三条边界：
 *   · 永不阻断：任何失败（docker 不在、容器未起、输出超限）都吞在内部只记一行——
 *     抓取是诊断动作，不得改变主判决（readyz / 观察窗口的结论）；
 *   · 有界：行数与字符数封顶——日志尾巴是诊断样本，不是归档；
 *   · 出站分离：完整尾巴只进宿主留痕（logs/ 下 0600）；回写 status 的只是
 *     buildLogSnippet 裁过的短片段（status 有 64KB 读取上限，界面要能读）。
 */
function captureTargetLogs(target) {
  // 服务名经枚举白名单后才能进 argv：它本来就只可能是这两值，写明是为了让
  // 「argv 里每个动态元素都来自封闭集合」这件事在代码层可被复核。
  const service = SERVICE_BY_COLOR[target];
  if (typeof service !== 'string' || !LOG_TARGET_SERVICES.includes(service)) return '';
  const args = [
    'compose',
    '-f',
    COMPOSE_FILE,
    '--profile',
    'green',
    'logs',
    '--no-color',
    '--tail',
    LOG_TAIL_ARG,
    service,
  ];
  try {
    const out = execFileSync('docker', args, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: LOG_CAPTURE_TIMEOUT_MS,
      maxBuffer: LOG_CAPTURE_MAX_BUFFER,
    });
    return typeof out === 'string' ? out.slice(-LOG_TAIL_MAX_CHARS) : '';
  } catch (err) {
    // 超时/超量时 err.stdout 里可能已有部分输出：那也是现场，照样收下
    log(`目标色日志抓取失败（${err.message}）：留痕与任务说明里只有判据本身`);
    return (typeof err.stdout === 'string' ? err.stdout : '').slice(-LOG_TAIL_MAX_CHARS);
  }
}

/** 离线模式专用：确认本地 docker 已有这个 digest 的镜像。
 *
 * 为什么不靠 compose 的默认拉取策略：\`up\` 的默认行为是「本地缺了才 pull」——
 * 本地没有时它**不会失败**，而是去联网。在内网机上表现为长时间卡住后超时，
 * 在断网机上表现为拉取报错，两种现场都不是「这个包还没导入」这句话。
 * 提前断言把这条最贵的失败点挪到备份之前，并把原因直接写在报错里。
 *
 * 只查 RepoDigests 不查 tag：与 scripts/importOfflineBundle.js 同一口径——
 * tag 说明不了装的是哪一版，digest 才能。
 */
function assertLocalImage(ref) {
  try {
    execFileSync('docker', ['image', 'inspect', '--format', '{{json .RepoDigests}}', ref], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (_) {
    fail(
      `离线模式：本地 docker 里没有镜像 ${ref}，未做任何变更。\n` +
        '  请先在目标机上导入离线包：node scripts/importOfflineBundle.js --bundle <目录> --apply\n' +
        '  离线模式不接受「本地没有就去 registry 拉」——那正是这个模式要避免的事。'
    );
  }
}

function printHelp() {
  process.stdout.write(
    [
      '蓝绿升级。默认只演练，加 --apply 才真正执行。',
      '',
      '  --image <ref>            新版本镜像，必须是 registry/repo@sha256:<64hex>',
      '                           也可用 HOT_UPGRADE_IMAGE 环境变量（不进 argv）',
      '  --nginx-conf <path>      nginx 配置路径（含 upstream fsms_app）',
      '  --status-file <path>     进度回写文件（应用侧轮询用；由宿主代理传入）',
      '  --readyz-timeout <sec>   等备色就绪的超时，默认 180',
      '  --observe-seconds <sec>  切流后观察窗口，默认 300；--apply 下不得低于 60',
      '  --offline                离线升级：镜像必须已由 scripts/importOfflineBundle.js 导入，执行期间不联网拉取',
      '  --apply                  真正执行（缺省为演练）',
      '  --help                   本帮助',
      '',
    ].join('\n')
  );
}

function buildPlan(opts) {
  const confPath = opts.nginxConf || DEFAULT_NGINX_CONF;
  if (!fs.existsSync(confPath)) {
    // 真实路径只写宿主 journal（运维看得到）；回写应用的文案用逻辑名，不泄漏宿主绝对路径
    log(`nginx 主配置不存在：${confPath}`);
    fail('nginx 主配置不存在（--nginx-conf 或 HOT_UPGRADE_NGINX_CONF 指定的文件），未做任何变更');
  }

  const active = policy.parseActiveUpstream(fs.readFileSync(confPath, 'utf8'));
  const target = active.color === 'blue' ? 'green' : 'blue';
  const targetPort = policy.PORT_BY_COLOR[target];

  // 镜像引用允许走环境变量：宿主代理调本脚本时，digest 不必出现在
  // /proc/<pid>/cmdline 里（虽然 digest 不是机密，但固定 argv 面更小）。
  const imageRef = (opts.image || process.env.HOT_UPGRADE_IMAGE || '').trim();
  if (!imageRef) fail('缺少镜像引用（--image 或 HOT_UPGRADE_IMAGE）', 'missing_image');
  const parsed = policy.parseImageRef(imageRef);
  policy.assertImageAllowed(
    parsed,
    String(process.env.HOT_UPGRADE_REGISTRY_ALLOWLIST || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  );

  const plan = {
    activeColor: active.color,
    activePort: active.port,
    targetColor: target,
    targetPort,
    image: parsed.ref,
    digest: parsed.digest,
    mode: opts.offline ? 'offline' : 'registry',
    nginxConf: confPath,
    observeSec: opts.observeSec,
  };

  if (statusSink) {
    statusSink.detail({ image: parsed.ref, activeColor: active.color, targetColor: target });
  }

  log('升级计划：');
  for (const [k, v] of Object.entries(plan)) log(`  ${k} = ${v}`);
  return { confPath, active, target, targetPort, parsed, plan };
}

function reportDryRun(opts) {
  if (statusSink) {
    statusSink.finish('failed', {
      outcome: 'dry_run',
      message: '演练模式：未做任何变更（代理只执行 --apply）',
    });
  }
  log('演练模式：未做任何改动。确认无误后加 --apply 执行。');
  return opts.dryRun ? 0 : 2;
}

/** 真正执行七步。任何一步 fail 都会抛错，不会继续往下走 */
async function executePlan({ confPath, active, target, targetPort, parsed, plan, opts }) {
  const state = { ...plan, startedAt: new Date().toISOString(), steps: [] };
  // 打印**实际生效值**：--apply 下 policy.parseArgs 会把下限抬到 MIN_OBSERVE_SEC
  log(`观察窗口实际生效值：${opts.observeSec}s（--apply 下限 ${policy.MIN_OBSERVE_SEC}s）`);
  const step = (name, detail = '') => {
    const entry = { name, detail, at: new Date().toISOString() };
    state.steps.push(entry);
    if (statusSink) statusSink.step(entry);
    log(`▶ ${name}${detail ? `：${detail}` : ''}`);
  };

  // 0. 离线模式前置：包必须已经在本机 docker 里。
  //    排在最前不是抠顺序——这是整条链上唯一「不碰数据、只读本地状态」的判据，
  //    该在付出一次全量备份的代价之前就把「包没导入」这件事拒绝掉。
  if (opts.offline) {
    step('assert-local-image', parsed.ref);
    assertLocalImage(parsed.ref);
  }

  // 1. 备份先行。失败即中止——此时尚未改动任何东西，是最便宜的失败点
  step('backup');
  run('bash', [path.join(ROOT, 'scripts', 'backup-mongo.sh')]);

  // 2. 起备色。--no-deps：绝不让 compose 顺带重建 mongo/redis（那才是真停机）
  step('start-target', `${SERVICE_BY_COLOR[target]} @ ${parsed.digest}`);
  // --no-build 不是优化：compose 文件里 app 段带 build:，少了它 `up` 会在部署机上
  // 重新构建一遍本仓库当前源码，并把标签指过去——线上跑的就不再是请求里那个 digest，
  // 而审计记录、镜像白名单校验全是对着 digest 做的（“升了，但升的不是那个版本”）。
  run('docker', compose('up', '-d', '--no-build', '--no-deps', SERVICE_BY_COLOR[target]), {
    [IMAGE_ENV_BY_COLOR[target]]: parsed.ref,
  });

  // 3. 就绪门控
  step('wait-readyz', `port ${targetPort}, timeout ${opts.readyzTimeoutSec}s`);
  const ready = await waitReadyz(targetPort, opts.readyzTimeoutSec, 3);
  if (!ready.ok) {
    // 判决已定，先抓现场再收尾：readyz 只给一句判据，根因在容器日志里，而
    // 抓取必须在 stopQuietly **之前**——停完容器这批输出就只剩 docker 自己记的部分。
    const targetLogs = captureTargetLogs(target);
    recordState({
      ...state,
      outcome: 'aborted_not_ready',
      reason: ready.reason,
      targetLogsTail: targetLogs,
    });
    // 未切流的分支要顺手停掉备色：它占着 3001、连着同一个库，还会被 Prometheus 抓成
    // 一个永远不健康的目标（BackendDown / MongoUnavailable 从此长鸣）。
    // 用 stop 而不是 rm：容器日志还在，排查按 docker logs 看。
    stopQuietly(target, '备色未就绪');
    fail(
      `备色未就绪（${ready.reason}）。旧色仍在服务，未切流。${logAppendix(targetLogs)}`,
      'aborted_not_ready'
    );
  }

  // 4. 迁移：用新版本的代码跑（备色容器里就是新镜像）
  step('migrate-up');
  try {
    run(
      'docker',
      compose(
        'run',
        '--rm',
        '--no-deps',
        SERVICE_BY_COLOR[target],
        'node',
        'node_modules/.bin/migrate-mongo',
        'up'
      ),
      { [IMAGE_ENV_BY_COLOR[target]]: parsed.ref }
    );
  } catch (_) {
    recordState({ ...state, outcome: 'aborted_migrate_failed' });
    fail('迁移失败。未切流，旧色继续服务；备色容器保留以便排查。', 'aborted_migrate_failed');
  }

  // 5-6. 切流 + 观察 + 失败回滚
  await switchAndVerify({ confPath, active, target, targetPort, opts, state, step });

  // 7. 停旧色：stop 而非 rm，保留回滚能力。
  //
  // 这一步失败**不得**把整次升级判成失败：此刻流量已经在新色、观察期已通过，
  // 线上事实是「升级成功、旧色容器还在跑」。报 failed 会让运维按失败处置
  //（甚至发起回滚），把一次成功的升级变成事故。只记 warning。
  let stopWarning = '';
  step('stop-previous', SERVICE_BY_COLOR[active.color]);
  try {
    run('docker', compose('stop', SERVICE_BY_COLOR[active.color]));
  } catch (err) {
    const detail = Number.isInteger(err && err.status)
      ? `退出码 ${err.status}`
      : '原因见宿主 journal';
    stopWarning =
      `旧色容器 ${SERVICE_BY_COLOR[active.color]} 停止失败（${detail}）；` +
      '本次升级已成功（流量在新色），请人工确认旧色是否仍在运行';
    process.stderr.write(`[hot-upgrade] 警告：${stopWarning}\n`);
  }

  state.outcome = 'success';
  state.finishedAt = new Date().toISOString();
  if (stopWarning) state.warnings = [stopWarning];
  recordState(state);
  if (statusSink) statusSink.finish('succeeded', { outcome: 'success', message: stopWarning });
  log(`升级完成：${active.color} -> ${target}（${parsed.digest}）`);
  log(
    `回滚方式：把 upstream 改回 ${active.port} 并 reload，然后 start ${SERVICE_BY_COLOR[active.color]}`
  );
}

async function main() {
  const opts = policy.parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    return 0;
  }

  statusSink = createStatusSink(opts.statusFile);
  const ctx = buildPlan(opts);
  if (!opts.apply || opts.dryRun) return reportDryRun(opts);
  await executePlan({ ...ctx, opts });
  return 0;
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => fail(err && err.message ? err.message : String(err)));
}

module.exports = { main, probeReadyz, waitReadyz, observe, buildLogSnippet };
