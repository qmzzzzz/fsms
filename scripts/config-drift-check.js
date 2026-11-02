'use strict';

/**
 * 部署面配置漂移检测（M-05）
 *
 * 问题：安全基线里最容易被悄悄改掉的不是代码，是**部署配置**——把容器的 read_only 删掉、
 * 给容器加回 CAP_SYS_ADMIN、把 nginx 的 TLS 协议降级、从 .env.example 里删掉一个必填密钥。
 * 这些改动都能过全部代码门禁，因为它们改的是 YAML 与配置模板，不是 .js。
 *
 * 做法：把「安全相关配置面」抽成逐项摘要（item -> sha256 前 16 位），与
 * deployment/config-drift-baseline.json 对账，输出 added / removed / changed 三类漂移。
 * 只输出条目名与状态，**不输出取值**：配置模板里可能夹带密钥样例，回显等于把基线变成泄露面。
 *
 * 边界（如实声明）：本脚本检的是仓库内的配置面（compose / Dockerfile / nginx 模板 / .env.example），
 * 也就是漂移被引入的地方。它不读 process.env——容器里实际生效的值由启动期断言与
 * config/validate.js 负责，因此本脚本不能替代「运行时配置与基线对账」。
 *
 * 退出码：0 无漂移；1 有漂移；2 输入不可解析或基线缺失。
 * 用法：node scripts/config-drift-check.js [--json] [--update]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const BASELINE_PATH = path.join(ROOT, 'deployment/config-drift-baseline.json');

// 容器安全相关标志：出现即入账，取值参与摘要（新增/删除/改值都会体现为漂移）
const COMPOSE_FLAGS = [
  'read_only',
  'privileged',
  'cap_drop',
  'cap_add',
  'security_opt',
  'user',
  'tmpfs',
  'network_mode',
  'pid',
  'ipc',
  'init',
  'userns_mode',
  'networks',
  'healthcheck',
];

// nginx 模板里参与账面的指令（TLS 与响应头）
const NGINX_DIRECTIVES = [
  'ssl_protocols',
  'ssl_ciphers',
  'ssl_prefer_server_ciphers',
  'ssl_session_tickets',
  'server_tokens',
  'add_header Strict-Transport-Security',
  'add_header X-Content-Type-Options',
  'add_header X-Frame-Options',
];

// .env.example 里「安全相关」的键名前缀：出现在模板里说明部署者能配到它
const ENV_KEY_PREFIXES = [
  'JWT_',
  'MFA_',
  'AUDIT_',
  'BACKUP_',
  'TLS_',
  'HTTPS_',
  'IP_',
  'CORS_',
  'PII_',
  'HMAC_',
  'ENCRYPTION_',
  'UPGRADE_',
  'TRUSTED_PROXY_',
  'ALLOWED_HOSTS',
  'PASSWORD_',
  'SESSION_',
  'SEED_',
];

const digestOf = (value) =>
  crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 16);

const readIfExists = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null);

/** 取容器服务的若干标志。yaml 不可解析时抛错（宁可报 2，也不静默给空账面） */
function composeItems(rootDir) {
  const file = path.join(rootDir, 'docker-compose.yml');
  const text = readIfExists(file);
  if (text === null) return {};
  const yaml = require('js-yaml');
  // compose 的 --wait 用法里会写 !override / !reset 这类自定义 tag；js-yaml 默认把它们当未知 tag
  // 直接抛错。这里只剥掉**行尾位置**的 tag 本身（取值里的 '!' 不动），保留键与后续块结构。
  const withoutTags = text.replace(/^(\s*[\w.-]+:\s*)![A-Za-z][\w-]*\s*$/gm, '$1');
  const parsed = yaml.load(withoutTags);
  const services = (parsed && parsed.services) || {};
  const items = {};
  for (const [name, service] of Object.entries(services)) {
    if (!service || typeof service !== 'object') continue;
    for (const flag of COMPOSE_FLAGS) {
      if (service[flag] === undefined) continue;
      items['compose:' + name + ':' + flag] = digestOf(service[flag]);
    }
    const memory =
      service.deploy && service.deploy.resources && service.deploy.resources.limits
        ? service.deploy.resources.limits.memory
        : undefined;
    if (memory !== undefined) items['compose:' + name + ':memory_limit'] = digestOf(memory);
  }
  return items;
}

/** Dockerfile：最后一条 USER 与是否存在 HEALTHCHECK（跑成 root 是配置层的降权失败） */
function dockerfileItems(rootDir) {
  const text = readIfExists(path.join(rootDir, 'Dockerfile'));
  if (text === null) return {};
  const items = {};
  const lines = text.split(/\r?\n/);
  const users = lines.filter((line) => /^\s*USER\s+/i.test(line));
  if (users.length > 0) items['dockerfile:USER'] = digestOf(users[users.length - 1].trim());
  items['dockerfile:HEALTHCHECK'] = digestOf(
    lines.some((line) => /^\s*HEALTHCHECK\s+/i.test(line))
  );
  return items;
}

/**
 * nginx 模板：逐条指令摘要（值可能含 ssl_ciphers 长串，同样只存摘要）。
 *
 * 【为什么必须把同一指令的**全部**副本收进同一个摘要】
 * 同一指令在模板里出现多份是常态而非异常：本仓 `deployment/nginx.conf.example` 里
 * `server_tokens` / HSTS / `X-Frame-Options` 各出现 3 次——443、80/跳转、另一处 server
 * 各下一份。原实现是逐行 `items['nginx:' + directive] = digest(本行)`，也就是**覆盖赋值**，
 * 账面上最终只剩**最后一份**。
 * 实测后果（第26轮审计探针 work/r26-ngx-copies-probe.js，修前原文见 work/r26-ngx-copies-before.log）：
 *   改第 197 行（第 1 份 HSTS）⇒ 报「无漂移」
 *   改第 266 行（第 2 份 HSTS）⇒ 报「无漂移」
 *   把第 266 行整行注释掉      ⇒ 报「无漂移」
 *   改第 312 行（第 3 份）     ⇒ 才报 changed
 * 即 3 份里 2 份没人看着。而「某个 server 块的安全头被摘掉 / 被降级」正是这道闸要拦的事，
 * 它属于「视野不覆盖」而不是风格问题：闸照样绿，因为绿是从**别的副本**得来的。
 *
 * 修法：按指令收集**全部**命中行（保持文件内顺序）、归一化空白后 join 成一份再取摘要。
 * 于是「改任意一份 / 删任意一份 / 整行注释掉其中一份 / 新增一份」都会改变摘要。
 *
 * 【为什么不用行号或「第 n 份」做键】在模板前面插一行（哪怕只是加一句注释）会让后续
 * 所有键的序号整体错位、一次性造出一片与安全无关的假漂移——那是「会误报的尺子比没有更坏」
 * 的形状：人被误报训练几轮之后就不再看这条闸的输出。
 */
function nginxItems(rootDir) {
  const text = readIfExists(path.join(rootDir, 'deployment/nginx.conf.example'));
  if (text === null) return {};
  // 先归一化再匹配：指令名与参数之间写成多个空格/制表符的那一行同样是「一份副本」，
  // 拿未归一化的行去 startsWith 会让它静静落空。本仓模板当前没有这种写法（实测 8 条指令
  // 的 strict/norm 命中数逐一相同，见 work/r26-ngx-strict-norm.log），但这是同一类「视野不覆盖」，
  // 顺手并进同一个归一化里不增加任何复杂度。
  const lines = text.split(/\r?\n/).map((line) => line.trim().replace(/\s+/g, ' '));
  const items = {};
  for (const directive of NGINX_DIRECTIVES) {
    const hits = lines.filter((line) => line.startsWith(directive));
    // 一条都没命中 ⇒ 不入账（保持既有语义：指令被整段删掉时该键消失 ⇒ 报 removed）
    if (hits.length === 0) continue;
    items['nginx:' + directive] = digestOf(hits.join('\n'));
  }
  return items;
}

/** .env.example：安全相关键的**存在性**（键名入账面，取值不入） */
function envExampleItems(rootDir) {
  const text = readIfExists(path.join(rootDir, '.env.example'));
  if (text === null) return {};
  const items = {};
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=/.exec(line);
    if (!match) continue;
    const key = match[1];
    if (!ENV_KEY_PREFIXES.some((prefix) => key.startsWith(prefix))) continue;
    items['env-example:' + key] = digestOf('present');
  }
  return items;
}

/** 全量账面：item -> 摘要。任何一处来源缺失都只跳过该来源（文件被删本身就是漂移的另一半）。 */
function collectItems(rootDir) {
  return Object.assign(
    {},
    composeItems(rootDir),
    dockerfileItems(rootDir),
    nginxItems(rootDir),
    envExampleItems(rootDir)
  );
}

/** 纯函数：逐项对账，返回按条目名排序的漂移清单（只含条目名与状态，不含取值） */
function diffItems(baseline, current) {
  const drift = [];
  for (const [item, digest] of Object.entries(current)) {
    if (!(item in baseline)) drift.push({ item, status: 'added' });
    else if (baseline[item] !== digest) drift.push({ item, status: 'changed' });
  }
  for (const item of Object.keys(baseline)) {
    if (!(item in current)) drift.push({ item, status: 'removed' });
  }
  return drift.sort((a, b) => a.item.localeCompare(b.item));
}

function loadBaseline(file = BASELINE_PATH) {
  const text = readIfExists(file);
  if (text === null) return null;
  const parsed = JSON.parse(text);
  return parsed && parsed.items ? parsed.items : null;
}

function main(argv) {
  const asJson = argv.includes('--json');
  const update = argv.includes('--update');

  let current;
  try {
    current = collectItems(ROOT);
  } catch (error) {
    process.stderr.write('配置面不可解析，拒绝给出结论：' + error.message + '\n');
    return 2;
  }

  if (update) {
    const payload = {
      note: 'M-05 部署面配置基线：由 scripts/config-drift-check.js --update 生成',
      items: current,
    };
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(payload, null, 2) + '\n', 'utf8');
    process.stdout.write('已重写基线：' + Object.keys(current).length + ' 项\n');
    return 0;
  }

  let baseline;
  try {
    baseline = loadBaseline();
  } catch (error) {
    process.stderr.write('基线不可解析：' + error.message + '\n');
    return 2;
  }
  if (baseline === null) {
    process.stderr.write(
      '基线缺失：先执行 node scripts/config-drift-check.js --update 并提交结果\n'
    );
    return 2;
  }

  const drift = diffItems(baseline, current);
  if (asJson) {
    process.stdout.write(
      JSON.stringify({ drift, baselineItems: Object.keys(baseline).length }, null, 2) + '\n'
    );
  } else if (drift.length === 0) {
    process.stdout.write('部署面配置无漂移（' + Object.keys(baseline).length + ' 项）\n');
  } else {
    for (const entry of drift)
      process.stdout.write(entry.status.toUpperCase() + '  ' + entry.item + '\n');
    process.stdout.write('漂移 ' + drift.length + ' 项；确认是有意变更后执行 --update 并提交\n');
  }
  return drift.length === 0 ? 0 : 1;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = {
  COMPOSE_FLAGS,
  NGINX_DIRECTIVES,
  ENV_KEY_PREFIXES,
  collectItems,
  diffItems,
  loadBaseline,
  BASELINE_PATH,
};
