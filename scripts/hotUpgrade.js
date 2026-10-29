#!/usr/bin/env node
/**
 * 蓝绿热升级（单机 docker-compose 拓扑，零停机）
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
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const policy = require('./hotUpgradePolicy');

const ROOT = path.resolve(__dirname, '..');
const COMPOSE_FILE = process.env.HOT_UPGRADE_COMPOSE_FILE || path.join(ROOT, 'docker-compose.yml');
const NGINX_BIN = process.env.HOT_UPGRADE_NGINX_BIN || 'nginx';
/** 实际部署里 nginx 主配置的位置；容器化 nginx 或自编译路径不同时用 --nginx-conf 覆盖 */
const DEFAULT_NGINX_CONF = process.env.HOT_UPGRADE_NGINX_CONF || '/etc/nginx/nginx.conf';

/** 颜色 ↔ compose 服务名 / 镜像变量。与 policy 的 PORT_BY_COLOR 必须一致 */
const SERVICE_BY_COLOR = { blue: 'app', green: 'app-green' };
const IMAGE_ENV_BY_COLOR = { blue: 'APP_IMAGE', green: 'APP_IMAGE_NEXT' };

const log = (msg) => process.stdout.write(`[hot-upgrade] ${msg}\n`);
const fail = (msg) => {
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

/** compose 前缀：显式 -f，避免命令受 cwd 影响（cwd 决定项目名，项目名决定卷） */
const compose = (...args) => ['compose', '-f', COMPOSE_FILE, ...args];

/**
 * 原子写配置：先写临时文件再 rename。
 *
 * 直接 writeFileSync 覆盖时，进程若在写到一半被杀，nginx 配置会变成半截文本——
 * 下一次 reload 直接失败，且现场看起来像「脚本把配置写坏了」。rename 在同分区是原子的。
 */
function writeConfAtomically(file, text) {
  const tmp = `${file}.hot-upgrade.tmp`;
  fs.writeFileSync(tmp, text, 'utf8');
  fs.renameSync(tmp, file);
}

/** 探一次 readyz；返回 { ok, reason }。网络错误也算不 ok，不吞 */
async function probeReadyz(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/readyz`, {
      headers: { Accept: 'application/json' },
    });
    const body = await res.json().catch(() => null);
    return policy.evaluateReadyz(res.status, body);
  } catch (err) {
    return { ok: false, reason: `连接失败：${err.message}` };
  }
}

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

/** 把 upstream 切到指定色并 reload；nginx -t 不通过则原样回滚文件 */
function switchTraffic(confPath, targetColor) {
  const original = fs.readFileSync(confPath, 'utf8');
  const next = policy.renderUpstream(original, targetColor);
  if (next === original) {
    log(`upstream 已在 ${targetColor}，无需改配置`);
  } else {
    writeConfAtomically(confPath, next);
  }
  try {
    run(NGINX_BIN, ['-t']);
  } catch (_) {
    // 配置自检失败：把文件恢复成原样，避免留下一个「nginx 起不来」的现场
    writeConfAtomically(confPath, original);
    throw new Error('nginx -t 未通过，已恢复原配置');
  }
  run(NGINX_BIN, ['-s', 'reload']);
  return original;
}

/** 留痕：每次升级写一份本地记录（审计链之外的第二份证据，便于事后复盘） */
function recordState(state) {
  const dir = path.join(ROOT, 'logs');
  try {
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(
      dir,
      `hot-upgrade-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    );
    fs.writeFileSync(file, JSON.stringify(state, null, 2), 'utf8');
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
    fail(`切流失败：${err.message}`);
  }

  step('observe', `${opts.observeSec}s`);
  const observed = await observe(targetPort, opts.observeSec, 5);
  if (observed.ok) return;

  step('rollback', `切回 ${active.color}`);
  try {
    switchTraffic(confPath, active.color);
  } catch (err) {
    // 最坏情况：流量可能还在新色，旧色也还在跑。必须把现场原样说清楚，
    // 而不是含糊地报「回滚失败」——运维要据此决定是手工切回还是直接停新色。
    recordState({ ...state, outcome: 'rollback_failed', reason: err.message });
    fail(
      `回滚切流失败（${err.message}）。当前流量可能仍在新色，` +
        `旧色容器 ${SERVICE_BY_COLOR[active.color]} 仍在运行。请立即人工确认。`
    );
  }
  recordState({ ...state, outcome: 'rolled_back', reason: observed.reason });
  fail(`观察期未通过（${observed.reason}），已切回 ${active.color}。`);
}

async function main() {
  const opts = policy.parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(
      [
        '蓝绿热升级。默认只演练，加 --apply 才真正执行。',
        '',
        '  --image <ref>            新版本镜像，必须是 registry/repo@sha256:<64hex>',
        '  --nginx-conf <path>      nginx 配置路径（含 upstream fsms_app）',
        '  --readyz-timeout <sec>   等备色就绪的超时，默认 180',
        '  --observe-seconds <sec>  切流后观察窗口，默认 300',
        '  --apply                  真正执行（缺省为演练）',
        '  --help                   本帮助',
        '',
      ].join('\n')
    );
    return 0;
  }

  const confPath = opts.nginxConf || DEFAULT_NGINX_CONF;
  if (!fs.existsSync(confPath)) fail(`nginx 配置不存在：${confPath}（用 --nginx-conf 指定）`);

  const conf = fs.readFileSync(confPath, 'utf8');
  const active = policy.parseActiveUpstream(conf);
  const target = active.color === 'blue' ? 'green' : 'blue';
  const targetPort = policy.PORT_BY_COLOR[target];

  const parsed = policy.parseImageRef(opts.image);
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
    nginxConf: confPath,
    observeSec: opts.observeSec,
  };

  log('升级计划：');
  for (const [k, v] of Object.entries(plan)) log(`  ${k} = ${v}`);

  if (!opts.apply || opts.dryRun) {
    log('演练模式：未做任何改动。确认无误后加 --apply 执行。');
    return opts.dryRun ? 0 : 2;
  }

  const startedAt = new Date().toISOString();
  const state = { ...plan, startedAt, steps: [] };
  const step = (name, detail = '') => {
    state.steps.push({ name, detail, at: new Date().toISOString() });
    log(`▶ ${name}${detail ? `：${detail}` : ''}`);
  };

  // 1. 备份先行。失败即中止——此时尚未改动任何东西，是最便宜的失败点
  step('backup');
  run('bash', [path.join(ROOT, 'scripts', 'backup-mongo.sh')]);

  // 2. 起备色。--no-deps：绝不让 compose 顺带重建 mongo/redis（那才是真停机）
  step('start-target', `${SERVICE_BY_COLOR[target]} @ ${parsed.digest}`);
  run('docker', compose('--profile', 'green', 'up', '-d', '--no-deps', SERVICE_BY_COLOR[target]), {
    [IMAGE_ENV_BY_COLOR[target]]: parsed.ref,
  });

  // 3. 就绪门控
  step('wait-readyz', `port ${targetPort}, timeout ${opts.readyzTimeoutSec}s`);
  const ready = await waitReadyz(targetPort, opts.readyzTimeoutSec, 3);
  if (!ready.ok) {
    recordState({ ...state, outcome: 'aborted_not_ready', reason: ready.reason });
    fail(`备色未就绪（${ready.reason}）。旧色仍在服务，未切流。`);
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
    fail('迁移失败。未切流，旧色继续服务；备色容器保留以便排查。');
  }

  // 5-6. 切流 + 观察 + 失败回滚
  await switchAndVerify({ confPath, active, target, targetPort, opts, state, step });

  // 7. 停旧色：stop 而非 rm，保留回滚能力
  step('stop-previous', SERVICE_BY_COLOR[active.color]);
  run('docker', compose('stop', SERVICE_BY_COLOR[active.color]));

  state.outcome = 'success';
  state.finishedAt = new Date().toISOString();
  recordState(state);
  log(`升级完成：${active.color} -> ${target}（${parsed.digest}）`);
  log(
    `回滚方式：把 upstream 改回 ${active.port} 并 reload，然后 start ${SERVICE_BY_COLOR[active.color]}`
  );
  return 0;
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => fail(err && err.message ? err.message : String(err)));
}

module.exports = { main, probeReadyz, waitReadyz, observe };
