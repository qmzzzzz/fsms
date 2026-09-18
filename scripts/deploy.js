#!/usr/bin/env node
/**
 * 一键部署（D-1）：拉取镜像 → 备份 → 迁移 → 切换 → 健康门禁 → 失败自动回滚
 *
 * 为什么需要这个脚本：
 *   此前发布是一串手敲命令（compose build / up -d / curl /health），散落在
 *   README 的「运维 Runbook」里。手敲的发布流程有三个固有缺陷：
 *     ① 顺序容易漏（最典型：忘了备份就发布，出问题才发现没有回滚抓手）；
 *     ② 判据靠人眼（「看起来起来了」不等于 /readyz 通过）；
 *     ③ 失败后的动作靠临场反应，而不是脚本化的既定路径。
 *   本脚本把这条路径固化为**一条命令**，把每个判据变成可失败的门禁。
 *
 * 设计原则（与仓库既有护栏一致）：
 *   - **fail-closed**：前置条件不满足即拒绝执行，不在缺条件时「尽力而为」；
 *   - **先备份后发布**：deployment/rollback-drill.md 的铁律——没有备份的发布
 *     不具备回滚资格。备份失败即中止，不进入后续步骤；
 *   - **回滚自动触发**：健康门禁不通过时自动切回上一版本，而不是等人工发现；
 *   - **可干跑**：--dry-run 打印完整计划与判据，便于评审与演练。
 *
 * 用法：
 *   APP_IMAGE=ghcr.io/owner/repo:sha-abc1234 node scripts/deploy.js
 *   APP_IMAGE=... node scripts/deploy.js --dry-run      # 只打印计划
 *   APP_IMAGE=... node scripts/deploy.js --skip-backup  # 明确跳过备份（仅演练用）
 *   APP_IMAGE=... node scripts/deploy.js --no-rollback  # 关闭失败自动回滚
 *
 * 退出码：
 *   0 = 部署成功（且健康门禁通过）
 *   1 = 部署失败（健康门禁未通过；已尝试回滚）
 *   2 = 前置条件不满足（拒绝执行，未做任何变更）
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// 与仓库其余入口（src/config/index.js、scripts/*.js 维护脚本）同一口径：先加载 .env。
// 不加载会出现一个实测过的陷阱：docker compose 自己会读 .env，而本脚本是 Node，
// 不读就拿不到里面的 APP_IMAGE / CORS_ORIGIN——操作员按 README 把变量写进 .env
// 后运行，会被前置校验抦下并报「APP_IMAGE 未设置」，而 compose 层面却明明能读到。
// 已设置的真实环境变量优先（dotenv 默认不覆盖已存在的值）。
require('dotenv').config({ path: path.join(ROOT, '.env'), quiet: true });

// ============================================================
// 纯逻辑层（不产生副作用，可被测试直接断言）
// ============================================================

/** 部署所需的密钥文件名（与 docker-compose.yml 的 secrets 段一一对应） */
const REQUIRED_SECRET_FILES = [
  'jwt_secret',
  'jwt_refresh_secret',
  'aes_secret_key',
  'hmac_secret',
  'mongodb_uri',
  'admin_initial_password',
  'mongo_root_username',
  'mongo_root_password',
  'grafana_admin_password',
];

/**
 * 校验前置条件。返回 { ok, errors, warnings }——**不打印、不退出**，
 * 由调用方决定如何呈现。这样测试可以直接断言校验结果，
 * 而不是去抓 stdout 文本。
 *
 * @param {Record<string,string|undefined>} env 环境变量（注入以便测试）
 * @param {typeof fs} fsImpl 文件系统实现（注入以便测试）
 */
function validatePreflight(env, fsImpl) {
  const errors = [];
  const warnings = [];

  // ① 镜像必须显式指定：
  //    默认值 fire-safety-app:local 是给本地开发用的，用它发布等于把
  //    「本机某个未版本化的构建」推上生产——线上跑的是哪个 commit 无从回答。
  const image = (env.APP_IMAGE || '').trim();
  if (!image) {
    errors.push(
      'APP_IMAGE 未设置。生产发布必须显式指定带版本 tag 的镜像（如 ghcr.io/<owner>/<repo>:sha-<7位>）。'
    );
  } else if (image === 'fire-safety-app:local') {
    errors.push(
      'APP_IMAGE 不能是本地开发默认值 fire-safety-app:local（该 tag 指向本机构建，无法回答线上是哪个 commit）。'
    );
  }

  // ② CORS_ORIGIN 必填：compose 的 `:?` 语法会在缺失时直接拒绝整个项目，
  //    在这里提前拦下能给出更清楚的提示（而不是让 compose 抛一段插值报错）。
  if (!(env.CORS_ORIGIN || '').trim()) {
    errors.push('CORS_ORIGIN 未设置（生产禁止通配符，须为明确的前端域名白名单）。');
  }

  // ③ 密钥目录：9 个文件一个都不能少。
  //    缺任何一个都会让容器起不来或带空密钥运行，且失败点在启动期、
  //    现象是「服务反复重启」，排查成本高——不如在这里一次列全。
  const secretsDir = path.join(ROOT, 'secrets');
  if (!fsImpl.existsSync(secretsDir)) {
    errors.push(
      `密钥目录不存在：${secretsDir}（先执行 node scripts/generate-secrets.js --out ./secrets）`
    );
  } else {
    const missing = [];
    for (const name of REQUIRED_SECRET_FILES) {
      const p = path.join(secretsDir, name);
      if (!fsImpl.existsSync(p)) {
        missing.push(name);
      } else if (fsImpl.readFileSync(p, 'utf8').trim() === '') {
        // 空文件比缺文件更隐蔽：文件存在、compose 校验通过、应用却拿到空串
        missing.push(`${name}（内容为空）`);
      }
    }
    if (missing.length > 0) {
      errors.push(`密钥文件缺失或为空：${missing.join(', ')}`);
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

/**
 * 生成部署步骤序列。
 *
 * 抽成纯函数是为了让「顺序」本身可被断言——发布流程最脆弱的
 * 恰恰是顺序（备份必须在迁移之前、健康门禁必须在切换之后）。
 */
function buildPlan({ skipBackup = false, noRollback = false, healthTimeoutMs = 120000 } = {}) {
  const steps = [];
  steps.push({ id: 'preflight', desc: '校验前置条件（镜像 / CORS_ORIGIN / 密钥文件）' });
  steps.push({ id: 'record-current', desc: '记录当前镜像，作为回滚目标' });
  if (!skipBackup) {
    steps.push({ id: 'backup', desc: '全量备份数据库（无备份则不具备回滚资格）' });
  }
  steps.push({ id: 'pull', desc: '拉取目标镜像' });
  steps.push({ id: 'migrate-status', desc: '查看待应用迁移（留痕）' });
  steps.push({ id: 'migrate-up', desc: '应用数据库迁移' });
  steps.push({ id: 'up', desc: '滚动切换 app 容器' });
  steps.push({
    id: 'health',
    desc: `健康门禁：轮询 /readyz 至通过（上限 ${Math.round(healthTimeoutMs / 1000)}s）`,
  });
  if (!noRollback) {
    steps.push({ id: 'rollback-on-failure', desc: '健康门禁失败时自动回滚到上一镜像' });
  }
  return steps;
}

/**
 * 回滚决策：给定健康门禁结果，决定是否需要回滚。
 * 单独成函数是为了让「什么情况下该回滚」可被逐条断言。
 */
function decideRollback({ healthOk, noRollback, hasPreviousImage }) {
  if (healthOk) return { rollback: false, reason: '健康门禁通过' };
  if (noRollback) return { rollback: false, reason: '已显式禁用自动回滚（--no-rollback）' };
  if (!hasPreviousImage) {
    return {
      rollback: false,
      reason: '无可回滚目标（首次部署或未记录到上一版本镜像）——需人工介入',
    };
  }
  return { rollback: true, reason: '健康门禁未通过且存在上一版本镜像' };
}

// ============================================================
// 副作用层：仅在作为脚本直接运行时执行
// ============================================================

/** 所有 compose / docker 命令的公共参数：显式指定 compose 文件，避免受 cwd 影响 */
const COMPOSE_ARGS = ['compose', '-f', path.join(ROOT, 'docker-compose.yml')];

/** 执行命令并实时透传输出；失败时抛错（由调用方决定是否降级处理） */
function run(file, args, opts = {}) {
  console.log(`$ ${[file, ...args].join(' ')}`);
  return execFileSync(file, args, {
    cwd: ROOT,
    stdio: 'inherit',
    windowsHide: true,
    ...opts,
  });
}

/** 执行命令并捕获输出（用于读取状态，失败时返回 null 而不抛出） */
function tryCapture(file, args) {
  try {
    return execFileSync(file, args, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    }).trim();
  } catch (_) {
    return null;
  }
}

/**
 * 读取当前正在运行的 app 镜像引用（作为回滚目标）。
 *
 * 取的是容器实际使用的镜像（docker inspect 的 Config.Image），
 * 而不是 compose 文件里的声明——两者可能不同（例如上次用 APP_IMAGE 覆盖启动），
 * 用声明值回滚会切到另一个版本。
 * 首次部署（容器不存在）时返回 null，调用方据此判定「无回滚目标」。
 */
function readCurrentImage() {
  const id = tryCapture('docker', [...COMPOSE_ARGS, 'ps', '-q', 'app']);
  if (!id) return null;
  // 可能有多行（多副本），取第一行即可——本项目 app 为单副本
  const firstId = id.split(/\r?\n/).filter(Boolean)[0];
  if (!firstId) return null;
  return tryCapture('docker', ['inspect', '--format={{.Config.Image}}', firstId]);
}

/**
 * 健康门禁：轮询 /readyz 直到 200 或超时。
 *
 * 为什么用 /readyz 而不是 /health：
 *   /health 只证明进程活着（永远返回 200，连 Mongo 都没连上也是 200）。
 *   /readyz 带 Mongo ping，失败返回 503——这才是「能干活」的判据。
 *   用 /health 做门禁会让「起来了但连不上库」的版本通过发布。
 *
 * 通过宿主映射端口访问（compose 里 app 绑定 127.0.0.1:3000）。
 */
async function waitForReady({ timeoutMs, intervalMs = 2000, probeUrl }) {
  const deadline = Date.now() + timeoutMs;
  let lastReason = '尚未探测';
  while (Date.now() < deadline) {
    const out = tryCapture('curl', [
      '--silent',
      '--output',
      '/dev/null',
      '--write-out',
      '%{http_code}',
      '--max-time',
      '5',
      probeUrl,
    ]);
    if (out === '200') return { ok: true, reason: 'readyz=200' };
    lastReason = out === null ? 'curl 失败（服务未监听？）' : `readyz=${out}`;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return { ok: false, reason: `超时（最后一次：${lastReason}）` };
}

/**
 * 记录回滚目标：读当前运行镜像并打印。返回镜像引用或 null（首次部署）。
 * 单独成函数，让 main() 只表达「步骤顺序」，细节各自内聚。
 */
function recordRollbackTarget() {
  const previousImage = readCurrentImage();
  console.log(
    previousImage
      ? `✓ 当前镜像（回滚目标）: ${previousImage}`
      : '· 未发现运行中的 app 容器（首次部署）'
  );
  return previousImage;
}

/** 备份数据库；失败即中止（无备份不具备回滚资格）。skip 为 true 时仅告警。 */
function backupDatabase(skip) {
  if (skip) {
    console.warn('⚠ 已跳过备份（--skip-backup）——本次发布不具备数据级回滚能力');
    return;
  }
  const uri = fs.readFileSync(path.join(ROOT, 'secrets', 'mongodb_uri'), 'utf8').trim();
  console.log('\n[备份] 全量备份数据库……');
  try {
    run('bash', [path.join(ROOT, 'scripts', 'backup-mongo.sh'), path.join(ROOT, 'backups')], {
      env: { ...process.env, MONGODB_URI: uri },
    });
    console.log('✓ 备份完成');
  } catch (err) {
    console.error('✗ 备份失败，中止部署（无备份不具备回滚资格）');
    process.exit(1);
  }
}

/** 拉取目标镜像；失败即中止（线上保持原版本运行）。 */
function pullImage() {
  console.log('\n[镜像] 拉取目标镜像……');
  try {
    run('docker', [...COMPOSE_ARGS, 'pull', 'app']);
  } catch (err) {
    console.error('✗ 镜像拉取失败，中止部署（线上保持原版本运行）');
    process.exit(1);
  }
}

/** 迁移：先打印当前位点留痕，再应用；失败即中止（未切换流量）。 */
function applyMigrations() {
  const migrateArgv = [
    ...COMPOSE_ARGS,
    'run',
    '--rm',
    '--no-deps',
    'app',
    'node',
    'node_modules/.bin/migrate-mongo',
  ];
  console.log('\n[迁移] 当前位点：');
  run('docker', [...migrateArgv, 'status']);
  console.log('\n[迁移] 应用待执行迁移……');
  try {
    run('docker', [...migrateArgv, 'up']);
  } catch (err) {
    console.error('✗ 迁移失败，中止部署（线上保持原版本运行，未切换流量）');
    process.exit(1);
  }
}

/** 滚动切换 app 容器；失败即中止。 */
function switchContainer() {
  console.log('\n[切换] 滚动更新 app 容器……');
  try {
    run('docker', [...COMPOSE_ARGS, 'up', '-d', '--no-build', 'app']);
  } catch (err) {
    console.error('✗ 容器切换失败');
    process.exit(1);
  }
}

/**
 * 回滚到指定镜像并复检健康；回滚失败不抛出（由调用方统一以退出码 1 收口）。
 * 回滚后的复检同样以 /readyz 为准——回滚成功与否要可观测，而非假定。
 */
async function rollbackTo(previousImage, probeUrl, recheckTimeoutMs) {
  console.log(`\n[回滚] 切回上一镜像：${previousImage}`);
  try {
    run('docker', [...COMPOSE_ARGS, 'up', '-d', '--no-build', 'app'], {
      env: { ...process.env, APP_IMAGE: previousImage },
    });
    const recheck = await waitForReady({ timeoutMs: recheckTimeoutMs, probeUrl });
    console.log(
      recheck.ok
        ? `✓ 回滚后服务就绪（${recheck.reason}）`
        : `✗ 回滚后仍未就绪（${recheck.reason}）——需人工介入`
    );
  } catch (err) {
    console.error(`✗ 回滚执行失败——需人工介入：${err.message}`);
  }
}

function parseArgs(argv) {
  return {
    dryRun: argv.includes('--dry-run'),
    skipBackup: argv.includes('--skip-backup'),
    noRollback: argv.includes('--no-rollback'),
    healthTimeoutMs: Number(process.env.DEPLOY_HEALTH_TIMEOUT_MS || 120000),
    // 回滚后复检的等待上限（原为写死 60s）：与健康门禁同样可配，
    // 既让部署环境能按实际启动耗时调，也使端到端测试不必真等 60 秒。
    rollbackTimeoutMs: Number(process.env.DEPLOY_ROLLBACK_TIMEOUT_MS || 60000),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const plan = buildPlan(args);
  const probeUrl = `http://127.0.0.1:${process.env.DEPLOY_PROBE_PORT || '3000'}/readyz`;

  console.log('===== 部署计划 =====');
  plan.forEach((s, i) => console.log(`  ${i + 1}. ${s.desc}`));
  console.log(`  目标镜像: ${process.env.APP_IMAGE || '(未设置)'}`);

  // ---- ① 前置条件（fail-closed：不满足即拒绝，未做任何变更）----
  const pre = validatePreflight(process.env, fs);
  if (!pre.ok) {
    console.error('\n前置条件不满足，拒绝执行（未做任何变更）：');
    for (const e of pre.errors) console.error(`  ✗ ${e}`);
    process.exit(2);
  }
  console.log('✓ 前置条件校验通过');

  if (args.dryRun) {
    console.log('\n--dry-run：仅打印计划，不执行任何变更。');
    process.exit(0);
  }

  // ---- ② 记录回滚目标（必须在切换之前读）----
  const previousImage = recordRollbackTarget();

  // ---- ③ 备份（铁律：先备份后发布）----
  backupDatabase(args.skipBackup);

  // ---- ④~⑤ 拉取镜像 + 迁移 ----
  pullImage();
  applyMigrations();

  // ---- ⑥ 切换 ----
  switchContainer();

  // ---- ⑦ 健康门禁 ----
  console.log(`\n[健康门禁] 轮询 ${probeUrl} ……`);
  const health = await waitForReady({ timeoutMs: args.healthTimeoutMs, probeUrl });
  console.log(health.ok ? `✓ ${health.reason}` : `✗ ${health.reason}`);

  // ---- ⑧ 回滚决策 ----
  const decision = decideRollback({
    healthOk: health.ok,
    noRollback: args.noRollback,
    hasPreviousImage: Boolean(previousImage),
  });
  console.log(`[回滚决策] ${decision.reason}`);

  if (health.ok) {
    console.log('\n✅ 部署成功。');
    process.exit(0);
  }

  if (decision.rollback) {
    await rollbackTo(previousImage, probeUrl, args.rollbackTimeoutMs);
  }
  console.error('\n❌ 部署失败。');
  process.exit(1);
}

// 仅在直接运行时执行副作用（被 require 时只导出纯逻辑，供测试断言）
if (require.main === module) {
  main().catch((err) => {
    console.error(`部署脚本异常：${err.message}`);
    process.exit(1);
  });
}

module.exports = {
  REQUIRED_SECRET_FILES,
  validatePreflight,
  buildPlan,
  decideRollback,
  ROOT,
};
