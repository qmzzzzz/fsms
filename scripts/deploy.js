#!/usr/bin/env node
/**
 * 一键部署（D-1）：拉取镜像 → 备份 → 迁移 → 切换 → 健康门禁 → 失败自动回滚
 * （仅当本次未应用数据库迁移时；有迁移则停住转人工恢复，见 O-2）
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
 *   - **回滚自动触发**：健康门禁不通过时自动切回上一版本——**仅限本次没有应用
 *     数据库迁移的情况**。迁移一旦执行，旧镜像跑在新 schema 上可能写坏数据，
 *     此时脚本停住并转人工恢复，而不是给出「已回滚」的假象（O-2）；
 *   - **可干跑**：--dry-run 打印完整计划、判据与真实 argv（与执行同源），便于评审与演练。
 *
 * 用法：
 *   APP_IMAGE=ghcr.io/owner/repo:sha-abc1234 node scripts/deploy.js
 *   # 工作流路径（deploy.yml）会先在 preflight 里 cosign keyless 验签、把 tag 解析成
 *   # digest 钉死引用 <repo>:<tag>@sha256:<64位hex> 再传入，并置
 *   # DEPLOY_REQUIRE_DIGEST_PIN=true 让本脚本拒绝一切非 digest 引用；
 *   # 手工发布同口径（buildx imagetools inspect <tag> 可取 digest）。
 *   APP_IMAGE=... node scripts/deploy.js --dry-run      # 只打印计划
 *   APP_IMAGE=... node scripts/deploy.js --skip-backup  # 明确跳过备份（仅演练用）
 *   APP_IMAGE=... node scripts/deploy.js --no-rollback  # 关闭失败自动回滚
 *
 * --skip-backup 的连带后果（不是只「少一次备份」）：跳过后**本次发布失去自动回滚资格**
 * （decideRollback 会拒绝在「一份备份都没有」时自动切旧镜像），
 * 健康门禁失败时脚本停在人工介入路径。
 *
 * 退出码：
 *   0 = 部署成功（且健康门禁通过）
 *   1 = 部署失败（健康门禁未通过；按资格判定后可能已回滚）
 *   2 = 前置条件不满足（配置非法 / 镜像 / CORS_ORIGIN+ALLOWED_HOSTS / 密钥文件；
 *       拒绝执行，未做任何变更）
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// 判据全部在 deployPolicy.js：本文件只负责执行外部命令、呈现结果、决定退出码。
const {
  ROOT,
  validatePreflight,
  buildPlan,
  decideRollback,
  isSameImageRef,
  parseAppliedMigrations,
  parseArgs,
} = require('./deployPolicy');
// 命令拼装只有这一处来源（O-5）：--dry-run 打印的 argv 与实际执行的是同一份构造器。
const {
  composeArgs,
  buildPullInvocation,
  buildMigrateInvocation,
  buildUpInvocation,
  buildProbeInvocation,
  buildBackupInvocation,
  buildCommandPlan,
  formatInvocation,
} = require('./deployCommands');

// 与仓库其余入口（src/config/index.js、scripts/*.js 维护脚本）同一口径：先加载 .env。
// 不加载会出现一个实测过的陷阱：docker compose 自己会读 .env，而本脚本是 Node，
// 不读就拿不到里面的 APP_IMAGE / CORS_ORIGIN——操作员按 README 把变量写进 .env
// 后运行，会被前置校验拦下并报「APP_IMAGE 未设置」，而 compose 层面却明明能读到。
// 已设置的真实环境变量优先（dotenv 默认不覆盖已存在的值）。
require('dotenv').config({ path: path.join(ROOT, '.env'), quiet: true });

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

/**
 * 执行命令、捕获并回显输出；失败时先把已捕获的 stdout/stderr 打出来再抛出。
 *
 * 与 run() 的区别：需要解析 stdout（迁移清单）时不能直接 stdio:inherit。
 * `docker compose run` 的 stdout 可能混有拉取/启动日志，解析方只认明确的行格式。
 */
function runCapture(file, args) {
  console.log(`$ ${[file, ...args].join(' ')}`);
  const echo = (stream, text) => {
    if (!text) return;
    stream.write(String(text).endsWith('\n') ? String(text) : `${text}\n`);
  };
  try {
    const stdout = execFileSync(file, args, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['inherit', 'pipe', 'pipe'],
      windowsHide: true,
    });
    echo(process.stdout, stdout);
    return String(stdout || '');
  } catch (err) {
    echo(process.stdout, err.stdout);
    echo(process.stderr, err.stderr);
    throw err;
  }
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
  const id = tryCapture('docker', [...composeArgs(), 'ps', '-q', 'app']);
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
    const probe = buildProbeInvocation(probeUrl);
    const out = tryCapture(probe.file, probe.args);
    if (out === '200') return { ok: true, reason: 'readyz=200' };
    lastReason = out === null ? 'curl 失败（服务未监听？）' : `readyz=${out}`;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return { ok: false, reason: `超时（最后一次：${lastReason}）` };
}

/**
 * 本次要发布的目标镜像引用。只此一处取值口径（trim），
 * 提前告警与回滚决策必须比同一串，否则两处判据会分叉。
 */
const targetImageRef = () => (process.env.APP_IMAGE || '').trim();

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
  // 按 :latest 这类可变标签发布时，"回滚"用的引用与目标同串 ⇒ 解析到同一个构建。
  // 现在就说破（此时迁移还没跑），别等健康门禁失败后才发现无处可回。
  if (isSameImageRef(previousImage, targetImageRef())) {
    console.warn(
      `⚠ 回滚目标与目标镜像引用相同（${previousImage}）：本次发布不具备版本级回滚能力，` +
        '失败时不会自动切镜像，请改用带版本 tag 或 digest 的引用发布。'
    );
  }
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
    // COMPOSE_FILE 必传：备份默认在 mongo 容器内执行（宿主机连不上只 expose 不 publish
    // 的服务），而 `docker compose exec` 必须指向与部署同一份 compose 文件，
    // 否则会命中另一个同名项目（脚本的 cwd 决定项目名，这里刻意不依赖 cwd）。
    const backup = buildBackupInvocation();
    run(backup.file, backup.args, {
      env: {
        ...process.env,
        MONGODB_URI: uri,
        COMPOSE_FILE: path.join(ROOT, 'docker-compose.yml'),
      },
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
    const pull = buildPullInvocation();
    run(pull.file, pull.args);
  } catch (err) {
    console.error('✗ 镜像拉取失败，中止部署（线上保持原版本运行）');
    process.exit(1);
  }
}

/**
 * 迁移：先打印当前位点留痕，再应用；失败即中止（未切换流量）。
 * 返回本次实际应用的迁移名（来自 `MIGRATED UP:` 行），供回滚决策判断 schema 是否已变。
 */
function applyMigrations() {
  const status = buildMigrateInvocation('status');
  const up = buildMigrateInvocation('up');
  console.log('\n[迁移] 当前位点：');
  run(status.file, status.args);
  console.log('\n[迁移] 应用待执行迁移……');
  let output = '';
  try {
    output = runCapture(up.file, up.args);
  } catch (err) {
    console.error('✗ 迁移失败，中止部署（线上保持原版本运行，未切换流量）');
    process.exit(1);
  }
  const applied = parseAppliedMigrations(output);
  if (applied.length > 0) {
    console.log(`✓ 本次应用 ${applied.length} 个迁移（schema 已变，自动回滚将转人工）：`);
    for (const name of applied) console.log(`  · ${name}`);
  } else {
    console.log('· 本次没有待应用的迁移（schema 未变）');
  }
  return applied;
}

/**
 * 滚动切换 app 容器；失败即中止。
 *
 * 失败时不自动回滚——但必须说明此刻的状态：本步骤只在 migrate-up **成功之后**
 * 才到达，所以线上是「旧版本 + 本次迁移后的 schema」，且此时没有任何东西会去复检健康。
 * 不写出来，操作员会以为「没切成功就等于什么都没发生」。
 */
function switchContainer(appliedMigrations) {
  console.log('\n[切换] 滚动更新 app 容器……');
  try {
    const up = buildUpInvocation();
    run(up.file, up.args);
  } catch (err) {
    console.error('✗ 容器切换失败');
    const schemaState =
      appliedMigrations.length > 0
        ? `本次已应用 ${appliedMigrations.length} 个迁移——线上旧版本正在新 schema 上运行。`
        : '本次没有应用迁移，schema 与发布前一致。';
    console.error(
      `⚠ 此刻状态：迁移已执行、容器未切换——${schemaState}` +
        '发布前的备份位于 ./backups，恢复/回退步骤见 deployment/rollback-drill.md。'
    );
    process.exit(1);
  }
}

/**
 * 回滚到指定镜像并复检健康；回滚失败不抛出（由调用方统一以退出码 1 收口）。
 * 回滚后的复检同样以 /readyz 为准——回滚成功与否要可观测，而非假定。
 *
 * 可达性（O-2）：decideRollback 只在本次**没有应用迁移**时才放行自动回滚，
 * 因此这里切回的镜像与当前 schema 是发布前的同一组合。仍要打印「只切镜像」：
 * 镜像回退不会撤销新版本失败前已写入的数据，数据级恢复是另一条人工路径。
 */
async function rollbackTo(previousImage, probeUrl, recheckTimeoutMs) {
  console.log(`\n[回滚] 切回上一镜像：${previousImage}`);
  console.error(
    '⚠ 回滚只切镜像：本次未应用迁移，schema 与发布前一致；但新版本失败前写入的数据不会被撤销。' +
      '若数据异常，请按 deployment/rollback-drill.md 评估是否从 ./backups 做数据级恢复。'
  );
  try {
    const up = buildUpInvocation();
    run(up.file, up.args, {
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

/**
 * --dry-run 的计划输出：逐条打印真实 argv（与实际执行共用 deployCommands 的构造器）。
 * 单独成函数是为了把分支留在 main() 之外——main 只表达步骤顺序。
 */
function printDryRunPlan(args, probeUrl) {
  console.log('\n[命令计划] 以下 argv 与实际执行同源（--dry-run 不执行任何一条）：');
  for (const step of buildCommandPlan({ probeUrl })) {
    if (step.id === 'backup' && args.skipBackup) {
      console.log('  · backup: 跳过（--skip-backup）');
      continue;
    }
    console.log(`  · ${step.id}: ${formatInvocation(step)}`);
  }
  console.log('\n--dry-run：仅打印计划，不执行任何变更。');
}

async function main() {
  // ---- ⓪ 配置本身也是前置条件：写错的数值会让下面的判据静默失真 ----
  const { args, errors: configErrors } = parseArgs(process.argv.slice(2), process.env);
  if (configErrors.length > 0) {
    console.error('\n配置不合法，拒绝执行（未做任何变更）：');
    for (const e of configErrors) console.error(`  ✗ ${e}`);
    process.exit(2);
  }
  const plan = buildPlan(args);
  const probeUrl = `http://127.0.0.1:${args.probePort}/readyz`;

  console.log('===== 部署计划 =====');
  plan.forEach((s, i) => console.log(`  ${i + 1}. ${s.desc}`));
  console.log(`  目标镜像: ${process.env.APP_IMAGE || '(未设置)'}`);

  // ---- ① 前置条件（fail-closed：不满足即拒绝，未做任何变更）----
  const pre = validatePreflight(process.env, fs);
  // warning 必须先于 ok 判定打印：它们不阻断，但恰恰是"本次发布带着某个已知缺陷继续"
  // 的唯一痕迹（如告警通道仍是占位）。只判 ok 而不显示 warnings，等于把"响"变成"哑"。
  if (pre.warnings.length > 0) {
    console.warn('\n前置校验警告（不阻断本次发布，但请确认）：');
    for (const w of pre.warnings) console.warn(`  ! ${w}`);
  }
  if (!pre.ok) {
    console.error('\n前置条件不满足，拒绝执行（未做任何变更）：');
    for (const e of pre.errors) console.error(`  ✗ ${e}`);
    process.exit(2);
  }
  console.log('✓ 前置条件校验通过');

  if (args.dryRun) {
    printDryRunPlan(args, probeUrl);
    process.exit(0);
  }

  // ---- ② 记录回滚目标（必须在切换之前读）----
  const previousImage = recordRollbackTarget();

  // ---- ③ 备份（铁律：先备份后发布）----
  backupDatabase(args.skipBackup);

  // ---- ④~⑤ 拉取镜像 + 迁移 ----
  pullImage();
  const appliedMigrations = applyMigrations();

  // ---- ⑥ 切换 ----
  switchContainer(appliedMigrations);

  // ---- ⑦ 健康门禁 ----
  console.log(`\n[健康门禁] 轮询 ${probeUrl} ……`);
  const health = await waitForReady({ timeoutMs: args.healthTimeoutMs, probeUrl });
  console.log(health.ok ? `✓ ${health.reason}` : `✗ ${health.reason}`);

  // ---- ⑧ 回滚决策 ----
  const decision = decideRollback({
    healthOk: health.ok,
    noRollback: args.noRollback,
    hasPreviousImage: Boolean(previousImage),
    backupTaken: !args.skipBackup,
    previousImage,
    targetImage: targetImageRef(),
    appliedMigrations,
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

// 本脚本不导出 API：判据在 scripts/deployPolicy.js（测试直接 require 那个模块）。
