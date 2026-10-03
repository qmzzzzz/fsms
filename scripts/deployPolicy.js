/**
 * 部署判据（scripts/deploy.js 的纯逻辑层）
 *
 * 为什么单独成文件：deploy.js 把「判据」与「执行」刻意分层——前者可在毫秒级被直接断言
 * （该不该拒绝、步骤顺序对不对、该不该回滚），后者只能靠子进程桩观测。
 * 两者挤在一个文件里时，体积棘轮（max-lines=300）迟早会逼其中一边被删注释或被拆分，
 * 分层后各自都能被 require，不需要为测试开后门。
 *
 * 本模块零副作用：不读 process.env（除参数默认值）、不碰文件系统、不打印、不退出。
 * env 与 fs 实现一律由调用方注入，见 validatePreflight / parseArgs 形参。
 */

'use strict';

const path = require('path');

/** 仓库根：密钥目录与 compose 文件都挂在这个根下（deploy.js 也要用，故一并导出） */
const ROOT = path.resolve(__dirname, '..');

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
  // Redis 认证口令（2026-10-01 审计 finding）：compose secrets 段与 redis/app
  // 两个消费方共用；缺文件时 redis 容器 requirepass 拿到空串、应用侧 NOAUTH，
  // 都在启动期才暴露——这里提前一个窗口拦下。与 compose 的一致性由
  // src/tests/deploy/deployScript.test.js 双向把守
  'redis_password',
];

/** compose 里用 `${VAR:?}` 硬声明的环境变量名 → 缺失时的提示语 */
const REQUIRED_COMPOSE_ENV = Object.freeze([
  ['CORS_ORIGIN', '生产禁止通配符，须为明确的前端域名白名单'],
  [
    'ALLOWED_HOSTS',
    'Host 头白名单，逗号分隔（如 fsms.example.com）；NODE_ENV=production 下缺失即启动失败',
  ],
]);

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
  } else if (
    (env.DEPLOY_REQUIRE_DIGEST_PIN || '').trim() === 'true' &&
    !/@sha256:[0-9a-f]{64}$/.test(image)
  ) {
    // ④ digest 钉闸（镜像验签闭环的最后一道）：tag 是 registry 端可被覆盖的可变指针，
    //    签名/SBOM/provenance 都锚在 digest 上——验完签却按 tag pull，验签等于没验。
    //    deploy.yml 的 preflight 会先 cosign 验签、把 tag 解析成 digest 并以
    //    `<repo>@sha256:…` 传入，两条工作流部署路径都显式置 DEPLOY_REQUIRE_DIGEST_PIN=true
    //    让本脚本拒绝一切非 digest 引用（含手误直接给 tag 的情况）。
    //    开关默认关闭：本地手工演练仍可用 tag 引用，不破坏既有用法。
    errors.push(
      'DEPLOY_REQUIRE_DIGEST_PIN=true 但 APP_IMAGE 不是 digest 钉死引用（应为 ' +
        '<registry>/<repo>:<tag>@sha256:<64位hex>）。工作流路径由 preflight 完成验签并解析 digest；' +
        '手工发布请先 docker buildx imagetools inspect <tag> 取 digest 后再传。'
    );
  }

  // ② compose 的 `:?` 变量一个都不能少：缺失时 compose 会在插值阶段直接拒绝整个项目。
  //    在这里提前拦下（而不是让 compose 抛一段插值报错）的意义不只是提示清楚——
  //    本脚本的「切换容器」是**备份与迁移之后**才执行的，靠 compose 去发现
  //    等于「数据库已改写、版本却没切」。原先只校验 CORS_ORIGIN，
  //    ALLOWED_HOSTS 同样是 `:?` 却漏了，正是这条路径（CI 未下发该变量）。
  //    清单与 compose 的一致性由测试从 docker-compose.yml 推导比对
  //    （src/tests/deploy/deployScript.test.js），新增 `:?` 变量忘了在此登记会直接红。
  for (const [name, hint] of REQUIRED_COMPOSE_ENV) {
    if (!(env[name] || '').trim()) {
      errors.push(`${name} 未设置（${hint}）。`);
    }
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

  const alerting = checkAlertingEndpoint(env, fsImpl);
  errors.push(...alerting.errors);
  warnings.push(...alerting.warnings);

  return { ok: errors.length === 0, errors, warnings };
}

/**
 * 告警接收端就绪度（2026-09-26 审计 Top-2）。
 *
 * 缺陷：docker-compose.yml 把**仓库内**的 deployment/observability/alertmanager.yml
 * 直接挂进容器，而该文件的 webhook 是占位 URL。于是「照抄仓库起服务」的生产上，
 * critical 告警全部发往 hooks.example.com —— 告警静默丢失，Prometheus 页面却一切正常，
 * 没有任何人被叫醒。文件头虽然写了「私有副本注入」，但**没有任何一处会检查有没有注入**：
 * 合规检查里的生产闸（ALERT_WEBHOOK_CHECK=production）只能人工手动触发，而 CI 又
 * 不能设它（仓库模板本身就是占位，设了必红）——于是"忘了注入"这条路上没有任何守卫。
 *
 * 判据同源：复用 scripts/compliance-alerting.js（合规检查第 8 项用的就是它），
 * 避免"同一个问题两处各写一份判据"而漂移。
 *
 * 两级判定用满它原本的设计：
 *   - production 态红、repo 态绿 ⇒ 纯粹是「模板占位未替换」⇒ 默认 fail-closed，
 *     只有显式声明 ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true（无告警的演练环境）才降级为告警；
 *   - 两态都红 ⇒ 是误配（明文 http / 残缺值）或整条链断开，**任何声明都不放行**。
 *
 * @returns {{errors: string[], warnings: string[]}}
 */
function checkAlertingEndpoint(env, fsImpl) {
  const errors = [];
  const warnings = [];
  // 文件头的「独立挂载覆盖」注入方式会改挂载点，故允许指向真实配置；
  // 这不是绕过——指向的文件仍要过同一道判据。
  const file =
    (env.ALERTMANAGER_CONFIG_PATH || '').trim() ||
    path.join(ROOT, 'deployment', 'observability', 'alertmanager.yml');
  let source = null;
  try {
    if (fsImpl.existsSync(file)) source = String(fsImpl.readFileSync(file, 'utf8'));
  } catch (_) {
    source = null;
  }
  if (source === null) {
    // 「读不到」不能只写 warning：调用方 validatePreflight 的裁决位是 `ok = errors.length === 0`
    // （scripts/deployPolicy.js:129），warnings 不进这个式子——
    // 只进 warnings 等于让门禁在最坏的一种输入下判绿——alertmanager.yml 被删/未挂载/
    // 权限不对（catch 把 EACCES、EISDIR 一并吞成 null）时告警链必然不可用，而发布照样通过。
    // 旧注释写「不静默放行」，但它只保证"话说出了口"，没保证"门真的关上"。
    // 判不到就是不过，和占位/误配同一档。
    if ((env.ALERT_CHECK_SKIPPED || '').trim() === 'true') {
      // 显式逃生口：调用方不是部署流程时（如把本模块当库用的静态合规脚本、CI 里只解析
      // 资源参数）没有 alertmanager.yml 是常态，硬拦会把合法用法变成必然失败。
      warnings.push(
        `已显式跳过告警接收端检查（ALERT_CHECK_SKIPPED=true）：未读取到 ${file}，` +
          '本次发布没有任何证据表明 critical 告警能触达任何人。'
      );
    } else {
      errors.push(
        `未能读取告警接收端配置（${file}）：无法确认 webhook 是否已注入真实通道——` +
          '「判不了」按不通过处理（与占位/误配同档）。处置三选一：' +
          '① 挂载真实配置（或用 ALERTMANAGER_CONFIG_PATH 指向它，指向的文件仍过同一道闸）；' +
          '② 确为无告警的演练环境，写 ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true；' +
          '③ 调用方不是部署流程（无 alertmanager.yml 属正常），写 ALERT_CHECK_SKIPPED=true。'
      );
    }
    return { errors, warnings };
  }
  const { evaluateAlertingDelivery } = require('./compliance-alerting');
  const production = evaluateAlertingDelivery(source, 'production');
  if (production.passed) return { errors, warnings };

  if (!evaluateAlertingDelivery(source, 'repo').passed) {
    errors.push(`${production.detail}（该形态在仓库态同样为红，不是模板占位，不接受豁免声明）`);
  } else if ((env.ALLOW_PLACEHOLDER_ALERT_WEBHOOK || '').trim() === 'true') {
    warnings.push(
      `已显式允许占位告警通道（ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true）：` +
        `本次发布后告警不会触达任何人。${production.detail}`
    );
  } else {
    errors.push(
      `${production.detail}。若本次确为无告警的演练环境，显式设置 ` +
        'ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true 后重跑。'
    );
  }
  return { errors, warnings };
}

/**
 * 生成部署步骤序列。
 *
 * 抽成纯函数是为了让「顺序」本身可被断言——发布流程最脆弱的
 * 恰恰是顺序（备份必须在迁移之前、健康门禁必须在切换之后）。
 */
function buildPlan({ skipBackup = false, noRollback = false, healthTimeoutMs = 120000 } = {}) {
  const steps = [];
  steps.push({
    id: 'preflight',
    desc: '校验前置条件（镜像 / compose 的 :? 必填变量 / 密钥文件 / 告警接收端是否已注入）',
  });
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
 * 两个镜像引用是否指向"同一个东西"（按引用串判等）。
 *
 * 判等口径只有一处：deploy.js 的提前告警与 decideRollback 的拒绝必须同判据，
 * 否则会出现"脚本提示能回滚、决策却拒绝"（或反之）的自相矛盾。
 * trim + 小写：registry/仓库段按 Docker 规范只能小写，tag 段虽大小写敏感，
 * 但把不等判成相等只会多拒一次自动回滚（宁可人工确认，不可谎报已回滚）。
 * 任一侧为空串时必须判"不同"——空引用不该触发同引用拒绝（那条路归 hasPreviousImage 管）。
 */
function isSameImageRef(a, b) {
  const norm = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');
  const x = norm(a);
  return x !== '' && x === norm(b);
}

/**
 * 回滚决策：给定健康门禁结果，决定是否需要回滚。
 * 单独成函数是为了让「什么情况下该回滚」可被逐条断言。
 *
 * @param {boolean} backupTaken 本次发布是否真的备份过（--skip-backup 时为 false）。
 *   默认 true，使既有调用点语义不变。
 * @param {string} [previousImage] 记录到的回滚目标镜像引用
 * @param {string} [targetImage] 本次要发布的目标镜像引用（APP_IMAGE）
 *   两者只用于「同引用」判定；不传时判定不生效，既有调用点语义不变。
 */
function decideRollback({
  healthOk,
  noRollback,
  hasPreviousImage,
  backupTaken = true,
  previousImage,
  targetImage,
}) {
  if (healthOk) return { rollback: false, reason: '健康门禁通过' };
  if (noRollback) return { rollback: false, reason: '已显式禁用自动回滚（--no-rollback）' };
  if (!hasPreviousImage) {
    return {
      rollback: false,
      reason: '无可回滚目标（首次部署或未记录到上一版本镜像）——需人工介入',
    };
  }
  // 回滚 = 用 previousImage 这个引用重新 up。引用相同 ⇒ 解析到同一个构建，
  // 于是"回滚"是一次空操作：容器照旧不健康（照旧退出 1），或照旧健康
  // （打印「✓ 回滚后服务就绪」，而线上其实还是刚发布的那个版本）。
  // 后者才是真害——操作者以为已退回旧版，实际没有。按 :latest 发布时必然走到这里。
  if (isSameImageRef(previousImage, targetImage)) {
    return {
      rollback: false,
      reason:
        `回滚目标与本次目标镜像引用相同（${previousImage}）——自动回滚只是用同一引用重建容器，` +
        '换不回任何版本，却会打印"已回滚"。请改用带版本 tag 或 digest 的镜像引用发布，' +
        '或人工确认后用 ./backups 做数据级恢复。',
    };
  }
  // 本脚本自己的铁律：「没有备份的发布不具备回滚资格」。原先 --skip-backup 只影响
  // 是否备份、不参与回滚决策，于是最危险的组合被自动放行：
  //   迁移已改写数据库 + 一份备份都没有 + 自动把镜像切回旧版本
  //   → 旧版本在没有退路的新 schema 上继续写数据，写坏了连现场都取不回来。
  // 此处改为拒绝自动回滚，并给出**可执行的前置动作**（先抢救当前库，再人工回滚）。
  // 可用性此时本就已失（健康门禁未过），停在这里不会比自动回滚更糟。
  if (!backupTaken) {
    return {
      rollback: false,
      reason:
        '健康门禁未通过，但本次发布跳过了备份（--skip-backup）且迁移已改写数据库——' +
        '按「无备份不具备回滚资格」不执行自动回滚。' +
        '请先 bash scripts/backup-mongo.sh ./backups 抢救当前数据，' +
        '再单独确认迁移是否向后兼容后人工回滚。',
    };
  }
  return { rollback: true, reason: '健康门禁未通过且存在上一版本镜像' };
}

/** deploy.js 的全部命令行开关（无位置参数）——未知参数判据的唯一事实来源 */
const DEPLOY_FLAGS = Object.freeze(['--dry-run', '--skip-backup', '--no-rollback']);

/**
 * 未知参数不能「当没看见」。原实现是 `argv.includes('--dry-run')` 三行独立判断，
 * 于是 `--dryrun`（少一个连字符，最容易敲错的一种）得到的是一次**真发布**：
 * 校验、备份、迁移、切容器全做，退出码 0，而操作者以为只是干跑。
 * 干跑与实发的差别恰是「会不会碰生产」，这个方向上不允许静默降级。
 *
 * 拼错时给出 closest 建议：把两侧的非字母字符抹平后比较，
 * `--dryrun` → `dryrun` 命中 `--dry-run` → `dryrun`，报错即可直接照抄修复。
 */
const suggestFlag = (token) => {
  const shape = (s) => s.replace(/[^a-z]/gi, '').toLowerCase();
  return DEPLOY_FLAGS.find((f) => shape(f) === shape(token));
};

/**
 * 解析单个数值型配置：未设置→默认值；设置了但非正整数→**报错**。
 *
 * 为什么必须报错而不是回退默认值：`Number('120s')` 得 NaN，而
 * `Date.now() + NaN = NaN` 让健康门禁的 `while (Date.now() < NaN)` 一次都不执行，
 * 直接返回「超时（尚未探测）」——于是一个**完全健康的版本被判失败并自动回滚**。
 * 一个手写的单位后缀（120s / 120000ms）就能把好发布回滚掉，且现场看起来
 * 像「新版本确实不健康」。这类「配置写错 → 判据静默失真」必须在前置阶段拦下。
 *
 * @returns {{value?:number, error?:string}}
 */
function parsePositiveInt(name, raw, fallback, { max } = {}) {
  const s = String(raw === undefined || raw === null ? '' : raw).trim();
  if (!s) return { value: fallback };
  if (!/^\d+$/.test(s)) return { error: `${name} 必须是正整数（当前值：「${raw}」）` };
  const n = Number(s);
  if (n <= 0) return { error: `${name} 必须大于 0（当前值：「${raw}」）` };
  if (max !== undefined && n > max) return { error: `${name} 不得超过 ${max}（当前值：${n}）` };
  return { value: n };
}

/**
 * 解析命令行开关与环境变量配置。返回 { args, errors }——
 * errors 非空时调用方应以退出码 2 拒绝执行（此时尚未产生任何副作用）。
 */
function parseArgs(argv, env = process.env) {
  const numbers = [
    [
      'DEPLOY_HEALTH_TIMEOUT_MS',
      env.DEPLOY_HEALTH_TIMEOUT_MS,
      120000,
      undefined,
      'healthTimeoutMs',
    ],
    [
      'DEPLOY_ROLLBACK_TIMEOUT_MS',
      env.DEPLOY_ROLLBACK_TIMEOUT_MS,
      60000,
      undefined,
      'rollbackTimeoutMs',
    ],
    ['DEPLOY_PROBE_PORT', env.DEPLOY_PROBE_PORT, 3000, 65535, 'probePort'],
  ];
  const args = {
    dryRun: argv.includes('--dry-run'),
    skipBackup: argv.includes('--skip-backup'),
    noRollback: argv.includes('--no-rollback'),
  };
  const errors = [];
  for (const token of argv) {
    if (DEPLOY_FLAGS.includes(token)) continue;
    const hint = suggestFlag(token);
    errors.push(
      `未知参数：「${token}」（本脚本只接受 ${DEPLOY_FLAGS.join(' / ')}）` +
        (hint ? `；是否想写 ${hint}？` : '')
    );
  }
  for (const [name, raw, fallback, max, key] of numbers) {
    const r = parsePositiveInt(name, raw, fallback, { max });
    if (r.error) errors.push(r.error);
    else args[key] = r.value;
  }
  return { args, errors };
}

module.exports = {
  ROOT,
  REQUIRED_SECRET_FILES,
  REQUIRED_COMPOSE_ENV,
  validatePreflight,
  checkAlertingEndpoint,
  buildPlan,
  isSameImageRef,
  decideRollback,
  parsePositiveInt,
  parseArgs,
  DEPLOY_FLAGS,
};
