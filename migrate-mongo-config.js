/**
 * migrate-mongo 配置（O-9：数据库迁移框架）
 *
 * 连接串与运行时同一口径：优先 MONGODB_URI（支持 *_FILE 注入），
 * 执行任何迁移命令前会先水合 secrets 文件，与 scripts/ 下各维护脚本的引导方式一致。
 *
 * 目标库判据（F-65）：
 * - 不再自带 `|| 'mongodb://127.0.0.1:27017/fire_safety_db'` 静默回退；
 *   未设置 MONGODB_URI 时由 destructiveGuard.resolveMongoUri 显式告警并说明来源，
 *   本地回退串也只保留 destructiveGuard 里那一份事实来源。
 * - 每次真正连库都回显目标库名（人在按回车前必须看见打到哪个库）。
 * - 设了 ALLOWED_SOURCE_DB 就按它拒绝越界库；**写命令（up/down）在未设置时拒绝执行**
 *   （审计 P2-34 拍板 fail-closed）：人工 migrate:up 误指库此前可无门槛直接生效。
 *   部署流水线如需应用迁移，必须在部署环境显式配置 ALLOWED_SOURCE_DB；
 *   只读命令（status）与不连库的 migrate:create 保持宽松。
 * - `migrate:create` 只写文件、不碰数据库，因此判据做成**惰性** getter：
 *   migrate-mongo 在 env/database.js 的 connect() 里才读 mongodb.url，
 *   惰性求值是它的既有语义，不是绕门。
 *
 * 常用命令（见 package.json）：
 *   npm run migrate:create -- <名称>   新建迁移文件（生成时间戳前缀，无需连库）
 *   npm run migrate:status             查看已应用/待应用清单
 *   npm run migrate:up                 应用全部待执行迁移
 *   npm run migrate:down               回滚最近一条迁移（回退策略）
 */

require('dotenv').config();
require('./src/config/secrets').hydrateSecretsFromFiles();

const { resolveMongoUri, assertApplyAllowed } = require('./scripts/destructiveGuard');

const SCRIPT_NAME = 'migrate-mongo-config.js';

// migrate-mongo 的写命令只有 up/down；status 只读，create/init 不连库（见 bin/migrate-mongo.js 的命令表）。
const MIGRATE_WRITE_COMMANDS = new Set(['up', 'down']);

/**
 * 识别本次 migrate-mongo 子命令。命令可能带前置选项（如 `-f custom.js up`），
 * 故跳过选项及其值后取第一个位置参数；不是已知命令时返回 null（交给 migrate-mongo 自行报错）。
 * @returns {string|null}
 */
function currentMigrateCommand() {
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '-f' || arg === '--file' || arg === '--migrations-dir') {
      i += 1; // 这三个选项各带一个值，连同值一起跳过
      continue;
    }
    if (arg.startsWith('-')) continue;
    return /^(up|down|status|create|init)$/.test(arg) ? arg : null;
  }
  return null;
}

/**
 * 解析迁移目标库；配置了白名单却不命中时抛出（而不是交出"能连上但连错库"的串）。
 * @returns {string} 可交给 MongoClient 的连接串
 */
function resolveTargetUri() {
  const { uri, dbName, host, isFallback } = resolveMongoUri({ scriptName: SCRIPT_NAME });
  const suggestedAllow = `ALLOWED_SOURCE_DB=${host ? `${host}/` : ''}${dbName || '<库名>'}`;
  const command = currentMigrateCommand();
  // P2-34：写命令在白名单未设置时拒绝执行（fail-closed）——人工 migrate:up/down 误指库
  // 直接改写该库 schema，此前处于无门槛状态。status/create 等非写命令不受影响。
  if (!process.env.ALLOWED_SOURCE_DB && MIGRATE_WRITE_COMMANDS.has(command)) {
    throw new Error(
      `[${SCRIPT_NAME}] 检测到迁移写命令（migrate-mongo ${command}）但未设置 ALLOWED_SOURCE_DB，已拒绝执行（fail-closed）。` +
        ` 请显式声明放行目标库后重试：${suggestedAllow} npm run migrate:${command}；` +
        ` 只读命令（status）无需该变量，部署流水线应用迁移前也必须显式配置它。`
    );
  }
  if (
    process.env.ALLOWED_SOURCE_DB &&
    // host 必须一起传：assertApplyAllowed 的收紧形态（条目写成 `host:port/db`）
    // 靠调用方提供的 host 比对，缺省成空串会让所有含 `/` 的条目**永不命中**——
    // 于是"把放行面收紧到某台机器"这个配置反而误拒，健康的目标库跑不动迁移。
    // isFallback 这里刻意不传：其他 --apply 脚本拒的是"回退库上的破坏性写"，
    // 而本仓已把"未配 MONGODB_URI 仍可迁移"定为既有口径（本地开发依赖它），
    // 两处必须同时改，故作为待决升级给使用方，不在这里单方面收紧。
    !assertApplyAllowed({ scriptName: SCRIPT_NAME, dbName, host, apply: true })
  ) {
    throw new Error(
      `[${SCRIPT_NAME}] 迁移目标库未通过 ALLOWED_SOURCE_DB 白名单校验，已中止（详见上方拒绝说明）。` +
        ` 本次目标库：${dbName || '(未解析出库名)'}；` +
        // 提示一律给全限定形态：写成裸库名等于建议运维把"只放行一台机器"放宽成
        // "放行任何机器上的同名库"——误拒的真正危害是运维为了跑成而放宽护栏
        ` 正确用法：${suggestedAllow} npm run migrate:up`
    );
  }
  if (!process.env.ALLOWED_SOURCE_DB) {
    console.warn(
      `[${SCRIPT_NAME}] 未设置 ALLOWED_SOURCE_DB：本次迁移目标库不做白名单校验。` +
        // 同上：建议值给全限定形态，不让"照提示配出来的白名单"比本次目标更宽
        ` 人工执行迁移时建议显式声明：${suggestedAllow} npm run migrate:up` +
        `（部署流水线内的 migrate up 由 scripts/deploy.js 的预检与备份负责，也需要该变量）`
    );
  }
  console.log(
    `[${SCRIPT_NAME}] 迁移目标库：${dbName}${isFallback ? '（来自本地默认库回退，见上方告警）' : ''}`
  );
  return uri;
}

const config = {
  mongodb: {
    // 惰性求值：见头注释「migrate:create 不碰数据库」一条
    get url() {
      return resolveTargetUri();
    },
    options: {
      // 迁移为低频维护操作，显式超时避免挂起
      serverSelectionTimeoutMS: 5000,
    },
  },
  migrationsDir: 'migrations',
  changelogCollectionName: '_migrations',
  migrationFileExtension: '.js',
  // 以文件名（时间戳前缀）为迁移标识，保持与生成命令默认行为一致
  useFileHash: false,
  moduleSystem: 'commonjs',
};

module.exports = config;
