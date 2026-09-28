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
 * - 设了 ALLOWED_SOURCE_DB 就按它拒绝越界库；**未设置时不拦**——原因不是偷懒：
 *   scripts/deploy.js 的部署步骤会在应用容器里跑 `migrate-mongo up`，
 *   而 compose 用 secret 文件下发 MONGODB_URI、容器里没有也不需要 ALLOWED_SOURCE_DB。
 *   在此 fail-closed 会把每次生产部署变成一个必须新增必配项的破坏性变更，
 *   故留作待决（见 zzqoderAuditLedger §6-J 与协作台账），由使用方拍口径。
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

/**
 * 解析迁移目标库；配置了白名单却不命中时抛出（而不是交出"能连上但连错库"的串）。
 * @returns {string} 可交给 MongoClient 的连接串
 */
function resolveTargetUri() {
  const { uri, dbName, host, isFallback } = resolveMongoUri({ scriptName: SCRIPT_NAME });
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
        ` 正确用法：ALLOWED_SOURCE_DB=${host ? `${host}/` : ''}${dbName || '<库名>'} npm run migrate:up`
    );
  }
  if (!process.env.ALLOWED_SOURCE_DB) {
    console.warn(
      `[${SCRIPT_NAME}] 未设置 ALLOWED_SOURCE_DB：本次迁移目标库不做白名单校验。` +
        // 同上：建议值给全限定形态，不让"照提示配出来的白名单"比本次目标更宽
        ` 人工执行迁移时建议显式声明：ALLOWED_SOURCE_DB=${host ? `${host}/` : ''}${dbName || '<库名>'} npm run migrate:up` +
        `（部署流水线内的 migrate up 由 scripts/deploy.js 的预检与备份负责，不需要该变量）`
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
