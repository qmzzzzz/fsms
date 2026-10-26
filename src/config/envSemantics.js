/**
 * NODE_ENV 归一与"生产语义"判定（从 config/validate.js 抽出，2026-10-26）
 *
 * ## 为什么单独成文件（A-1 去环）
 * 这三个函数原本住在 `config/validate.js` 里，而 `utils/logger.js` 顶层
 * `require('../config/validate')` 只为取 `requiresProductionSemantics`——
 * 于是**日志工具反过来把整个配置校验图拉进了自己的加载链**
 * （validate → deploymentCredentialGuards / legacyCbcGuard / loginEncryptGuard
 *  → metrics / passwordHistory → …），并在依赖图上形成 logger ↔ config 的环。
 *
 * 方向是错的：日志是最底层的诊断设施，它不该依赖"配置是否合法"这一层。
 * 把判据搬到**零 require 的叶子模块**后：
 *   - `logger.js` → `config/envSemantics`（叶子），不再触达 validate；
 *   - `validate.js` 继续 re-export 这三个函数，对外契约不变
 *     （`config/immutableConfigGuard`、`app.js`、`index.js` 等调用点一行不用改）。
 *
 * ## 判据（fail-closed）原文保留如下
 *
 * 原先整套生产硬闸的入口是 `nodeEnv !== 'production'` 的字面量比较，等于把
 * 「弱密钥能否启动 / 有无 ALLOWED_HOSTS / 有无 REDIS_URL / API 文档是否默认打开」
 * 全部押在一个字符串的拼写上。实测：
 *   NODE_ENV=prod JWT_SECRET=change-this-secret（就在 WEAK_SECRETS 黑名单里）
 *   → validateConfig() 直接 return，进程零校验启动；
 *   同一环境把值改成 production → 报 8 条致命并 exit(1)。
 * `prod` / `Production` / `" production "` 都是真实部署里常见的写法，
 * 而失败的表象是"CI 与本地全绿"，没有任何信号。
 *
 * 判据：
 *   - 开发家族（development/dev/local/test/ci）→ 允许跳过致命校验（保持既有语义）；
 *   - 预发家族（staging/stage）→ 同样跳过（ADR-005 明确的环境边界，见
 *     src/tests/nodeEnvGateFailsClosed.test.js 对该行为的既有断言）；
 *   - 生产家族（production/prod/live）→ 执行硬闸；
 *   - **其余任何值 → 也执行硬闸并额外报一条致命错**：猜错的代价必须是
 *     "启动不起来"，而不是"生产以零校验启动"。"其余任何值"包含**配了但为空**
 *     （`NODE_ENV=`）——那是部署脚本里最常见的失误，不是"没配"（F-216）。
 *
 * **本文件不得 require 任何模块**：一旦引入依赖，它就不再是叶子，
 * 抽出来就白做了（`logger` 会重新被拉进配置图）。这条约束由
 * `src/tests/architecture/requireCycles.test.js` 的分量登记间接守护。
 */

'use strict';

const DEV_ENV_ALIASES = new Set(['development', 'dev', 'local', 'test', 'ci']);
const PROD_ENV_ALIASES = new Set(['production', 'prod', 'live']);
const STAGING_ENV_ALIASES = new Set(['staging', 'stage']);

function normalizeNodeEnv() {
  const raw = process.env.NODE_ENV;
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  // F-216：`value || 'development'` 把"配了但配成空"和"根本没配"并成一类，
  // 于是本文件头上那条契约（"其余任何值 → 也执行硬闸并额外报一条致命错"）
  // 对 `NODE_ENV=`（compose 的 `environment:` 只写键名、Dockerfile 的
  // `ARG NODE_ENV=` 未传值、.env 里留一行 `NODE_ENV=`，三者都得到它）不成立：
  // requiresProductionSemantics() 返回 false ⇒ validateConfig() 第一行就 return
  // ⇒ 生产以零校验启动，且一行日志都不打。空串仍归一为"未识别"（'' 不属于任何
  // 家族），只有**真正未设置**才落 development。
  return value || (raw === undefined ? 'development' : '');
}

function isProductionLikeEnv() {
  return PROD_ENV_ALIASES.has(normalizeNodeEnv());
}

/**
 * 该环境是否必须按生产语义行事（生产家族 + 一切无法识别的值）。
 *
 * 这是"fail-closed"唯一落点：凡按字面量 'production' 分叉的**安全**开关
 * （cookie Secure、API 文档默认位、前端托管、密钥强度审计留痕）都必须用它，
 * 而不是 isProductionLikeEnv()——后者只认显式生产名，会让 `prodution` 这类
 * 拼写错误重新变成"闸照常关、安全属性静默失效"。
 * 由本函数把"未识别 = 按生产办"这条规则说一次，避免每个调用点各自猜方向。
 */
function requiresProductionSemantics() {
  const env = normalizeNodeEnv();
  if (DEV_ENV_ALIASES.has(env) || STAGING_ENV_ALIASES.has(env)) return false;
  return true;
}

module.exports = {
  DEV_ENV_ALIASES,
  PROD_ENV_ALIASES,
  STAGING_ENV_ALIASES,
  normalizeNodeEnv,
  isProductionLikeEnv,
  requiresProductionSemantics,
};
