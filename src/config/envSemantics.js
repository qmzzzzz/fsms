/**
 * NODE_ENV 归一与"生产语义"判定（零 require 的叶子模块，供 logger 等低层设施使用）。
 *
 * 判据（fail-closed）：
 *   - development/dev/local/test/ci：允许跳过致命校验；
 *   - staging/stage：同样跳过（ADR-005 的环境边界）；
 *   - production/prod/live：执行硬闸；
 *   - 其余任何值（含配了但为空的 `NODE_ENV=`）→ 也执行硬闸并额外报一条致命错。
 * 空值不得回落 development：猜错的代价必须是"启动不起来"，而不是"生产以零校验启动"。
 *
 * 本文件不得 require 任何模块：一旦引入依赖就不再是叶子，logger 会重新被拉进配置图
 * （由 src/tests/architecture/requireCycles.test.js 的分量登记守护）。
 * validate.js 继续 re-export 本模块三个函数，对外契约不变。
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
 * Whether runtime behavior should use development diagnostics/defaults.
 * Keep this separate from `requiresProductionSemantics()`: staging is
 * intentionally non-production for hard validation, but it must not inherit
 * local CORS fallbacks or verbose development error output.
 */
function isDevelopmentLikeEnv(value) {
  const env = value === undefined ? normalizeNodeEnv() : String(value).trim().toLowerCase();
  return DEV_ENV_ALIASES.has(env);
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
  isDevelopmentLikeEnv,
  requiresProductionSemantics,
};
