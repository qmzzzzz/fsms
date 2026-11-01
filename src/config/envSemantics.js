/**
 * NODE_ENV 归一与"生产语义"判定（零 require 的叶子模块，供 logger 等低层设施使用）。
 *
 * 判据（fail-closed）：development/dev/local/test/ci 可跳过；production/prod/live 与
 * staging/stage 执行硬闸（预发默认同生产，放宽须显式声明）；其余任何值（含 `NODE_ENV=`）
 * 也执行硬闸并额外报一条致命错——空值不得回落 development：猜错的代价必须是"启动不起来"。
 *
 * 本文件不得 require 任何模块：一旦引入依赖就不再是叶子，logger 会重新被拉进配置图
 * （由 src/tests/architecture/requireCycles.test.js 的分量登记守护）。
 */

'use strict';

const DEV_ENV_ALIASES = new Set(['development', 'dev', 'local', 'test', 'ci']);
const PROD_ENV_ALIASES = new Set(['production', 'prod', 'live']);
const STAGING_ENV_ALIASES = new Set(['staging', 'stage']);
const STAGING_LENIENCY_ENV = 'FSMS_ALLOW_STAGING_LENIENT'; // 预发宽松的唯一开关（只有精确 true 生效）

function normalizeNodeEnv() {
  const raw = process.env.NODE_ENV;
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  // F-216：空串与"未设置"必须分开——`value || 'development'` 会把两者并成一类，
  // 于是本文件头那条契约（"其余任何值 → 也执行硬闸"）对 `NODE_ENV=`（compose 只写键名、
  // Dockerfile 的 `ARG NODE_ENV=` 未传值、.env 留一行）不成立：空串归一为"未识别"
  // （'' 不属于任何家族），只有**真正未设置**才落 development。
  return value || (raw === undefined ? 'development' : '');
}

function isProductionLikeEnv() {
  return PROD_ENV_ALIASES.has(normalizeNodeEnv());
}

/**
 * 运行时是否该用开发态诊断/默认值：staging 不得继承本地 CORS 回退与 verbose 错误输出
 * （它只是"不走生产硬闸"，不是"开发态"）。
 */
function isDevelopmentLikeEnv(value) {
  const env = value === undefined ? normalizeNodeEnv() : String(value).trim().toLowerCase();
  return DEV_ENV_ALIASES.has(env);
}

function isStagingLikeEnv(value) {
  const env = value === undefined ? normalizeNodeEnv() : String(value).trim().toLowerCase();
  return STAGING_ENV_ALIASES.has(env);
}

/** 预发是否被部署方显式声明为"接受不加固"；只有精确 true 生效，其余一律按严 */
function stagingLeniencyAcknowledged() {
  return (
    String(process.env[STAGING_LENIENCY_ENV] || '')
      .trim()
      .toLowerCase() === 'true'
  );
}

/**
 * 该环境是否必须按生产语义行事（生产家族 + 一切无法识别的值）。凡按字面量 'production'
 * 分叉的**诊断/运营**开关（日志格式、采样率、前端托管）都必须用它，而不是 isProductionLikeEnv()
 * ——后者只认显式生产名，会让 `prodution` 这类拼写错误重新变成"闸照常关、安全属性静默失效"。
 */
function requiresProductionSemantics() {
  const env = normalizeNodeEnv();
  if (DEV_ENV_ALIASES.has(env) || STAGING_ENV_ALIASES.has(env)) return false;
  return true;
}

/**
 * 启动硬闸与安全属性（文档默认位、cookie Secure、限流参数越界）是否按生产办。与
 * requiresProductionSemantics() 分开是有意的：staging 在诊断口径上仍算非生产，但
 * "能否跳过整张生产配置表"不得由 NODE_ENV 一个字面量单独决定——staging 默认与 production
 * 同判，只有显式 FSMS_ALLOW_STAGING_LENIENT=true 才放宽，后果由启动日志逐条列出。
 */
function requiresProductionHardening() {
  const env = normalizeNodeEnv();
  if (DEV_ENV_ALIASES.has(env)) return false;
  if (STAGING_ENV_ALIASES.has(env)) return !stagingLeniencyAcknowledged();
  return true;
}

module.exports = {
  DEV_ENV_ALIASES,
  PROD_ENV_ALIASES,
  STAGING_ENV_ALIASES,
  STAGING_LENIENCY_ENV,
  normalizeNodeEnv,
  isProductionLikeEnv,
  isDevelopmentLikeEnv,
  isStagingLikeEnv,
  stagingLeniencyAcknowledged,
  requiresProductionSemantics,
  requiresProductionHardening,
};
