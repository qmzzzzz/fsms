/**
 * 遗留 CBC 解密开关的启动期告警（2026-09-30）
 *
 * 单独成模块的两个理由（与 utils/metricsAuditDrops.js、metricsRuntime.js 同惯例）：
 *   ① config/validate.js 的行数已贴着 max-lines 棘轮上限——该文件自己的注释就写着
 *      「新增校验须放在独立函数内」；
 *   ② 这条判据有一处**反直觉的取舍**（下详），值得有名字与独立文档，而不是
 *      夹在三条并行告警里。
 *
 * 【为什么是"告警 + 提醒"而不是"拒绝启动"】
 * `ALLOW_LEGACY_CBC_DECRYPT=true` 重新打开的是**无认证 AES-CBC 的填充预言机攻击面**，
 * 严重性足以让人第一反应是"生产就该拒绝启动"。但该开关的**存在意义**恰恰是
 * "存量密文尚未迁完"——而迁移脚本本身可能需要服务可用。启动阻断会把运维锁进
 * "起不来 ⇒ 迁不了 ⇒ 更起不来"的死锁。
 * 正确的收口是"可见 + 提醒"：日志告警 + 监控面计数（incSecurityAlert）+ 明确文案。
 * 这与 ALLOWED_HOSTS 那类"未配置就不可用"的致命项有本质区别——后者阻断是安全的，
 * 因为修复它不需要服务先跑起来。
 *
 * 【为什么必须同时计入 incSecurityAlert】
 * 升级前它只值 collectProductionWarnings 里一行文本。生产环境该开关若长期挂着，
 * 那条 warn 会被日常日志淹没，而告警面（security_alerts_total / 概览高危计数）
 * 完全看不见它——"可检测 ≠ 已告警"。
 */

const CBC_FLAG_NAME = 'ALLOW_LEGACY_CBC_DECRYPT';

/** 开关是否开启（本文件是唯一判据，避免 'true' 字面量散落） */
const isLegacyCbcDecryptEnabled = () => process.env[CBC_FLAG_NAME] === 'true';

/** 告警文案（拆出来便于测试逐字断言） */
const legacyCbcWarningMessage = () =>
  `${CBC_FLAG_NAME}=true：无认证的 AES-CBC 遗留密文解密仍处于开启状态，` +
  '填充预言机攻击面未收口。存量数据迁移完成后请立即移除该开关。';

/**
 * 若开关开启：计入安全告警。
 *
 * 指标端在建配置阶段可能尚未就绪，且 validate 是导出 API（测试直接调用）：
 * 吞掉异常，口径同 utils/auditWriteFailure 的"指标端不可用时仅保留日志"。
 * **不影响启动行为**——见文件头的取舍说明。
 *
 * @returns {boolean} 是否处于开启状态（供调用方决定要不要推文案）
 */
const reportLegacyCbcDecryptIfEnabled = () => {
  if (!isLegacyCbcDecryptEnabled()) return false;
  try {
    require('../utils/metrics').incSecurityAlert('legacy_cbc_decrypt_enabled', 'high');
  } catch (_) {
    /* 指标端不可用：调用方推的 warning 文案仍是唯一留痕 */
  }
  return true;
};

/**
 * 遗留 CBC + immutable 档位（改配置需配套数据迁移）告警的合并出口。
 *
 * 为什么合并成一个函数而不是两个：collectProductionWarnings 是**唯一**的告警汇总
 * 出口，而 validate.js 的净代码行已贴着 max-lines 棘轮上限（实测 301/300、
 * 棘轮会判 max-lines 回退）。合并后 validate.js 只需**把原来那条 `if` 换成
 * 一个 `for...of`**——净增 0 行，两条判据都还在，且各自的取舍文档仍在各自模块里。
 *
 * 顺序与合并前一致：先 CBC（高危，重开填充预言机面），后 immutable。
 * 副作用（incSecurityAlert）由各自模块负责，本函数只做编排。
 *
 * @returns {string[]} 告警消息列表
 */
const cbcAndInvariantWarnings = () => {
  const warnings = [];
  if (reportLegacyCbcDecryptIfEnabled()) warnings.push(legacyCbcWarningMessage());
  warnings.push(...require('./immutableConfigGuard').collectInvariantWarnings());
  return warnings;
};

module.exports = {
  isLegacyCbcDecryptEnabled,
  legacyCbcWarningMessage,
  reportLegacyCbcDecryptIfEnabled,
  cbcAndInvariantWarnings,
  CBC_FLAG_NAME,
};
