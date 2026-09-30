/**
 * 审计哈希链相关的告警类型（2026-09-30）
 *
 * 单独成文件而不是直接写进 services/securityAlert.js 的 ALERT_TYPES 字面量，
 * 是因为后者的行数已贴着 max-lines 棘轮上限（300）：新增三个条目会让它回退。
 * 散列进字面量还会破坏「一处集中登记」的可读性——而本仓的 `ALERT_TYPES`
 * 被测试逐字断言（tests/services/auditChainGuardedIntegrity.test.js 的 D 段）。
 *
 * 三条类型各对应一条**此前只有 logger（或完全无出口）**的失效路径：
 *   - AUDIT_HASH_COMPUTE_FAILED：auditBuffer 算 hash 失败 ⇒ 批次无哈希落库。
 *     原实现只有 logger.warn，而这是"链出现缺口"的唯一直接信号。
 *   - AUDIT_CHAIN_BREAK_DETECTED：周期核验发现真实断裂。原实现里核验只在
 *     有人手动调 GET /api/security/audit-logs/verify 或跑离线脚本时才发生——
 *     "篡改会留痕"成立，但"痕迹会被发现"不成立。
 *   - LEGACY_CBC_DECRYPT_ENABLED：启动期 CBC 解密开关仍为 true（填充预言机面未收口）。
 *     原实现只是 config/validate.js 里一行文本告警，进不了监控面。
 *
 * 三者的 data 里都没有攻击者可控的自由字符串（类型与层级都是固定字面量），
 * 不构成 metrics 的高基数风险。
 */

const AUDIT_CHAIN_ALERT_TYPES = {
  AUDIT_HASH_COMPUTE_FAILED: 'audit_hash_compute_failed',
  AUDIT_CHAIN_BREAK_DETECTED: 'audit_chain_break_detected',
  LEGACY_CBC_DECRYPT_ENABLED: 'legacy_cbc_decrypt_enabled',
};

module.exports = { AUDIT_CHAIN_ALERT_TYPES };
