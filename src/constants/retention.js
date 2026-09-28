/**
 * 审计与日志留存期的单一声明（P3-46）
 *
 * 背景：`AUDIT_RETENTION_DAYS` 此前在四处各自解析，三种口径：
 *  - models/AuditLog.js      钳制到 [90, 3650] —— 这是**真正生效**的 TTL
 *  - utils/logger.js         `parseInt(...) || 180` —— 日志文件 maxFiles
 *  - controllers/security..  `parseInt(...) || 180` —— 合规仪表盘对外展示值
 *  - scripts/compliance-check.js 自行复刻钳制逻辑
 *
 * 实测后果（AUDIT_RETENTION_DAYS 取值 → 各处结果）：
 *  - `1`   → TTL 90 天，但日志文件只留 **1 天**，仪表盘对外报 **1**
 *  - `-5`  → TTL 90 天，但 logger 得到非法的 `maxFiles: '-5d'`
 *  - `0`   → TTL 90 天，其余两处因 `|| 180` 回退到 180
 *
 * 即：合规报表上的留存天数与数据库实际留存不一致，而日志文件可能远短于审计库。
 * 「对外声明留存 N 天、实际只留了更少」在合规语境下比配置错误本身更严重。
 *
 * 故此处集中声明，并同时导出「原始配置值」与「生效值」——
 * 二者不等即说明运维配置被静默修正过，compliance-check 据此告警。
 */

// 合规最低留存（等保/ISO 审计日志普遍要求 ≥ 90 天）
const MIN_RETENTION_DAYS = 90;
// 上限 10 年：更大的值会让 expireAfterSeconds 失去实际意义，且易由笔误产生
const MAX_RETENTION_DAYS = 3650;
const DEFAULT_RETENTION_DAYS = 180;

/**
 * F-213：解析必须严格（`Number` 而不是 `parseInt(x, 10)`）。
 *
 * `parseInt` 的成功集比"运维写的这个数字"宽得多——它吃掉尾部垃圾只留前缀：
 *  - `90x` → 90，且因为 RAW===生效值，`wasAdjusted` 为 **false**、
 *    `describeRetention()` 报「在允许区间内，原样生效」。
 *    这正是本文件立单源时要消灭的那一类：文件头写着"二者不等即说明配置被静默改写过"，
 *    而"静默改写"恰好发生在两数相等的那条分支上。
 *  - `1e3`（compose 里表达 1000 的常见写法）→ **1** → 被钳到合规下限 **90 天**，
 *    本意 1000 天的留存实际只剩 9 天里的一天不到，而报表口径已随之改写。
 *
 * 空串必须显式归入「未配置数值」：`Number('')` 是 0，会被下面的钳制当成"0 天"
 * 抬到 90 天，而 `AUDIT_RETENTION_DAYS=`（.env 里删掉值就等于这个）今天走的是
 * 默认 180 那条路，不能借这次收紧把它换成另一个生效值。
 */
const RAW_ENV_VALUE = process.env.AUDIT_RETENTION_DAYS;
const RAW_RETENTION_DAYS =
  typeof RAW_ENV_VALUE === 'string' && RAW_ENV_VALUE.trim() === '' ? NaN : Number(RAW_ENV_VALUE);

/** 配置是否提供了可解析的数值（未配置或非数值时为 false） */
const isConfigured = Number.isFinite(RAW_RETENTION_DAYS);

/** 实际生效的留存天数：非法值回退默认，合法值钳制到 [90, 3650] */
const RETENTION_DAYS = isConfigured
  ? Math.min(Math.max(RAW_RETENTION_DAYS, MIN_RETENTION_DAYS), MAX_RETENTION_DAYS)
  : DEFAULT_RETENTION_DAYS;

/** 配置值是否被钳制或回退（true 表示运维的配置未被原样采用） */
const wasAdjusted = isConfigured
  ? RAW_RETENTION_DAYS !== RETENTION_DAYS
  : RAW_ENV_VALUE !== undefined;

/**
 * 生成配置状态的可读说明，供启动日志与合规检查脚本共用
 * @returns {string} 说明文本
 */
const describeRetention = () => {
  if (!isConfigured) {
    return RAW_ENV_VALUE === undefined
      ? `未配置 AUDIT_RETENTION_DAYS，采用默认 ${RETENTION_DAYS} 天`
      : `AUDIT_RETENTION_DAYS=${JSON.stringify(RAW_ENV_VALUE)} 无法解析为整数，` +
          `已回退到默认 ${RETENTION_DAYS} 天`;
  }
  if (wasAdjusted) {
    return (
      `AUDIT_RETENTION_DAYS=${RAW_RETENTION_DAYS} 超出允许区间 ` +
      `[${MIN_RETENTION_DAYS}, ${MAX_RETENTION_DAYS}]，实际生效 ${RETENTION_DAYS} 天`
    );
  }
  return `AUDIT_RETENTION_DAYS=${RETENTION_DAYS} 天（在允许区间内，原样生效）`;
};

module.exports = {
  MIN_RETENTION_DAYS,
  MAX_RETENTION_DAYS,
  DEFAULT_RETENTION_DAYS,
  RAW_RETENTION_DAYS,
  RETENTION_DAYS,
  RETENTION_SECONDS: RETENTION_DAYS * 24 * 60 * 60,
  isConfigured,
  wasAdjusted,
  describeRetention,
};
