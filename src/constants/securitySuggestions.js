/**
 * 安全建议码表的单一来源
 *
 * 背景（i18n 缺口）：`suggestions` 原先是**后端直接拼好的中文句子**
 * （securityController.js 的 my-info 与 stats 两处共 5 条）。这类字段一旦是
 * 成句文案，就没有任何办法在英文界面里正确显示——前端拿到的是已经定型的
 * 中文串，vue-i18n 无从下手。表现是：管理员把界面切到 en-US，「我的安全信息」
 * 的建议列表与安全概览的建议仍是中文。
 *
 * 修法与仓内既有口径一致（utils/labelMaps.js 的 DEVICE_TYPE、constants/alarm.js
 * 的 ALARM_TYPES、utils/auditLabels.js 的 audit.action.*）：**后端只出稳定码，
 * 文案归前端词表**。本文件是那份码表的唯一声明处——前端词表
 * （web-admin/src/utils/securityLabels.js）必须逐一覆盖，由
 * web-admin/src/tests/utils/securitySuggestionParity.test.js 直接 createRequire
 * 本文件对账（同 labelMapsSemantics / deviceStatusParity 的做法），
 * 所以「后端加一码、前端漏翻」会让该用例变红，而不是在界面上静默显示裸码。
 *
 * 为什么是两个端点共用一份码表：两处产出的都是「安全建议」，只是触发条件不同
 * （my-info 看本人登录历史，stats 看全局概览）。分成两份清单就会出现同一个语义
 * 两个码，前端要维护两套映射——正是 labelMaps.js 文件头记的那类漂移。
 *
 * 兼容性：`suggestions` 的**类型不变**（仍是 string[]），只有取值从成句中文
 * 变为稳定码；前端映射带**原始串回退**（未知码原样显示），故老客户端/老响应
 * 不会白屏，也不会把裸码当作正文。
 */

const SECURITY_SUGGESTION_CODES = Object.freeze({
  /** my-info：距上次登录 > 30 天 */
  ACCOUNT_INACTIVE_LONG: 'account_inactive_long',
  /** my-info：近 10 条登录记录里失败 > 3 次 */
  REPEATED_LOGIN_FAILURES: 'repeated_login_failures',
  /** stats：riskScore > 70 */
  HIGH_RISK_SCORE: 'high_risk_score',
  /** stats：failedLogins > 10 */
  EXCESSIVE_FAILED_LOGINS: 'excessive_failed_logins',
  /** stats：unusualAccess > 5 */
  UNUSUAL_TIME_ACCESS: 'unusual_time_access',
});

// 全集（前端词表按此对账）。顺序即声明顺序，无业务含义。
const SECURITY_SUGGESTION_VALUES = Object.freeze(Object.values(SECURITY_SUGGESTION_CODES));

module.exports = { SECURITY_SUGGESTION_CODES, SECURITY_SUGGESTION_VALUES };
