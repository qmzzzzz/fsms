/**
 * 哨兵用户名（canary username）告警类型（2026-10-19）
 *
 * 单独成文件而不是直接写进 services/securityAlert.js 的 ALERT_TYPES 字面量，
 * 与 auditChainAlertTypes.js 同因：securityAlert.js 的行数已贴着 max-lines 棘轮
 * 上限（300，文件内 :15 有自述），新增条目会让它回退；且 ALERT_TYPES 被出站
 * 告警契约逐字核账（tests/services/outboundAlertContract.test.js 的 D2）。
 *
 * 语义：凭证失败且用户名**查无此人**、但取值命中哨兵名单
 * （constants/canaryAccounts.js）⇒ 确定性探测信号——真实用户走不到「用户名
 * 不存在」分支，构造性保证见 services/canaryWatch.js。检测器同见彼处；
 * 审计 action 与本类型同值（canary_username_attempt）：审计无条件写，
 * 网络告警按「同一哨兵每业务日一次」频控。
 *
 * 指标卡口：incSecurityAlert 只取 (type, level) 两个标签
 * （securityAlertDelivery.js:179），二者都是固定字面量；攻击者可控的 username
 * 只进告警消息文本与审计行，不进指标标签，不构成高基数风险。
 */

const CANARY_ALERT_TYPES = {
  CANARY_USERNAME_ATTEMPT: 'canary_username_attempt',
};

module.exports = { CANARY_ALERT_TYPES };
