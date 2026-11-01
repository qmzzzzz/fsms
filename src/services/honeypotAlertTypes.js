const HONEYPOT_ALERT_TYPES = {
  HONEYPOT_LOGIN: 'honeypot_login',
  HONEYPOT_PROBE: 'honeypot_probe',
  HONEYPOT_CHAIN_ESCALATED: 'honeypot_chain_escalated', // 同一来源 IP 在一个业务日内跨过 ≥2 个蜜罐阶段（判据见 services/honeypotChainWatch.js）
}; // 蜜罐账户被成功登录 / 陷阱会话内的后续探测 / 事件链跨阶段升级：定义在此叶子模块，判据与每业务日一次频控见 services/honeypotWatch.js 与 services/honeypotChainWatch.js

module.exports = { HONEYPOT_ALERT_TYPES };
