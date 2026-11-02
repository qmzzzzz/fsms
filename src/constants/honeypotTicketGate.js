const { matchRoute, TRAP_HANDLING } = require('./honeypotRouteTable');

const REAUTH_TICKET_REQUIRED_CODE = 'REAUTH_TICKET_REQUIRED'; // 与 middleware/security/reauthTicket.js 的缺票闸逐字同码：陷阱不可能持票（POST /api/security/reauth 是 deny403），「缺票」是这些路由上唯一可能的真实答案
const REAUTH_REQUIRED_PAYLOAD = Object.freeze({
  kind: 'codeError',
  code: REAUTH_TICKET_REQUIRED_CODE,
});

const reauthPayload = () => REAUTH_REQUIRED_PAYLOAD; // 冻结单例：调用方只读，同一份拒绝对象在马甲的两个面上逐字相同

const isReauthGated = (row) => Boolean(row) && row.handling === TRAP_HANDLING.REAUTH; // 声明轴：闸写在路由表的那一行上，不另立第二份端点清单

const reauthGateOf = ({ method, path: target } = {}) => {
  const route = matchRoute({ method, path: target }); // 路径口径与判定层同源：大小写、一个尾斜杠、HEAD 回退 GET 都不用在调用点重写一遍
  return isReauthGated(route) ? reauthPayload() : null;
};

module.exports = {
  REAUTH_TICKET_REQUIRED_CODE,
  isReauthGated,
  reauthGateOf,
  reauthPayload,
};
