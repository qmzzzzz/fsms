/**
 * 需要校验来源/写审计的 HTTP 方法（单一事实来源）
 *
 * `originCheck.js`、`security/auditLog.js`、`protocolCompliance.js` 都必须指向这里，
 * 不得各抄一份四动词数组——任一处增删就会出现「CSRF 拦了但没审计」或反之；而 auditLog
 * 为拿到 originCheck 的副本会反向 require 它，构成 `originCheck → security/index →
 * auditLog → originCheck` 的惰性环。本模块零 require，是叶子，环随之消失。
 */

const WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);

module.exports = { WRITE_METHODS };
