/**
 * 需要校验来源/写审计的 HTTP 方法（单一事实来源）
 *
 * 此前 `originCheck.js`、`security/auditLog.js`、`protocolCompliance.js` 各自抄一份
 * 四动词数组，任一处增删就会出现「CSRF 拦了但没审计」或反之；而 auditLog 为拿到
 * originCheck 的副本，又反向 require 了 originCheck，构成
 * `originCheck → security/index → auditLog → originCheck` 的惰性环。
 *
 * 抽成零 require 的叶子后：三个消费方都指向这里，环随之消失。
 */

const WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);

module.exports = { WRITE_METHODS };
