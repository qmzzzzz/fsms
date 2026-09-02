/**
 * 日志上下文（报告 O-5）：基于 AsyncLocalStorage 的请求级日志关联
 *
 * 问题：requestId 中间件完整生成/回传 X-Request-Id，但从未注入 winston——
 * 单请求的多条日志无法通过 request id 一键关联，跨日志检索单次请求链路
 * 只能靠时间戳猜测。
 *
 * 方案：requestId 中间件把后续处理包进 ALS run 上下文；logger 的 winston
 * format 在每条日志序列化前读取上下文并合并 requestId。异步链（await/
 * Promise/定时器）天然继承 store，业务代码零改动。
 *
 * 脱离请求上下文的日志（定时任务/启动期）读不到 store，行为不变。
 */

const { AsyncLocalStorage } = require('async_hooks');

const logContextStorage = new AsyncLocalStorage();

/**
 * 在指定上下文内执行回调（requestId 中间件专用入口）
 */
const runWithLogContext = (store, callback) => logContextStorage.run(store, callback);

/**
 * 读取当前日志上下文（logger format 内调用）；脱离上下文返回 null
 */
const getLogContext = () => logContextStorage.getStore() || null;

module.exports = { runWithLogContext, getLogContext };
