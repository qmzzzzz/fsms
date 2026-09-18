/**
 * 退出前日志强制落盘（P1-13）
 *
 * 【问题】winston 的文件 transport 是**异步**写入：调用 logger.error() 之后立即
 * process.exit()，日志往往还停在内存队列里随进程消失。启动期配置校验失败、
 * 数据库连不上、端口被占用——这些恰恰是最需要事后取证的时刻，却最容易丢日志。
 *
 * 【本机实测】（2026-09-17，Node v24.15.0 / winston 3.19.0 /
 * winston-daily-rotate-file；探针 .audit-flushprobe*.cjs，每条独立进程）
 *
 *   写法                                        error-*.log 是否落盘
 *   logger.error() 后立即 process.exit(1)        丢失（文件 0 字节）
 *   忙等 100ms 后 exit（同步阻塞，微任务不推进）   丢失
 *   logger.end() 后 exit                         丢失
 *   logger.end() + 忙等 100ms 后 exit             丢失
 *   logger.end(cb) 的 cb 里 exit                 丢失
 *   setTimeout(() => exit(1), 50 / 100 / 150)   落盘
 *
 * 结论：**同步**上下文（config/validate.js 的 validateConfig 是同步 API，
 * 测试以 expect(() => validateConfig()).toThrow('process.exit called') 断言，
 * 不能改成 setTimeout）靠「等待」或 end() 都救不回文件写入，只能直接同步写文件；
 * **异步**上下文则用 exitAfterFlush() 让事件循环推进一轮再退出。
 *
 * 【双写说明（如实记录）】flushLogsSync 是独立于 winston 队列的同步追加，
 * 因此**不会**与异步 transport 去重。真实退出路径下异步那份必然丢失（上表），
 * 文件里只有同步这一份；只有在「process.exit 被 mock/延迟」的场景（如单测）
 * 异步写入也会落地，同一行可能出现两次。重复行不影响取证，故不引入去重逻辑。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

/** 与 utils/logger.js 的 logsDir 同规则推导（logger 未导出该值，保持一致而非复制常量值） */
const DEFAULT_LOG_DIR = path.join(__dirname, '../../logs');

/** winston/logform 把最终渲染文本挂在该符号上（info[Symbol.for('message')]） */
const MESSAGE = Symbol.for('message');

/**
 * 当日文件名戳（与 logger.js 的 datePattern: 'YYYY-MM-DD' 同口径）
 * @param {Date} [now] 注入时间便于测试
 * @returns {string} 形如 2026-09-17
 */
function dateStamp(now = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

/**
 * 用 logger 自身的 format 渲染一行，保证同步写出的文本与异步 transport 逐字一致。
 * logger 不可用（加载失败）时退化为最小可用格式，绝不抛错——调用方正处于退出流程。
 */
function renderLine(level, message, meta) {
  try {
    const logger = require('./logger');
    const info = { level, message, ...(meta || {}) };
    const rendered = logger.format.transform(info)[MESSAGE];
    if (typeof rendered === 'string') return rendered;
  } catch (_) {
    /* 落到下面的降级格式 */
  }
  return `${new Date().toISOString()} [${level}]: ${message}`;
}

/**
 * 同步追加一行到与 winston 同名的日志文件。
 *
 * error 级别同时补写 combined——与 logger.js 的 transport 配置一致
 *（errorRotateTransport 与 fileRotateTransport 都会收到 error 记录）。
 *
 * 注：winston 在单文件超过 maxSize: '10m' 时会轮转为 xxx.log.1，本函数始终追加到
 * 基础名，因此极端情况下可能让基础文件略超 10m——优先保证「这条记录在」，
 * 而不是让退出流程去做轮转判断。
 *
 * @param {string} level winston 级别名（error / warn / info ...）
 * @param {string} message 消息文本
 * @param {object} [meta] 附加字段（会并入渲染上下文）
 * @param {{logDir?: string, now?: Date}} [options] 仅供测试注入
 * @returns {string} 实际写入的文本行（便于测试断言）
 */
function flushLogsSync(level, message, meta, options = {}) {
  const logDir = options.logDir || DEFAULT_LOG_DIR;
  const line = renderLine(level, message, meta);
  const stamp = dateStamp(options.now);
  const targets =
    level === 'error' ? [`error-${stamp}.log`, `combined-${stamp}.log`] : [`combined-${stamp}.log`];

  for (const name of targets) {
    try {
      fs.mkdirSync(logDir, { recursive: true });
      fs.appendFileSync(path.join(logDir, name), line + os.EOL, 'utf8');
    } catch (e) {
      // 落盘失败不能改变退出码，但也不能完全静默——stderr 至少留痕
      console.error(`[loggerFlush] 同步写入 ${name} 失败：${e && e.message ? e.message : e}`);
    }
  }
  return line;
}

/**
 * 异步上下文的安全退出：先结束 logger（排空 transport 队列），再让事件循环推进
 * 一轮后退出。
 *
 * 返回**永不 resolve** 的 Promise：调用方应 `return`/`await` 它，否则会在
 * 「即将退出」的窗口里继续执行后续启动步骤（把「启动失败」变成「带故障继续启动」）。
 * 例如 config/database.js 的 connectDB 用 `return exitAfterFlush(1)` 挂起自身，
 * 使 startServer 不会在数据库不可用时继续 initializeSystem。
 *
 * @param {number} [code=1] 退出码
 * @param {{delayMs?: number}} [options] delayMs 默认 100（报告 P1-13 要求 ≥100ms）
 * @returns {Promise<never>} 永不 settle
 */
function exitAfterFlush(code = 1, options = {}) {
  const delayMs = Number.isFinite(options.delayMs) ? options.delayMs : 100;
  try {
    const logger = require('./logger');
    if (typeof logger.end === 'function') logger.end();
  } catch (_) {
    /* logger 不可用时无需 flush，直接进入延迟退出 */
  }
  setTimeout(() => process.exit(code), delayMs);
  return new Promise((resolve) => {
    // 故意永不 resolve：见上方 JSDoc
    void resolve;
  });
}

module.exports = { flushLogsSync, exitAfterFlush, DEFAULT_LOG_DIR, dateStamp };
