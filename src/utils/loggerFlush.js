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

/** 日志目录：与 utils/logger.js 的 transport 同一个声明（可用 LOG_DIR 覆盖） */
const { LOG_DIR: DEFAULT_LOG_DIR } = require('./logPaths');

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
 * 异步上下文的安全退出：让事件循环推进一轮（winston 的文件 transport 在这一轮里
 * 把队列写完）后再退出。
 *
 * 返回**永不 resolve** 的 Promise：调用方应 `return`/`await` 它，否则会在
 * 「即将退出」的窗口里继续执行后续启动步骤（把「启动失败」变成「带故障继续启动」）。
 * 例如 config/database.js 的 connectDB 用 `return exitAfterFlush(1)` 挂起自身，
 * 使 startServer 不会在数据库不可用时继续 initializeSystem。
 *
 * 【F-187：这里绝不能再调 logger.end()】
 * 本函数原先先 `logger.end()` 再 setTimeout，理由是"排空 transport 队列"。实测两件事都不成立：
 *   ① 排空收益为零——同一份夹具去掉 end() 后，异步那行照样落到 error-*.log / combined-*.log
 *      （end() 从来就不是 winston 文件 transport 的落盘开关，真正起作用的是下面这个 setTimeout，
 *       与本文件顶部实测表里 `logger.end() 后 exit → 丢失` 那行一致）；
 *   ② 副作用是致命的——end() 之后再调用**任意** logger 级别（实测 error/warn/info 6/6 复现）
 *      会**同步**抛 `ERR_STREAM_WRITE_AFTER_END`。而退出窗口是有事件的：
 *      index.js:195 用的是 delayMs=500，这期间在途请求的错误处理（errorHandler → logger.error）、
 *      以及二次信号 handler 的 `logger.warn`（index.js:112，它排在 exitAfterFlush 之前但会撞上
 *      第一轮已经调过 end() 的 logger）都会抛；index.js 的 uncaughtException 兜底自己也要
 *      logger.error，于是兜底再抛一次 ⇒ 关停链的取证行写不出去、退出码也不再是调用方要的那个。
 *      "二次 Ctrl-C"是运维最常见的手势，而这条路径上没有任何一处能靠 try/catch 补救——
 *      抛错的调用点本身就是日志语句。
 * 结论：end() 是纯副作用，删掉。需要真正排空的组件（logShipper 的批量缓冲）有自己的 close()，
 * 由关闭链显式 await（见本文件 drainShippingBuffer，F-186），而不是靠把整个 logger 关掉来"顺带"完成。
 *
 * @param {number} [code=1] 退出码
 * @param {{delayMs?: number}} [options] delayMs 默认 100（报告 P1-13 要求 ≥100ms）
 * @returns {Promise<never>} 永不 settle
 */
function exitAfterFlush(code = 1, options = {}) {
  const delayMs = Number.isFinite(options.delayMs) ? options.delayMs : 100;
  setTimeout(() => process.exit(code), delayMs);
  return new Promise((resolve) => {
    // 故意永不 resolve：见上方 JSDoc
    void resolve;
  });
}

/**
 * 关停时排空 SIEM 转发缓冲（F-186）
 *
 * 【缺陷】`HttpShipperTransport.close()` 是 F-98/P3-31 精心做出来的「按批排空 + 有界退出 +
 * 如实报剩余行数」，但它在生产里**没有任何调用点**——三个绿色用例测的全是这个没人调的方法。
 *
 * 【机制（两支探针实测，纠正了本函数初版写下的判断）】
 *   ① `logger.end()` **是**够得到 close() 的：`Logger.end()` → `_final()` 对每个 transport 调
 *      `end()`（winston/lib/winston/logger.js:350-361）→ transport 发 'finish' →
 *      readable-stream 的 pipe 收尾 `onfinish` → `src.unpipe(dest)`
 *      （readable-stream/lib/_stream_readable.js:656-670，注释原文
 *      "Both close and finish should trigger unpipe, but only once."）
 *      → TransportStream 的 `once('unpipe')` → `close()`（winston-transport/modern.js:40-54）。
 *      实测：closeCalled=1、unpipes=1、finishes=1、25/25 送达。初版这里写的是"end() 只关掉
 *      Writable，够不到 close()"——**错的**：只读到 winston 那一层就下结论，漏了 Node 自己的
 *      pipe 收尾。台账里对侧 F-98 那句"logger.end() 确实会走到 close()"是对的。
 *   ② 但 end() **触发而不等待**：同一夹具（25 行、每批 40ms 网络延迟）end() 之后立刻
 *      process.exit() 只送达 5/25，等 100ms 送达 15/25，200ms 才全量。送达与否取决于
 *      end() 之后进程还活着多久，而且**无声**——没有任何一处报"这一轮丢了 20 行"。
 *   ③ 更要紧的是：F-187 删掉了生产里唯一的 `logger.end()` 调用点（end() 之后再打任意一条
 *      日志都同步抛 ERR_STREAM_WRITE_AFTER_END，对落盘零收益），所以现在非测试代码里
 *      `logger.end()` 出现 0 次 ⇒ 'unpipe' 永不发生 ⇒ close() 的唯一调用点就是本函数。
 * 于是每次关闭，缓冲里最多 `BUFFER_CAP` 行日志一行都不会送达 SIEM，且**无声**——
 * 丢的恰恰是"为什么要关闭"那一段。
 *
 * 【为什么预算在调用方钳而不改 close()】close() 自带的 deadline 是 `timeoutMs + 1000`，
 * 与本进程关停总预算（F-103）无耦合；本步排在链尾，只能用 `stepAllowMs(0)` 的剩余量。
 * 超预算时返回 'over-budget' 交调用方如实播报，而不是静等 close() 自己跑完。
 *
 * 【不改 logShipper.js】那是另一条在途改动链的私有领地；本函数只用它的公开 close()，
 * 并用 `instanceof` 认出实例（未启用转发时 transports 里没有它 ⇒ 'no-shipper'，不报错）。
 *
 * @param {{logger?: object, allowMs?: number}} [options] logger 仅供测试注入；
 *        allowMs 为本步可用的毫秒数，非有限值表示不限制
 * @returns {Promise<'no-shipper'|'drained'|'over-budget'|'failed'>} 结局码，由调用方分派日志
 */
async function drainShippingBuffer(options = {}) {
  const target = options.logger || require('./logger');
  let shipper = null;
  try {
    const { HttpShipperTransport } = require('./logShipper');
    shipper = (target.transports || []).find((t) => t instanceof HttpShipperTransport) || null;
  } catch (e) {
    // 此处不能用 logger：本模块的存在理由就是"logger 可能已经不可用"
    console.error(
      `[loggerFlush] 无法定位 SIEM 转发 transport，跳过排空：${e && e.message ? e.message : e}`
    );
    return 'no-shipper';
  }
  if (!shipper || typeof shipper.close !== 'function') return 'no-shipper';

  // close() 自己已经把所有失败路径变成 console 告警 + 正常返回；这里再兜一层，
  // 既避免"竞速输了、close() 随后 reject"变成 unhandledRejection，也让失败可见
  const closing = Promise.resolve()
    .then(() => shipper.close())
    .then(
      () => 'drained',
      (e) => {
        console.error(`[loggerFlush] SIEM 转发缓冲排空失败：${e && e.message ? e.message : e}`);
        return 'failed';
      }
    );

  if (!Number.isFinite(options.allowMs)) return closing;

  let timer = null;
  const overBudget = new Promise((resolve) => {
    timer = setTimeout(() => resolve('over-budget'), options.allowMs);
    if (timer.unref) timer.unref();
  });
  const outcome = await Promise.race([closing, overBudget]);
  if (timer) clearTimeout(timer);
  return outcome;
}

/** 崩溃路径上不能假设 `e` 是 Error（throw 字符串/对象都见过） */
function errText(e) {
  return e && e.message ? e.message : e;
}

/**
 * 排空结果 → 该写哪一行日志（单一来源：三条退出路径共用，措辞不会分叉）。
 * 返回 null 表示"这种情况保持静默"——未启用转发（no-shipper）是生产默认形态，
 * 每次关停写一条只是噪声；崩溃路径的成功也不写（那行日志排在排空之后，送不出去）。
 */
function drainReportLine(outcome, { tag, allowMs, reportDrained }) {
  if (outcome === 'over-budget') {
    return {
      level: 'warn',
      text:
        `${tag}：SIEM 日志转发缓冲未在 ${allowMs}ms 内排空，` +
        '剩余行随进程退出丢弃（预算见调用点与 utils/shutdownBudget.js）',
    };
  }
  if (outcome === 'failed') {
    return {
      level: 'error',
      text: `${tag}：SIEM 日志转发缓冲排空异常，详见 stderr 的 [loggerFlush] 行`,
    };
  }
  if (outcome === 'drained' && reportDrained) {
    return { level: 'info', text: `${tag}：SIEM 日志转发缓冲已排空` };
  }
  return null;
}

/**
 * 带"如实报"的排空（F-186b）：三条退出路径（优雅关闭 / uncaughtException /
 * unhandledRejection）共用同一套结果口径，避免"其中一条忘了报剩余行数"。
 *
 * 永不 reject —— 这正是它存在的理由：调用点是崩溃处理链，链尾没有 catch，
 * 一次 reject 会变成新的 unhandledRejection（再走一遍崩溃链）。而 F-187 已经证明
 * "报结果的那条 logger 调用"本身也是会抛的站点（logger 被 end() 之后再打日志即
 * 同步抛 ERR_STREAM_WRITE_AFTER_END），所以连报告这一步也在 try 里，抛了就退回 stderr。
 *
 * @param {object} [options] 透传给 drainShippingBuffer（logger/allowMs）
 * @param {string} [options.tag] 结果行的前缀，如 '优雅关闭' / 'uncaughtException'
 * @param {boolean} [options.reportDrained] 成功也写一行。崩溃路径不写：那行日志排在
 *        排空**之后**，写出去也送不出去了，只在 stderr 留一条也算取证（故成功时静默）
 * @returns {Promise<string>} 'drained' | 'over-budget' | 'failed' | 'no-shipper'
 */
async function bestEffortDrain(options = {}) {
  const { tag = '关闭链', reportDrained = false } = options;
  let outcome;
  try {
    outcome = await drainShippingBuffer(options);
  } catch (e) {
    outcome = 'failed';
    console.error(`[loggerFlush] ${tag} 排空 SIEM 转发缓冲时抛出：${errText(e)}`);
  }
  const line = drainReportLine(outcome, { tag, allowMs: options.allowMs, reportDrained });
  if (line) {
    try {
      const target = options.logger || require('./logger');
      target[line.level](line.text);
    } catch (e) {
      console.error(`[loggerFlush] ${line.text}（logger 不可用：${errText(e)}）`);
    }
  }
  return outcome;
}

module.exports = {
  flushLogsSync,
  exitAfterFlush,
  drainShippingBuffer,
  bestEffortDrain,
  DEFAULT_LOG_DIR,
  dateStamp,
};
