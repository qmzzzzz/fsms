/**
 * 日志目录的单一声明
 *
 * 此前两处各自算同一个表达式（`utils/logger.js` 的 logsDir 与
 * `utils/loggerFlush.js` 的 DEFAULT_LOG_DIR），注释还写着"保持一致而非复制常量值"——
 * 但那正是复制：两处对"日志落在哪"各自负责，改一处就会让同步落盘兜底写到
 * 异步 transport 之外的目录，而这类错只有在进程崩溃当天才会暴露。
 *
 * 同时提供 `LOG_DIR` 覆盖：容器里日志目录常要指向挂载卷；测试也必须有独立目录——
 * 断言"崩溃现场一定落盘"的用例若去读共享的当日文件，会被按大小轮转
 * （daily-rotate 的 maxSize）与并发写者同时干扰，表现为随机且无法复现的假红。
 */

const path = require('path');

/** 缺省仍是仓库 logs/（相对本文件上两级），与既有行为一致 */
const LOG_DIR = process.env.LOG_DIR
  ? path.resolve(process.env.LOG_DIR)
  : path.join(__dirname, '../../logs');

module.exports = { LOG_DIR };
