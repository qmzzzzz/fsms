const winston = require('winston');
require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');
const os = require('os');

const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// 请求级日志关联（报告 O-5）：requestId 中间件把请求处理包进 AsyncLocalStorage，
// 此 format 在每条日志序列化前读取上下文并合并 requestId——业务代码零改动，
// 单请求的多条日志可通过 request id 一键关联；脱离请求上下文的日志行为不变
const { getLogContext } = require('./logContext');
const attachRequestContext = winston.format((info) => {
  const ctx = getLogContext();
  if (ctx && ctx.requestId) {
    info.requestId = ctx.requestId;
  }
  return info;
});

const logFormat =
  process.env.NODE_ENV === 'production'
    ? winston.format.combine(
        attachRequestContext(),
        winston.format.timestamp(),
        winston.format.json()
      )
    : winston.format.combine(
        attachRequestContext(),
        winston.format.timestamp(),
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          let msg = `${timestamp} [${level}]: ${message}`;
          if (Object.keys(meta).length > 0) {
            msg += ` ${JSON.stringify(meta)}`;
          }
          return msg;
        })
      );

// P3-46：与审计库 TTL 共用同一份留存声明。
// 原实现 `parseInt(...) || 180` 与模型侧的钳制口径不一致：
// AUDIT_RETENTION_DAYS=1 时审计库留 90 天而日志文件只留 1 天，
// 取证时会出现「审计记录还在、对应的原始日志已被轮转删除」；
// 负值更会生成非法的 maxFiles: '-5d'
const { RETENTION_DAYS } = require('../constants/retention');
const logRetentionDays = `${RETENTION_DAYS}d`;

const fileRotateTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logsDir, 'combined-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '10m',
  maxFiles: logRetentionDays,
});

const errorRotateTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logsDir, 'error-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '10m',
  maxFiles: logRetentionDays,
  level: 'error',
});

/**
 * 进程级异常落盘（P3-32）
 *
 * index.js 已注册 process.on('uncaughtException'/'unhandledRejection')，
 * 但那里走的是 logger.error(message)——**堆栈在生产分支被刻意省略**
 * （只记 message 与 name，避免堆栈进入通用日志）。结果是进程崩溃这个
 * 最需要取证的场景反而缺少调用栈，只能靠 message 猜。
 *
 * 这里用 winston 的 exceptionHandlers/rejectionHandlers 单独落一份完整堆栈到
 * exceptions-*.log：文件与常规日志隔离，不影响 combined/error 的对外口径，
 * 又保证崩溃现场可追。
 *
 * exitOnError: false 是关键——winston 配置 exceptionHandlers 后默认会
 * 自行 process.exit(1)，那会抢在 index.js 的处理器 flush 审计缓冲之前退出，
 * 把 P3-33 刚修好的「退出前落库」重新破坏掉。
 *
 * 测试环境（T-1）不挂载这两个处理器：winston 每次创建 logger 都会向
 * process 追加 uncaughtException/unhandledRejection 监听，而
 * jest.resetModules 会让本模块被反复重新执行——监听器随之累积，
 * 触发 MaxListenersExceededWarning 并拖住 worker 优雅退出。
 * 测试进程无需崩溃取证，直接跳过。
 */
const exceptionRotateTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logsDir, 'exceptions-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '10m',
  maxFiles: logRetentionDays,
});

const isTestEnv = process.env.NODE_ENV === 'test';
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: {
    service: process.env.SERVICE_NAME || 'fire-safety-api',
    hostname: os.hostname(),
    pid: process.pid,
  },
  transports: [fileRotateTransport, errorRotateTransport],
  ...(isTestEnv
    ? {}
    : {
        exceptionHandlers: [exceptionRotateTransport],
        rejectionHandlers: [exceptionRotateTransport],
      }),
  exitOnError: false,
});

logger.add(
  new winston.transports.Console({
    format: logFormat,
  })
);

const shippingUrl = process.env.LOG_SHIPPING_URL;
if (shippingUrl) {
  try {
    const { HttpShipperTransport } = require('./logShipper');
    logger.add(
      new HttpShipperTransport({
        url: shippingUrl,
        token: process.env.LOG_SHIPPING_TOKEN,
        batchSize: parseInt(process.env.LOG_SHIPPING_BATCH, 10) || undefined,
        intervalMs: parseInt(process.env.LOG_SHIPPING_INTERVAL_MS, 10) || undefined,
        timeoutMs: parseInt(process.env.LOG_SHIPPING_TIMEOUT_MS, 10) || undefined,
      })
    );
    logger.info(`日志转发已启用 → ${shippingUrl}`);
  } catch (e) {
    // 此时 logger 本体（文件+console transport）已可用，走 logger.warn 保持口径统一（报告 O-7）
    logger.warn(`日志转发 transport 挂载失败：${e.message}`);
  }
}

module.exports = logger;
