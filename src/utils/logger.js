const winston = require('winston');
require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');
const os = require('os');
// helpers.js 无任何顶层 require，方向单一（helpers 不认识 logger），无加载环
const { stripControlChars } = require('./helpers');

const { LOG_DIR: logsDir } = require('./logPaths');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// 请求级日志关联（报告 O-5）：requestId 中间件把请求处理包进 AsyncLocalStorage，
// 此 format 在每条日志序列化前读取上下文并合并 requestId——业务代码零改动，
// 单请求的多条日志可通过 request id 一键关联；脱离请求上下文的日志行为不变。
// userId（报告 5.6）：authenticate 认证成功后经 extendLogContext 注入，
// 此后同一请求的所有日志自动携带 userId，控制器无需显式传 meta
const { getLogContext } = require('./logContext');
const attachRequestContext = winston.format((info) => {
  const ctx = getLogContext();
  if (ctx && ctx.requestId) {
    info.requestId = ctx.requestId;
  }
  if (ctx && ctx.userId) {
    info.userId = ctx.userId;
  }
  return info;
});

// 落盘格式是**安全开关**，不是审美开关：printf 把 message 里的 \n 原样写成新行
// （等于凭空多一行可伪造的日志），json 才会转义；且只有 json 模式让
// service/hostname/requestId 保持成可被 ELK/log-shipper 解析的字段。
// 判据必须与 cookie Secure、API 文档默认位同一套"未识别即按生产办"的语义
// （见 config/validate.requiresProductionSemantics 的说明），不能押在字面量
// 'production' 上：`NODE_ENV=prod` 这一路此前是"配置按生产校验、cookie 带 Secure、
// 文档关闭，日志却退回 printf"——恰好把最容易配错的部署变成唯一不可解析的格式。
// 无环说明：validate.js 顶层不 require 任何模块（logger 只在校验函数内惰性取），
// 所以这里可以顶层取。
const { requiresProductionSemantics } = require('../config/validate');
const productionSemantics = requiresProductionSemantics();

// 落盘前的统一清洗（同类，但落在最后一道边界上）：
// ① 各中间件已就地清洗自己写的字段，但 logger 是**所有**调用方的公共出口，
//    这里不兜底就等于要求每个调用点都记得清洗（本仓已多次出现"同语义多处各抄一遍、
//    漏一处"的缺陷族）。
// ② 不做长度上限时，一个 1MB 的 username（express.json limit 内）会变成一行日志，
//    既撑爆磁盘也把 grep/ELK 的解析拖死。
// 注意：非生产走 printf，\n 会原样落盘 = 伪造整行日志；
// 生产走 json，JSON.stringify 会转义 \n 但**不转义** U+2028-U+202E / U+2066-U+2069
// （Bidi 类，可篡改终端显示顺序），所以两种模式都需要这条，不是只补 dev。
const MAX_LOG_MESSAGE_CHARS = 8192;
const MAX_LOG_FIELD_CHARS = 1024;
// 纯函数形态：winston format 只是它的一层包装。
// 单独导出是为了能被确定性单元测试直接调用——走"真写文件再读回来"的断言
// 依赖 daily-rotate 的异步落盘时序与本地时区文件名，实测在同机其它套件并发时
// 不稳定（表现为"一条都没新增"的假失败）。断言不该建立在时序上。
const sanitizeLogInfo = (info) => {
  if (typeof info.message === 'string') {
    info.message = stripControlChars(info.message, MAX_LOG_MESSAGE_CHARS);
  }
  for (const [key, value] of Object.entries(info)) {
    if (key === 'message' || typeof value !== 'string') continue;
    info[key] = stripControlChars(value, MAX_LOG_FIELD_CHARS);
  }
  return info;
};
const sanitizeLogRecords = winston.format(sanitizeLogInfo);

/**
 * winston level 解析（类：配置读不懂必须响，不能静默）
 *
 * 原实现 `process.env.LOG_LEVEL || 'info'` 不做任何校验。winston 的
 * `_isLevelEnabled` 拿 `levels[sysLevel]` 做数值比较，于是
 * `LOG_LEVEL="info "`（.env/compose 里极易写出的尾空格）或 `LOG_LEVEL=Error`
 * 会让 `levels['info '] === undefined` → `0 >= undefined` 为 false →
 * **所有记录（含 error）静默不落盘**，进程照常启动、退出码 0，
 * 故障现场没有任何日志可查。
 * 这里归一 + 白名单校验，并在被覆盖时**用正确的级别把这件事记下来**。
 */
const WINSTON_NPM_LEVELS = winston.config.npm.levels;
const resolveLogLevel = () => {
  const raw = process.env.LOG_LEVEL;
  const normalized = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (normalized === '') return 'info';
  if (WINSTON_NPM_LEVELS[normalized] !== undefined) return normalized;
  // logger 尚未创建，这里不能用 logger.warn —— 用 console.error 保证一定看得见
  console.error(
    `LOG_LEVEL 取值 "${raw}" 不是 winston 已知级别（${Object.keys(WINSTON_NPM_LEVELS).join('/')}），` +
      '已按 info 运行；若不修好，日志级别会静默失效'
  );
  return 'info';
};
const jsonFormat = winston.format.combine(
  attachRequestContext(),
  winston.format.timestamp(),
  sanitizeLogRecords(),
  winston.format.json()
);
// printf 版式一份定义、两条链复用（console 带 colorize / file 不带）
// meta 序列化必须兜住循环引用与 BigInt：JSON.stringify 遇到这两者会**抛错**，
// 而抛在 transport 的 transform 里 = 这条日志直接消失（exitOnError:false 还会
// 把 transport 错误一起吞掉），最坏情形是"出事故时恰好那条日志不存在"。
const serializeMeta = (meta) => {
  try {
    return JSON.stringify(meta);
  } catch (_) {
    try {
      return require('util').inspect(meta, { depth: 2 });
    } catch (__) {
      return '[meta 无法序列化]';
    }
  }
};
const printfLayout = winston.format.printf(({ timestamp, level, message, ...meta }) => {
  let msg = `${timestamp} [${level}]: ${message}`;
  if (Object.keys(meta).length > 0) {
    msg += ` ${serializeMeta(meta)}`;
  }
  return msg;
});
// 颜色码只进 Console：dev/test 的 combined 文件此前被 colorize 污染，
// ANSI 码随行落盘对 grep/ELK 等日志解析器不友好（2026-09-05 实证）
const consoleFormat = productionSemantics
  ? jsonFormat
  : winston.format.combine(
      attachRequestContext(),
      winston.format.timestamp(),
      sanitizeLogRecords(),
      winston.format.colorize(),
      printfLayout
    );
const fileFormat = productionSemantics
  ? jsonFormat
  : winston.format.combine(
      attachRequestContext(),
      winston.format.timestamp(),
      sanitizeLogRecords(),
      printfLayout
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
  level: resolveLogLevel(),
  format: fileFormat,
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
    format: consoleFormat,
  })
);

const shippingUrl = process.env.LOG_SHIPPING_URL;
// 实际挂载成功的 transport 实例；null 表示"没挂"。isShippingEnabled() 以它为准。
let shippingTransport = null;
if (shippingUrl) {
  try {
    const { HttpShipperTransport, resolveShippingTarget } = require('./logShipper');
    // F-215：挂载期先把出站目标解析一遍，再构造 transport。
    // resolveShippingTarget 原先只在**每个批次发送时**被 _post 调用，于是
    // `new HttpShipperTransport` 与下面那句「已启用」永远不会因为 URL 无效而失败
    // ——**这个 catch 抓不到任何跟 URL 有关的错**，它实际只覆盖 require 和构造。
    // 生产 Node 实测（LOG_SHIPPING_URL 三种取值，捕获 winston 的 console 输出）：
    //   https://siem.example.test/ingest → saysEnabled=true  saysMountFailed=false（正确）
    //   htps://siem.example.test/ingest  → saysEnabled=true  saysMountFailed=false（错）
    //   not-a-url                        → saysEnabled=true  saysMountFailed=false（错）
    // 也就是说配置写错时：落盘的 combined-*.log 里写着"日志转发已启用"，而且真的挂上了
    // 一个每批必死的 transport——它会拉起 intervalMs 定时器、把整条日志流堆进
    // BUFFER_CAP=5000 的缓冲、堆满后裁头留断档标记，而唯一的失败信号是 _flush 里
    // 每分钟一条、走 console.error 且**不经过 winston** 的告警（容器不采 stderr 就全无声）。
    // 判据本身早在 logShipperSchemeAllowlist 那轮就修了（非法 scheme 不再
    // 静默降级成明文出站），该轮注释点名的残留——"运维看到的仍是『日志转发已启用』"
    // ——就是这里。解析放在数值读取**之前**：一条已经死了的配置不该再刷三条
    // LOG_SHIPPING_BATCH 之类的告警，操作员只需要看到一句"挂载失败：原因"。
    resolveShippingTarget(shippingUrl);
    // 这三处原为 `parseInt(env,10) || undefined`，负值会被原样采纳
    // （如 batchSize=-1 → 每批都"超限"）。fallback 传 undefined 保持既有语义：
    // 缺省时交给传输层自己的默认值。此处**不能用 logger**（正在加载 logger），
    // 故 onInvalid 用 console.warn——与 config/index.js 的 P2-39 同一处理理由。
    const { readPositiveNumberEnv } = require('./envNumber');
    const shippingNum = (name) =>
      readPositiveNumberEnv(name, undefined, {
        integer: true,
        onInvalid: (n, raw) =>
          console.warn(`[logger] ${n}=${JSON.stringify(raw)} 非法（须为正整数），已忽略该覆盖项`),
      });
    const transport = new HttpShipperTransport({
      url: shippingUrl,
      token: process.env.LOG_SHIPPING_TOKEN,
      batchSize: shippingNum('LOG_SHIPPING_BATCH'),
      intervalMs: shippingNum('LOG_SHIPPING_INTERVAL_MS'),
      timeoutMs: shippingNum('LOG_SHIPPING_TIMEOUT_MS'),
    });
    logger.add(transport);
    shippingTransport = transport;
    logger.info(`日志转发已启用 → ${shippingUrl}`);
  } catch (e) {
    // 此时 logger 本体（文件+console transport）已可用，走 logger.warn 保持口径统一（报告 O-7）
    logger.warn(`日志转发 transport 挂载失败：${e.message}`);
  }
}

/**
 * 日志转发**是否真的在跑**（合规面板读这里，不要读 process.env）
 *
 * `!!process.env.LOG_SHIPPING_URL` 回答的是"配过这么个变量"，回答不了
 * "日志正在往 SIEM 送"：变量可以写成不可解析的串（F-215 修前连挂载都不会失败），
 * 也可以指向一个永久 4xx 的端点。本仓同一对象里的邻居（walEnabled /
 * monitorRunning / monitorHealth）一律查运行态，只有这一个查环境变量，
 * 属于同一缺陷类（有出口、口径不一致）。
 * 判据取"实例仍在 transports 里"而不是"曾经挂上过"：关停序列若摘掉它，答案要跟着变。
 */
logger.isShippingEnabled = () =>
  Boolean(shippingTransport) && logger.transports.includes(shippingTransport);

module.exports = logger;
// 仅供测试/调试（与 utils/metrics.js 的 `_counters` 同一约定）：
// 落盘清洗是纯函数，直接调用它做断言，比"写文件再读回来"可靠
logger.__test = { sanitizeLogInfo, serializeMeta, resolveLogLevel, fileFormat };
