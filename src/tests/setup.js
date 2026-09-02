// Jest setup 文件（setupFiles）
// 在每个测试文件运行前同步执行，仅做环境变量设置
// 数据库进程由 globalSetup.js 统一启动

// 默认值取自 constants.js，与 globalSetup.js 同源。
// 此前两处各写一套字面量，改一处忘一处就会出现「全局已设、单文件回退默认值」的漂移。
const {
  TEST_JWT_SECRET,
  TEST_AES_SECRET_KEY,
  TEST_HMAC_SECRET,
  DEFAULT_CORS_ORIGIN,
} = require('./constants');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || TEST_JWT_SECRET;
process.env.AES_SECRET_KEY = process.env.AES_SECRET_KEY || TEST_AES_SECRET_KEY;
process.env.HMAC_SECRET = process.env.HMAC_SECRET || TEST_HMAC_SECRET;
process.env.CORS_ORIGIN = process.env.CORS_ORIGIN || DEFAULT_CORS_ORIGIN;

/**
 * 测试数据库隔离（P3-51 → T-1 加强）
 *
 * 问题（P3-51 第一版）：globalSetup 只启动**一个** MongoMemoryServer，而
 * `maxWorkers: '50%'` 让多个测试文件并行执行。所有 worker 连同一个库，
 * 「造数」互相可见：countDocuments 断言随机失败、固定编码撞 E11000、
 * deleteMany 顺手删掉别人正在用的数据。
 * 当时按 JEST_WORKER_ID 分配了 worker 级独立库（jest_w1、jest_w2...）。
 *
 * 残留问题（T-1）：同一 worker 内的多个测试文件**串行共用**该库。
 * 数据残留照样跨文件传播——典型症状是上一文件写入的 IP 黑名单/
 * 账号锁定/角色变更被下一文件读到，出现「合法路径 403」这类
 * 顺序相关的偶发红，单跑该文件又永远复现不了。
 *
 * 解法：setupFiles 在**每个测试文件**执行前都会重新运行（同一文件内
 * 只跑一次），在此给库名追加「时间戳+随机」文件级后缀，使每个测试
 * 文件拥有全新空库——全量结果从此与执行顺序、并行分布无关。
 * 同一 mongod 进程内建库开销极低，不额外增加启动成本。
 *
 * 为什么放在 setupFiles 而不是 globalSetup：
 * globalSetup 在主进程执行一次，那里没有 JEST_WORKER_ID，也不感知文件边界；
 * setupFiles 在测试进程内、且早于测试文件被 require 时执行，
 * 正好能在任何 `mongoose.connect(process.env.MONGODB_URI)` 之前改写 URI。
 */
const WORKER_DB_PREFIX = 'jest_w';
const workerId = process.env.JEST_WORKER_ID || '1';
const baseUri = process.env.MONGODB_URI;

if (baseUri && !baseUri.includes(WORKER_DB_PREFIX)) {
  // getUri() 形如 mongodb://127.0.0.1:23892/ （无库名，可能带查询串）
  const [origin, query] = baseUri.split('?');
  const withoutTrailingSlash = origin.replace(/\/+$/, '');
  // 去掉可能已存在的库名段（形如 .../test），只保留 host:port
  const hostPart = withoutTrailingSlash.replace(/(mongodb:\/\/[^/]+)(\/.*)?$/, '$1');
  // 文件级后缀：毫秒时间戳（36 进制）+ 随机串，同/跨文件均不会碰撞
  const fileSuffix = `f${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  process.env.MONGODB_URI = `${hostPart}/${WORKER_DB_PREFIX}${workerId}_${fileSuffix}${query ? `?${query}` : ''}`;
}

// 供 globalTeardown 识别并清理全部 worker 库
process.env.JEST_WORKER_DB_PREFIX = WORKER_DB_PREFIX;
