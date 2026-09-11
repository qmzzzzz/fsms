// Jest setup 文件（setupFiles）
// 在每个测试文件运行前同步执行，仅做环境变量设置
// 数据库进程由 globalSetup.js 统一启动

// 默认值取自 constants.js，与 globalSetup.js 同源。
// 此前两处各写一套字面量，改一处忘一处就会出现「全局已设、单文件回退默认值」的漂移。
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  TEST_JWT_SECRET,
  TEST_JWT_REFRESH_SECRET,
  TEST_AES_SECRET_KEY,
  TEST_HMAC_SECRET,
  DEFAULT_CORS_ORIGIN,
} = require('./constants');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = TEST_JWT_SECRET;
process.env.JWT_REFRESH_SECRET = TEST_JWT_REFRESH_SECRET;
process.env.AES_SECRET_KEY = TEST_AES_SECRET_KEY;
process.env.HMAC_SECRET = TEST_HMAC_SECRET;
process.env.CORS_ORIGIN = process.env.CORS_ORIGIN || DEFAULT_CORS_ORIGIN;

// config 每个测试文件都会重新 require，并再次执行 dotenv + secrets 注入。
// 这里预置与测试密钥同值的本地文件，让 *_FILE 指向测试副本；已设置的
// 环境变量不会被 dotenv 覆盖，从而隔离开发者本机的生产密钥文件。
const secretWorkerId = process.env.JEST_WORKER_ID || '1';
const testSecretDir = fs.mkdtempSync(
  path.join(os.tmpdir(), `xf-test-secrets-worker-${secretWorkerId}-`)
);
const testSecretFiles = {
  JWT_SECRET_FILE: 'jwt',
  JWT_REFRESH_SECRET_FILE: 'jwt_refresh',
  AES_SECRET_KEY_FILE: 'aes',
  HMAC_SECRET_FILE: 'hmac',
};
const testSecretValues = {
  jwt: TEST_JWT_SECRET,
  jwt_refresh: TEST_JWT_REFRESH_SECRET,
  aes: TEST_AES_SECRET_KEY,
  hmac: TEST_HMAC_SECRET,
};
for (const [envKey, fileName] of Object.entries(testSecretFiles)) {
  const filePath = path.join(testSecretDir, fileName);
  fs.writeFileSync(filePath, testSecretValues[fileName], 'utf8');
  process.env[envKey] = filePath;
}

// setupFiles 对每个测试文件都会执行。使用独立的临时目录并登记到当前 worker，
// 待 worker 退出时统一清理，避免 globalTeardown 在其他测试文件仍在 require
// config 时删除共享目录，造成「密钥文件偶发不存在」。
if (!globalThis.__XF_TEST_SECRET_DIRS__) {
  globalThis.__XF_TEST_SECRET_DIRS__ = new Set();
  process.on('exit', () => {
    for (const dir of globalThis.__XF_TEST_SECRET_DIRS__) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}
globalThis.__XF_TEST_SECRET_DIRS__.add(testSecretDir);

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
