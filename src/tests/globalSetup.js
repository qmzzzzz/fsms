// Jest 全局 setup：使用 mongodb-memory-server 启动内存 MongoDB
// 无需外部 MongoDB 服务，CI 和本地均可直接运行

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const {
  TEST_JWT_SECRET,
  TEST_JWT_REFRESH_SECRET,
  TEST_AES_SECRET_KEY,
  TEST_HMAC_SECRET,
  DEFAULT_CORS_ORIGIN,
} = require('./constants');

let mongoServer;

// MongoDB 二进制源（2026-09-04 修复 CI）：npmmirror 的 6.0.14 历史路径已 404。
// 恢复默认官方源，由 mongodb-memory-server 按发行版、架构与版本生成准确包名；
// 受限网络仍可通过 MONGOMS_DOWNLOAD_URL 显式覆盖。
const MONGO_VERSION = '6.0.14';

module.exports = async function globalSetup() {
  // 设置环境变量。默认值统一取自 constants.js —— 与 setup.js 同源，
  // 避免两处各写一套字面量导致全局与单文件取值漂移。
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = TEST_JWT_SECRET;
  process.env.JWT_REFRESH_SECRET = TEST_JWT_REFRESH_SECRET;
  process.env.AES_SECRET_KEY = TEST_AES_SECRET_KEY;
  process.env.HMAC_SECRET = TEST_HMAC_SECRET;
  delete process.env.JWT_SECRET_FILE;
  delete process.env.JWT_REFRESH_SECRET_FILE;
  delete process.env.AES_SECRET_KEY_FILE;
  delete process.env.HMAC_SECRET_FILE;
  process.env.CORS_ORIGIN = process.env.CORS_ORIGIN || DEFAULT_CORS_ORIGIN;

  // 启动内存 MongoDB（镜像源不提供 .md5 校验文件，关闭 MD5 校验，完整性由解压过程保证）
  mongoServer = await MongoMemoryServer.create({
    binary: {
      version: MONGO_VERSION,
      checkMD5: false,
    },
  });
  // 暴露实例供 globalTeardown 显式停止，避免 mongod 子进程残留导致 Jest 无法退出
  globalThis.__MONGO_MEMORY_SERVER__ = mongoServer;
  const mongoUri = mongoServer.getUri();
  process.env.MONGODB_URI = mongoUri;

  // 连接内存数据库
  await mongoose.connect(mongoUri);

  // 清空所有集合
  const collections = await mongoose.connection.db.collections();
  for (const collection of collections) {
    await collection.deleteMany({});
  }

  console.log('✅ 测试环境已初始化（内存 MongoDB）');
};
