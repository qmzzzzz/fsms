// Jest 全局 setup：使用 mongodb-memory-server 启动内存 MongoDB
// 无需外部 MongoDB 服务，CI 和本地均可直接运行

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const {
  TEST_JWT_SECRET,
  TEST_AES_SECRET_KEY,
  TEST_HMAC_SECRET,
  DEFAULT_CORS_ORIGIN,
} = require('./constants');

let mongoServer;

// MongoDB 二进制下载源策略（2026-08-20 修复 M-03）：
// - 显式设置 MONGOMS_DOWNLOAD_URL 时，mongodb-memory-server 会用正则解析该 URL 的包名，
//   且正则的平台组仅接受 linux|win32|osx|macos；而 MongoDB ≥4.3 的 Windows 官方包名为
//   "mongodb-windows-x86_64-*.zip"，自定义镜像 URL 一旦使用该命名会在解析阶段直接报错
//   （NoRegexMatchError），导致 Windows 本地 npm test 必现失败。
// - 因此：仅在 Linux（CI/国内服务器）自动注入 npmmirror 镜像（linux 命名可被正确解析）；
//   Windows/macOS 走库的默认下载逻辑（fastdl.mongodb.org，包名由库自行生成，不经过正则解析）。
// - 如你的网络无法访问 fastdl.mongodb.org，可自行设置 MONGOMS_DOWNLOAD_URL，
//   但包名必须使用库可解析的命名（平台段为 linux/win32/osx/macos）。
const MONGO_VERSION = '6.0.14';
if (!process.env.MONGOMS_DOWNLOAD_URL && process.platform === 'linux') {
  process.env.MONGOMS_DOWNLOAD_URL = `https://registry.npmmirror.com/-/binary/mongodb/mongodb-linux-x86_64-${MONGO_VERSION}.zip`;
}

module.exports = async function globalSetup() {
  // 设置环境变量。默认值统一取自 constants.js —— 与 setup.js 同源，
  // 避免两处各写一套字面量导致全局与单文件取值漂移。
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = process.env.JWT_SECRET || TEST_JWT_SECRET;
  process.env.AES_SECRET_KEY = process.env.AES_SECRET_KEY || TEST_AES_SECRET_KEY;
  process.env.HMAC_SECRET = process.env.HMAC_SECRET || TEST_HMAC_SECRET;
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
