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

// MongoDB 二进制源：默认官方源，由 mongodb-memory-server 按发行版、架构与版本生成准确包名；
// 受限网络仍可通过 MONGOMS_DOWNLOAD_URL 显式覆盖。
// S-3：与生产 compose / e2e-browser service 的 8.0.34 对齐（原 6.0.14 已随 6.0 线 EOL）。
// 本地若已有其它 8.x 二进制，可用 MONGOMS_SYSTEM_BINARY 指向它，避免重复下载。
const MONGO_VERSION = '8.0.34';

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

  /**
   * POSIX shell 解析（Windows 上 PATH 里那个 bash 常是"没装发行版的 WSL 桩"；详见
   * src/tests/helpers/posixShell.js 的模块注释）。
   *
   * 为什么必须在 globalSetup 这一层做：测试进程里改 process.env.PATH **不影响**子进程的
   * 可执行文件查找——Windows 上 libuv 是按真实进程环境块解析 bash 的，而 jest 的沙箱
   * process.env 与真实环境块不是同一个东西（实测：同一个进程里改沙箱 PATH 后
   * spawnSync('bash') 依旧命中 WSL 桩）。globalSetup 跑在 jest 主进程、其环境变量随
   * worker 派生一起继承，只有在这里改，用例里那句 spawnSync('bash') 才会真的命中可用 shell。
   */
  const { ensureShellOnPath } = require('./helpers/posixShell');
  const resolvedShell = ensureShellOnPath();
  if (resolvedShell) {
    if (resolvedShell.source !== 'posix') {
      console.log(
        `[test-env] shell 门禁使用 ${resolvedShell.cmd}（来源 ${resolvedShell.source}）：` +
          'Windows/MSYS 语义下的绿不等价于 Linux 权威结论，CI 仍是最终口径。'
      );
    }
  } else {
    console.warn(
      '[test-env] 未找到可用的 POSIX shell（PATH 上的 bash 跑不通；Windows 上多为未装发行版的 WSL 桩）。' +
        '依赖 shell 的门禁（src/tests/deploy/** 等）本轮会红，属环境缺失而非代码缺陷；' +
        '修法：装 Git Bash 或 WSL 发行版，或用 FSMS_TEST_SHELL 显式指定可用的 bash。'
    );
  }

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
