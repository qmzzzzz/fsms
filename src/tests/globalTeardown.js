// Jest 全局 teardown：关闭内存 MongoDB 和 mongoose 连接

const mongoose = require('mongoose');

module.exports = async function globalTeardown() {
  // P3-51：worker 库由 setup.js 按 JEST_WORKER_ID 分配（jest_w1、jest_w2...），
  // 主进程的 mongoose 连接指向的是 globalSetup 里那个无库名的 URI，
  // 只 dropDatabase() 清不掉 worker 库。改为枚举并删除全部 jest_w* 库。
  //
  // 内存库随 mongod 进程退出而整体消失，这里显式清理的意义是：
  // 在 --watch 模式下 globalTeardown 之后可能复用同一实例，
  // 残留库会让下一轮跑到脏数据。
  try {
    const admin = mongoose.connection.db.admin();
    const { databases } = await admin.listDatabases();
    const prefix = process.env.JEST_WORKER_DB_PREFIX || 'jest_w';
    for (const { name } of databases) {
      if (!name.startsWith(prefix)) continue;
      await mongoose.connection.useDb(name).dropDatabase();
    }
  } catch (_) {
    /* 连接可能已关闭或无权限，忽略 */
  }

  try {
    await mongoose.connection.dropDatabase();
  } catch (_) {
    /* 连接可能已关闭，忽略 */
  }
  await mongoose.connection.close();

  // 显式停止内存 MongoDB 子进程，避免残留导致 Jest 无法退出
  const server = globalThis.__MONGO_MEMORY_SERVER__;
  if (server) {
    await server.stop({ doCleanup: true }).catch(() => {});
  }
  console.log('✅ 测试环境已清理');
};
