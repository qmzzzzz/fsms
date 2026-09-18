/**
 * 数据库配置文件
 * 负责 MongoDB 连接管理（含重试、连接事件监听）
 */

const mongoose = require('mongoose');
const logger = require('../utils/logger');
const { exitAfterFlush } = require('../utils/loggerFlush');
const config = require('./index');

const MAX_RETRIES = 5;
const RETRY_DELAY_MS = 3000;
// 指数退避封顶：避免后期重试等待过长（5 次重试总耗时约 75 秒）
const MAX_RETRY_DELAY_MS = 30000;

/**
 * 计算第 attempt 次重试前的等待时长：RETRY_DELAY_MS * 2^attempt，封顶 MAX_RETRY_DELAY_MS
 * @param {number} attempt 重试轮次（从 0 开始）
 */
const retryDelayMs = (attempt) => {
  const base = Math.min(RETRY_DELAY_MS * 2 ** attempt, MAX_RETRY_DELAY_MS);
  // 抖动因子 0.5~1.5：多实例同时重启时避免同步撞库重连（thundering herd）
  return Math.round(base * (0.5 + Math.random()));
};

// 连接池与超时参数（P2-70：原为硬编码，现全部可配；缺省值保持与原先一致）。
// 各参数对性能的影响与调参方向：
//   MONGO_MAX_POOL_SIZE       并发请求数上限的实质瓶颈（原 10 在高并发下排队等待）
//   MONGO_MIN_POOL_SIZE       预热连接数，过低会让突发流量付出建连延迟
//   MONGO_SERVER_SELECTION_TIMEOUT_MS  初始选主超时：过大会让「连不上」迟迟不报错
//   MONGO_SOCKET_TIMEOUT_MS   空闲 socket 超时：过小会在慢查询上误断
//   MONGO_HEARTBEAT_MS        心跳频率：过低增加无谓流量
// 解析失败或非正值一律回落默认，避免把 0/负值传给驱动（驱动行为未定义）。
const envInt = (name, fallback) => {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const maxPoolSize = envInt('MONGO_MAX_POOL_SIZE', 20);
const minPoolSize = envInt('MONGO_MIN_POOL_SIZE', 2);
const serverSelectionTimeoutMS = envInt('MONGO_SERVER_SELECTION_TIMEOUT_MS', 5000);
const socketTimeoutMS = envInt('MONGO_SOCKET_TIMEOUT_MS', 45000);
const heartbeatFrequencyMS = envInt('MONGO_HEARTBEAT_MS', 10000);

/**
 * 连接 MongoDB（带指数退避重试）
 * @param {number} [retries=MAX_RETRIES] 剩余重试次数
 */
const connectDB = async (retries = MAX_RETRIES) => {
  try {
    const conn = await mongoose.connect(config.mongodbUri, {
      serverSelectionTimeoutMS, // 初始连接超时（MONGO_SERVER_SELECTION_TIMEOUT_MS）
      socketTimeoutMS, // socket 空闲超时（MONGO_SOCKET_TIMEOUT_MS）
      heartbeatFrequencyMS, // 心跳频率（MONGO_HEARTBEAT_MS）
      maxPoolSize, // 连接池上限（MONGO_MAX_POOL_SIZE）
      minPoolSize, // 连接池预热（MONGO_MIN_POOL_SIZE）
    });

    logger.info(`MongoDB 连接成功：${conn.connection.host}:${conn.connection.port}`);
    return conn;
  } catch (error) {
    if (retries > 0) {
      // 指数退避：第 n 次重试等待 RETRY_DELAY_MS * 2^n（3s → 6s → 12s → 24s → 30s 封顶）
      const delayMs = retryDelayMs(MAX_RETRIES - retries);
      logger.warn(
        `数据库连接失败，${delayMs / 1000}s 后重试（剩余 ${retries} 次）：${error.message}`
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      return connectDB(retries - 1);
    }
    logger.error(`数据库连接失败（已重试 ${MAX_RETRIES} 次）：${error.message}`);
    // P1-13：等 transport 队列排空后再退出（原为紧接 exit，日志实测丢失）。
    return exitAfterFlush(1);
  }
};

// 连接事件监听（运行中断线自动重连由 mongoose 处理，此处仅记录日志）
mongoose.connection.on('disconnected', () => {
  logger.warn('MongoDB 连接断开，Mongoose 将自动尝试重连');
});

mongoose.connection.on('reconnected', () => {
  logger.info('MongoDB 已重新连接');
});

mongoose.connection.on('error', (err) => {
  logger.error(`MongoDB 连接错误：${err.message}`);
});

module.exports = connectDB;
