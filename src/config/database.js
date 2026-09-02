/**
 * 数据库配置文件
 * 负责 MongoDB 连接管理（含重试、连接事件监听）
 */

const mongoose = require('mongoose');
const logger = require('../utils/logger');
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

// 连接池上限：默认 20（原 10 在高并发下易排队等待连接），
// 可通过 MONGO_MAX_POOL_SIZE 按压测结果调整
const maxPoolSize = (() => {
  const n = parseInt(process.env.MONGO_MAX_POOL_SIZE, 10);
  return Number.isFinite(n) && n > 0 ? n : 20;
})();

/**
 * 连接 MongoDB（带指数退避重试）
 * @param {number} [retries=MAX_RETRIES] 剩余重试次数
 */
const connectDB = async (retries = MAX_RETRIES) => {
  try {
    const conn = await mongoose.connect(config.mongodbUri, {
      serverSelectionTimeoutMS: 5000, // 初始连接超时 5 秒
      socketTimeoutMS: 45000, // socket 空闲超时
      heartbeatFrequencyMS: 10000, // 心跳频率
      maxPoolSize, // 连接池大小
      minPoolSize: 2,
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
    process.exit(1);
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
