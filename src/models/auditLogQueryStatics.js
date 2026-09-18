/**
 * AuditLog 查询类静态方法：个人操作日志与异常行为聚合。
 */

const { BUSINESS_TIMEZONE, OFF_HOURS_START, OFF_HOURS_END } = require('../constants/timezone');

const applyQueryStatics = (schema, responseExclude) => {
  schema.statics.getUserActivity = async function (userId, options = {}) {
    const { days = 7, limit = 100, category } = options;
    const safeLimit = Math.max(1, Math.min(limit, 500));
    const safeDays = Math.max(1, Math.min(days, 365));
    const query = {
      userId,
      timestamp: { $gte: new Date(Date.now() - safeDays * 24 * 60 * 60 * 1000) },
    };
    if (category) query.category = category;

    return this.find(query).sort({ timestamp: -1 }).limit(safeLimit).select(responseExclude);
  };

  schema.statics.detectAnomalies = async function (options = {}) {
    const { windowMinutes = 5, threshold = 10 } = options;
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
    const failureMatch = { timestamp: { $gte: windowStart }, success: false };

    const failedOperations = await this.aggregate([
      { $match: failureMatch },
      { $group: { _id: '$userId', count: { $sum: 1 } } },
      { $match: { count: { $gte: threshold } } },
    ]);

    const failedOperationsByIp = await this.aggregate([
      { $match: failureMatch },
      { $group: { _id: '$ip', count: { $sum: 1 } } },
      { $match: { count: { $gte: threshold } } },
    ]);

    const unusualTimeOperations = await this.aggregate([
      { $match: { timestamp: { $gte: windowStart } } },
      {
        $addFields: {
          hour: { $hour: { date: '$timestamp', timezone: BUSINESS_TIMEZONE } },
        },
      },
      {
        $match: {
          $or: [{ hour: { $lt: OFF_HOURS_END } }, { hour: { $gte: OFF_HOURS_START } }],
        },
      },
      { $group: { _id: '$userId', count: { $sum: 1 } } },
      // L-20：原为硬编码 5，而同一函数的 failedOperations / failedOperationsByIp
      // 都用 threshold 参数——调用方以为统一调整了阈值，实际"非常规时间访问"
      // 始终按 5 计。现统一为 threshold，与其余两路口径一致。
      { $match: { count: { $gte: threshold } } },
    ]);

    return { failedOperations, failedOperationsByIp, unusualTimeOperations };
  };
};

module.exports = { applyQueryStatics };
