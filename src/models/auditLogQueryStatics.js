/**
 * AuditLog 查询类静态方法：个人操作日志与异常行为聚合。
 */

const { BUSINESS_TIMEZONE, OFF_HOURS_START, OFF_HOURS_END } = require('../constants/timezone');

/**
 * 跑一条聚合，可选带服务端上限，返回可 await 的聚合对象。
 *
 * 上限必须由**调用方**决定：定时任务（auditMonitor）一定要带——挂死的一轮会把它
 * 自己的单轮闸门永久占住，检测随之静默停摆；HTTP 侧调用方不传 ⇒ 行为与改动前
 * 逐字相同（包括 `aggregate` 被 mock 成 Promise 的测试替身）。
 */
function aggregateWithBudget(model, pipeline, maxTimeMS) {
  // 无预算时保持**单参调用**的原样形状：`aggregate(pipe, undefined)` 虽然等价，
  // 但会把断言调用参数的测试替身从 1 参变成 2 参——"行为逐字不变"应当连调用面一起不变。
  if (!maxTimeMS) return model.aggregate(pipeline);
  // 预算走 aggregate 的第二参（options）：Mongoose 8 的 Aggregate 实例上**没有**
  // .maxTimeMS() 链式方法（实测 typeof agg.maxTimeMS === 'undefined'，聚合侧只暴露
  // allowDiskUse 一类），写成链式会在运行时抛 TypeError——用替身做的单测看不见，
  // 所以判据里必须有一条走真实模型（见 auditMonitorDetectionCoverage 真库用例）。
  return model.aggregate(pipeline, { maxTimeMS });
}

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
    // scopeFilter 由调用方注入（默认空＝全库）：定时任务 auditMonitor 不给任何人收窄，
    // 而 GET /security/stats 把按 userId 分组的结果回给发起请求的管理员，必须按操作者数据范围过滤
    // maxTimeMS 缺省＝不限（HTTP 路径原行为），定时任务侧按生效间隔传预算
    const { windowMinutes = 5, threshold = 10, scopeFilter = {}, maxTimeMS = 0 } = options;
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
    const failureMatch = { ...scopeFilter, timestamp: { $gte: windowStart }, success: false };

    const failedOperations = await aggregateWithBudget(
      this,
      [
        { $match: failureMatch },
        { $group: { _id: '$userId', count: { $sum: 1 } } },
        { $match: { count: { $gte: threshold } } },
      ],
      maxTimeMS
    );

    const failedOperationsByIp = await aggregateWithBudget(
      this,
      [
        { $match: failureMatch },
        { $group: { _id: '$ip', count: { $sum: 1 } } },
        { $match: { count: { $gte: threshold } } },
      ],
      maxTimeMS
    );

    const unusualTimeOperations = await aggregateWithBudget(
      this,
      [
        { $match: { ...scopeFilter, timestamp: { $gte: windowStart } } },
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
      ],
      maxTimeMS
    );

    return { failedOperations, failedOperationsByIp, unusualTimeOperations };
  };
};

module.exports = { applyQueryStatics };
