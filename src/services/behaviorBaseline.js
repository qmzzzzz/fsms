/**
 * 行为基线服务（本地特征提取 + 阈值统计）
 *
 * 定位：为后续行为分析/机器学习预留标准化的数据接口，当前只做「特征提取」与
 * 「基于历史分布的阈值统计」，不做模型训练、不引入 ML 依赖、不做外部调用。
 *
 * 两层能力：
 * 1. extractFeatures(userId, windowDays)
 *    从 AuditLog 聚合出用户在观察窗内的行为特征向量（请求量、失败率、活跃时段
 *    分布、IP 多样性、指纹多样性、写操作占比、高危操作数等）。
 *    输出为扁平的数值对象，可直接作为后续模型的输入行。
 *
 * 2. evaluateDeviation(userId, options)
 *    以「基线窗（较长，默认 30 天）」为参照，评估「近期窗（较短，默认 1 天）」
 *    的偏离程度。使用均值 + 标准差的 z-score 判定，避免依赖固定魔法阈值。
 *    返回每个维度的 z 值与超阈维度列表，供告警或人工复核使用。
 *
 * 说明：z-score 是统计方法而非机器学习；此处刻意保持可解释、可审计，
 * 便于等保测评时说明判定依据。
 */

const mongoose = require('mongoose');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { BUSINESS_TIMEZONE, OFF_HOURS_START, OFF_HOURS_END } = require('../constants/timezone');
// 写方法名单的单一事实来源就是 CSRF 那道闸用的同一份（原此处第三份拷贝，
// 任一处增删会让"基线里的 writes"与"被拦/被审计的写操作"口径分叉）
const WRITE_METHODS = require('../middleware/originCheck').WRITE_METHODS;
// 高危档同样不许在这儿复述一遍（F-149）：本服务的 highRisk 计数与审计页 level=error、
// 告警取数、概览高危次数共用 constants/audit.js 由有序等级表切出来的同一段。
const { AUDIT_ERROR_RISK_LEVELS } = require('../constants/audit');

const HIGH_RISK_LEVELS = AUDIT_ERROR_RISK_LEVELS;

/**
 * userId 归一化为 ObjectId：$match 不做隐式类型转换（与 find() 不同），
 * 传字符串会匹配不到任何文档并静默返回空基线——静默的"无数据"最难排查
 */
const toObjectId = (id) => {
  if (id instanceof mongoose.Types.ObjectId) return id;
  return mongoose.Types.ObjectId.isValid(id) ? new mongoose.Types.ObjectId(String(id)) : id;
};

// 默认窗口配置
const DEFAULT_BASELINE_DAYS = 30;
const DEFAULT_RECENT_DAYS = 1;
// z-score 超过该值视为显著偏离（约对应正态分布下 0.3% 的尾部概率）
const DEFAULT_Z_THRESHOLD = 3;

/**
 * 窗口参数必须是正整数天。
 *
 * 本模块原先不校验：`windowDays=0` ⇒ `since=now` 查不到东西、
 * `requestsPerDay = total/0 = Infinity`（序列化后变 null，看起来像"无数据"）；
 * `windowDays=-7` ⇒ `since` 落在**未来**，永远空结果，却返回"评估完成、偏离度 0"；
 * `minSamples=0` ⇒ 样本数判据恒假 ⇒ 拿 1 个样本算 σ=0 然后按 ±Infinity 报警。
 * 这三种都不是"查无数据"，而是**产出了一个看起来可信的判定**。
 * 本服务是给告警/人工复核用的判定端，宁可直接拒绝：抛错由 evaluateDeviation
 * 的既有 catch 转成 `evaluated:false, reason:"评估异常…"`，调用方看得见原因。
 */
function requirePositiveDays(name, value) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new TypeError(`${name} 必须是正整数天（单位：天），收到 ${JSON.stringify(value)}`);
  }
  return value;
}

/**
 * 单日特征的聚合管道片段（extractFeatures 与 collectDailySamples 共用）
 *
 * P3-20：改为在数据库侧聚合。原实现把窗口内**全部原始行**拉进 Node 再遍历
 * （基线窗 31 天 × 高频用户可达数十万行），单次评估即造成百 MB 级瞬时内存，
 * 且并发评估会叠加。distinct 统计用 $addToSet 在库内完成，只回传聚合结果。
 *
 * @param {object} groupId $group 的 _id 表达式（null=整窗，日期串=按天）
 * @returns {object[]} 聚合阶段数组
 */
const dailyFeatureStages = (groupId) => [
  {
    $group: {
      _id: groupId,
      total: { $sum: 1 },
      failures: { $sum: { $cond: [{ $eq: ['$success', false] }, 1, 0] } },
      writes: { $sum: { $cond: [{ $in: ['$method', WRITE_METHODS] }, 1, 0] } },
      highRisk: { $sum: { $cond: [{ $in: ['$riskLevel', HIGH_RISK_LEVELS] }, 1, 0] } },
      offHours: {
        $sum: {
          $cond: [
            {
              $or: [
                {
                  $lt: [
                    { $hour: { date: '$timestamp', timezone: BUSINESS_TIMEZONE } },
                    OFF_HOURS_END,
                  ],
                },
                {
                  $gte: [
                    { $hour: { date: '$timestamp', timezone: BUSINESS_TIMEZONE } },
                    OFF_HOURS_START,
                  ],
                },
              ],
            },
            1,
            0,
          ],
        },
      },
      // $addToSet 自动去重；null/缺失值需在投影阶段剔除
      ips: { $addToSet: '$ip' },
      fingerprints: { $addToSet: '$fingerprint' },
    },
  },
  {
    $project: {
      total: 1,
      failures: 1,
      writes: 1,
      highRisk: 1,
      offHours: 1,
      // 过滤空值后取基数：$addToSet 会把 null 也收进集合，直接 $size 会多算 1
      distinctIPs: { $size: { $filter: { input: '$ips', cond: { $ne: ['$$this', null] } } } },
      distinctFingerprints: {
        $size: { $filter: { input: '$fingerprints', cond: { $ne: ['$$this', null] } } },
      },
    },
  },
];

/** 把聚合行转换为对外的特征对象 */
const toFeatureRow = (row) => ({
  totalRequests: row.total,
  failureRate: row.total ? row.failures / row.total : 0,
  writeRatio: row.total ? row.writes / row.total : 0,
  highRiskCount: row.highRisk,
  distinctIPs: row.distinctIPs,
  distinctFingerprints: row.distinctFingerprints,
  offHoursRatio: row.total ? row.offHours / row.total : 0,
});

/**
 * 提取指定用户在观察窗内的行为特征
 *
 * @param {string} userId 用户 ID
 * @param {number} [windowDays=1] 观察窗天数
 * @returns {Promise<object>} 特征对象；无数据时各项为 0
 */
async function extractFeatures(userId, windowDays = DEFAULT_RECENT_DAYS) {
  requirePositiveDays('extractFeatures 的 windowDays', windowDays);
  const since = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000);

  const [row] = await AuditLog.aggregate([
    { $match: { userId: toObjectId(userId), timestamp: { $gte: since } } },
    ...dailyFeatureStages(null),
  ]);

  if (!row || row.total === 0) {
    return {
      windowDays,
      totalRequests: 0,
      failureRate: 0,
      writeRatio: 0,
      highRiskCount: 0,
      distinctIPs: 0,
      distinctFingerprints: 0,
      offHoursRatio: 0,
      requestsPerDay: 0,
    };
  }

  const f = toFeatureRow(row);
  return {
    windowDays,
    totalRequests: f.totalRequests,
    failureRate: round(f.failureRate),
    writeRatio: round(f.writeRatio),
    highRiskCount: f.highRiskCount,
    distinctIPs: f.distinctIPs,
    distinctFingerprints: f.distinctFingerprints,
    offHoursRatio: round(f.offHoursRatio),
    requestsPerDay: round(f.totalRequests / windowDays),
  };
}

/**
 * 按天聚合基线窗内的每日特征，用于计算均值与标准差
 *
 * 已知统计偏差（改动前请读）：$group 按日期分桶只会产出**有审计记录的那些天**，
 * 零活跃日不会补一行 0。于是"三天打鱼两天晒网"的用户，其基线均值来自活跃日，
 * 天然偏高；他再次活跃时偏离度被低估（漏报方向）。反之若把零活跃日补成 0，
 * σ 会同时被拉大、均值被拉低，突发行为更容易触发告警（误报方向）。
 * 现实现取前者（活跃日基线）：`samples.length < minSamples` 那条判据正是靠
 * "活跃天数"表达"样本是否够"，补零会让它永远够。此处不静默改动语义，
 * 需要更保守的口径时应当显式新增一种 baselineMode，而不是悄悄换统计量。
 *
 * @param {string} userId 用户 ID
 * @param {number} baselineDays 基线窗天数
 * @param {number} [excludeRecentDays=0] 从窗口末端剔除的天数（用于排除观测窗自身）
 * @returns {Promise<object[]>} 每日特征数组
 */
async function collectDailySamples(userId, baselineDays, excludeRecentDays = 0) {
  requirePositiveDays('collectDailySamples 的 baselineDays', baselineDays);
  if (!Number.isInteger(excludeRecentDays) || excludeRecentDays < 0) {
    throw new TypeError(
      `collectDailySamples 的 excludeRecentDays 必须是非负整数天，收到 ${JSON.stringify(excludeRecentDays)}`
    );
  }
  const since = new Date(Date.now() - baselineDays * 24 * 60 * 60 * 1000);
  // 窗口末端前移 excludeRecentDays 天：保证基线样本不包含最近 N 天的观测期数据，
  // 否则观测窗自身混入基线会把均值拉向观测值，稀释偏离度
  const until = new Date(Date.now() - excludeRecentDays * 24 * 60 * 60 * 1000);

  // P3-20：按天分桶改在数据库侧完成（$dateToString + $group），
  // 只回传每天一行的聚合结果，不再把原始行拉进内存。
  // 时区取业务时区单一声明，避免 UTC 容器下跨日错位（P3-18）
  const rows = await AuditLog.aggregate([
    { $match: { userId: toObjectId(userId), timestamp: { $gte: since, $lt: until } } },
    ...dailyFeatureStages({
      $dateToString: { format: '%Y-%m-%d', date: '$timestamp', timezone: BUSINESS_TIMEZONE },
    }),
  ]);

  return rows.map((row) => {
    const f = toFeatureRow(row);
    return {
      totalRequests: f.totalRequests,
      failureRate: f.failureRate,
      writeRatio: f.writeRatio,
      highRiskCount: f.highRiskCount,
      distinctIPs: f.distinctIPs,
      distinctFingerprints: f.distinctFingerprints,
    };
  });
}

/**
 * 计算数组的均值与样本标准差
 */
function meanStd(values) {
  const n = values.length;
  if (n === 0) return { mean: 0, std: 0 };
  const mean = values.reduce((s, v) => s + v, 0) / n;
  if (n === 1) return { mean, std: 0 };
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / (n - 1);
  return { mean, std: Math.sqrt(variance) };
}

/** 参与偏离判定的维度（比率类与量类混合，量类需按窗长归一） */
const DIMENSIONS = [
  'totalRequests',
  'failureRate',
  'writeRatio',
  'highRiskCount',
  'distinctIPs',
  'distinctFingerprints',
];
// 归一化特征：窗口内累计计数（除以窗长得日均）
const VOLUME_FEATURES = new Set([
  'totalRequests',
  'highRiskCount',
  'distinctIPs',
  'distinctFingerprints',
]);
// 不归一化特征：failureRate / writeRatio 是窗口内比率，与窗长无关
//
// 只有**可加**的量能除以窗长。totalRequests/highRiskCount 是事件计数，
// 7 天累计 ÷ 7 = 日均，与单日基线同量纲；而 distinctIPs/distinctFingerprints 是
// **去重基数**——7 天里出现过的 IP 去重后除以 7，既不是日均基数、也不能与单日基数比：
// 一个 7 天窗内的真实激增（如 20 个新 IP）被摊成 2.86，σ 又来自单日基数，
// 结果是把异常**摊薄成正常**（漏报方向，对安全检测是最坏的一侧）。
// 因此这两个维度只在 recentDays === 1（除法为恒等）时参与告警；
// 窗长 >1 时仍计算并返回 z 值供人工参考，但标记 comparable:false 且不计入 anomalies。
const NON_ADDITIVE_FEATURES = new Set(['distinctIPs', 'distinctFingerprints']);

/**
 * 逐维度计算 z-score 并收集超阈维度。
 * 从 evaluateDeviation 里抽出：一是让统计判据能脱离聚合管道被单测直接驱动，
 * 二是 evaluateDeviation 加了参数校验后整体圈复杂度会越过棘轮上限（只许降不许升）。
 * @returns {{scores: object, anomalies: string[]}}
 */
function scoreDimensions({ samples, recent, recentDays, zThreshold }) {
  const scores = {};
  const anomalies = [];

  for (const dim of DIMENSIONS) {
    const { mean, std } = meanStd(samples.map((s) => s[dim]));
    const rawObserved = recent[dim];
    const observed = VOLUME_FEATURES.has(dim) ? rawObserved / recentDays : rawObserved;
    const comparable = !(NON_ADDITIVE_FEATURES.has(dim) && recentDays !== 1);
    // std 为 0 表示历史该维度恒定：偏离常量时按方向取 ±Infinity，避免除零。
    // 方向语义与下方判定一致——骤降（如休假）不告警，仅骤升告警
    const z =
      std === 0
        ? observed === mean
          ? 0
          : observed > mean
            ? Infinity
            : -Infinity
        : (observed - mean) / std;
    scores[dim] = {
      observed: round(observed),
      baselineMean: round(mean),
      baselineStd: round(std),
      z: Number.isFinite(z) ? round(z) : null,
      comparable,
    };
    // 只关注「异常升高」方向：请求量骤降通常是休假而非攻击。
    // z 为 Infinity 时必大于任何有限阈值，无需额外的 isFinite 判断（数值输入下不会产生 NaN）
    if (comparable && z > zThreshold) anomalies.push(dim);
  }

  return { scores, anomalies };
}

/**
 * 评估近期行为相对基线的偏离程度
 *
 * @param {string} userId 用户 ID
 * @param {object} [options]
 * @param {number} [options.baselineDays=30] 基线窗天数
 * @param {number} [options.recentDays=1] 近期窗天数
 * @param {number} [options.zThreshold=3] z-score 告警阈值
 * @param {number} [options.minSamples=7] 基线最少样本天数，不足则不判定
 * @returns {Promise<object>} 评估结果
 */
async function evaluateDeviation(userId, options = {}) {
  const {
    baselineDays = DEFAULT_BASELINE_DAYS,
    recentDays = DEFAULT_RECENT_DAYS,
    zThreshold = DEFAULT_Z_THRESHOLD,
    minSamples = 7,
  } = options;

  try {
    requirePositiveDays('baselineDays', baselineDays);
    requirePositiveDays('recentDays', recentDays);
    requirePositiveDays('minSamples', minSamples);
    if (!Number.isFinite(zThreshold) || zThreshold <= 0) {
      throw new TypeError(`zThreshold 必须是正数，收到 ${JSON.stringify(zThreshold)}`);
    }
    const [recent, samples] = await Promise.all([
      extractFeatures(userId, recentDays),
      // 基线窗向前多取 recentDays 天并剔除末端，保证基线不含观测窗自身（见 collectDailySamples）
      collectDailySamples(userId, baselineDays + recentDays, recentDays),
    ]);

    // 样本不足时不做判定：小样本下标准差极不稳定，容易产出大量假阳性
    if (samples.length < minSamples) {
      return {
        userId: String(userId),
        evaluated: false,
        reason: `基线样本不足（${samples.length}/${minSamples} 天）`,
        recent,
      };
    }

    // 「量」型特征在近期窗内是多天累计值，须先按 recentDays 归一化为日均量，
    // 再与「单日粒度」的基线样本比较；否则 recentDays>1 时观测值天然大于单日均值，必然假阳性。
    const { scores, anomalies } = scoreDimensions({ samples, recent, recentDays, zThreshold });

    return {
      userId: String(userId),
      evaluated: true,
      baselineDays,
      recentDays,
      sampleDays: samples.length,
      zThreshold,
      scores,
      anomalies,
      isAnomalous: anomalies.length > 0,
      recent,
    };
  } catch (err) {
    logger.error('行为基线评估失败', { userId, error: err.message });
    return {
      userId: String(userId),
      evaluated: false,
      reason: `评估异常：${err.message}`,
    };
  }
}

/**
 * 保留 4 位小数，避免浮点噪声污染输出与后续比对
 */
function round(v) {
  return Math.round(v * 10000) / 10000;
}

module.exports = {
  extractFeatures,
  collectDailySamples,
  evaluateDeviation,
  meanStd,
  DEFAULT_BASELINE_DAYS,
  DEFAULT_RECENT_DAYS,
  DEFAULT_Z_THRESHOLD,
};
