const AuditLog = require('../models/AuditLog');
const securityAlert = require('./securityAlert');
const logger = require('../utils/logger');
const { normalizeIP } = require('../utils/ipUtils');
const { businessDateParts, businessDayBounds } = require('../constants/timezone');
const { readPositiveNumberEnv } = require('../utils/envNumber');

const { ALERT_TYPES } = securityAlert; // 审计 action 必须裸写 ALERT_TYPES.<KEY>：tests/helpers/auditWriteSites.js 的 resolveActionExpr 只认这一形态

const DEFAULT_INTERVAL_MS = 5 * 60 * 1000; // 与 services/auditMonitor.js 同档：同一张审计表上的只读聚合，负载量级相同
const MIN_INTERVAL_MS = 60 * 1000; // 低于 1 分钟只是把同一批当日行反复扫一遍，纯放大负载
const MAX_INTERVAL_MS = 24 * 60 * 60 * 1000; // 必须远低于 2^31-1：Node 把超界的 setInterval 静默压成 1ms（TimeoutOverflowWarning），"配 34 天"会变成每毫秒一轮聚合，而面板照报 34 天
const MIN_ROUND_BUDGET_MS = 60 * 1000; // 单轮聚合的服务端时间下限（口径同 auditMonitor 的 roundBudgetMs）
const CHAIN_MIN_STAGES = 2; // 升级阈值：当日**不同阶段**数 ≥2；同一阶段重复 N 次不算链（那是各检测器自己的频控口径）
const ESCALATION_LIMIT = 50; // 单轮最多**升级** 50 个来源：一轮就升上百条即分布式撞库，告警面本身不能变成风暴；当日已升级过的 IP 在选候选时就被剔出，不占名额——否则它们每轮都挤在前 50、尾部候选被永久饿死

const STAGE_ACTIONS = Object.freeze([
  'login_failed',
  'canary_username_attempt',
  'honeypot_login',
  'honeypot_probe',
]); // 链的四个阶段（唯一事实来源）：撞库口令失败 → 猜哨兵用户名 → 诱饵口令命中 → 陷阱会话内探测

const STAGE_LABELS = Object.freeze({
  login_failed: '撞库口令失败',
  canary_username_attempt: '猜哨兵用户名',
  honeypot_login: '诱饵口令命中',
  honeypot_probe: '陷阱会话内探测',
}); // 阶段名 → 告警文案标签；键集必须与 STAGE_ACTIONS 相等（同一用例双向核对，防止只改一边）

let scanTimer = null;
let scanRunning = false;
let effectiveIntervalMs = DEFAULT_INTERVAL_MS;
const health = {
  runs: 0,
  failures: 0,
  consecutiveFailures: 0,
  skippedOverlaps: 0,
  escalated: 0,
  escalationFailures: 0,
  unparsableSources: 0,
  droppedCandidates: 0,
  lastCandidates: 0,
  lastPendingCandidates: 0,
  lastRunAt: null,
  lastSuccessAt: null,
  lastEscalatedIp: null,
  lastFailureAt: null,
  lastFailureMessage: null,
};

const INITIAL_HEALTH = { ...health }; // 初值快照（单一声明）：__resetForTest 按它整份复位，日后新增计数不会漏复位

const failureText = (err) => (err && err.message ? err.message : err); // 同 utils/auditWriteFailure.errText：非 Error 抛出物也留得下可读文本

const roundBudgetMs = () => Math.floor(Math.max(MIN_ROUND_BUDGET_MS, effectiveIntervalMs)); // 预算跟着间隔走：调大间隔只为降负载时，单轮允许的时间同步放宽

const stageLabel = (action) => STAGE_LABELS[action] || action; // 未登记的阶段名原样返回，不静默替换成标签

function chainPipeline(start, end) {
  return [
    {
      $match: {
        action: { $in: STAGE_ACTIONS },
        timestamp: { $gte: start, $lte: end },
        ip: { $nin: [null, ''] }, // 缺 IP 的行不参与：把「来源不明」的攻击者并成一条链是制造假告警，不是发现真攻击
      },
    },
    {
      $group: {
        _id: '$ip',
        stages: { $addToSet: '$action' },
        events: { $sum: 1 },
        firstSeenAt: { $min: '$timestamp' },
        lastSeenAt: { $max: '$timestamp' },
      },
    },
    { $sort: { lastSeenAt: -1 } },
  ];
}

const toChainIp = (rawIp) => normalizeIP(rawIp); // 先归一化再合并：::ffff:1.2.3.4 与 1.2.3.4 必须算同一条链，否则「同一个人」的判定会被格式差撕开；归一化不通过的文本一律不成键（同 forensicTrigger 口径）——否则任意攻击者文本都能自成一条链，且 markForensicTarget 对它是拒绝的，取证静默丢失

const newChainEntry = (ip, row) => ({
  ip,
  stages: new Set(),
  events: 0,
  firstSeenAt: row.firstSeenAt,
  lastSeenAt: row.lastSeenAt,
});

function absorbRow(entry, row) {
  for (const stage of (row && row.stages) || []) entry.stages.add(stage);
  entry.events += (row && row.events) || 0;
  if (row.firstSeenAt && (!entry.firstSeenAt || row.firstSeenAt < entry.firstSeenAt)) {
    entry.firstSeenAt = row.firstSeenAt;
  }
  if (row.lastSeenAt && (!entry.lastSeenAt || row.lastSeenAt > entry.lastSeenAt)) {
    entry.lastSeenAt = row.lastSeenAt;
  }
  return entry;
}

const isChain = (entry) => entry.stages.size >= CHAIN_MIN_STAGES;
const toChain = (entry) => ({ ...entry, stages: [...entry.stages].sort() });

function mergeChains(rows) {
  const byIp = new Map(); // 仅本轮内存在：跨轮去重靠审计行本身（见 escalateChain），不是进程内状态
  let skippedSources = 0; // 归一化不通过而被丢弃的分组数：丢得再多也要能从 getHealth().unparsableSources 看见，不允许静默
  for (const row of rows) {
    const ip = toChainIp(row && row._id);
    if (!ip) {
      skippedSources += 1;
      continue;
    }
    byIp.set(ip, absorbRow(byIp.get(ip) || newChainEntry(ip, row), row));
  }
  return {
    chains: [...byIp.values()]
      .filter(isChain)
      .map(toChain)
      .sort((a, b) => (b.lastSeenAt || 0) - (a.lastSeenAt || 0)),
    skippedUnparsable: skippedSources,
  };
}

const escalatedIpsToday = async (window) => {
  const ips = await AuditLog.distinct('ip', {
    action: ALERT_TYPES.HONEYPOT_CHAIN_ESCALATED,
    timestamp: { $gte: window.start, $lte: window.end },
  });
  return new Set(Array.isArray(ips) ? ips.filter(Boolean) : []);
}; // 一轮一次取「当日已升级来源」集合，而不是逐候选计数：逐候选计数会让已升级的 IP 每轮都挤占单轮名额，尾部候选被永久饿死（实测 52 个候选时最旧的两个连跑三轮都没升级）

const chainEscalatedToday = async (ip, window) =>
  (await AuditLog.countDocuments({
    action: ALERT_TYPES.HONEYPOT_CHAIN_ESCALATED,
    ip,
    timestamp: { $gte: window.start, $lte: window.end },
  })) > 0; // 「当日每 IP 只升级一次」的凭据是审计行本身：跨重启、跨实例一致，无需进程内 Map；候选侧已用一轮一次的 distinct 集合预先剔除，这里留作写前复核（两个实例同轮起跑时唯一的最后一道闸），代价是每轮 ≤ ESCALATION_LIMIT 次计数查询

async function escalateChain(chain, dayWindow, window) {
  if (await chainEscalatedToday(chain.ip, window)) return 'duplicate';
  const { stages } = chain;
  try {
    await AuditLog.create({
      action: ALERT_TYPES.HONEYPOT_CHAIN_ESCALATED,
      category: 'security',
      username: 'anonymous', // 链的判定维度是来源 IP、不挂任何账号；username 为审计必填，取与 rateLimitEscalationBan 同一占位值
      ip: chain.ip,
      riskLevel: 'critical',
      riskFactors: [
        'honeypot_chain_escalated',
        'deceptive_account_interaction',
        ...stages.map((stage) => 'chain_stage_' + stage),
      ],
      reason: 'honeypot_chain_escalated',
      body: {
        ip: chain.ip,
        stages,
        events: chain.events,
        dayWindow,
        firstSeenAt: chain.firstSeenAt,
        lastSeenAt: chain.lastSeenAt,
      },
    });
  } catch (err) {
    logger.error('蜜罐事件链升级审计写入失败（本轮不投递，下一轮重试）：' + failureText(err), {
      ip: chain.ip,
    });
    health.escalationFailures += 1;
    return 'failed';
  }
  const markOptions = { reason: 'honeypot_chain', source: 'honeypotChainWatch' }; // 跨阶段确认 = 已确认攻击源：与蜜罐登录同一条取证触发钩子
  try {
    require('./forensicTrigger').markForensicTarget(chain.ip, markOptions);
  } catch (_) {} // mark 内部吞异常并计数（fail-visible），这里只兜 require 期异常；标记失败不得改变升级与投递
  securityAlert.dispatchNotification(
    securityAlert.ALERT_TYPES.HONEYPOT_CHAIN_ESCALATED,
    securityAlert.ALERT_LEVELS.CRITICAL,
    '来源 IP ' +
      chain.ip +
      ' 当日跨越 ' +
      stages.length +
      ' 个蜜罐阶段：' +
      stages.map(stageLabel).join(' → '),
    { ip: chain.ip, stages, events: chain.events, dayWindow }
  );
  return 'escalated';
}

async function runScan() {
  if (scanRunning) {
    health.skippedOverlaps += 1; // 一轮一闸：上一轮还没跑完（DB 慢）时不再压一轮进来
    logger.warn('蜜罐事件链巡检上一轮未结束，本轮跳过');
    return;
  }
  scanRunning = true;
  health.runs += 1;
  health.lastRunAt = new Date().toISOString();
  try {
    const dayWindow = businessDateParts().dateStr;
    const window = businessDayBounds(dayWindow);
    const rows = await AuditLog.aggregate(chainPipeline(window.start, window.end), {
      maxTimeMS: roundBudgetMs(), // 服务端预算：慢到跑不完时由 Mongo 掐断并抛错，不拖着事件循环
    });
    const merged = mergeChains(Array.isArray(rows) ? rows : []);
    health.unparsableSources += merged.skippedUnparsable;
    health.lastCandidates = merged.chains.length;
    const done = await escalatedIpsToday(window);
    const pending = merged.chains.filter((chain) => !done.has(chain.ip));
    health.lastPendingCandidates = pending.length;
    const batch = pending.slice(0, ESCALATION_LIMIT);
    health.droppedCandidates += pending.length - batch.length; // 累计「推迟次数」：同一候选推迟多轮会重复计入，判读看的是它在涨、不是涨到几
    for (const chain of batch) {
      if ((await escalateChain(chain, dayWindow, window)) === 'escalated') {
        health.escalated += 1;
        health.lastEscalatedIp = chain.ip;
      }
    }
    health.consecutiveFailures = 0; // 整轮跑完才归零：断在候选处理里的那一轮不是成功轮（旧位置在聚合之后，会把「读失败」的连续计数抹成 1）
    health.lastSuccessAt = new Date().toISOString(); // 与 lastRunAt 配对：面板据两者比较即可判断上一轮是跑完了还是断了，不必再拿 lastFailureAt 反推
  } catch (err) {
    health.failures += 1;
    health.consecutiveFailures += 1;
    health.lastFailureAt = new Date().toISOString();
    health.lastFailureMessage = failureText(err);
    logger.error('蜜罐事件链巡检执行失败：' + failureText(err));
  } finally {
    scanRunning = false;
  }
}

function start() {
  if (scanTimer) return; // 幂等：重复 start 不产生第二个定时器
  let intervalMs = readPositiveNumberEnv('HONEYPOT_CHAIN_INTERVAL_MS', DEFAULT_INTERVAL_MS, {
    onInvalid: (name, raw, fallback) =>
      logger.warn(
        name + '=' + JSON.stringify(raw) + ' 非法（须为正数），已按默认 ' + fallback + 'ms 处理'
      ),
  });
  if (intervalMs < MIN_INTERVAL_MS) {
    logger.warn(
      'HONEYPOT_CHAIN_INTERVAL_MS=' +
        intervalMs +
        ' 低于最小间隔 ' +
        MIN_INTERVAL_MS +
        'ms，已抬升到最小值'
    );
    intervalMs = MIN_INTERVAL_MS;
  }
  if (intervalMs > MAX_INTERVAL_MS) {
    logger.warn(
      'HONEYPOT_CHAIN_INTERVAL_MS=' +
        intervalMs +
        ' 高于最大间隔 ' +
        MAX_INTERVAL_MS +
        'ms，已压到最大值（Node 对超界 setInterval 会静默改成 1ms）'
    );
    intervalMs = MAX_INTERVAL_MS;
  }
  effectiveIntervalMs = intervalMs;
  scanTimer = setInterval(() => {
    runScan().catch((err) => logger.error('蜜罐事件链巡检定时任务异常：' + failureText(err)));
  }, intervalMs);
  if (typeof scanTimer.unref === 'function') scanTimer.unref(); // 不阻止进程退出（测试环境尤其需要）
  logger.info(
    '蜜罐事件链巡检已启动（间隔 ' +
      intervalMs / 1000 +
      's，单轮最多升级 ' +
      ESCALATION_LIMIT +
      ' 个来源）'
  );
}

function stop() {
  if (!scanTimer) return;
  clearInterval(scanTimer);
  scanTimer = null;
  logger.info('蜜罐事件链巡检已停止');
}

const isRunning = () => scanTimer !== null;

function getHealth() {
  return {
    ...health,
    running: isRunning(),
    intervalMs: effectiveIntervalMs,
    minStages: CHAIN_MIN_STAGES,
    escalationLimit: ESCALATION_LIMIT,
  };
}

function __resetForTest() {
  scanRunning = false; // 某条用例留下「永不 settle 的轮次」，不复位会把后续用例全变成静默跳过（同 auditMonitor 钩子）
  effectiveIntervalMs = DEFAULT_INTERVAL_MS; // 上一条用例配的间隔不得泄漏到下一条的读数断言
  Object.assign(health, INITIAL_HEALTH); // 计数与「最后一轮」读数一并回到初值；定时器仍归 stop() 管
}

module.exports = {
  start,
  stop,
  runScan,
  isRunning,
  getHealth,
  __resetForTest,
  STAGE_ACTIONS,
  STAGE_LABELS,
  CHAIN_MIN_STAGES,
};
