'use strict';

/**
 * 撞库画像的读侧派生（P2 情报）：给定一批审计行，现算「来源段 + 字典特征 + 成功率」的排序画像。
 *
 * 三条结构性约束（判据见 tests/ci/stuffingProfileContract.test.js）：
 *  ① 无模块级样本容器：聚合状态全部是本函数的局部 Map，两次调用之间不共享任何东西（画像不是累加器）；
 *  ② 窗口自述：每个出口条目都带 windowStart/windowEnd，空窗口也照常回窗口端点，不许用「没有条目」表示「没问题」；
 *  ③ 只读派生：本模块不写任何审计行，样本来自已经落下的蜜罐阶段行。
 */

const AuditLog = require('../models/AuditLog');
const { RETENTION_SECONDS } = require('../constants/retention');
const { businessDayBounds, businessDateParts } = require('../constants/timezone');
const {
  MIN_SAMPLES,
  SAMPLED_ACTIONS,
  SUCCESS_ACTION,
  accountOf,
  accumulateShape,
  byStrength,
  emptyGroup,
  ipSegment,
  toEntry,
} = require('../constants/stuffingProfile');
const {
  normalizeHoneypotUsername,
  parseHoneypotUsernames,
} = require('../constants/honeypotAccounts'); // 诱饵名只作**排除**用（诱饵放行的成功不算真实成功），永不出现在输出里

const TRACKED_ACTIONS = Object.freeze([...SAMPLED_ACTIONS, SUCCESS_ACTION]);

/**
 * 窗口 = 业务日 ∩ 保留期。保留期之外的行已不存在于集合里（TTL），下界仍然要夹——
 * 否则显式传入一个早于保留期的业务日会得到一份「空窗口」，而空窗口的含义是证据没了，不是没攻击。
 */
const resolveWindow = ({ businessDay, now = Date.now() } = {}) => {
  const day =
    typeof businessDay === 'string' && businessDay !== '' ? businessDay : businessDateParts().dateStr;
  const bounds = businessDayBounds(day);
  const retentionFloor = now - RETENTION_SECONDS * 1000;
  const startMs = Math.max(bounds.start.getTime(), retentionFloor);
  const endMs = bounds.end.getTime();
  return Object.freeze({
    businessDay: bounds.dateStr,
    windowStart: new Date(startMs).toISOString(),
    windowEnd: bounds.end.toISOString(),
    expired: startMs > endMs,
    start: new Date(startMs),
    end: bounds.end,
  });
};

/**
 * 纯聚合：输入审计行（lean 文档），输出条目 + 丢弃计数。
 * `droppedUnparsable` 单独回传——IP 解析不通过的行不参与聚合，也绝不回落到裸文本键（否则所有解析失败者会被并成一个假来源）。
 */
const aggregateRows = (rows, window, options = {}) => {
  const lureNames = options.lureNames || parseHoneypotUsernames().names;
  const isLure = (username) => {
    const normalized = normalizeHoneypotUsername(username);
    return normalized !== null && lureNames.includes(normalized);
  };
  const groups = new Map();
  let droppedUnparsable = 0;
  for (const row of rows || []) {
    const sourceKey = ipSegment(row && row.ip);
    if (!sourceKey) {
      droppedUnparsable += 1;
      continue;
    }
    const group = groups.get(sourceKey) || groups.set(sourceKey, emptyGroup(sourceKey)).get(sourceKey);
    const account = accountOf(row && row.username);
    if (account !== '') group.accounts.add(account);
    if (row.action === SUCCESS_ACTION) {
      if (isLure(row.username)) continue; // 诱饵会话签发时也会落一条 login_success：它不是「真实登录成功」，计进去成功率就被诱饵自己抬到 100%
      group.successes += 1;
      continue;
    }
    group.attempts += 1;
    accumulateShape(group, row.body && row.body.credentialShape);
  }
  const entries = [];
  let droppedBelowMin = 0;
  for (const group of groups.values()) {
    if (group.attempts < MIN_SAMPLES) {
      droppedBelowMin += 1;
      continue;
    }
    entries.push(toEntry(group, window));
  }
  entries.sort(byStrength);
  return Object.freeze({
    businessDay: window.businessDay,
    windowStart: window.windowStart,
    windowEnd: window.windowEnd,
    entries,
    expired: Boolean(window.expired),
    droppedUnparsable,
    droppedBelowMin,
  });
};

const buildProfile = async ({ businessDay, now = Date.now() } = {}) => {
  const window = resolveWindow({ businessDay, now });
  const rows = await AuditLog.find({
    action: { $in: TRACKED_ACTIONS },
    timestamp: { $gte: window.start, $lte: window.end },
  })
    .select('action username ip body')
    .lean();
  return aggregateRows(rows, window);
};

module.exports = {
  TRACKED_ACTIONS,
  aggregateRows,
  buildProfile,
  resolveWindow,
};