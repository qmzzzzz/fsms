/**
 * 取证触发标记表（P1）——「这个 IP 要不要走二级全量捕获」的唯一事实来源。
 *
 * 解决的问题：取证级捕获（请求体/响应体全量）成本高、隐私面大，不能常态开着。
 * 本模块维护一张「已确认攻击源」IP 表：P2 捕获管道按表决定是否升级为全量捕获；
 * 由三处 v1 钩子写入（黑名单命中 / 蜜罐登录 / 暴破自动封禁执行点），
 * 标记表本身不反向依赖任何业务模块（保持叶子地位，避免加载期成环）。
 *
 * 【滑动窗口】markForensicTarget 对已存在的标记「命中即续期」（默认 30 分钟）：
 * 攻击者持续活动 ⇒ 标记持续有效；停手满 30 分钟后自动回落常态捕获。
 * isForensicTarget 是只读判定（不续期、不改淘汰序），挂请求热路径很安全。
 *
 * 【容量与淘汰】FORENSIC_TRIGGER_MAX_IPS（默认 4096）封顶，超容按 LRU 淘汰：
 * 先清已过期条目，再淘汰「最久未被标记/续期」的；同毫秒并列时取先插入的（seq）。
 * 淘汰只逐条进行、绝不整体清空（rateLimitEscalation 同款纪律）：整体清空的形态里，
 * 轮换 IP 灌新标记就能让在案攻击源的取证态集体消失——等于给攻击者留擦痕迹的路径；
 * 而「最久未复核」恰好正是最该为新鲜确认让位的条目。
 *
 * 【失败语义】一切异常都不得影响请求主流程（fail-open），但必须计数可见（fail-visible）：
 * 所有导出吞内部异常、failures++、（限频）error 日志，并暴露在 getForensicTriggerStats；
 * 调用方不需要（也不应该）再为标记失败做业务兜底。
 *
 * 【ip 口径】一律先 normalizeIP()：调用方应传 clientIpForSecurityDecision(req) 的结果；
 * 未识别/空 IP 一律判 false / 拒绝标记并计数——绝不把不可解析文本当键。
 *
 * env（模块内直读 + 默认值，不新增 config 注册）：
 *   FORENSIC_TRIGGER_ENABLED  仅精确 'false' 关闭；其余值（含未配置）都为开；
 *   FORENSIC_TRIGGER_TTL_MS   滑动窗口时长，默认 1800000（30 分钟）；
 *   FORENSIC_TRIGGER_MAX_IPS  容量上限，默认 4096，超限按 LRU 淘汰。
 * v1 未覆盖（登记为 v1b）：限流升级触顶、401/403 风暴、验证码失败风暴、全局限速异常；扫描探测族已于 2026-11-05 由 services/scanProbeDetector 覆盖（路径指纹与 404 风暴均标记取证），其余三族仍待续。
 */

const logger = require('../utils/logger');
const { normalizeIP } = require('../utils/ipUtils');
const { readPositiveNumberEnv } = require('../utils/envNumber');
const { errText } = require('../utils/auditWriteFailure');

const DEFAULT_TTL_MS = 30 * 60 * 1000; // 滑动窗口默认 30 分钟（env 可覆盖）
const DEFAULT_MAX_IPS = 4096; // 容量默认 4096（env 可覆盖）；超容按 LRU 淘汰
const FAILURE_LOG_INTERVAL_MS = 60 * 1000; // 异常日志限频：单点异常不得把日志刷爆

const ENABLED = process.env.FORENSIC_TRIGGER_ENABLED !== 'false'; // 仅精确 'false' 关（见文件头）
const TTL_MS = readPositiveNumberEnv('FORENSIC_TRIGGER_TTL_MS', DEFAULT_TTL_MS, {
  onInvalid: (name, raw, fallback) =>
    logger.error(`取证触发 TTL 配置非法（${name}=${raw}），本次进程回落 ${fallback}ms`),
});
const MAX_IPS = readPositiveNumberEnv('FORENSIC_TRIGGER_MAX_IPS', DEFAULT_MAX_IPS, {
  integer: true,
  onInvalid: (name, raw, fallback) =>
    logger.error(`取证触发容量配置非法（${name}=${raw}），本次进程回落 ${fallback}`),
});

// 键 = normalizeIP 后的地址；值 = { ip, reason, source, evidence, ttlMs, markedAt, lastMarkedAt, expiresAt, seq }
const marksByIp = new Map();
let seq = 0; // 插入序号：LRU 并列（同一毫秒续期）时的 tiebreak，先来先淘汰
const counters = { marks: 0, renewals: 0, evictions: 0, rejected: 0, failures: 0 };
let lastEvictionAt = null;
let lastError = null;
let lastErrorAt = null;
let lastMark = null;
let lastFailureLogAt = 0;

/** 内部异常统一落点（fail-visible）：计数 + 限频日志；被 catch 的不保证是 Error，统一走 errText */
function noteFailure(err) {
  const message = String(errText(err));
  counters.failures += 1;
  lastError = message;
  lastErrorAt = Date.now();
  if (lastErrorAt - lastFailureLogAt >= FAILURE_LOG_INTERVAL_MS) {
    lastFailureLogAt = lastErrorAt;
    logger.error(`取证标记表异常（本次调用降级为不标记，不影响主流程）: ${message}`);
  }
}

function pruneExpired(now) {
  for (const [key, rec] of marksByIp) if (rec.expiresAt <= now) marksByIp.delete(key); // 过期即死，留着只占容量
}

function countLive(now) {
  let live = 0;
  for (const rec of marksByIp.values()) if (rec.expiresAt > now) live += 1; // 只读统计（stats 用），不删
  return live;
}

/** 逐条淘汰「最久未被标记/续期」的一条；并列取 seq 小的。返回是否真的删了一条。 */
function evictOldest() {
  let victimKey = null;
  let victim = null;
  for (const [key, rec] of marksByIp) {
    const older =
      victim === null ||
      rec.lastMarkedAt < victim.lastMarkedAt ||
      (rec.lastMarkedAt === victim.lastMarkedAt && rec.seq < victim.seq);
    if (older) {
      victimKey = key;
      victim = rec;
    }
  }
  if (victim === null) return false;
  marksByIp.delete(victimKey);
  counters.evictions += 1;
  lastEvictionAt = Date.now();
  return true;
}

/** 单笔标记 TTL：显式传入须为正有限数，否则回落模块默认（非法入参不抛错） */
function pickTtl(ttlMs) {
  return Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : TTL_MS;
}

/** 标记一个取证目标（命中即续期）。ip 须为 clientIpForSecurityDecision(req) 的结果；
 *  返回 true=已建立/续期，false=未标记（关闭/非法 IP/内部异常，均有计数） */
function markForensicTarget(ip, options = {}) {
  try {
    const key = normalizeIP(ip);
    if (!key) {
      counters.rejected += 1;
      return false;
    }
    if (!ENABLED) return false;
    const now = Date.now();
    const ttlMs = pickTtl(options.ttlMs);
    const reason = typeof options.reason === 'string' ? options.reason : 'unspecified';
    const source = typeof options.source === 'string' ? options.source : 'unknown';
    const existing = marksByIp.get(key);
    if (existing && existing.expiresAt > now) {
      // 命中续期：到期时间与归因刷新到最新，LRU 时间戳随之后移（活跃攻击源不先被淘汰）
      existing.expiresAt = now + ttlMs;
      existing.ttlMs = ttlMs;
      existing.lastMarkedAt = now;
      existing.reason = reason;
      existing.source = source;
      existing.evidence = options.evidence;
      counters.marks += 1;
      counters.renewals += 1;
      lastMark = { ip: key, reason, source, at: now };
      return true;
    }
    if (existing) marksByIp.delete(key); // 已过期：按全新标记处理，不算续期
    pruneExpired(now);
    while (marksByIp.size >= MAX_IPS) {
      if (!evictOldest()) break;
    }
    seq += 1;
    marksByIp.set(key, {
      ip: key,
      reason,
      source,
      evidence: options.evidence,
      ttlMs,
      markedAt: now,
      lastMarkedAt: now,
      expiresAt: now + ttlMs,
      seq,
    });
    counters.marks += 1;
    lastMark = { ip: key, reason, source, at: now };
    return true;
  } catch (err) {
    noteFailure(err); // 极端情形（如敌意 options 代理）：吞掉并计数，绝不外抛
    return false;
  }
}

/**
 * 只读判定：该 IP 当前是否为取证目标。未识别/空 IP 一律 false。
 * 不续期、不写状态（请求热路径可高频调用）。
 * @param {string} ip
 * @returns {boolean}
 */
function isForensicTarget(ip) {
  try {
    const key = normalizeIP(ip);
    if (!key) {
      counters.rejected += 1;
      return false;
    }
    if (!ENABLED) return false;
    const rec = marksByIp.get(key);
    return !!rec && rec.expiresAt > Date.now();
  } catch (err) {
    noteFailure(err);
    return false;
  }
}

/**
 * 按 IP 读取标记（P2 归因用，只读不续期）。过期即删并返回 null，与 isForensicTarget 同口径——
 * 归因读到的必须是"此刻仍有效"的标记，不回放历史标记的过期理由。
 */
function getForensicTarget(ip) {
  try {
    const key = normalizeIP(ip);
    if (!key || !ENABLED) return null;
    const rec = marksByIp.get(key);
    if (!rec) return null;
    if (rec.expiresAt <= Date.now()) {
      marksByIp.delete(key);
      return null;
    }
    return {
      reason: rec.reason,
      source: rec.source,
      evidence: rec.evidence,
      markedAt: rec.markedAt,
      ttlMs: rec.ttlMs,
    };
  } catch (err) {
    noteFailure(err);
    return null;
  }
}

/**
 * 清除一个取证标记（人工/测试用）。返回是否删除到条目。
 * @param {string} ip
 * @returns {boolean}
 */
function clearForensicTarget(ip) {
  try {
    const key = normalizeIP(ip);
    if (!key) {
      counters.rejected += 1;
      return false;
    }
    return marksByIp.delete(key);
  } catch (err) {
    noteFailure(err);
    return false;
  }
}

/**
 * 运维可见快照（fail-visible 的唯一读取面）：开关/参数 + markedIps（存活数）+
 * 计数（marks/renewals/evictions/rejected/failures）+ lastEvictionAt/lastError/lastMark。
 * @returns {object}
 */
function getForensicTriggerStats() {
  const now = Date.now();
  try {
    pruneExpired(now); // 顺手回收，让 markedIps 反映真实存活量
  } catch (err) {
    noteFailure(err); // 统计失败也必须可见，但绝不外抛
  }
  return {
    enabled: ENABLED,
    ttlMs: TTL_MS,
    maxIps: MAX_IPS,
    markedIps: countLive(now),
    marks: counters.marks,
    renewals: counters.renewals,
    evictions: counters.evictions,
    lastEvictionAt,
    rejected: counters.rejected,
    failures: counters.failures,
    lastError,
    lastErrorAt,
    lastMark: lastMark ? { ...lastMark } : null,
  };
}

module.exports = {
  isForensicTarget,
  markForensicTarget,
  clearForensicTarget,
  getForensicTarget,
  getForensicTriggerStats,
};
