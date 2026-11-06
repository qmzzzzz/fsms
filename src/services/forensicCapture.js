/**
 * 取证捕获编排（P2，2026-10-31）
 *
 * 只服务 forensicTrigger 标记过的 IP：把请求/响应两侧的取证级全量落到独立集合。
 * 常态请求零成本（未标记即 next()）。
 *
 * 本模块负责**编排**（判据 → 预算/采样 → 缓冲 → WAL → 落库 → 计数），
 * 载荷构建（脱敏/掩码/封顶/摘要/哈希）在 forensicCapturePayload.js——拆开的理由是
 * 每条脱敏规则都要能被单独喂输入断言，而不是靠端到端跑一遍顺带覆盖。
 *
 * 三条纪律（任务书 §1.3/§1.4）：采样/丢弃/截断/降级一律有计数与限频 warn（绝不静默）；
 * 口令类只存 { len, hmac }；任何异常只计数、绝不 500、绝不拖慢响应。
 */

const logger = require('../utils/logger');
const { errText } = require('../utils/auditWriteFailure');
const { readPositiveNumberEnv } = require('../utils/envNumber');
const metrics = require('../utils/metrics');
const wal = require('./forensicCaptureWal');
const payload = require('./forensicCapturePayload');
const { deterministicId } = require('./forensicCaptureCodec');
const num = (name, fallback, integer = false) =>
  readPositiveNumberEnv(name, fallback, {
    integer,
    onInvalid: (n, raw, d) => logger.error(`${n}=${JSON.stringify(raw)} 非法，已按默认 ${d} 处理`),
  });

// 容量闸（任务书 §1.3 默认值）
const PER_IP_PER_MIN = num('FORENSIC_PER_IP_PER_MIN', 300, true);
const PER_IP_BYTES_PER_MIN = num('FORENSIC_PER_IP_BYTES_PER_MIN', 5 * 1024 * 1024);
const GLOBAL_DAILY_BYTES = num('FORENSIC_GLOBAL_DAILY_BYTES', 2 * 1024 * 1024 * 1024);
const SAMPLE_EVERY_N = Math.max(1, num('FORENSIC_SAMPLE_EVERY_N', 10, true));

const BUFFER_LIMIT = 50;
const BUFFER_HARD_LIMIT = 500;
const FLUSH_INTERVAL_MS = 2000;
const WARN_INTERVAL_MS = 60000;
const LAST_ERROR_MAX = 200;

const state = {
  buffer: [],
  flushTimer: null,
  flushing: false,
  dropped: 0,
  rejected: 0,
  captured: 0,
  sampled: 0,
  bytes: 0,
  lastError: null,
  writeFailures: 0,
  lastWarnAt: 0,
  dayKey: new Date().toISOString().slice(0, 10),
  dayBytes: 0,
  ipWindows: new Map(),
  anchorTimer: null,
  lastAnchorDateKey: null,
};

/** 限频 warn（默认 60s 一条）：计数在累加，日志不刷屏 */
const warnRateLimited = (msg) => {
  const now = Date.now();
  if (now - state.lastWarnAt < WARN_INTERVAL_MS) return;
  state.lastWarnAt = now;
  logger.warn(msg);
};

/** 错误文本截断后再进统计：stats 会被 /metrics 与面板读取，不得塞大对象 */
const noteError = (err) => {
  const text = errText(err);
  state.lastError = text.slice(0, LAST_ERROR_MAX);
};

/** 每次判据现读 env：测试可逐用例开关，运维改开关不必重启构建 */
const isCaptureEnabled = () => process.env.FORENSIC_CAPTURE_ENABLED !== 'false';

/**
 * 入口判据：开关 + 触发标记。任何异常（trigger 模块缺失/抛错）⇒ 跳过并计数，
 * 绝不向上抛——取证是增强能力，不能成为请求链上的单点故障。
 */
const shouldCapture = (ip) => {
  if (!isCaptureEnabled()) return false;
  try {
    return Boolean(require('./forensicTrigger').isForensicTarget(ip));
  } catch (err) {
    state.rejected += 1;
    noteError(`trigger_unavailable: ${errText(err)}`);
    // 告警指标自身也可能抛错（指标层拆分/替换/桩件），抛出来会穿透 fail-open 边界，
    // 所以逐站点就地吞：字面量必须留在调用点，门禁按它枚举 type。
    try {
      metrics.incSecurityAlert('forensic_capture_trigger_unavailable', 'medium'); // §1.3：降级必须可告警，台账见 constants/failOpenSites.js
    } catch {
      /* 告警是增强能力：失败不得影响请求，也不得改变捕获路径 */
    }
    warnRateLimited(`取证触发判据不可用，已跳过捕获（累计 ${state.rejected} 次）：${errText(err)}`);
    return false;
  }
};

/** 全局日预算：跨日重置；只有**真放行**的记录占预算（采样跳过的不占，避免假耗尽） */
const budgetHasRoom = (size) => {
  const key = new Date().toISOString().slice(0, 10);
  if (key !== state.dayKey) {
    state.dayKey = key;
    state.dayBytes = 0;
  }
  if (state.dayBytes + size <= GLOBAL_DAILY_BYTES) return true;
  warnRateLimited(
    `取证捕获全局日预算已耗尽（${state.dayBytes}/${GLOBAL_DAILY_BYTES} 字节），停捕并计数`
  );
  return false;
};

/** 单 IP 分钟窗：配额内放行；超配额按 1/N 采样（采样本身也计数，不静默） */
const takeIpQuota = (ip, size) => {
  const now = Date.now();
  let win = state.ipWindows.get(ip);
  if (!win || now - win.start >= 60000) {
    win = { start: now, count: 0, bytes: 0, sampled: 0 };
    state.ipWindows.set(ip, win);
  }
  const over = win.count >= PER_IP_PER_MIN || win.bytes + size > PER_IP_BYTES_PER_MIN;
  win.count += 1;
  win.bytes += size;
  if (!over) return 'allow';
  win.sampled += 1;
  return win.sampled % SAMPLE_EVERY_N === 0 ? 'allow' : 'sample';
};

/**
 * 预算/配额裁决：'allow' | 'sample' | 'drop'。
 * 只有**真放行**的记录占日预算——采样跳过的不占（否则高频 IP 的采样会把全局预算
 * 先耗光，表现为"预算已尽"而实际没存几条，属假耗尽）。
 */
const admit = (ip, size) => {
  if (!budgetHasRoom(size)) return 'drop';
  const verdict = takeIpQuota(ip, size);
  if (verdict === 'allow') state.dayBytes += size;
  return verdict;
};

/** 构建一条取证记录（输入 req 快照与已脱敏的响应段；不读响应对象，故纯函数式） */
const buildRecord = ({ req, ip, trigger, response }) => {
  const { auditPath, deriveAuditMeta } = require('../utils/auditMeta');
  const { computeFingerprint, ipSegment } = require('../utils/fingerprint');
  const { computeDeviceKey } = require('../utils/forensicDeviceKey');
  const meta = deriveAuditMeta(req) || {};
  const u = req.user || {};
  // 主体/会话标识：从 req.user 取（未认证请求一律 null，不落空串）；长度按模型 maxlength 封顶
  const identity = {
    userId: u.userId ? payload.fitToMax(String(u.userId), 128) : null,
    username: u.username ? payload.fitToMax(u.username, 128) : null,
    sessionId: u.sessionId ? payload.fitToMax(u.sessionId, 128) : null,
  };
  return {
    createdAt: new Date(),
    ip,
    ipSegment: ipSegment(ip),
    method: req.method,
    path: auditPath(req),
    action: meta.action || null,
    category: meta.category || null,
    ...identity,
    fingerprint: computeFingerprint(req),
    deviceKey: computeDeviceKey(req),
    trigger: {
      reason: (trigger && trigger.reason) || null,
      markedAt: (trigger && trigger.markedAt) || null,
    },
    request: {
      headers: payload.maskHeaders(req.headers, payload.REQ_HEADER_CAP),
      ...payload.captureRequestBody(req),
      query: payload.sanitizeQueryPayload(req.query || {}),
      params: payload.sanitizeQueryPayload(req.params || {}),
    },
    response: payload.normalizeResponsePart(response),
    device: payload.buildDevicePart(req),
    location: payload.buildLocationPart(ip),
    net: payload.buildNetPart(req),
  };
};

/** 缓冲超硬上限：丢最旧并计数（不静默），返回被丢弃条数 */
const trimBuffer = () => {
  if (state.buffer.length <= BUFFER_HARD_LIMIT) return 0;
  const overflow = state.buffer.length - BUFFER_HARD_LIMIT;
  state.buffer.splice(0, overflow);
  state.dropped += overflow;
  warnRateLimited(`取证缓冲超过硬上限，已丢弃最旧 ${overflow} 条（累计 ${state.dropped} 次）`);
  return overflow;
};

/** 入队：预算/采样 → 记录哈希 → WAL → 缓冲。返回是否真的捕获。 */
const record = ({ req, ip, trigger, response }) => {
  try {
    const doc = buildRecord({ req, ip, trigger, response });
    const size = Buffer.byteLength(JSON.stringify(doc), 'utf8');
    const verdict = admit(ip, size);
    if (verdict === 'drop') {
      state.dropped += 1;
      return false;
    }
    if (verdict === 'sample') {
      state.sampled += 1;
      return false;
    }
    wal.assignSeq(doc);
    // 持久化到模型字段 seq：__walSeq 是 WAL 行号，strict schema 不认，直接落库会被静默丢弃，
    // 而 P2b 清单锚定要按它写 firstSeq/lastSeq ⇒ 必须显式镜像一份到 seq
    doc.seq = doc.__walSeq || null;
    doc.recordHash = payload.recordHashOf(doc);
    // 确定性 _id（由 recordHash 派生）：让"重试同一批"变成幂等——重复行会被 _id 唯一约束
    // 挡住，不会把同一条记录存两遍（此前是"落库失败整批重试"，部分成功时必然写重）。
    doc._id = deterministicId(doc.recordHash);
    state.buffer.push(doc);
    state.captured += 1;
    state.bytes += size;
    wal.appendLine(JSON.stringify(doc));
    trimBuffer();
    if (state.buffer.length >= BUFFER_LIMIT) flush().catch(() => {});
    return true;
  } catch (err) {
    state.rejected += 1;
    noteError(err);
    warnRateLimited(`取证记录构建失败，已跳过（累计 ${state.rejected} 次）：${errText(err)}`);
    return false;
  }
};

/** 批量落库；失败整批回退进缓冲（有上限），绝不丢弃而不计数 */

const createFlusher = require('./forensicCaptureFlush').createFlusher;
const flush = createFlusher({
  state,
  noteError,
  warnRateLimited,
  errText,
  bufferHardLimit: BUFFER_HARD_LIMIT,
});

const { createLifecycle } = require('./forensicCaptureLifecycle');
const { start, stop, flushAndStop } = createLifecycle({
  state,
  wal,
  flush,
  trimBuffer,
  intervalMs: FLUSH_INTERVAL_MS,
});

/** 冻结契约（§2.2 逐字）：{captured,sampled,dropped,rejected,bytes,walDropped,lastError} */
function getForensicCaptureStats() {
  return {
    captured: state.captured,
    sampled: state.sampled,
    dropped: state.dropped,
    rejected: state.rejected,
    bytes: state.bytes,
    walDropped: wal.getStats().walDroppedLines,
    lastError: state.lastError,
  };
}

/** 仅供测试重置（不带 __ 前缀：testHookConsumerGate 的钩子总数只许减不许增） */
function resetForTests() {
  for (const k of ['dropped', 'rejected', 'captured', 'sampled', 'bytes', 'dayBytes']) state[k] = 0;
  state.buffer.length = 0;
  state.lastError = null;
  state.dayKey = new Date().toISOString().slice(0, 10);
  state.ipWindows.clear();
  wal.resetCounters();
}

module.exports = {
  // 模型访问器：本集合的读写者只有取证链，把模型从**服务层**暴露给控制器，
  // 控制器因此不必 require('../models/…')（分层纪律 D-1a：新 controller 一律经服务层）。
  // 返回的是同一个 mongoose 模型对象，不复制、不包装——包装会让 .find() 的链式语义在
  // 两处各有一份定义，而分层闸要求的是"不直连"，不是"再抄一层API"。
  captureModel: () => require('../models/ForensicCapture'),
  // 编排
  isCaptureEnabled,
  shouldCapture,
  record,
  buildRecord,
  flush,
  start,
  stop,
  flushAndStop,
  getForensicCaptureStats,
  resetForTests,
  // 载荷构建转发（调用方只需记一个模块名）
  buildResponsePart: payload.buildResponsePart,
  captureRequestBody: payload.captureRequestBody,
  maskHeaders: payload.maskHeaders,
  maskResponseHeaders: payload.maskResponseHeaders,
  summarizeSetCookie: payload.summarizeSetCookie,
  sanitizeBodyForForensic: payload.sanitizeBodyForForensic,
  sanitizeQueryPayload: payload.sanitizeQueryPayload,
  capText: payload.capText,
  canonicalJson: payload.canonicalJson,
  recordHashOf: payload.recordHashOf,
};
