/** 热升级队列读写（应用侧）：应用只回答「能不能升、请求是否被接受、任务到哪一步」，执行与判断在宿主代理。 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const config = require('../config');
const upgradeConfig = require('../config/upgrade');
const policy = require('../../scripts/hotUpgradePolicy');
const { signUpgradeRequest, normalizeMode } = require('./upgradeRequestSignature');
const { toEpochMs } = require('../utils/helpers');

const MAX_JSON_BYTES = 64 * 1024;
const JOB_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TERMINAL_STATES = new Set(['succeeded', 'failed']);
const ACTIVE_STATES = new Set(['queued', 'running']);
const ENQUEUE_LOCK_NAME = '.enqueue.lock';
const ENQUEUE_LOCK_STALE_MS = 30 * 1000;

const isJobId = (value) => typeof value === 'string' && JOB_ID_RE.test(value);

class QueueIoError extends Error {
  constructor(reason, message) {
    super(message);
    this.name = 'QueueIoError';
    // 读不到 ≠ 不存在（§1.1）：否则并发升级闸会被 EACCES 静默摘掉；code 复用 UPGRADE_QUEUE_UNAVAILABLE
    this.code = 'UPGRADE_QUEUE_UNAVAILABLE';
    this.reason = reason;
  }
}

const QUEUE_IO_REASON_TEXT = {
  list_failed: '目录不可列举',
  read_failed: '文件不可读',
  not_regular: '不是普通文件',
  too_large: '超过大小上限',
  parse_failed: '内容不是合法 JSON',
  not_object: '内容不是 JSON 对象',
  invalid_heartbeat: '心跳字段无法解析',
}; // 失败原因 → 运维可读文案；target 只取路径末段，绝对路径不出站

const queueIoError = (reason, target, cause) => {
  const where =
    String(target || '')
      .split(/[\\/]/)
      .filter(Boolean)
      .pop() || 'queue';
  const detail = (cause && cause.code) || QUEUE_IO_REASON_TEXT[reason] || reason;
  return new QueueIoError(reason, `升级队列读取失败（${where}：${detail}）`);
};

function currentColor() {
  // 两色容器都监听 3000，PORT 分不出颜色：备色由 compose 注入 DEPLOY_COLOR，不认它会把备色报成 blue。
  const explicit = String(process.env.DEPLOY_COLOR || '').trim();
  if (policy.PORT_BY_COLOR[explicit]) return explicit;
  return policy.COLOR_BY_PORT[Number(process.env.PORT) || 3000] || 'unknown';
}

const otherColor = (color) => (color === 'blue' ? 'green' : color === 'green' ? 'blue' : ''); // 目标色 = 非当前色；颜色未知时不猜

function readJsonFile(file) {
  let fd; // 只有 ENOENT ⇒ null；其余失败（EACCES/EIO/坏 JSON/超限…）一律抛 QueueIoError（§1.1 根因：不许与「不存在」同形）
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw queueIoError('read_failed', file, err);
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw queueIoError('not_regular', file);
    if (stat.size > MAX_JSON_BYTES) throw queueIoError('too_large', file);
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(fd, 'utf8'));
    } catch (err) {
      throw queueIoError('parse_failed', file, err);
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw queueIoError('not_object', file);
    }
    return parsed;
  } finally {
    try {
      fs.closeSync(fd);
    } catch {} // 关闭失败不得掩盖已判定结果（原实现 closeSync 抛错会替换掉业务错误）
  }
}

function ensureDir(dir, mode) {
  // mkdir 的 mode 只作用于**新建**目录：目录早已存在（旧版本、手工 mkdir）时权限位不收敛，等于队列目录一直是 0755。
  fs.mkdirSync(dir, { recursive: true, mode });
  if (mode) {
    try {
      fs.chmodSync(dir, mode);
    } catch {}
  }
}

/** 原子写：同目录临时文件 + rename，避免代理读到半截 JSON */
function writeJsonAtomic(file, value, mode = 0o644) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(tmp, 'wx', mode);
  try {
    fs.writeFileSync(fd, JSON.stringify(value, null, 2), 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
}

function listJsonFiles(dir) {
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch (err) {
    if (err.code === 'ENOENT') return []; // 目录不存在=空队列；其余（EACCES/EIO/ENOTDIR）必须上抛：读不到 ≠ 没有任务（§1.1）
    throw queueIoError('list_failed', dir, err);
  }
  return names
    .filter((name) => name.endsWith('.json') && !name.startsWith('.'))
    .map((name) => path.join(dir, name));
}

/** 心跳 bundles 归一化：代理写入时已封顶（每类 10 条、逐字段截断），这里再防「心跳文件被手写坏」的形态——字段非字符串、条目非对象都折成缺省，不让一个坏心跳炸掉概览。 */
const BUNDLE_LIST_LIMIT = 10;

function normalizeBundleEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const dirName = asString(raw.dirName).slice(0, 128);
  if (!dirName) return null; // 没有目录名的条目无法在界面上呈现，按不存在处理
  return {
    dirName,
    ref: asString(raw.ref).slice(0, 512),
    digest: asString(raw.digest).slice(0, 71),
    repository: asString(raw.repository).slice(0, 256),
    version: asString(raw.version).slice(0, 64),
    buildId: asString(raw.buildId).slice(0, 128),
    createdAt: asString(raw.createdAt).slice(0, 32),
  };
}

function normalizeHeartbeatBundles(raw) {
  const empty = { available: [], invalid: [] };
  if (!raw || typeof raw !== 'object') return empty;
  const take = (list, map) =>
    Array.isArray(list) ? list.map(map).filter(Boolean).slice(0, BUNDLE_LIST_LIMIT) : [];
  return {
    available: take(raw.available, normalizeBundleEntry),
    invalid: take(raw.invalid, (item) => {
      if (!item || typeof item !== 'object') return null;
      const dirName = asString(item.dirName).slice(0, 128);
      if (!dirName) return null;
      return { dirName, error: asString(item.error).slice(0, 200) };
    }),
  };
}

/** 心跳 intake 归一化（inbox → bundles）：pending=待落位、rejected=落位失败及原因、landed=本轮落位目录；与 bundles 同纪律（逐字段截断、数量封顶）——心跳 0644 全局可读，不能被畸形 inbox 撑成 DoS。 */
function normalizeHeartbeatIntake(raw) {
  const empty = { pending: [], rejected: [], landed: '' };
  if (!raw || typeof raw !== 'object') return empty;
  const clipName = (v) => asString(v).slice(0, 128);
  const pending = Array.isArray(raw.pending)
    ? raw.pending.map(clipName).filter(Boolean).slice(0, BUNDLE_LIST_LIMIT)
    : [];
  const rejected = Array.isArray(raw.rejected)
    ? raw.rejected
        .map((item) => {
          if (!item || typeof item !== 'object') return null;
          const archive = clipName(item.archive);
          return {
            // archive 可空（inbox 本身不可读时没有具体归档名），outcome/reason 仍在
            archive,
            outcome: asString(item.outcome).slice(0, 64),
            reason: asString(item.reason).slice(0, 300),
          };
        })
        .filter((item) => item && (item.archive || item.outcome))
        .slice(0, BUNDLE_LIST_LIMIT)
    : [];
  return { pending, rejected, landed: clipName(raw.landed) };
}

function readHeartbeat() {
  const beat = readJsonFile(upgradeConfig.heartbeatFile);
  if (!beat) return null; // 不存在 = 代理从未上报；字段读得出却不可用（下行 throw）算异常——两类不许同码
  const lastSeenAt = toEpochMs(beat.lastSeenAt);
  if (!Number.isFinite(lastSeenAt))
    throw queueIoError('invalid_heartbeat', upgradeConfig.heartbeatFile);
  const ageMs = Date.now() - lastSeenAt;
  const reasons = Array.isArray(beat.reasons)
    ? beat.reasons.filter((r) => typeof r === 'string').slice(0, 10)
    : [];
  return {
    lastSeenAt: new Date(lastSeenAt).toISOString(),
    // 心跳来自未来（时钟不同步）一律按过期处理：宁可少放行，也不要在坏时钟上发版
    stale: ageMs < 0 || ageMs > upgradeConfig.agentStaleMs,
    version: typeof beat.version === 'string' ? beat.version : '',
    ready: typeof beat.ready === 'boolean' ? beat.ready : false,
    clockSkew: ageMs < 0, // 与「单纯过期」区分开：英文界面按 code 呈现不同措辞；真正的处置是校时而非查代理
    reasons: ageMs < 0 ? [...reasons, '心跳时间晚于当前时间（宿主与应用时钟不同步）'] : reasons,
    bundles: normalizeHeartbeatBundles(beat.bundles),
    intake: normalizeHeartbeatIntake(beat.intake),
  };
}

function collectQueueDirProblems() {
  const checks = [
    [
      upgradeConfig.requestsDir,
      fs.constants.W_OK,
      'REQUESTS_DIR_UNWRITABLE',
      '升级队列的请求目录不可写（UPGRADE_QUEUE_DIR 未挂载或权限不足）',
    ],
    [
      upgradeConfig.statusDir,
      fs.constants.R_OK,
      'STATUS_DIR_UNREADABLE',
      '升级队列的状态目录不可读（UPGRADE_QUEUE_DIR 未挂载或权限不足）',
    ],
    [
      path.join(upgradeConfig.queueDir, 'processing'),
      fs.constants.R_OK,
      'PROCESSING_DIR_UNREADABLE',
      '升级队列的执行目录不可读（UPGRADE_QUEUE_DIR 未挂载或权限不足；读不到会让「已有任务」判据失效）',
    ],
  ];
  const problems = [];
  for (const [dir, mode, code, reason] of checks) {
    try {
      fs.accessSync(dir, mode);
    } catch {
      problems.push({ code, reason });
    }
  }
  return problems;
} // processing 一行此前从未被探测（§1.1）：它读不到时「已有任务」判据会静默失效；部署契约本就要求应用可读该目录

/** 就绪判据：任一条不满足 POST 都必须拒绝；reasons 给运维看（只回逻辑名，绝对路径不出站）。缺 HMAC_SECRET 或 代理在线但配置不完整时若放行，只会得到"永远被拒的请求"——只回 false 又会让按钮变灰的原因成谜。 */
function getReadiness() {
  const reasons = [];
  const codes = [];
  if (!upgradeConfig.enabled) {
    codes.push('UPGRADE_DISABLED');
    reasons.push('UPGRADE_ENABLED 未开启');
  }

  if (upgradeConfig.registryAllowlist.length === 0) {
    codes.push('ALLOWLIST_EMPTY');
    reasons.push('HOT_UPGRADE_REGISTRY_ALLOWLIST 为空（空白名单按全拒处理）');
  }

  if (!config.hmacSecret) {
    codes.push('HMAC_SECRET_MISSING');
    reasons.push('HMAC_SECRET 未配置（无法签发升级请求）');
  }

  for (const problem of collectQueueDirProblems()) {
    codes.push(problem.code);
    reasons.push(problem.reason);
  }

  let heartbeat = null;
  let heartbeatError = null;
  try {
    heartbeat = readHeartbeat();
  } catch (err) {
    heartbeatError = err;
  }
  if (heartbeatError) {
    codes.push('HEARTBEAT_UNREADABLE'); // 心跳「存在但读不出」≠「从未上报」：后者让运维去查代理而不是查挂载/权限（§1.1）
    reasons.push(
      `升级代理心跳不可读（${heartbeatError.reason || 'io'}）：文件存在但读不出来，检查 UPGRADE_QUEUE_DIR 挂载与权限`
    );
  } else if (!heartbeat) {
    codes.push('AGENT_NEVER_REPORTED');
    reasons.push('升级代理从未上报心跳');
  } else if (heartbeat.stale) {
    codes.push(heartbeat.clockSkew ? 'CLOCK_SKEW' : 'AGENT_HEARTBEAT_STALE');
    reasons.push('升级代理心跳已过期');
  } else if (heartbeat.ready === false) {
    codes.push('AGENT_NOT_READY');
    reasons.push(
      heartbeat.reasons.length > 0
        ? `升级代理未就绪：${heartbeat.reasons.join('；')}`
        : '升级代理未就绪'
    );
  }

  return {
    ready: reasons.length === 0,
    reasons,
    codes,
    enabled: upgradeConfig.enabled,
    allowlist: upgradeConfig.registryAllowlist,
    heartbeat,
  };
}

/** digest 钉扎 + 白名单：形态错 ⇒ 400、不在白名单 ⇒ 403；code 由两段校验各自决定，不靠中文文案子串反推（改文案会静默改变错误码）。 */
function validateImage(image) {
  let parsed;
  try {
    parsed = policy.parseImageRef(image);
  } catch (err) {
    return { ok: false, code: 'UPGRADE_IMAGE_INVALID', message: err.message };
  }
  try {
    policy.assertImageAllowed(parsed, upgradeConfig.registryAllowlist);
  } catch (err) {
    return { ok: false, code: 'UPGRADE_IMAGE_NOT_ALLOWED', message: err.message };
  }
  return { ok: true, parsed };
}

const asString = (value) => (typeof value === 'string' ? value : '');
const asNullableString = (value) => (typeof value === 'string' ? value : null);

function normalizeRequester(raw) {
  if (!raw || typeof raw !== 'object') return { userId: '', username: '' };
  return { userId: asString(raw.userId), username: asString(raw.username) };
}

function normalizeSteps(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((step) => step && typeof step === 'object')
    .slice(-40)
    .map((step) => ({
      name: asString(step.name).slice(0, 64),
      detail: asString(step.detail).slice(0, 300),
      at: asNullableString(step.at),
    }));
}

function normalizeJob(raw, fallback = {}) {
  if (!raw || typeof raw !== 'object') return null;
  const id = isJobId(raw.id) ? raw.id : fallback.id;
  if (!id) return null;
  const validState =
    typeof raw.state === 'string' &&
    (ACTIVE_STATES.has(raw.state) || TERMINAL_STATES.has(raw.state));
  const state = validState ? raw.state : fallback.state || 'queued';
  return {
    id,
    state,
    image: asString(raw.image),
    mode: raw.mode === 'offline' ? 'offline' : 'registry', // 旧状态文件没有 mode 字段：按 registry 呈现
    requestedBy: normalizeRequester(raw.requestedBy),
    requestedAt: asNullableString(raw.requestedAt),
    startedAt: asNullableString(raw.startedAt),
    finishedAt: asNullableString(raw.finishedAt),
    updatedAt: asNullableString(raw.updatedAt),
    outcome: asString(raw.outcome),
    message: asString(raw.message),
    activeColor: asString(raw.activeColor),
    targetColor: asString(raw.targetColor),
    steps: normalizeSteps(raw.steps),
  };
}

function readJob(id) {
  const fromStatus = normalizeJob(readJsonFile(path.join(upgradeConfig.statusDir, `${id}.json`)));
  if (fromStatus) return fromStatus;

  const processingFile = path.join(upgradeConfig.queueDir, 'processing', `${id}.json`);
  const processing = normalizeJob(readJsonFile(processingFile), { id, state: 'running' });
  if (processing) return processing;

  return normalizeJob(readJsonFile(path.join(upgradeConfig.requestsDir, `${id}.json`)), {
    id,
    state: 'queued',
  });
}

function listJobs(limit = upgradeConfig.historyLimit) {
  const jobs = listJsonFiles(upgradeConfig.statusDir)
    .map((file) => normalizeJob(readJsonFile(file)))
    .filter(Boolean);
  const at = (job) => toEpochMs(job.requestedAt || job.startedAt || 0) || 0;
  jobs.sort((a, b) => at(b) - at(a));
  return jobs.slice(0, limit);
}

function findActiveJob() {
  for (const file of listJsonFiles(upgradeConfig.statusDir)) {
    const job = normalizeJob(readJsonFile(file));
    if (job && ACTIVE_STATES.has(job.state)) return job;
  }
  const processing = listJsonFiles(path.join(upgradeConfig.queueDir, 'processing'));
  if (processing.length > 0) {
    const job = normalizeJob(readJsonFile(processing[0]));
    return job || { id: path.basename(processing[0], '.json'), state: 'running' };
  }
  const requests = listJsonFiles(upgradeConfig.requestsDir);
  if (requests.length > 0) {
    const job = normalizeJob(readJsonFile(requests[0]));
    return job || { id: path.basename(requests[0], '.json'), state: 'queued' };
  }
  return null;
}

/** 写入升级请求；抛出的 error.code 供控制器映射成稳定错误码 */
function withEnqueueLock(fn) {
  ensureDir(upgradeConfig.requestsDir, 0o700);
  const lockFile = path.join(upgradeConfig.requestsDir, ENQUEUE_LOCK_NAME);
  let fd = null;
  for (let attempt = 0; attempt < 2 && fd === null; attempt += 1) {
    try {
      fd = fs.openSync(lockFile, 'wx', 0o600);
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      try {
        if (Date.now() - fs.statSync(lockFile).mtimeMs > ENQUEUE_LOCK_STALE_MS) {
          fs.unlinkSync(lockFile);
          continue;
        }
      } catch {
        continue;
      }
      throw Object.assign(new Error('升级请求正在入队，请稍后重试'), {
        code: 'UPGRADE_ALREADY_RUNNING',
      });
    }
  }
  if (fd === null) {
    throw Object.assign(new Error('升级请求正在入队，请稍后重试'), {
      code: 'UPGRADE_ALREADY_RUNNING',
    });
  }
  try {
    fs.writeSync(fd, String(process.pid));
    fs.closeSync(fd);
    fd = null;
    return fn();
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
    try {
      fs.unlinkSync(lockFile);
    } catch {}
  }
}

function createUpgradeRequest({ image, mode, user, sourceIp = '', now = Date.now() }) {
  const readiness = getReadiness();
  if (!upgradeConfig.enabled) {
    throw Object.assign(new Error('热升级未启用'), { code: 'UPGRADE_DISABLED' });
  }
  if (readiness.codes.includes('ALLOWLIST_EMPTY')) {
    throw Object.assign(new Error('镜像白名单未配置'), { code: 'UPGRADE_DISABLED' });
  }

  const validation = validateImage(image);
  if (!validation.ok) {
    throw Object.assign(new Error(validation.message), { code: validation.code });
  }

  if (!readiness.ready) {
    throw Object.assign(new Error(readiness.reasons.join('；')), {
      code: 'UPGRADE_QUEUE_UNAVAILABLE',
    });
  }

  const id = crypto.randomUUID();
  const requestedAt = new Date(now).toISOString();
  const activeColor = currentColor();
  // mode 只在签名 canonical 里分型（offline 多一段）：离线请求能否执行由宿主代理判定（本地是否有声明该 digest 的包 + 全量校验），应用侧不预判——预判会引用一份可能已被搬走的包，而代理每轮扫描的心跳只是候选。
  const payload = {
    id,
    image: validation.parsed.ref,
    mode: normalizeMode(mode),
    requestedAt,
    requestedBy: {
      userId: String(user?.userId || ''),
      username: String(user?.username || ''),
    },
    sourceIp: String(sourceIp || ''),
    activeColor, // 颜色在这里就算出来：否则审计里的 targetColor 永远是一串空值
    targetColor: otherColor(activeColor),
  };
  const signature = signUpgradeRequest(config.hmacSecret, {
    id,
    image: payload.image,
    mode: payload.mode,
    requestedAt,
    userId: payload.requestedBy.userId,
  });

  return withEnqueueLock(() => {
    const active = findActiveJob();
    if (active) {
      throw Object.assign(new Error('已有升级任务进行中或排队'), {
        code: 'UPGRADE_ALREADY_RUNNING',
        details: { jobId: active.id },
      });
    }
    const file = path.join(upgradeConfig.requestsDir, `${id}.json`);
    try {
      writeJsonAtomic(file, { ...payload, signature }, 0o600);
    } catch (err) {
      throw Object.assign(new Error(`升级请求写入失败：${err.message}`), {
        code: 'UPGRADE_QUEUE_UNAVAILABLE',
      });
    }
    return {
      job: normalizeJob({ ...payload, state: 'queued', signature }, { id, state: 'queued' }),
    };
  });
}

function getOverview({ buildInfo, now = Date.now() }) {
  const readiness = getReadiness();
  let jobs = [];
  let active = null;
  let queueReadError = null;
  try {
    jobs = listJobs();
    // active 必须覆盖 requests/processing：否则 202 后代理写 status 前的窗口会显示「没有进行中的任务」，用户会再点一次（撞 409）。
    const foundActive = findActiveJob();
    active = foundActive ? readJob(foundActive.id) || foundActive : null;
  } catch (err) {
    if (!(err instanceof QueueIoError)) throw err; // 展示面不因一个坏文件整页 500，但也不折成「没有任务」（§1.1）：降级为 ready=false + QUEUE_IO_UNREADABLE
    queueReadError = err;
  }

  const port = Number(process.env.PORT) || 3000;
  const color = currentColor();
  const codeList = [...readiness.codes];
  const reasonList = [...readiness.reasons];
  if (queueReadError) {
    codeList.push('QUEUE_IO_UNREADABLE');
    reasonList.push(queueReadError.message);
  }

  return {
    server: { ...buildInfo, color, port },
    upgrade: {
      ready: readiness.ready && !queueReadError,
      enabled: readiness.enabled,
      reasons: reasonList,
      // 稳定原因码（与 reasons 同序）：英文界面据此本地化，中文界面继续用 reasons 原文
      reasonCodes: codeList,
      allowlist: readiness.allowlist,
      heartbeat: readiness.heartbeat,
      // 离线包候选（代理心跳携带）：仅用于展示与下拉，不是完整性背书——全量校验在代理执行时做
      bundles: readiness.heartbeat ? readiness.heartbeat.bundles : { available: [], invalid: [] },
      // 落位通道状态（inbox → bundles）：pending = 传完待落位，rejected = 落位失败及原因
      intake: readiness.heartbeat
        ? readiness.heartbeat.intake
        : { pending: [], rejected: [], landed: '' },
      activeJob: active,
      latestJob: jobs[0] || active,
      history: jobs,
    },
    checkedAt: new Date(now).toISOString(),
  };
}

module.exports = {
  isJobId,
  getReadiness,
  validateImage,
  createUpgradeRequest,
  getOverview,
  listJobs,
  readJob,
  findActiveJob,
  normalizeJob,
};
