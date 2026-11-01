/**
 * 请求级幂等（`Idempotency-Key`，审计一-1）。设计取舍见 docs/adr/ADR-014。
 *
 * 语义：同键同载荷的第二次到达原样回放第一次响应（`Idempotency-Replayed: true`）；同键不同载荷 409 `IDEMPOTENCY_KEY_REUSED`；上一请求在途 409 `IDEMPOTENCY_IN_PROGRESS`，在途超过租约（5 分钟）即视为无主、可被同键接管（崩溃/被杀/部署重启都不会再有人来收尾，不能把键钉满 24h）；业务非 2xx ⇒ 释放键；2xx 但响应体超限/无体 ⇒ **保留键**并标 `replayOmitted`（重试只拿到「已完成、无响应体」，绝不重放执行）；过期记录不是判据、可被同键接管。键**可选**（不带则不判），前端每次提交默认带上。存储不可用时 fail-open 放行并告警：丢的是去重便利，fail-closed 会把可用性事故扩大成写入事故。
 */

const logger = require('../utils/logger');
const { incSecurityAlert } = require('../utils/metrics');

const degradeOpen = (reason, err) => {
  logger.warn(`${reason}：${err.message}`);
  incSecurityAlert('idempotency_degraded', 'high'); // 降级放行的唯一出口：日志之外必须留可告警计数（constants/failOpenSites.js：「grep 日志」不是运维动作）
};
const ApiResponse = require('../utils/apiResponse');
const IdempotencyRecord = require('../models/IdempotencyRecord');
const {
  parseIdempotencyKey,
  hashIdempotencyKey,
  fingerprintRequestBody,
} = require('../utils/idempotencyKey');

/** 键保留窗口：24 小时。比任何"用户可能重试"的时间尺度都长，又不至于长期堆积。 */
const RETENTION_MS = 24 * 60 * 60 * 1000;
/** 回放响应体的上限（字节）：只回放小表单类响应，避免把大导出留在记录里 */
const MAX_REPLAY_BYTES = 64 * 1024;
/** 在途租约（ADR-014 决策 7）：in_progress 超时无人收尾（进程被杀/部署重启/永久挂起）即视为无主、可被同键接管——不能把键钉满 24h；取值远大于全部幂等端点（均为亚秒级）。 */
const IN_PROGRESS_LEASE_MS = 5 * 60 * 1000;
const HEADER = 'idempotency-key';
const REPLAY_OMITTED_MESSAGE = '该请求已处理完成（响应体超过回放上限或未留存），未重复执行';

const readHeader = (req) => {
  const value = req.headers?.[HEADER];
  return Array.isArray(value) ? value[0] : value;
};

/** 把一个已完成的记录回放给调用方：有体按原状态码/原媒体类型回放，无体则显式降级（绝不重复执行） */
const replayStored = (res, record) => {
  res.setHeader('Idempotency-Replayed', 'true');
  // Location 是首次响应的事实（资源确实已创建）：降级回放也要还原，绝不伪造、也不吞掉
  if (record.responseLocation) res.setHeader('Location', record.responseLocation);
  const statusCode = record.statusCode || 200;
  if (record.replayOmitted) {
    res.setHeader('Idempotency-Replay-Omitted', 'true'); // 首次响应已交付过，这里只回放"已完成"这个结论
    return res.status(statusCode).json({
      success: true,
      replayed: true,
      responseOmitted: true,
      message: REPLAY_OMITTED_MESSAGE,
      data: null,
    });
  }
  if (record.contentType) {
    return res.status(statusCode).type(record.contentType).send(record.responseBody);
  }
  return res.status(statusCode).json(record.responseBody);
};

/** 冲突判定：同键第二条请求的结论。@returns {'replay'|'payload_mismatch'|'in_progress'|'stale'|'expired'} */
const expiryOf = (doc) => {
  const explicit = doc.expiresAt ? new Date(doc.expiresAt).getTime() : NaN;
  if (Number.isFinite(explicit)) return explicit;
  const created = doc.createdAt ? new Date(doc.createdAt).getTime() : NaN;
  // 历史行缺 expiresAt：按 createdAt + 24h 折算。直接判「缺失=过期」会在滚动发布期把 1 分钟前的完成态当过期重放
  return Number.isFinite(created) ? created + RETENTION_MS : 0;
};
/** 无主界限（expiresAt 口径）：expiresAt = 认领 + 保留窗口 ⇒ 「认领超过一个租约」写成 expiresAt ≤ 现在 + 保留窗口 − 租约 */
const staleClaimDeadline = () => new Date(Date.now() + RETENTION_MS - IN_PROGRESS_LEASE_MS);
const classifyExisting = (existing, requestHash) => {
  const claimExpiry = expiryOf(existing); // 本次受理 + 保留窗口：显式 expiresAt 优先，缺失按 createdAt 折算——判据与接管共用同一把尺子
  if (!(claimExpiry > Date.now())) return 'expired'; // 过期即无判据：TTL 只保证「最终」回收，尺子必须自带有效时刻
  if (existing.requestHash !== requestHash) return 'payload_mismatch';
  if (existing.state === 'completed') return 'replay';
  return claimExpiry > staleClaimDeadline().getTime() ? 'in_progress' : 'stale'; // 在途超租约 ⇒ 无主：崩溃/被杀/永久挂起都不会再有人来收尾
};

/** 响应体字节数：JSON 按序列化后的字节（就是回放时写出的那些字节），文本/二进制按原始字节 */
const bodyBytes = (kind, body) => {
  if (kind === 'json') return Buffer.byteLength(JSON.stringify(body ?? null));
  if (kind === 'text') return Buffer.byteLength(String(body));
  return 0;
};

/**
 * 2xx 存储判据与写入形态收口：!ok 删记录（释放键）；超限/无体留 completed +
 * replayOmitted（容量上限与"有没有体"只影响回放能力，不影响去重）；否则存可回放体。
 * @param {object} p
 * @param {string} p.contentTypeOf - 文本类响应的 Content-Type 取值函数（读 res 头）
 */
const buildOutcomeUpdate = ({
  keyHash,
  statusCode,
  ok,
  kind,
  storedBody,
  size,
  location,
  contentTypeOf,
}) => {
  const replayable =
    ok && kind !== 'none' && !Buffer.isBuffer(storedBody) && size <= MAX_REPLAY_BYTES;
  if (!ok) {
    return IdempotencyRecord.deleteOne({ keyHash });
  }
  if (!replayable) {
    return IdempotencyRecord.updateOne(
      { keyHash },
      {
        $set: {
          state: 'completed',
          statusCode,
          responseBody: null,
          contentType: null,
          responseLocation: location,
          replayOmitted: true,
        },
      }
    );
  }
  return IdempotencyRecord.updateOne(
    { keyHash },
    {
      $set: {
        state: 'completed',
        statusCode,
        responseBody: storedBody ?? null,
        contentType: kind === 'text' ? String(contentTypeOf() || 'text/html; charset=utf-8') : null,
        responseLocation: location,
        replayOmitted: false,
      },
    }
  );
};

/** 响应回填：任何出口都要收尾——2xx 落 completed（可回放的存体、无体的标降级），非 2xx 删记录（释放键）。 */
function captureOutcome(res, keyHash, replayBodyFilter = null) {
  let settled = false;
  let streamed = false;
  const settle = (kind, body) => {
    if (settled) return;
    settled = true;
    const statusCode = res.statusCode;
    const ok = statusCode >= 200 && statusCode < 300;
    if (streamed) kind = 'none'; // 已流过 res.write：响应体不可知，绝不能把从未发出的字节存成可回放
    const location =
      typeof res.getHeader('location') === 'string' ? res.getHeader('location') : null;
    // replayBodyFilter（审计 2026-11-02 C-F4）：挂载点声明的回放体裁剪。响应回放
    // 副本是响应 PII 加密体系外的明文旁路（留存 24h）——回含 PII 的 scope 必须在
    // 挂载点声明裁剪，只留重试方所需的结论字段（首次响应已交付，字段缺失对
    // 重试方无损）。裁剪先行，容量判据按裁剪后的体计算。
    //
    // filter 抛错必须吞掉并降级为「不可回放」（审计 2026-11-02 复审 F1-3）：
    // settled 已在入口置位，这里抛出会让 buildOutcomeUpdate 永不执行 ⇒ 记录
    // 卡死 in_progress ⇒ 5 分钟租约后同键重试**二次执行已成功的写入**（违反
    // 「回填失败只告警，不在响应路径上抛错」的本函数纪律）。filter 失败 =
    // 不可回放（replayOmitted），不是不可完成。
    let filterFailed = false;
    let storedBody = body;
    if (ok && kind === 'json' && replayBodyFilter && body !== null && body !== undefined) {
      try {
        storedBody = replayBodyFilter(body);
      } catch (e) {
        logger.warn('幂等回放体裁剪失败，降级为不可回放（首次响应已交付）', {
          err: String((e && e.message) || e),
        });
        filterFailed = true;
        storedBody = null;
      }
    }
    // filter 失败复用「无体」出口：completed + replayOmitted，释放回放语义；
    // 单一执行路径——降级分支绝不能绕过下方唯一的 update.exec()。
    const effectiveKind = filterFailed ? 'none' : kind;
    const size = ok ? bodyBytes(effectiveKind, storedBody) : 0;
    const update = buildOutcomeUpdate({
      keyHash,
      statusCode,
      ok,
      kind: effectiveKind,
      storedBody,
      size,
      location,
      contentTypeOf: () => res.getHeader('content-type'),
    });
    // 回填失败只告警：最坏结果是"下次同键请求按首次处理"（重复一次），比在响应路径上抛错（用户看到 500 但数据已写）好。
    update.exec().catch((err) => {
      degradeOpen('幂等记录回填失败（该键下次可能按首次提交处理）', err);
    });
  };

  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);
  const originalEnd = res.end.bind(res);
  const originalWrite = res.write.bind(res);

  res.json = (body) => {
    settle('json', body);
    return originalJson(body);
  };
  res.send = (chunk) => {
    if (chunk === null || chunk === undefined) settle('text', '');
    else if (typeof chunk === 'string' || Buffer.isBuffer(chunk)) settle('text', chunk);
    else settle('json', chunk); // 对象/布尔/数字：Express 内部转给 res.json，先落结论（json 包装会去重）
    return originalSend(chunk);
  };
  res.write = (chunk, ...rest) => {
    streamed = true;
    return originalWrite(chunk, ...rest);
  };
  res.end = (chunk, encoding) => {
    if (streamed)
      settle('none'); // 流过 res.write 的响应体不可知 ⇒ 只记"已完成"，不假装能回放
    else if (chunk === null || chunk === undefined || typeof chunk === 'function')
      settle('text', '');
    else if (typeof chunk === 'string' || Buffer.isBuffer(chunk)) settle('text', chunk);
    else settle('none');
    return originalEnd(chunk, encoding);
  };
  // 最后一道保险：上面任何包装都没接住（例如框架内部直接交付）时，响应真的完成也必须留下结论
  res.once('finish', () => settle('none'));
  res.once('close', () => {
    if (res.headersSent) settle('none'); // 客户端中途断开（无 finish）：响应已开始也要收尾，否则键 24h 钉在 in_progress
  });
  return res;
}

/** 过期记录的原子接管：以 expiresAt 为条件改写这一行（不是先删后建，那会在两步之间丢键）；null = 别人抢先 */
const takeOverExpired = (keyHash, requestHash, expiresAt) =>
  IdempotencyRecord.findOneAndUpdate(
    {
      keyHash,
      $or: [
        { expiresAt: { $lte: new Date() } },
        { expiresAt: null, createdAt: { $lte: new Date(Date.now() - RETENTION_MS) } },
        { expiresAt: null, createdAt: null },
      ],
    },
    {
      $set: {
        state: 'in_progress',
        requestHash,
        statusCode: null,
        responseBody: null,
        contentType: null,
        replayOmitted: false,
        expiresAt,
      },
    },
    { new: true }
  )
    .lean()
    .catch((err) => {
      degradeOpen('幂等记录过期接管失败，按首次提交放行', err);
      return null;
    });

/** 超租约在途记录的原子接管：条件带 state=in_progress——那行若在这段窗口里被收尾成 completed，本条件必不匹配 ⇒ 重试拿回放，绝不抢走已交付的结论 */
const takeOverStale = (keyHash, requestHash, expiresAt) =>
  IdempotencyRecord.findOneAndUpdate(
    {
      keyHash,
      state: 'in_progress',
      $or: [
        { expiresAt: { $lte: staleClaimDeadline() } },
        { expiresAt: null, createdAt: { $lte: new Date(Date.now() - IN_PROGRESS_LEASE_MS) } },
      ],
    },
    {
      $set: {
        requestHash,
        statusCode: null,
        responseBody: null,
        contentType: null,
        replayOmitted: false,
        expiresAt, // 租约随接管重置：后续同键请求重新落回「在途 409」，不会变成人人可夺
      },
    },
    { new: true }
  )
    .lean()
    .catch((err) => {
      degradeOpen('幂等记录在途接管失败，按首次提交放行', err);
      return null;
    });

/** 键已存在时的结论：'first' = 本请求接管了无主记录（按首次提交继续）；'done' = 响应已写/已放行 */
async function resolveConflict(res, { keyHash, requestHash, expiresAt }) {
  let existing;
  try {
    existing = await IdempotencyRecord.findOne({ keyHash }).lean();
  } catch (readErr) {
    degradeOpen('幂等记录读取失败，按首次提交放行', readErr);
    return 'first';
  }
  if (!existing) return 'first'; // 恰好被 TTL 清掉：按首次提交
  let verdict = classifyExisting(existing, requestHash);
  if (verdict === 'expired' || verdict === 'stale') {
    const takenOver =
      verdict === 'stale'
        ? await takeOverStale(keyHash, requestHash, expiresAt)
        : await takeOverExpired(keyHash, requestHash, expiresAt);
    if (takenOver) {
      if (verdict === 'stale') {
        logger.warn(
          '幂等键的在途记录超过租约，已按无主接管并重新执行（上一次受理疑似崩溃/被杀/永久挂起）'
        );
        incSecurityAlert('idempotency_lease_takeover', 'medium'); // 接管 = 在「上一次是否已落库」未知时再执行一次，可能重复写：必须能从计数看见
      }
      return 'first';
    }
    existing = await IdempotencyRecord.findOne({ keyHash })
      .lean()
      .catch(() => null); // 竞争失败：别人刚接手
    if (!existing) return 'first';
    verdict = classifyExisting(existing, requestHash);
  }
  if (verdict === 'replay') replayStored(res, existing);
  else if (verdict === 'in_progress') ApiResponse.codeError(res, 'IDEMPOTENCY_IN_PROGRESS');
  else if (verdict === 'payload_mismatch') ApiResponse.codeError(res, 'IDEMPOTENCY_KEY_REUSED');
  else ApiResponse.codeError(res, 'IDEMPOTENCY_IN_PROGRESS');
  return 'done';
}

let indexReady = null; // 判据载体必须先真的存在：autoIndex 后台建索引失败只打日志、插入照常成功 ⇒ 去重静默失效（services/reauthTicketStore.js 同型教训）
const ensureKeyIndex = () => {
  if (!indexReady) {
    indexReady = IdempotencyRecord.createIndexes().catch((err) => {
      indexReady = null; // 下次重试：一次失败不该让本进程永久放弃该判据
      throw new Error(`幂等判据不可用（keyHash 唯一索引建立失败）：${err.message}`);
    });
  }
  return indexReady;
};

/** 中间件工厂：scope 写进哈希（不同端点的同名键不相撞）；required=true 时缺键即拒（默认放行，见文件头）。 */
const idempotency = (options = {}) => {
  const { scope, required = false, replayBodyFilter = null } = options;
  const resolvedScope = String(scope || '');
  if (!resolvedScope) throw new Error('idempotency: 必须显式给出 scope（否则跨端点的键会相撞）');

  return async function idempotencyMiddleware(req, res, next) {
    const parsed = parseIdempotencyKey(readHeader(req));
    if (!parsed.ok) {
      // 两条拒绝分支各自点名错误码（不写成三元）：码字面量必须留在调用点上，「发出的码必须已注册」那道门禁按字面量扫描。
      if (parsed.reason === 'missing') {
        if (!required) return next();
        return ApiResponse.codeError(res, 'IDEMPOTENCY_KEY_REQUIRED');
      }
      return ApiResponse.codeError(res, 'IDEMPOTENCY_KEY_INVALID');
    }

    const userId = req.user?.userId;
    if (!userId) {
      // 无身份时无法建立判据：放行（认证闸在更外层，匿名到达说明路由漏挂鉴权）；
      // 真出现匿名到达说明路由挂错鉴权，那是另一个问题，不该被这里的 400 掩盖。
      return next();
    }

    const keyHash = hashIdempotencyKey({ scope: resolvedScope, userId, key: parsed.key });
    const requestHash = fingerprintRequestBody(req.body);
    const expiresAt = new Date(Date.now() + RETENTION_MS);
    const claim = () =>
      IdempotencyRecord.create({
        keyHash,
        userId,
        scope: resolvedScope,
        requestHash,
        state: 'in_progress',
        expiresAt,
      });

    try {
      await ensureKeyIndex(); // 索引没建起来就不许把插入当判据：失败落到下面同一个降级出口（fail-open + 告警）
      // 插入成功 = 本次是这个键的第一次到达（唯一索引是判据本体，不是先查后写的快照）
      await claim();
    } catch (err) {
      if (err.code !== 11000) {
        degradeOpen('幂等键登记失败，按首次提交放行（去重本次不生效）', err);
        return next();
      }
      // 键已存在：重放 / 改载荷 / 并发在途 / 过期残留，四种结论见 resolveConflict
      if ((await resolveConflict(res, { keyHash, requestHash, expiresAt })) === 'done') return;
    }

    captureOutcome(res, keyHash, replayBodyFilter);
    return next();
  };
};

module.exports = { HEADER, IN_PROGRESS_LEASE_MS, MAX_REPLAY_BYTES, RETENTION_MS, idempotency };
