/**
 * 取证捕获中间件（P2，2026-10-31）
 *
 * 挂载位置与 auditLog 同段（body parser 之后）：入口先判"本 IP 是否被 forensicTrigger 标记"，未标记直接 next()——常态请求不付出任何采集成本（任务书 §1.1 两级捕获的一级）。
 *
 * 行为约束（全部由对拍用例锁定）：① 不改写响应——json/send/write/end 的入参、返回值、this、异常原样透传；② 不阻塞响应——所有脱敏/哈希/落库都在 response 'finish' 之后的 setImmediate 里；③ 任何异常只计数（service.rejected），绝不 500、绝不拖慢请求。
 *
 * 响应侧只做"取引用 + 数字节"：body 内容在 finish 之后才序列化/截断/哈希。
 */

const service = require('../../services/forensicCapture');

/** 取请求 IP（与准入/审计同一把尺）；异常返回空串 */
const resolveIp = (req) => {
  try {
    const { clientIpForSecurityDecision, normalizeIP } = require('../../utils/ipUtils');
    return normalizeIP(clientIpForSecurityDecision(req)) || '';
  } catch {
    return '';
  }
};

/** 触发快照：标记原因/时间只读一次，避免响应后才去查标记表（那时可能已过期） */
const triggerSnapshotOf = (ip) => {
  try {
    const trigger = require('../../services/forensicTrigger');
    if (typeof trigger.getForensicTarget === 'function') {
      const info = trigger.getForensicTarget(ip) || {};
      return { reason: info.reason || null, markedAt: info.markedAt || null };
    }
    // 兼容兜底：仅当 lastMark 恰好就是本 IP 才敢归因，否则留空（宁缺毋猜）
    const last = (trigger.getForensicTriggerStats() || {}).lastMark;
    if (last && last.ip === ip && last.reason) {
      return { reason: last.reason, markedAt: last.at ? new Date(last.at) : null };
    }
    return { reason: null, markedAt: null };
  } catch {
    return { reason: null, markedAt: null };
  }
};

const byteLengthOf = (chunk) => {
  if (chunk === null || chunk === undefined) return 0;
  if (Buffer.isBuffer(chunk)) return chunk.length;
  return Buffer.byteLength(String(chunk), 'utf8');
};

function forensicCapture() {
  return (req, res, next) => {
    const ip = resolveIp(req);
    // 双层兜底第一层：shouldCapture 内部已吞异常，但其未来改动不该决定 HTTP 语义
    let capture = false;
    try {
      capture = Boolean(ip) && service.shouldCapture(ip);
    } catch {
      capture = false;
    }
    if (!capture) return next();

    const trigger = triggerSnapshotOf(ip);
    let bodyRef;
    let hasBodyRef = false;
    let streamed = false;
    let streamBytes = 0;
    let done = false;

    const originalJson = res.json ? res.json.bind(res) : null;
    const originalSend = res.send ? res.send.bind(res) : null;
    const originalWrite = typeof res.write === 'function' ? res.write.bind(res) : null;
    const originalEnd = typeof res.end === 'function' ? res.end.bind(res) : null;

    if (originalJson) {
      res.json = function json(body) {
        bodyRef = body;
        hasBodyRef = true;
        return originalJson(body);
      };
    }
    if (originalSend) {
      res.send = function send(body) {
        if (!hasBodyRef) {
          bodyRef = body;
          hasBodyRef = true;
        }
        return originalSend(body);
      };
    }
    // 只有**真正的流式**才计 streamed：res.json/res.send 内部也会调 end(chunk)，但那是一次性正文
    // （已经由 json/send 取到 bodyRef），否则每条 JSON 响应都退化成"只剩字节数的元数据"，正文取证价值归零。
    if (originalWrite) {
      res.write = function write(chunk, ...rest) {
        if (!hasBodyRef) {
          streamed = true;
          streamBytes += byteLengthOf(chunk);
        }
        return originalWrite(chunk, ...rest);
      };
    }
    if (originalEnd) {
      res.end = function end(chunk, ...rest) {
        if (!hasBodyRef && chunk !== undefined && chunk !== null) {
          streamed = true;
          streamBytes += byteLengthOf(chunk);
        }
        return originalEnd(chunk, ...rest);
      };
    }

    const finalize = () => {
      if (done) return;
      done = true;
      // setImmediate：响应已 flush，重活（脱敏/哈希/入队）不占响应时延
      setImmediate(() => {
        try {
          const headers = typeof res.getHeaders === 'function' ? res.getHeaders() : {};
          const contentType = String(headers['content-type'] || '');
          const bodyText = hasBodyRef
            ? typeof bodyRef === 'string'
              ? bodyRef
              : bodyRef === undefined
                ? ''
                : JSON.stringify(bodyRef)
            : '';
          const bytes = streamBytes || byteLengthOf(bodyText);
          const response = service.buildResponsePart({
            status: res.statusCode,
            headers,
            contentType,
            body: bodyText,
            bytes,
            complete: res.writableFinished === true,
            streamed,
          });
          service.record({ req, res, ip, trigger, response });
        } catch {
          /* record 内部已计数；此处只保证不抛到 setImmediate 外层 */
        }
      });
    };

    res.once('finish', finalize);
    res.once('close', finalize);
    return next();
  };
}

module.exports = { forensicCapture };
