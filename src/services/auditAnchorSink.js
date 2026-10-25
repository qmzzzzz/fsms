/**
 * 审计检查点**外部锚定**的传输层（P1，2026-10-24）
 *
 * 缺口形状（已回源复核）：`auditChainCheckpoint` 的检查点文件默认落在本机 `logs/`，
 * 与 Mongo 同一个主权边界。于是这条路径成立，且**不需要 HMAC_SECRET**：
 *
 *   改审计链（删 / 改 / 插）→ 删掉本地检查点文件 → 重新跑一次 create
 *
 * 新的检查点会为被篡改后的链尾重新签名（签名由服务自己算），旧锚点随文件一起消失，
 * `verifyCheckpoints` 看到的是一个自洽、从未失配的检查点集合 ⇒ 判 PASS。这不是实现
 * bug，而是「锚点与受保护数据同主权」的必然结果；`auditChainCheckpoint` 的头注释
 * 早已自陈「只产出锚点，不做传输」，本模块补的就是这一段传输。
 *
 * 【本模块只做两件事】
 *   ship  —— 把本地检查点**追加**到受保护数据之外的存储；
 *   fetch —— 把外部副本读回来（核验时的比对在 `auditChainCheckpoint.compareAnchors`，
 *            那边是纯函数，不碰网络）。
 *
 * 【为什么锚点存储必须是 append-only】
 * 本模块从不删除、不覆盖外部存储。幂等性靠接收端按 `signature` 去重。如果锚点存储
 * 允许改写，攻击者只要把外部副本一起改掉，比对就重新变成「两边一致」——又退回原点了。
 *
 * 【能力边界（如实记录，不得读成「完整防篡改」）】
 *   · 能同时改 Mongo、本地检查点文件**与外部锚点存储**的人仍然可以重写全部三者。
 *     外部锚定的全部价值来自「外部存储由另一个主体持有」（不同凭据 / WORM 保留策略 /
 *     第三方时间戳），这一点由部署决定，**不由本模块保证**。
 *   · 尚未 ship 的检查点不受保护：从 create 到 ship 之间的窗口里，删文件重锚不会被
 *     外部比对发现（只会显示「有一条没外发」）。缩短窗口的办法是 create 之后紧跟
 *     ship（`create --ship`，推荐的 cron 形态）。
 *   · HMAC_SECRET 轮换会让旧锚点验签失败 ⇒ 外锚证据链断裂。轮换期间必须保留旧密钥
 *     用于核验；本模块按单密钥设计，多密钥核验不在范围内。
 *   · 本模块**不保证**外部存储真的在另一台机器上：`file:` sink 完全可能是同一块盘。
 *     那是部署问题，`verify --anchors` 只能证明「外部副本里有的，本地都有」。
 *
 * 【sink 契约】
 *   file:<path>       追加 JSONL，每行一条检查点记录（与本地检查点文件同格式）。
 *                     写入前按 signature 去重；读取时坏行直接报错（不跳过）。
 *   http(s)://<base>  GET  <base>            → 200 {"anchors":[<record>...]}；404 视为空存储
 *                     POST <base> {"anchorVersion":1,"anchors":[<record>...]}
 *                                          → 2xx 表示已持久化
 *                     接收端必须按 signature 幂等、只追加不覆盖。
 *   未配置            ship 报 sink_not_configured（不静默跳过）；verify 见 CLI。
 *
 * 【本模块不记日志】
 * 结果以结构化对象返回，由 CLI 决定怎么打印。原因：它是被 cron 与人工同时调用的
 * 离线工具；更要紧的是「投递失败」与「锚点失配」必须能分别判读，混进一行 warn 里
 * 就分不开了（`securityAlertDelivery` 把告警落日志是合理的，因为它在线）。
 */

'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const {
  CHECKPOINT_VERSION,
  hmacSecretOf,
  readCheckpoints,
  signCheckpoint,
} = require('./auditChainCheckpoint');

const SINK_ENV = 'AUDIT_ANCHOR_SINK';
const ALLOWLIST_ENV = 'AUDIT_ANCHOR_ALLOWLIST';
const ANCHOR_PAYLOAD_VERSION = 1;
const DEFAULT_ANCHOR_TIMEOUT_MS = 5000;
// 外部存储是**别人**的端点：响应体大小必须有上限，否则一个被接管的锚点服务
// 可以用一条无限长的 JSON 把核验进程撑爆。8MB 够放十万级检查点。
const MAX_ANCHOR_RESPONSE_BYTES = 8 * 1024 * 1024;

/**
 * 解析 sink 配置。
 *
 * 主机白名单不是硬闸而是**误配护栏**：sink 地址来自运维环境变量，与 MONGODB_URI
 * 同级信任，挡住的主要是「拼错域名把审计锚点发给陌生人」。因此与
 * `securityAlertDelivery` 同口径——配了就校验，没配只警告不阻断。
 *
 * @param {string} [raw] 显式 sink（CLI `--anchors=...`）；省略则读环境变量
 * @returns {{kind: 'file'|'http'|null, reason?: string, warnings: string[], path?: string, url?: string, host?: string}}
 */
function resolveSink(raw) {
  const value = raw === undefined || raw === null ? process.env[SINK_ENV] : raw;
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text) return { kind: null, reason: 'not_configured', warnings: [] };

  if (/^file:/i.test(text)) {
    const target = text.slice('file:'.length);
    if (!target) return { kind: null, reason: 'file_path_empty', warnings: [] };
    return {
      kind: 'file',
      path: path.resolve(process.cwd(), target),
      warnings: [],
    };
  }

  let url;
  try {
    url = new URL(text);
  } catch (_) {
    return { kind: null, reason: 'url_unparsable', warnings: [] };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { kind: null, reason: 'protocol_not_allowed', warnings: [] };
  }

  const host = url.hostname.toLowerCase();
  const allowlist = (process.env[ALLOWLIST_ENV] || '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (allowlist.length > 0 && !allowlist.includes(host)) {
    return { kind: null, reason: 'host_not_allowlisted', host, warnings: [] };
  }

  const warnings = [];
  if (allowlist.length === 0) {
    warnings.push(
      `${ALLOWLIST_ENV} 未配置：审计锚点将发往任意主机 ${host}（建议显式声明，防止拼错域名把锚点发给陌生地址）`
    );
  }
  return { kind: 'http', url: text, host, warnings };
}

/** 带绝对截止与结算守卫的 JSON GET（理由同 utils/httpPostJson 的 B-M2 注释）。 */
function httpGetJson(rawUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(rawUrl);
    } catch (err) {
      reject(new Error(`URL 无法解析：${err.message}`));
      return;
    }

    let settled = false;
    let deadline = null;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      if (deadline) clearTimeout(deadline);
      fn(value);
    };

    const mod = target.protocol === 'https:' ? https : http;
    const req = mod.request(
      target,
      { method: 'GET', headers: { Accept: 'application/json' }, timeout: timeoutMs },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on('error', (err) => settle(reject, err));
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_ANCHOR_RESPONSE_BYTES) {
            settle(reject, new Error(`锚点存储响应体超过 ${MAX_ANCHOR_RESPONSE_BYTES} 字节上限`));
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () =>
          settle(resolve, {
            status: res.statusCode || 0,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        );
      }
    );
    req.on('error', (err) => settle(reject, err));
    req.on('timeout', () => {
      const err = new Error(`请求超时 ${timeoutMs}ms`);
      settle(reject, err);
      req.destroy(err);
    });
    deadline = setTimeout(() => {
      const err = new Error(`请求截止 ${timeoutMs}ms 内未完成`);
      settle(reject, err);
      try {
        req.destroy(err);
      } catch (_) {
        /* 已销毁则忽略 */
      }
    }, timeoutMs);
    if (deadline.unref) deadline.unref();
    req.end();
  });
}

/**
 * 读回外部锚点副本。
 *
 * 每种失败都独立编码，**不折叠成「空列表」**：空列表在比对侧等于「外部没有东西」，
 * 而「存储坏了」与「存储里确实没东西」是两件完全不同的事——前者必须判「判据不可用」，
 * 后者才是 no_external_anchors。
 *
 * @returns {Promise<{ok: boolean, present?: boolean, anchors: object[], error?: string, detail?: string}>}
 */
async function readAnchorStore(sink, { timeoutMs = DEFAULT_ANCHOR_TIMEOUT_MS } = {}) {
  if (!sink || !sink.kind) {
    return { ok: false, error: 'sink_not_configured', anchors: [] };
  }

  if (sink.kind === 'file') {
    if (!fs.existsSync(sink.path)) return { ok: true, present: false, anchors: [] };
    try {
      return { ok: true, present: true, anchors: readCheckpoints(sink.path).map((e) => e.record) };
    } catch (err) {
      return { ok: false, error: 'anchor_store_malformed', detail: err.message, anchors: [] };
    }
  }

  let response;
  try {
    response = await httpGetJson(sink.url, timeoutMs);
  } catch (err) {
    return { ok: false, error: 'anchor_store_unreachable', detail: err.message, anchors: [] };
  }
  // 404 = 存储还没建（首次 ship 之前）⇒ 空存储，不是故障。
  if (response.status === 404) return { ok: true, present: false, anchors: [] };
  if (response.status < 200 || response.status >= 300) {
    return {
      ok: false,
      error: 'anchor_store_http_error',
      detail: `HTTP ${response.status}`,
      anchors: [],
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(response.body);
  } catch (err) {
    return { ok: false, error: 'anchor_store_not_json', detail: err.message, anchors: [] };
  }
  // 形状校验：`{}` 必须判错而不是被当成「零个锚点」。后者会让 verify 在
  // 「存储返回了看不懂的东西」时判 PASS —— 这正是要禁止的静默通过。
  if (!parsed || !Array.isArray(parsed.anchors)) {
    return {
      ok: false,
      error: 'anchor_store_bad_shape',
      detail: '响应缺少 anchors 数组',
      anchors: [],
    };
  }
  return { ok: true, present: true, anchors: parsed.anchors };
}

/**
 * 追加到外部锚点存储（只追加，不删除、不覆盖）。
 *
 * @param {object} sink resolveSink 的结果
 * @param {object[]} records 待追加的检查点记录
 * @returns {Promise<{ok: boolean, accepted: number, error?: string, detail?: string}>}
 */
async function appendToAnchorStore(sink, records, { timeoutMs = DEFAULT_ANCHOR_TIMEOUT_MS } = {}) {
  if (!Array.isArray(records) || records.length === 0) return { ok: true, accepted: 0 };

  if (sink.kind === 'file') {
    // 文件 sink 的幂等由这里负责（http sink 由接收端负责）：
    // 并发跑两个 ship 时差集计算会重叠，落两行重复锚点。比对按 signature 集合做，
    // 判定不受影响，但重复行会让 WORM 文件无谓增长，顺手去重。
    let known = new Set();
    if (fs.existsSync(sink.path)) {
      try {
        known = new Set(readCheckpoints(sink.path).map((e) => e.record.signature));
      } catch (err) {
        return { ok: false, accepted: 0, error: 'anchor_store_malformed', detail: err.message };
      }
    }
    const fresh = records.filter((record) => !known.has(record.signature));
    if (fresh.length === 0) return { ok: true, accepted: 0 };
    fs.mkdirSync(path.dirname(sink.path), { recursive: true, mode: 0o700 });
    fs.appendFileSync(sink.path, fresh.map((r) => `${JSON.stringify(r)}\n`).join(''), {
      mode: 0o600,
    });
    return { ok: true, accepted: fresh.length };
  }

  const { postJson } = require('../utils/httpPostJson');
  const body = JSON.stringify({ anchorVersion: ANCHOR_PAYLOAD_VERSION, anchors: records });
  let response;
  try {
    response = await postJson(sink.url, {}, body, timeoutMs);
  } catch (err) {
    return { ok: false, accepted: 0, error: 'anchor_store_unreachable', detail: err.message };
  }
  if (!response.ok) {
    return {
      ok: false,
      accepted: 0,
      error: 'anchor_store_http_error',
      detail: `HTTP ${response.status}`,
    };
  }
  return { ok: true, accepted: records.length };
}

/**
 * 把本地检查点外发到锚点存储（幂等：只发存储里还没有的那些）。
 *
 * 【只外发能验过签名的锚点】
 * 顺序不能反。先 ship 再验签的话，一条被篡改过的检查点会被推进 append-only 存储，
 * 而 WORM 里**删不掉**——之后每一次核验都要面对这条伪造锚点。所以这里宁可整体拒绝
 * 外发并列出出错行号，也不做「跳过坏行继续发」：后者等于让攻击者用一行垃圾永久
 * 阻断（或永久污染）锚点链，且现场看起来只是「有几行怪怪的」。
 *
 * @param {{filePath?: string, sink?: object, secret?: string, timeoutMs?: number}} [options]
 * @returns {Promise<{ok: boolean, shipped: number, alreadyAnchored: number, pending: number,
 *   invalid: Array<{line:number, headId:string|null, createdAt:string}>, error?: string,
 *   detail?: string, warnings: string[]}>}
 */
async function shipCheckpoints({ filePath, sink, secret, timeoutMs } = {}) {
  const resolved = sink === undefined ? resolveSink() : sink;
  const warnings = (resolved && resolved.warnings) || [];
  const base = { shipped: 0, alreadyAnchored: 0, pending: 0, invalid: [], warnings };

  if (!resolved || !resolved.kind) {
    return {
      ...base,
      ok: false,
      error: 'sink_not_configured',
      detail: resolved && resolved.reason,
    };
  }
  const hmacSecret = hmacSecretOf(secret);
  if (!hmacSecret) return { ...base, ok: false, error: 'hmac_not_configured' };

  let entries;
  try {
    entries = readCheckpoints(filePath);
  } catch (err) {
    return { ...base, ok: false, error: 'file_unreadable', detail: err.message };
  }
  if (entries.length === 0) return { ...base, ok: true };

  const valid = [];
  const invalid = [];
  for (const { line, record } of entries) {
    const signatureOk = record && record.signature === signCheckpoint(record, hmacSecret);
    if (signatureOk && record.version === CHECKPOINT_VERSION) {
      valid.push(record);
    } else {
      invalid.push({
        line,
        headId: record ? record.headId : null,
        createdAt: record && record.createdAt,
      });
    }
  }
  if (invalid.length > 0) {
    return {
      ...base,
      ok: false,
      error: 'local_checkpoint_invalid',
      invalid,
      pending: valid.length,
    };
  }

  const store = await readAnchorStore(resolved, { timeoutMs });
  if (!store.ok) {
    return { ...base, ok: false, error: store.error, detail: store.detail, pending: valid.length };
  }

  const anchored = new Set(
    store.anchors.map((record) => record && record.signature).filter(Boolean)
  );
  const diff = valid.filter((record) => !anchored.has(record.signature));
  if (diff.length === 0) {
    return { ...base, ok: true, alreadyAnchored: valid.length };
  }

  const appended = await appendToAnchorStore(resolved, diff, { timeoutMs });
  if (!appended.ok) {
    return {
      ...base,
      ok: false,
      error: appended.error,
      detail: appended.detail,
      alreadyAnchored: valid.length - diff.length,
      pending: diff.length,
    };
  }
  return {
    ...base,
    ok: true,
    shipped: appended.accepted,
    alreadyAnchored: valid.length - diff.length,
  };
}

module.exports = {
  ANCHOR_PAYLOAD_VERSION,
  SINK_ENV,
  ALLOWLIST_ENV,
  DEFAULT_ANCHOR_TIMEOUT_MS,
  resolveSink,
  readAnchorStore,
  appendToAnchorStore,
  shipCheckpoints,
};
