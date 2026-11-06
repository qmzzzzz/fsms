// L4 客户端地址还原的部署与协议论证见 ADR-021；这里只保留连接层约束。
// 在 HTTP 解析前重写 socket 地址，HTTP、WS、审计和安全判据才能共享同一来源。
// PROXY 头有权改写地址：必须用原始对端与 TRUSTED_PROXY_CIDRS 判信任，不能信头内声明。
// 无签名原样透传以兼容直连探活；畸形头或未信任对端发头必须断开，不能忽略后继续解析。
// 名单非法时全部拒绝；未配置时只信回环，生产启用由配置闸强制要求显式名单。
// 仅支持明文内层 HTTP：TLSSocket 从句柄读取，无法消费 unshift 的握手字节，会永久悬挂。
// TLS 应由 LB 或宿主 nginx 终结/消费 PROXY 头；不得把本前置层接到进程内 HTTPS。
// 前置层持有 accept 权，避免与 HTTP 内部 connection 监听器抢首段数据。
// 前置层负责 listen/error/停 accept；内层负责 WS 与 HTTP 连接清理，两层登记同一 socket。
// connection 回调同步挂 data；不使用 pauseOnConnect/pause，避免交接后连接不再流动。
// 摘 data → unshift 剩余字节 → emit 必须同步完成，防止丢字节或重复消费头。
// 本模块不读环境或写日志/指标；index.js 注入 onRejection，留痕失败不得改变断开动作。

'use strict';

const net = require('net');

const { isPeerTrustedProxy, normalizeIP, parseIP } = require('./ipUtils');

/** PROXY protocol v1 文本签名（"PROXY "，6 字节） */
const V1_SIGNATURE = Buffer.from('PROXY ', 'ascii');
/** PROXY protocol v2 二进制签名（spec §3：12 字节，内容为 \r\n\r\n\0\r\nQUIT\n） */
const V2_SIGNATURE = Buffer.from([
  0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
]);

/**
 * v1 整行（含 CRLF）字节上限。spec 对 IPv4 行给的是 105、IPv6 行 107；
 * 统一取 108：既覆盖最长合法行，又保证「超长即拒」的判定窗口足够小，
 * 不会给慢速攻击者一条 64KB 的行缓冲。改小会拒掉合法 IPv6 行，改大扩攻击面。
 */
const V1_MAX_LINE_BYTES = 108;

/** v2 固定头长：12 字节签名 + ver_cmd(1) + fam(1) + len(2) */
const V2_FIXED_HEADER_BYTES = 16;
/** v2 地址+TLV 段上限：spec 的 uint16 长度天然有界，绝对上限 = 16 + 65535 */
const V2_MAX_TOTAL_BYTES = V2_FIXED_HEADER_BYTES + 0xffff;

/**
 * 两签名中较长者（v2 的 12 字节）：「完全不是 PROXY 头」的最长判定窗口。
 * 少于该长度且仍是某签名的**真前缀**时必须继续等（首段常被 TCP 分段拆开）；
 * 一旦越出真前缀，立即判 not-proxy，不给等待窗口留悬挂连接。
 * （刻意**不**用 16 字节当嗅探窗口：HTTP 请求可能短于 16 字节，判定只依赖签名。）
 */
const SNIFF_LIMIT_BYTES = Math.max(V1_SIGNATURE.length, V2_SIGNATURE.length);

/**
 * 头阶段默认超时（毫秒）：从 accept 到「透传判定完成或头解析完成」的硬上限。
 * 设计对照：内层 headersTimeout=85s 是慢速 loris 的 HTTP 层防线，但它的计时起点
 * 在解析器收到首字节之后；头阶段在这之前，若不另设上限，「连接了但不发完整头」
 * 就是一条永远挂着的 socket。10s 对真实 LB 绰绰有余（头在首字节包里），
 * 对健康检查（连了不发/发了就关）也足够宽。超时**不进安全计数**：
 * 它的成因大多是探活与扫描，逐条告警会把 security_alerts_total 刷成扫描器账本。
 */
const DEFAULT_HEADER_TIMEOUT_MS = 10_000;

/** 判定结果的四种状态（parseProxyProtocolHeader 的返回契约，测试逐格钉） */
const ParseStatus = {
  /** 首段尚不足以判定：仍是某签名的真前缀，或 v1 行/v2 段还没收满 */
  NEED_MORE_DATA: 'need-more-data',
  /** 确定不是 PROXY 头：透传（整个缓冲原样退还给连接） */
  NOT_PROXY: 'not-proxy',
  /** 合法的 v1/v2 头：携带还原四元组与应消费的字节数 */
  OK: 'ok',
  /** 签名成立但内容非法：断开连接（对端可信与否只影响留痕口径，不影响走向） */
  INVALID: 'invalid',
};

/** v1 地址族 → 期望的 IP 版本（parseIP 后按 kind 复核，防 TCP4 塞 IPv6 文本） */
const V1_PROTO_KINDS = { TCP4: 'ipv4', TCP6: 'ipv6' };

/** v2 ver_cmd 字节：高半字节版本号，低半字节命令（LOCAL=0 / PROXY=1） */
const V2_VERSION = 2;
const V2_CMD = { LOCAL: 0x0, PROXY: 0x1 };
/** v2 fam 字节高半字节的 family 白名单（低半字节为传输协议，STREAM/DGRAM 均收） */
const V2_FAMILY = { UNSPEC: 0x0, INET: 0x1, INET6: 0x2, UNIX: 0x3 };
/** PROXY 命令下各 family 的地址段长度（含 src/dst 地址与 sport/dport 各 2 字节） */
const V2_PROXY_ADDR_BYTES = { [V2_FAMILY.INET]: 12, [V2_FAMILY.INET6]: 36 };

/**
 * 16 字节以内把 IPv6 二进制转成八组十六进制的全写法文本（按 uint16 逐组读取），
 * 交给 normalizeIP 收敛（它同时完成 RFC5952 压缩与 IPv4-mapped ::ffff:a.b.c.d →
 * 纯 IPv4 的口径统一，与 v1/HTTP 侧的地址形态同源，避免引入对 ipaddr 的第二个
 * 直接依赖点）。
 */
const ipv6BytesToText = (buf, offset) => {
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(buf.readUInt16BE(offset + i).toString(16));
  }
  return groups.join(':');
};

/**
 * v1 TCP4/TCP6 行的字段复核（parseProxyV1 的复杂度拆分，只管带地址的两种协议）。
 * 三组判据独立：字段个数、地址形态与族别、端口数值——全部通过才产出四元组。
 * 返回契约与解析器一致（ok / invalid）。
 */
function parseV1AddressedFields(fields) {
  const [proto, srcText, dstText, sportText, dportText] = fields;
  const expectKind = V1_PROTO_KINDS[proto];
  if (!expectKind) {
    return { status: ParseStatus.INVALID, reason: `v1-unknown-proto:${proto}` };
  }
  if (fields.length !== 5) {
    return { status: ParseStatus.INVALID, reason: `v1-field-count:${fields.length}` };
  }
  // 地址形态复核：parseIP 解析不出（或歧义写法）即拒；族别不符（TCP4 塞 IPv6）即拒
  const src = parseIP(srcText);
  const dst = parseIP(dstText);
  if (!src || src.kind() !== expectKind) {
    return { status: ParseStatus.INVALID, reason: `v1-src-not-${proto}` };
  }
  if (!dst || dst.kind() !== expectKind) {
    return { status: ParseStatus.INVALID, reason: `v1-dst-not-${proto}` };
  }
  if (!/^\d{1,5}$/.test(sportText) || !/^\d{1,5}$/.test(dportText)) {
    return { status: ParseStatus.INVALID, reason: 'v1-port-not-numeric' };
  }
  const sourcePort = Number.parseInt(sportText, 10);
  const destPort = Number.parseInt(dportText, 10);
  if (sourcePort > 0xffff || destPort > 0xffff) {
    return { status: ParseStatus.INVALID, reason: 'v1-port-out-of-range' };
  }
  const sourceIp = normalizeIP(srcText);
  const destIp = normalizeIP(dstText);
  if (!sourceIp || !destIp) {
    // normalizeIP 对上面 parseIP 已放行的地址恒成功；null 只会出现在「判据与归一化口径漂移」的实现错误里，按畸形拒并留可定位的原因
    return { status: ParseStatus.INVALID, reason: 'v1-address-normalize-failed' };
  }
  return {
    status: ParseStatus.OK,
    version: 1,
    local: false,
    sourceIp,
    sourcePort,
    destIp,
    destPort,
  };
}

/**
 * PROXY protocol v1 行解析（纯函数）。返回契约见 ParseStatus；
 * consumed = 头总长（含 CRLF），need-more-data/not-proxy 时为 0。
 *
 * 严格性取向：字段个数、地址族与文本形态、端口数值全部复核后才认账 ——
 * 头是「重写地面真相」的凭据，宽松解析等于允许名单内对端（或被攻破的 LB）
 * 塞进任何文本。CRLF 必须成对出现：只收到 LF（老实现/手写客户端）按畸形拒 ——
 * 头凭据上的宽容没有收益，直连路径的合法流量根本不会进这个分支。
 */
function parseProxyV1(buf) {
  const lineEnd = buf.indexOf(0x0a); // 找行终止符：找不到时按上限判「超长」而不是无限等 —— spec 的合法行 ≤108，收满还没见 CRLF 的只可能是畸形或攻击载荷，没有第三种解释
  if (lineEnd < 0) {
    if (buf.length > V1_MAX_LINE_BYTES) {
      return { status: ParseStatus.INVALID, reason: 'v1-line-exceeds-108-bytes' };
    }
    return { status: ParseStatus.NEED_MORE_DATA };
  }
  if (lineEnd + 1 > V1_MAX_LINE_BYTES) {
    // 行长在已知边界内才做文本校验，杜绝拿攻击载荷做超长 split
    return { status: ParseStatus.INVALID, reason: 'v1-line-exceeds-108-bytes' };
  }
  if (buf[lineEnd - 1] !== 0x0d) {
    return { status: ParseStatus.INVALID, reason: 'v1-line-not-crlf-terminated' };
  }
  const line = buf.slice(0, lineEnd + 1).toString('ascii');
  const consumed = lineEnd + 1;
  // 字段区切到 \r 之前（lineEnd-1）：lineEnd 指向 \n，\r 在其前一位 ——
  // 不排除它会让最后一个端口带上 \r，在端口校验处报出误导性的「非数字」
  // "PROXY " 签名在嗅探阶段已确认，这里不再复核；字段按单空格切，多空格即畸形
  const fields = line.slice(V1_SIGNATURE.length, lineEnd - 1).split(' ');

  if (fields[0] === 'UNKNOWN') {
    // UNKNOWN：spec 规定后续内容必须整体忽略，连接按「无地址信息」处理 —— 保留真实对端（不重写）。健康检查走这条，不能因为字段缺失拒掉
    return { status: ParseStatus.OK, version: 1, local: true, consumed };
  }

  return { ...parseV1AddressedFields(fields), consumed }; // 带地址的两种协议交给字段复核；无论 ok/invalid，consumed 都是整行（含 CRLF）
}

/**
 * v2 PROXY 命令的 family 白名单与地址段提取（parseProxyV2 的复杂度拆分）。
 * 入参的 buf 已保证「总长足够」（调用方按 len 复核过），本函数只管三件事：
 * family 是否可还原、地址段是否够长、按 family 读出四元组并归一化。
 * consumed 不在此处产出（调用方统一补），故返回值不含它。
 */
function parseV2ProxyPayload(buf, family, addrTlvLen) {
  if (family === V2_FAMILY.UNSPEC) {
    // PROXY 命令下的两族禁入：UNSPEC 是 spec 明令禁止的组合；UNIX 的「地址」是路径文本，重写 remote* 无意义且开伪造口子（见本文件头「形态与硬限制」）
    return { status: ParseStatus.INVALID, reason: 'v2-unspec-with-proxy-cmd' };
  }
  if (family === V2_FAMILY.UNIX) {
    return { status: ParseStatus.INVALID, reason: 'v2-unix-addr-unsupported' };
  }
  const addrBytes = V2_PROXY_ADDR_BYTES[family];
  if (!addrBytes) {
    return { status: ParseStatus.INVALID, reason: `v2-family:${family}` };
  }
  if (addrTlvLen < addrBytes) {
    return { status: ParseStatus.INVALID, reason: 'v2-address-truncated' };
  }

  let sourceIp;
  let destIp;
  let sourcePort;
  let destPort;
  if (family === V2_FAMILY.INET) {
    sourceIp = normalizeIP(`${buf[16]}.${buf[17]}.${buf[18]}.${buf[19]}`);
    destIp = normalizeIP(`${buf[20]}.${buf[21]}.${buf[22]}.${buf[23]}`);
    sourcePort = buf.readUInt16BE(24);
    destPort = buf.readUInt16BE(26);
  } else {
    sourceIp = normalizeIP(ipv6BytesToText(buf, 16)); // INET6：src(16B) → dst(16B) → sport(2B) → dport(2B)，TLV 段随 consumed 整体跳过；mapped 形态（::ffff:a.b.c.d）由 normalizeIP 收敛为纯 IPv4
    destIp = normalizeIP(ipv6BytesToText(buf, 32));
    sourcePort = buf.readUInt16BE(48);
    destPort = buf.readUInt16BE(50);
  }
  if (!sourceIp || !destIp) {
    return { status: ParseStatus.INVALID, reason: 'v2-address-normalize-failed' };
  }
  return {
    status: ParseStatus.OK,
    version: 2,
    local: false,
    sourceIp,
    sourcePort,
    destIp,
    destPort,
  };
}

/**
 * PROXY protocol v2 头解析（纯函数）。返回契约与 parseProxyV1 相同。
 *
 * 刻意不支持的输入（都判 invalid 而不是「尽力而为」）：
 *   - 非 2 版本 / 未知命令 / 未知 family：spec 保留值今天没有语义，接受它等于
 *     为未来未定义行为预付信任；
 *   - PROXY 命令 + UNSPEC / UNIX：见 parseV2ProxyPayload 内注释；
 *   - PROXY 命令 + 地址段短于该 family 的固定长度：截断头。
 * TLV 段整段跳过：本功能只消费四元组，不解析 PP2 subtype（安全边界外的元数据
 * 不给信任加码，也不为它承担解析风险）。
 */
function parseProxyV2(buf) {
  if (buf.length < V2_FIXED_HEADER_BYTES) {
    // 固定头 16 字节：签名在嗅探阶段已确认，ver/cmd/fam/len 占 12..15
    return { status: ParseStatus.NEED_MORE_DATA };
  }
  const verCmd = buf[12];
  if (verCmd >> 4 !== V2_VERSION) {
    return { status: ParseStatus.INVALID, reason: `v2-version:${verCmd >> 4}` };
  }
  const cmd = verCmd & 0x0f;
  if (cmd !== V2_CMD.LOCAL && cmd !== V2_CMD.PROXY) {
    return { status: ParseStatus.INVALID, reason: `v2-cmd:${cmd}` };
  }
  const addrTlvLen = buf.readUInt16BE(14);
  const totalNeeded = V2_FIXED_HEADER_BYTES + addrTlvLen;
  if (buf.length < totalNeeded) {
    return { status: ParseStatus.NEED_MORE_DATA };
  }
  const consumed = totalNeeded;

  if (cmd === V2_CMD.LOCAL) {
    // LOCAL：spec 规定地址段无语义（长度可为 0），内容一律忽略、保留真实对端
    return { status: ParseStatus.OK, version: 2, local: true, consumed };
  }

  return { ...parseV2ProxyPayload(buf, buf[13] >> 4, addrTlvLen), consumed }; // PROXY 命令交给 payload 提取；consumed 由本层统一补（payload 不管头长）
}

/**
 * 首段判定入口（纯函数，消费方逐段喂数据直到状态离开 need-more-data）。
 *
 * 嗅探判定的次序是刻意的：v1 签名（"PROXY "）以字母开头、v2 签名以 \r 开头，
 * 两者对任何非空前缀互斥，先比谁都不会误吞对方；真前缀（含 "PROXY" 5 字节这类
 * 两可形态）继续等，越出真前缀（如 `PROXYX`）立即判 not-proxy。
 *
 * @param {Buffer} buf 已收到的首段
 * @returns {{status: string, ...}} 见 ParseStatus 与 parseProxyV1/parseProxyV2
 */
function parseProxyProtocolHeader(buf) {
  if (buf.length === 0) {
    return { status: ParseStatus.NEED_MORE_DATA };
  }
  const v2SigLen = Math.min(buf.length, V2_SIGNATURE.length);
  const v1SigLen = Math.min(buf.length, V1_SIGNATURE.length);
  const isV2SigPrefix = buf.slice(0, v2SigLen).equals(V2_SIGNATURE.slice(0, v2SigLen));
  const isV1SigPrefix = buf.slice(0, v1SigLen).equals(V1_SIGNATURE.slice(0, v1SigLen));
  if (isV2SigPrefix && buf.length < V2_SIGNATURE.length) {
    // 真前缀继续等（此时两签名互斥 ⇒ 至多一臂成立，先后顺序无关）
    return { status: ParseStatus.NEED_MORE_DATA };
  }
  if (isV1SigPrefix && buf.length < V1_SIGNATURE.length) {
    return { status: ParseStatus.NEED_MORE_DATA };
  }
  if (isV2SigPrefix) {
    // 走到这里：buf 至少含一个完整签名。v2 签名 12 字节 > v1 的 6 字节，先判 v2 不会把 v1 连接误送进 v2 解析（前缀互斥保证两者只取其一）
    return parseProxyV2(buf);
  }
  if (isV1SigPrefix) {
    return parseProxyV1(buf);
  }
  return { status: ParseStatus.NOT_PROXY, consumed: 0 };
}

/**
 * 把还原的四元组写进 socket 的 remote* 与 local* 属性。
 *
 * 为什么是 Object.defineProperty 而不是赋值：现代 Node（≥12）把 remoteAddress/
 * remotePort/localAddress/localPort 定义为 **原型上的 lazy getter（无 setter）**，
 * 严格模式下直接赋值会抛 TypeError；在实例上 defineProperty 生成自有数据属性、
 * 影子化原型 getter，读取方（proxy-addr、socket.io、审计）拿到的即重写值。
 * 值全部取自解析结果（normalizeIP 收敛后的规范文本），不透传原始字节文本。
 *
 * @param {import('net').Socket} socket 待重写的连接
 * @param {{sourceIp: string, sourcePort: number, destIp: string, destPort: number}} r
 */
function overrideSocketAddresses(socket, r) {
  const entries = [
    ['remoteAddress', r.sourceIp],
    ['remotePort', r.sourcePort],
    ['remoteFamily', r.sourceIp.includes(':') ? 'IPv6' : 'IPv4'],
    ['localAddress', r.destIp],
    ['localPort', r.destPort],
  ];
  for (const [key, value] of entries) {
    if (value === undefined || value === null) continue;
    try {
      Object.defineProperty(socket, key, {
        value,
        configurable: true,
        writable: true,
        enumerable: true,
      });
    } catch (_err) {
      // 兜底路径仅在「自有属性已存在且不可配置」的异常形态下触发。
      // 改写失败不能让连接悬挂在半还原状态：断开并以 false 告知调用方，
      // 由其跳过后续转交（带着未还原地址进内层 = 冒用失败态的地面真相）
      socket.destroy();
      return false;
    }
  }
  return true;
}

// innerServer 仅接收转交的 HTTP socket，不自行 listen；关停时先停止前置层 accept。
// trustedProxies 为配置模块的解析产物；onRejection 只负责留痕，不得阻断连接清理。
function createProxyProtocolFrontServer(innerServer, options = {}) {
  const trustedProxies = options.trustedProxies;
  const headerTimeoutMs =
    Number.isFinite(options.headerTimeoutMs) && options.headerTimeoutMs > 0
      ? options.headerTimeoutMs
      : DEFAULT_HEADER_TIMEOUT_MS;
  const onRejection = typeof options.onRejection === 'function' ? options.onRejection : null;

  const front = net.createServer((socket) => {
    let settled = false; // 头阶段结束（无论走向）后置 true，各路径据此停手
    let headerBuffer = Buffer.alloc(0);
    let headerTimer = null; // timer 声明先于创建：finishHeaderPhase 的调用方（error 监听器）挂在连接上早于 timer 创建，用 let 占位避免闭包引用落在初始化之前

    const finishHeaderPhase = () => {
      if (!settled) {
        settled = true;
        if (headerTimer) clearTimeout(headerTimer);
      }
    };

    // 头阶段独占的 socket 错误处理：ECONNRESET 等若无人接听会把整个进程打崩
    //（error 事件无监听即 uncaught）。转交内层前必须摘掉 —— 内层对解析错误有
    // 自己的处置（如 clientError 回 400 后再断），我们的 destroy 会抢在它前面，
    // 把「响应错误」降级成「裸断连」
    const onHeaderPhaseError = () => {
      finishHeaderPhase();
      socket.destroy();
    };
    socket.on('error', onHeaderPhaseError);

    headerTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy(); // 超时不进安全计数（见 DEFAULT_HEADER_TIMEOUT_MS 注释）：探活/扫描不值得告警，但必须断开 —— 「等一个永远不来的头」本身就是资源占用
    }, headerTimeoutMs);

    socket.on('close', () => finishHeaderPhase()); // 连接关闭时清 timer：不清理的话每个夭折连接会把 10s timer 挂在事件循环上，扫描器开几百个连接就能把 timer 队列撑成内存账单

    const rejectAndDestroy = (reason) => {
      const peer = String(socket.remoteAddress || '(unknown)');
      finishHeaderPhase();
      socket.destroy();
      if (onRejection) {
        try {
          onRejection({ peer, reason });
        } catch (_err) {
          /* 留痕失败不改变断开动作；错误交由调用方在自己的实现里兜 */
        }
      }
    };

    const onData = (chunk) => {
      if (settled) return; // 超时/错误/关闭竞态后迟到的数据
      headerBuffer = headerBuffer.length === 0 ? chunk : Buffer.concat([headerBuffer, chunk]);
      const decision = parseProxyProtocolHeader(headerBuffer);
      if (decision.status === ParseStatus.NEED_MORE_DATA) {
        if (headerBuffer.length > V2_MAX_TOTAL_BYTES) {
          // 双重保险（belt）：结构性上限（v1 108 / v2 16+65535）已把 need-more 的可能长度封死，这里再拦一次防解析器实现错误把上限打穿
          socket.removeListener('data', onData);
          rejectAndDestroy('header-exceeds-absolute-limit');
        }
        return; // 继续收下一段（受 headerTimer 与上方 belt 双重约束）
      }
      socket.removeListener('data', onData);
      finishHeaderPhase();

      if (decision.status === ParseStatus.NOT_PROXY) {
        // 三态之 1：无签名 ⇒ 原样透传。判定用过的字节全部退还，
        // HTTP/TLS 从第一个字节看到完整的原始流
        socket.unshift(headerBuffer);
        socket.removeListener('error', onHeaderPhaseError);
        innerServer.emit('connection', socket);
        return;
      }
      if (decision.status === ParseStatus.INVALID) {
        // 签名成立但内容非法：无论对端可信与否都断开 —— 头凭据已损坏，
        // 「忽略头继续解析」等于把垃圾字节推给下一个解析器
        rejectAndDestroy(`malformed-header:${decision.reason}`);
        return;
      }

      const peer = String(socket.remoteAddress || ''); // 三态之 2/3：合法头，按对端名单裁决
      if (!isPeerTrustedProxy(peer, trustedProxies)) {
        rejectAndDestroy(`untrusted-peer:${peer}`);
        return;
      }
      if (!decision.local) {
        // 重写失败（defineProperty 被拒的异常形态）时连接已被内部销毁，
        // 不能再把半还原状态的连接转交给内层
        if (!overrideSocketAddresses(socket, decision)) {
          return;
        }
      }
      // 头已消费：只把剩余字节还给流，内层看到的即纯 HTTP/TLS 流。
      // 本地命令（UNKNOWN/LOCAL）不重写 —— spec 语义是「本次连接没有可信的
      // 地址信息可用」，保留真实对端是唯一诚实的做法
      socket.unshift(headerBuffer.slice(decision.consumed));
      socket.removeListener('error', onHeaderPhaseError);
      innerServer.emit('connection', socket);
    };

    socket.on('data', onData);
  });

  return front;
}

module.exports = {
  ParseStatus,
  V1_SIGNATURE,
  V2_SIGNATURE,
  V1_MAX_LINE_BYTES,
  V2_FIXED_HEADER_BYTES,
  V2_MAX_TOTAL_BYTES,
  SNIFF_LIMIT_BYTES,
  DEFAULT_HEADER_TIMEOUT_MS,
  parseProxyProtocolHeader,
  createProxyProtocolFrontServer,
  _internal: { parseProxyV1, parseProxyV2, overrideSocketAddresses }, // 供测试直接钉判据（解析器分步行为与重写原语），不设 re-export 别名，单一出口
};
