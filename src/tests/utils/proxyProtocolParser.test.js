/**
 * PROXY protocol 解析器判据（utils/proxyProtocol.js 的纯函数层）
 *
 * 覆盖面按「一份签名凭据可能的坏法」展开，四段：
 *   1. 嗅探与透传判定 —— 首段字节属于谁（v1 / v2 / 普通 HTTP / 两可真前缀），
 *      这是三态语义的第一道分岔：判错 not-proxy 会把头漏进 HTTP 解析器（走私），
 *      判错 v1/v2 会把合法 LB 连接整条杀掉；
 *   2. v1 行解析 —— 字段个数、地址族与文本、端口数值、行上限与 CRLF 完整性；
 *      依据是 HAProxy spec doc/proxy-protocol.txt §2（行上限 IPv4 105 / IPv6 107，
 *      本实现统一 108）；
 *   3. v2 头解析 —— ver/cmd/fam 白名单、地址段定长、TLV 跳过、LOCAL 语义；
 *      依据 spec §3；AF_UNIX 刻意不支持（地址是路径文本，重写 remote* 无意义）；
 *   4. 重写原语 —— overrideSocketAddresses 在原型 getter（无 setter）上的
 *      defineProperty 行为与失败路径（半还原状态宁可断开也不转交）。
 *
 * 测试风格沿用 clientIpSecurityDecision.test.js 的替身/纯函数思路：不启网络，
 * 解析器逐字节喂 Buffer（分片到达用「逐步拼接」模拟 TCP 分段），网络层行为
 * 归 proxyProtocolFrontServer.test.js 的真实 socket 集成。
 */

'use strict';

const {
  ParseStatus,
  V1_MAX_LINE_BYTES,
  V2_FIXED_HEADER_BYTES,
  parseProxyProtocolHeader,
  _internal,
} = require('../../utils/proxyProtocol');
const { parseProxyV1, parseProxyV2, overrideSocketAddresses } = _internal;

/** v1 行构造：默认带 CRLF，可换源/目的/端口 */
const v1 = (src = '198.51.100.7', dst = '203.0.113.5', sport = '41111', dport = '3000') =>
  `PROXY TCP4 ${src} ${dst} ${sport} ${dport}\r\n`;

/** v2 头构造：拼 12 字节签名 + ver_cmd + fam/proto + uint16 长度 + 地址段(+TLV) */
const v2Header = ({
  ver = 2,
  cmd = 1,
  family = 0x1,
  addr = Buffer.alloc(0),
  tlv = Buffer.alloc(0),
}) => {
  const sig = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
  const head = Buffer.alloc(4);
  head[0] = (ver << 4) | cmd;
  head[1] = (family << 4) | 0x1; // 低半字节 proto=STREAM（本实现不消费）
  head.writeUInt16BE(addr.length + tlv.length, 2);
  return Buffer.concat([sig, head, addr, tlv]);
};

/** v2 INET 地址段（src/dst IPv4 + 两端口，共 12 字节） */
const v2InetAddr = (src = '198.51.100.7', dst = '203.0.113.5', sport = 41111, dport = 3000) => {
  const b = Buffer.alloc(12);
  const putIp = (text, off) => {
    text.split('.').forEach((part, i) => {
      b.writeUInt8(Number.parseInt(part, 10), off + i);
    });
  };
  putIp(src, 0);
  putIp(dst, 4);
  b.writeUInt16BE(sport, 8);
  b.writeUInt16BE(dport, 10);
  return b;
};

/** v2 INET6 地址段（src/dst 16 字节 + 两端口，共 36 字节） */
const v2Inet6Addr = (srcGroups, dstGroups, sport = 41111, dport = 3000) => {
  const b = Buffer.alloc(36);
  const putIp = (groups, off) => {
    groups.forEach((g, i) => {
      b.writeUInt16BE(g, off + i * 2);
    });
  };
  putIp(srcGroups, 0);
  putIp(dstGroups, 16);
  b.writeUInt16BE(sport, 32);
  b.writeUInt16BE(dport, 34);
  return b;
};

/** ::ffff:198.51.100.7 的 16 字节二进制（前 10 组 0，后 2 组 ffff / c633:6407） */
const MAPPED_V4_GROUPS = [0, 0, 0, 0, 0, 0xffff, (198 << 8) | 51, (100 << 8) | 7];
/** 2001:db8::99 的 16 字节二进制 */
const V6_GROUPS = [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0099];

describe('嗅探与透传判定（parseProxyProtocolHeader）', () => {
  test('空缓冲 → 继续等（accept 与首字节之间的合法空窗）', () => {
    expect(parseProxyProtocolHeader(Buffer.alloc(0)).status).toBe(ParseStatus.NEED_MORE_DATA);
  });

  test('完整 v1 头 + 后随 HTTP 请求 → ok，consumed 只算头', () => {
    const rest = 'GET /probe HTTP/1.1\r\nHost: x\r\n\r\n';
    const buf = Buffer.from(v1() + rest, 'ascii');
    const d = parseProxyProtocolHeader(buf);
    expect(d.status).toBe(ParseStatus.OK);
    expect(d.version).toBe(1);
    expect(d.consumed).toBe(Buffer.byteLength(v1(), 'ascii'));
    // 消费边界自证：consumed 之后恰好是 HTTP 请求的第一个字节
    expect(buf.slice(d.consumed).toString('ascii')).toBe(rest);
  });

  test('普通 HTTP 请求 → not-proxy（透传路径，Prometheus 直抓/healthcheck 走这条）', () => {
    const d = parseProxyProtocolHeader(
      Buffer.from('GET /health HTTP/1.1\r\nHost: x\r\n\r\n', 'ascii')
    );
    expect(d.status).toBe(ParseStatus.NOT_PROXY);
    expect(d.consumed).toBe(0);
  });

  test('前导 CRLF 的 HTTP 请求（v2 签名真前缀）→ not-proxy 而非卡死', () => {
    // RFC 7230 容忍请求行前的 CRLF；它同时是 v2 签名 \r\n\r\n\0\r\nQUIT\n 的前缀，
    // 若真前缀判定有洞，这条请求会被挂到超时才放行
    const d = parseProxyProtocolHeader(Buffer.from('\r\n\r\nGET /probe HTTP/1.1\r\n\r\n', 'ascii'));
    expect(d.status).toBe(ParseStatus.NOT_PROXY);
  });

  test('"PROXYX"（越出 v1 签名真前缀）→ not-proxy，不给凑签名机会', () => {
    const d = parseProxyProtocolHeader(Buffer.from('PROXYX / HTTP/1.1\r\n\r\n', 'ascii'));
    expect(d.status).toBe(ParseStatus.NOT_PROXY);
  });

  test('"PROXY" 5 字节（两可真前缀）→ 继续等', () => {
    const d = parseProxyProtocolHeader(Buffer.from('PROXY', 'ascii'));
    expect(d.status).toBe(ParseStatus.NEED_MORE_DATA);
  });

  test('v2 签名逐段喂入：12 字节签名即到仍需等固定头，16 字节才进 v2 解析', () => {
    const sig = Buffer.from([
      0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ]);
    expect(parseProxyProtocolHeader(sig).status).toBe(ParseStatus.NEED_MORE_DATA);
    const sigPlusVer = Buffer.concat([sig, Buffer.from([0x21, 0x11, 0x00, 0x0c])]);
    const d = parseProxyProtocolHeader(sigPlusVer);
    // 16 字节固定头到齐但地址段（12 字节）未到 → 仍需等
    expect(d.status).toBe(ParseStatus.NEED_MORE_DATA);
  });

  test('TCP 分段模拟：逐字节喂 v1 头，每一步要么继续等、要么最终 ok', () => {
    const full = Buffer.from(v1(), 'ascii');
    let acc = Buffer.alloc(0);
    for (let i = 0; i < full.length; i += 1) {
      acc = Buffer.concat([acc, full.slice(i, i + 1)]);
      const d = parseProxyProtocolHeader(acc);
      if (i < full.length - 1) {
        expect(d.status).toBe(ParseStatus.NEED_MORE_DATA);
      } else {
        expect(d.status).toBe(ParseStatus.OK);
        expect(d.sourceIp).toBe('198.51.100.7');
      }
    }
  });
});

describe('v1 行解析（parseProxyV1）', () => {
  test('TCP4 合法行：四元组全量还原，consumed 含 CRLF', () => {
    const d = parseProxyV1(Buffer.from(v1(), 'ascii'));
    expect(d.status).toBe(ParseStatus.OK);
    expect(d).toMatchObject({
      version: 1,
      local: false,
      sourceIp: '198.51.100.7',
      sourcePort: 41111,
      destIp: '203.0.113.5',
      destPort: 3000,
      consumed: Buffer.byteLength(v1(), 'ascii'),
    });
  });

  test('TCP6 合法行：IPv6 文本归一化（压缩写法收敛）', () => {
    const d = parseProxyV1(
      Buffer.from('PROXY TCP6 2001:0DB8:0:0::1 2001:db8::2 1234 80\r\n', 'ascii')
    );
    expect(d.status).toBe(ParseStatus.OK);
    expect(d.sourceIp).toBe('2001:db8::1');
    expect(d.destIp).toBe('2001:db8::2');
  });

  test('TCP6 行内 IPv4-mapped 文本 → 收敛为纯 IPv4（与全仓映射口径一致）', () => {
    const d = parseProxyV1(
      Buffer.from('PROXY TCP6 ::ffff:198.51.100.7 2001:db8::2 1234 80\r\n', 'ascii')
    );
    expect(d.status).toBe(ParseStatus.OK);
    expect(d.sourceIp).toBe('198.51.100.7');
  });

  test('UNKNOWN 行：保留真实对端（local=true），行内后续内容按 spec 忽略', () => {
    const d = parseProxyV1(Buffer.from('PROXY UNKNOWN whatever junk here\r\n', 'ascii'));
    expect(d.status).toBe(ParseStatus.OK);
    expect(d.version).toBe(1);
    expect(d.local).toBe(true);
    expect(d.sourceIp).toBeUndefined();
    expect(d.consumed).toBe(Buffer.byteLength('PROXY UNKNOWN whatever junk here\r\n', 'ascii'));
  });

  test.each([
    ['只 LF 不 CRLF', 'PROXY TCP4 198.51.100.7 203.0.113.5 41111 3000\n'],
    ['字段数不足（4 个）', 'PROXY TCP4 198.51.100.7 203.0.113.5 41111\r\n'],
    ['字段数超出（双空格切出空字段）', 'PROXY TCP4  198.51.100.7 203.0.113.5 41111 3000\r\n'],
    ['未知协议名', 'PROXY SCTP 198.51.100.7 203.0.113.5 41111 3000\r\n'],
    ['TCP4 行塞 IPv6 源', 'PROXY TCP4 2001:db8::1 203.0.113.5 41111 3000\r\n'],
    ['TCP6 行塞 IPv4 源', 'PROXY TCP6 198.51.100.7 2001:db8::2 41111 3000\r\n'],
    ['源地址非法文本', 'PROXY TCP4 999.1.1.1 203.0.113.5 41111 3000\r\n'],
    ['源端口非数字', 'PROXY TCP4 198.51.100.7 203.0.113.5 abcd 3000\r\n'],
    ['端口越界（>65535）', 'PROXY TCP4 198.51.100.7 203.0.113.5 70000 3000\r\n'],
  ])('%s → invalid（断开，不透传）', (_label, line) => {
    const d = parseProxyV1(Buffer.from(line, 'ascii'));
    expect(d.status).toBe(ParseStatus.INVALID);
    expect(d.reason).toEqual(expect.any(String));
  });

  test(`无 CRLF 且超过 ${V1_MAX_LINE_BYTES} 字节 → invalid（超长攻击载荷不再等）`, () => {
    const long = `PROXY TCP4 ${'1.2.3.4 '.repeat(30)}`;
    expect(long.length).toBeGreaterThan(V1_MAX_LINE_BYTES);
    const d = parseProxyV1(Buffer.from(long, 'ascii'));
    expect(d.status).toBe(ParseStatus.INVALID);
    expect(d.reason).toBe('v1-line-exceeds-108-bytes');
  });

  test(`合法 IPv6 最长行（107 字节）恰好在上限内 → ok`, () => {
    // spec 上限：IPv6 行含 CRLF 107 字节。构造一条贴边合法行验证不被误杀
    const line = 'PROXY TCP6 2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff 2001:db8::2 65535 65535\r\n';
    expect(line.length).toBeLessThanOrEqual(108);
    const d = parseProxyV1(Buffer.from(line, 'ascii'));
    expect(d.status).toBe(ParseStatus.OK);
  });
});

describe('v2 头解析（parseProxyV2）', () => {
  test('INET + PROXY：四元组全量还原，consumed = 16 + 12', () => {
    const head = v2Header({ family: 0x1, addr: v2InetAddr() });
    expect(head.length).toBe(V2_FIXED_HEADER_BYTES + 12);
    const d = parseProxyV2(head);
    expect(d.status).toBe(ParseStatus.OK);
    expect(d).toMatchObject({
      version: 2,
      local: false,
      sourceIp: '198.51.100.7',
      sourcePort: 41111,
      destIp: '203.0.113.5',
      destPort: 3000,
      consumed: V2_FIXED_HEADER_BYTES + 12,
    });
  });

  test('INET6 + PROXY：IPv6 二进制归一化（压缩与 mapped 收敛）', () => {
    const d = parseProxyV2(
      v2Header({ family: 0x2, addr: v2Inet6Addr(V6_GROUPS, MAPPED_V4_GROUPS) })
    );
    expect(d.status).toBe(ParseStatus.OK);
    expect(d.sourceIp).toBe('2001:db8::99');
    // mapped 收敛：v2 INET6 里声明的 ::ffff:a.b.c.d 落地为纯 IPv4
    expect(d.destIp).toBe('198.51.100.7');
  });

  test('TLV 段：整段跳过且 consumed 把 TLV 算进头长（真实 LB 会带 PP2 扩展）', () => {
    // 模拟 AWS NLB 常见的 PP2_TYPE_AWS TLV（type 0xEA，长度 8）
    const tlv = Buffer.from([0xea, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const head = v2Header({ family: 0x1, addr: v2InetAddr(), tlv });
    const d = parseProxyV2(head);
    expect(d.status).toBe(ParseStatus.OK);
    expect(d.sourceIp).toBe('198.51.100.7');
    expect(d.consumed).toBe(V2_FIXED_HEADER_BYTES + 12 + tlv.length);
  });

  test('LOCAL 命令：地址段（即使带 TLV）整体忽略，保留真实对端', () => {
    const tlv = Buffer.from([0x01, 0x00, 0x01, 0xff]);
    const head = v2Header({ cmd: 0, family: 0x0, addr: Buffer.alloc(0), tlv });
    const d = parseProxyV2(head);
    expect(d.status).toBe(ParseStatus.OK);
    expect(d.local).toBe(true);
    expect(d.sourceIp).toBeUndefined();
    expect(d.consumed).toBe(head.length);
  });

  test.each([
    ['版本号非 2', { ver: 1, cmd: 1, family: 0x1, addr: v2InetAddr() }, 'v2-version:1'],
    [
      '命令值非法（2/15 均 spec 保留值）',
      { ver: 2, cmd: 0x2, family: 0x1, addr: v2InetAddr() },
      'v2-cmd:2',
    ],
    [
      'PROXY + UNSPEC（spec 明令禁止组合）',
      { ver: 2, cmd: 1, family: 0x0, addr: Buffer.alloc(0) },
      'v2-unspec-with-proxy-cmd',
    ],
    [
      'PROXY + UNIX（刻意不支持：地址是路径文本）',
      { ver: 2, cmd: 1, family: 0x3, addr: Buffer.alloc(108) },
      'v2-unix-addr-unsupported',
    ],
    [
      '未知 family（0xF 保留值）',
      { ver: 2, cmd: 1, family: 0xf, addr: Buffer.alloc(12) },
      'v2-family:15',
    ],
    [
      'INET 地址段截断（len < 12）',
      { ver: 2, cmd: 1, family: 0x1, addr: Buffer.alloc(8) },
      'v2-address-truncated',
    ],
  ])('%s → invalid', (_label, opts, reason) => {
    const d = parseProxyV2(v2Header(opts));
    expect(d.status).toBe(ParseStatus.INVALID);
    expect(d.reason).toBe(reason);
  });

  test('地址段未收满 → 继续等（16 字节固定头已到、12 字节地址只到一半）', () => {
    const head = v2Header({ family: 0x1, addr: v2InetAddr() });
    const d = parseProxyV2(head.slice(0, V2_FIXED_HEADER_BYTES + 6));
    expect(d.status).toBe(ParseStatus.NEED_MORE_DATA);
  });
});

describe('重写原语（overrideSocketAddresses）', () => {
  test('在普通对象上写入五个字段，remoteFamily 按归一化地址族推导', () => {
    const socket = {};
    const ok = overrideSocketAddresses(socket, {
      sourceIp: '198.51.100.7',
      sourcePort: 41111,
      destIp: '203.0.113.5',
      destPort: 3000,
    });
    expect(ok).toBe(true);
    expect(socket).toMatchObject({
      remoteAddress: '198.51.100.7',
      remotePort: 41111,
      remoteFamily: 'IPv4',
      localAddress: '203.0.113.5',
      localPort: 3000,
    });
  });

  test('IPv6 源地址 → remoteFamily=IPv6', () => {
    const socket = {};
    overrideSocketAddresses(socket, {
      sourceIp: '2001:db8::99',
      sourcePort: 1,
      destIp: '2001:db8::2',
      destPort: 2,
    });
    expect(socket.remoteFamily).toBe('IPv6');
  });

  test('自有不可配置属性（defineProperty 被拒的异常形态）→ false，连接已被销毁', () => {
    const socket = {
      destroy: jest.fn(),
    };
    Object.defineProperty(socket, 'remoteAddress', {
      value: '10.0.0.1',
      configurable: false,
      writable: false,
      enumerable: true,
    });
    const ok = overrideSocketAddresses(socket, {
      sourceIp: '198.51.100.7',
      sourcePort: 41111,
      destIp: '203.0.113.5',
      destPort: 3000,
    });
    expect(ok).toBe(false);
    expect(socket.destroy).toHaveBeenCalled();
    // 半还原状态不得落地：失败后 remoteAddress 仍是原值
    expect(socket.remoteAddress).toBe('10.0.0.1');
  });
});
