/**
 * PROXY protocol 前置服务器接线（utils/proxyProtocol.js 的网络层行为）
 *
 * 解析器判据归 proxyProtocolParser.test.js（纯函数层），本文件用**真实 TCP
 * 连接**钉住工厂与三态语义的走向 —— 这一层的历史坑全部长在流控制与时序上
 * （'data' 监听挂上才 flowing、unshift 的时机、error 监听与内层 400 响应的
 * 竞争），纯函数测试看不见它们：
 *   1. 还原路径：v1/v2 头消费后 req.ip / socket 对端 / 归因分类一致
 *      （本仓信任模型的自洽性是本功能的验收标准，见 utils/proxyProtocol.js 头注）；
 *   2. 透传路径：无签名 HTTP 正常服务（容器网 Prometheus 直抓 /metrics 与
 *      docker healthcheck 依赖这条）；v2 签名真前缀形态（前导 CRLF 请求）不卡死；
 *   3. 拒绝路径：未信任对端发头 → 断开 + onRejection 留痕（index.js 在此接线
 *      incSecurityAlert）；名单内对端发畸形头 → 同样断开但原因不同；
 *   4. 韧性：部分头超时断开（不进计数）、逐字节分片到达、keep-alive 复用、
 *      LOCAL/UNKNOWN 保留真实对端、IPv6 监听。
 *
 * 信任名单用「注入判据对象」模拟不同对端：本机测试永远从 127.0.0.1 发起，
 * 显式注入 10.99.0.0/24 名单即可让回环成为「未信任对端」——判据本体
 * （isPeerTrustedProxy）的真实行为已在 trustedProxyCidrs.test.js 钉过，这里
 * 只消费它的结论。
 */

'use strict';

const http = require('http');
const net = require('net');
const express = require('express');

const { createProxyProtocolFrontServer } = require('../../utils/proxyProtocol');
const { parseTrustedProxyCidrs, toTrustedProxies } = require('../../config/trustedProxies');
const { classifyIpAttribution } = require('../../utils/ipUtils');

const V1_HEADER = 'PROXY TCP4 198.51.100.7 203.0.113.5 41111 3000\r\n';

/** v2 头构造（与 parser 测试同构，这里只为给网络层喂真实字节） */
const v2InetHeader = (src = '198.51.100.7', dst = '203.0.113.5', sport = 41111, dport = 3000) => {
  const sig = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
  const addr = Buffer.alloc(12);
  [src, dst].forEach((text, i) => {
    text.split('.').forEach((part, j) => addr.writeUInt8(Number.parseInt(part, 10), i * 4 + j));
  });
  addr.writeUInt16BE(sport, 8);
  addr.writeUInt16BE(dport, 10);
  const head = Buffer.alloc(4);
  head[0] = 0x21; // ver=2, cmd=PROXY
  head[1] = 0x11; // family=INET, proto=STREAM
  head.writeUInt16BE(addr.length, 2);
  return Buffer.concat([sig, head, addr]);
};

/**
 * 起一个「前置 + 内层 express」探针：/probe 回 JSON（req.ip、socket 对端、归因）。
 * trust proxy 的取值由用例注入（直连形态 false / 经代理形态 1）。
 */
const startProbe = async ({ trustedProxies, headerTimeoutMs, trustProxyHops = false } = {}) => {
  const app = express();
  app.set('trust proxy', trustProxyHops);
  app.disable('x-powered-by');
  app.get('/probe', (req, res) => {
    res.json({
      ip: req.ip,
      peer: req.socket.remoteAddress,
      attribution: classifyIpAttribution(req),
    });
  });
  const inner = http.createServer(app);
  const rejections = [];
  const front = createProxyProtocolFrontServer(inner, {
    trustedProxies,
    headerTimeoutMs,
    onRejection: (info) => rejections.push(info),
  });
  await new Promise((resolve) => front.listen(0, '127.0.0.1', resolve));
  return { front, inner, port: front.address().port, rejections };
};

/**
 * 条件等待（谓词驱动，setImmediate 让步事件循环）——不用固定睡眠：
 * noFixedSleepRatchet 门禁的纪律是「延迟要么是被测对象、要么换成条件等待」。
 * 这里等待的全部是网络状态（响应到达、连接关闭），sleep 换不来正确性只会拉长时间。
 */
const waitFor = async (predicate, { timeoutMs = 3000, label = '条件' } = {}) => {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`waitFor 超时（${label} 未在 ${timeoutMs}ms 内成立）`);
    }
    await new Promise((r) => setImmediate(r));
  }
};

const stopProbe = async ({ front, inner }) => {
  await new Promise((resolve) => front.close(() => resolve()));
  // 内层从未 listen，close 只做登记清理（回调必到），防 jest 句柄泄漏告警
  if (inner) await new Promise((resolve) => inner.close(() => resolve()));
};

/**
 * HTTP 探针客户端：发 payload，读完整响应（按 Content-Length 收尾）。
 * 返回 {statusLine, body, closed: boolean}；closed=true 表示连接被服务端断开
 * 且未收到任何 HTTP 响应（拒绝路径的判定依据）。
 */
const probe = (port, payload, { timeoutMs = 4000 } = {}) =>
  new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1');
    const chunks = [];
    let responded = false;
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('probe timeout'));
    }, timeoutMs);
    const finish = (result) => {
      clearTimeout(timer);
      resolve(result);
    };
    sock.on('data', (c) => {
      chunks.push(c);
      const text = Buffer.concat(chunks).toString('utf8');
      const headerEnd = text.indexOf('\r\n\r\n');
      if (headerEnd >= 0 && !responded) {
        responded = true;
        const [statusLine] = text.split('\r\n');
        const lenMatch = text.match(/content-length:\s*(\d+)/i);
        const bodyStart = headerEnd + 4;
        const need = lenMatch ? Number.parseInt(lenMatch[1], 10) : 0;
        if (text.length - bodyStart >= need) {
          sock.destroy();
          finish({ statusLine, body: text.slice(bodyStart, bodyStart + need), closed: false });
        }
      }
    });
    sock.on('close', () => {
      if (!responded) finish({ statusLine: '', body: '', closed: true });
    });
    sock.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    sock.write(payload);
  });

/** 期望被服务端断开且零响应（伪造/畸形/超时路径的统一断言） */
const expectRejected = async (port, payload) => {
  const r = await probe(port, payload);
  expect(r.closed).toBe(true);
  expect(r.statusLine).toBe('');
  return r;
};

/** 未配置名单时的「未信任对端」夹具：10.99.0.0/24 之外一律不可信（含回环） */
const UNTRUSTED_LIST = toTrustedProxies(parseTrustedProxyCidrs('10.99.0.0/24'));

describe('还原路径：PROXY 头消费后全链路取到真实客户端', () => {
  test('v1 头（直连形态，trust proxy 关）→ req.ip 与 socket 对端都是 LB 声明的客户端', async () => {
    const p = await startProbe();
    try {
      const r = await probe(
        p.port,
        `${V1_HEADER}GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`
      );
      expect(r.statusLine).toContain('200');
      const body = JSON.parse(r.body);
      expect(body.ip).toBe('198.51.100.7');
      expect(body.peer).toBe('198.51.100.7');
      expect(body.attribution.kind).toBe('direct');
      expect(p.rejections).toHaveLength(0);
    } finally {
      await stopProbe(p);
    }
  });

  test('v2 头（INET）→ 同样还原，且 TLV/端口字节不进 HTTP 流', async () => {
    const p = await startProbe();
    try {
      const r = await probe(
        p.port,
        Buffer.concat([
          v2InetHeader('203.0.113.99', '203.0.113.5', 55555, 3000),
          Buffer.from('GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n', 'ascii'),
        ])
      );
      expect(r.statusLine).toContain('200');
      const body = JSON.parse(r.body);
      expect(body.ip).toBe('203.0.113.99');
      expect(body.peer).toBe('203.0.113.99');
    } finally {
      await stopProbe(p);
    }
  });

  test('经代理形态（trust proxy=1 + LB 顺带 XFF）→ 归因仍 direct，惩罚目标即真实客户端', async () => {
    // 关键自洽性用例：PROXY 头还原后 socket 对端 = 真实客户端，XFF 左端与其一致
    // ⇒ classifyIpAttribution 两侧同值判 direct（而不是误判 trusted_proxy/
    //   public_peer_header），封禁链天然落在真实客户端。isPeerTrustedProxy 的第三臂
    // 即便判「对端不可信」（还原后的客户端不在名单内），裁决退路（socket 对端）
    // 也是同一个地址 —— 取值收敛是本仓信任模型不被打破的验收点
    const p = await startProbe({ trustProxyHops: 1 });
    try {
      const r = await probe(
        p.port,
        `${V1_HEADER}GET /probe HTTP/1.1\r\nHost: x\r\n` +
          'X-Forwarded-For: 198.51.100.7\r\nConnection: close\r\n\r\n'
      );
      expect(r.statusLine).toContain('200');
      const body = JSON.parse(r.body);
      expect(body.ip).toBe('198.51.100.7');
      expect(body.attribution.kind).toBe('direct');
    } finally {
      await stopProbe(p);
    }
  });

  test('v1 UNKNOWN（LB 健康检查）→ 保留真实对端，不重写', async () => {
    const p = await startProbe();
    try {
      const r = await probe(
        p.port,
        'PROXY UNKNOWN\r\nGET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'
      );
      expect(r.statusLine).toContain('200');
      const body = JSON.parse(r.body);
      expect(body.ip).toBe('127.0.0.1');
      expect(body.peer).toBe('127.0.0.1');
    } finally {
      await stopProbe(p);
    }
  });

  test('逐字节分片到达（TCP 分段极端形态）→ 还原不丢不乱', async () => {
    const p = await startProbe();
    try {
      const payload = `${V1_HEADER}GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`;
      const sock = net.connect(p.port, '127.0.0.1');
      const chunks = [];
      const resp = await new Promise((resolve, reject) => {
        sock.on('data', (c) => chunks.push(c));
        sock.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
        sock.on('error', reject);
        setTimeout(() => {
          sock.destroy();
          reject(new Error('byte-by-byte probe timeout'));
        }, 4000);
        let i = 0;
        const writeNext = () => {
          if (i >= payload.length) return;
          sock.write(payload[i]);
          i += 1;
          setTimeout(writeNext, 2);
        };
        writeNext();
      });
      expect(resp).toContain('200');
      expect(resp).toContain('198.51.100.7');
    } finally {
      await stopProbe(p);
    }
  });
});

describe('透传路径：无签名连接原样服务', () => {
  test('普通 HTTP 请求（Prometheus 直抓/healthcheck 形态）→ 200 且对端为本机', async () => {
    const p = await startProbe();
    try {
      const r = await probe(p.port, 'GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
      expect(r.statusLine).toContain('200');
      const body = JSON.parse(r.body);
      expect(body.ip).toBe('127.0.0.1');
      expect(body.peer).toBe('127.0.0.1');
      expect(p.rejections).toHaveLength(0);
    } finally {
      await stopProbe(p);
    }
  });

  test('前导 CRLF 的请求（v2 签名真前缀）→ 透传而非卡死/断开', async () => {
    const p = await startProbe();
    try {
      const r = await probe(
        p.port,
        '\r\n\r\nGET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'
      );
      expect(r.statusLine).toContain('200');
    } finally {
      await stopProbe(p);
    }
  });

  test('keep-alive 复用：头只消费一次，第二笔请求照常（且重写保持）', async () => {
    const p = await startProbe();
    try {
      // 单一累积器贯穿整条连接：两笔响应都在同一缓冲里清点，
      // 避免分段挂监听器把响应 1 留在被丢弃的缓冲里
      const sock = net.connect(p.port, '127.0.0.1');
      let all = '';
      sock.on('data', (c) => {
        all += c.toString('utf8');
      });
      sock.write(`${V1_HEADER}GET /probe HTTP/1.1\r\nHost: x\r\n\r\n`);
      // 数据驱动等待：响应 1 到达后立即发第二笔（真实 keep-alive 复用时序）
      await waitFor(() => /HTTP\/1\.1 200/.test(all), { label: '响应 1 到达' });
      sock.write('GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
      await waitFor(() => (all.match(/HTTP\/1\.1 200/g) || []).length >= 2, {
        label: '响应 2 到达',
      });
      const statusCount = (all.match(/HTTP\/1\.1 200/g) || []).length;
      expect(statusCount).toBe(2);
      // 头只消费一次 ⇒ 两笔请求都由同一条重写后的连接服务
      expect((all.match(/"ip":"198\.51\.100\.7"/g) || []).length).toBe(2);
      sock.destroy();
    } finally {
      await stopProbe(p);
    }
  });
});

describe('拒绝路径：名单是重写权的唯一凭据', () => {
  test('未信任对端发合法 v1 头 → 断开 + onRejection(untrusted-peer)', async () => {
    const p = await startProbe({ trustedProxies: UNTRUSTED_LIST });
    try {
      await expectRejected(p.port, `${V1_HEADER}GET /probe HTTP/1.1\r\nHost: x\r\n\r\n`);
      expect(p.rejections).toHaveLength(1);
      expect(p.rejections[0].reason).toContain('untrusted-peer');
      expect(p.rejections[0].peer).toBe('127.0.0.1');
    } finally {
      await stopProbe(p);
    }
  });

  test('未信任对端发 v2 头 → 同样断开（签名形态不影响裁决）', async () => {
    const p = await startProbe({ trustedProxies: UNTRUSTED_LIST });
    try {
      await expectRejected(
        p.port,
        Buffer.concat([
          v2InetHeader(),
          Buffer.from('GET /probe HTTP/1.1\r\nHost: x\r\n\r\n', 'ascii'),
        ])
      );
      expect(p.rejections[0].reason).toContain('untrusted-peer');
    } finally {
      await stopProbe(p);
    }
  });

  test('名单内对端发畸形头 → 断开 + malformed-header 留痕', async () => {
    const p = await startProbe(); // 未配名单：兼容档回环可信，127.0.0.1 是「名单内」
    try {
      await expectRejected(
        p.port,
        `PROXY TCP4 not-an-ip 203.0.113.5 41111 3000\r\nGET /probe HTTP/1.1\r\n\r\n`
      );
      expect(p.rejections).toHaveLength(1);
      expect(p.rejections[0].reason).toContain('malformed-header');
    } finally {
      await stopProbe(p);
    }
  });

  test('部分头超时 → 断开但**不进**安全计数（探活/扫描不冒充攻击）', async () => {
    const p = await startProbe({ headerTimeoutMs: 250 });
    try {
      // 只发 v1 签名前缀，等超时
      await expectRejected(p.port, 'PROXY ');
      expect(p.rejections).toHaveLength(0);
    } finally {
      await stopProbe(p);
    }
  });

  test('发头后正常请求的连接不受其他连接被拒影响（隔离性）', async () => {
    const p = await startProbe({ trustedProxies: UNTRUSTED_LIST });
    try {
      // 一条被拒（回环不在 10.99.0.0/24）
      await expectRejected(p.port, `${V1_HEADER}GET /probe HTTP/1.1\r\nHost: x\r\n\r\n`);
      // 透传路径仍正常（伪造连接不毒化监听器状态）
      const r = await probe(p.port, 'GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
      expect(r.statusLine).toContain('200');
    } finally {
      await stopProbe(p);
    }
  });
});

describe('监听与关闭语义', () => {
  test('IPv6 监听（::1）→ 还原路径同样成立', async () => {
    const app = express();
    app.set('trust proxy', false);
    app.disable('x-powered-by');
    app.get('/probe', (req, res) => res.json({ ip: req.ip, peer: req.socket.remoteAddress }));
    const inner = http.createServer(app);
    const front = createProxyProtocolFrontServer(inner, {});
    await new Promise((resolve) => front.listen(0, '::1', resolve));
    const port = front.address().port;
    try {
      const r = await new Promise((resolve, reject) => {
        const sock = net.connect(port, '::1');
        const chunks = [];
        sock.on('data', (c) => chunks.push(c));
        sock.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
        sock.on('error', reject);
        setTimeout(() => {
          sock.destroy();
          reject(new Error('ipv6 probe timeout'));
        }, 4000);
        sock.write(
          Buffer.from(
            'PROXY TCP6 2001:db8::99 2001:db8::2 5555 3000\r\n' +
              'GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n',
            'ascii'
          )
        );
      });
      expect(r).toContain('200');
      expect(r).toContain('2001:db8::99');
    } finally {
      await new Promise((resolve) => front.close(() => resolve()));
    }
  });

  test('优雅关闭：front.close() 停止 accept，新连接被拒', async () => {
    const p = await startProbe();
    try {
      // 完成一次请求后彻底关闭客户端（front.close 的排空回调等全部连接消亡，
      // 不断开客户端会让下面的 await 挂到 jest 超时）
      const r = await probe(p.port, 'GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
      expect(r.statusLine).toContain('200');
      await new Promise((resolve) => p.front.close(() => resolve()));
      const refused = await new Promise((resolve) => {
        const s = net.connect(p.port, '127.0.0.1');
        s.on('error', () => resolve('refused'));
        s.on('connect', () => {
          s.destroy();
          resolve('connected');
        });
      });
      expect(refused).toBe('refused');
    } finally {
      // front 已在用例内关闭；inner 未 listen，无需 close
    }
  });
});
