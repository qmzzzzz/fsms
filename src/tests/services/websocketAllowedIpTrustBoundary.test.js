/**
 * WS 与 HTTP 的 allowedIPs 必须站在同一侧可信边界（F-B43，2026-10-01 第 5 轮）
 *
 * 缺陷形状（并行 agent 报告，本文件先独立复现再修）：
 * HTTP 侧的 allowedIPs 判定改用 `utils/ipUtils.js` 的 `clientIpForSecurityDecision`
 * ——可信边界内取 req.ip，边界外退回**不可伪造的 socket 对端**；而 WS 侧的
 * `_assertHandshakeIpAllowed` 当时仍直接用 `resolveHandshakeClientIP`（= express 的
 * req.ip）。结果是**一条伪造的 X-Forwarded-For 只在 WS 面生效**：真实地址不在允许范围
 * 内的人，HTTP 被拒（AUTH_IP_RANGE_DENIED）却能从 WS 面进入 alarm / device-alert /
 * role-management 房间。把"两侧同样弱"的均匀缺陷修成"HTTP 强、WS 弱"的不均匀缺陷，
 * 比不修更危险——读侧的收紧会看起来已经完成。
 *
 * 本文件的口径：
 *  1. **一致性**用真实 express 取得 HTTP 侧结论（trust proxy 用真实 hop 数配置，
 *     对端地址在 req.ip 被读取**之前**改写，因为 proxy-addr 是惰性求值的），
 *     再把同一次请求的头与对端交给 WS 侧函数比对。不在测试里复述任何一侧的判据。
 *  2. **行为**用 allowedIPs 闸的实际返回值断言"伪造头买不到访问控制"，并配
 *     反向对照（经 nginx 的正常流量不得被误伤）——防止把闸做成恒拒绝。
 *  3. 第 3 组用例（2026-10-10 #24 R1 起改口径）：封禁面**已与准入面同柄**——HTTP 的
 *     checkIPBlacklist 与 WS 的封禁闸都改取 clientIpForSecurityDecision（security.js:685
 *     已换尺），公网对端 + 伪造 XFF 一律退回 socket 对端。本组改钉"WS 闸与 HTTP 侧查同一个
 *     安全裁决地址"：准入 / HTTP 封禁 / WS 封禁三处共用一把尺，不再有"封了 X 却拦不住 Y"。
 */

const express = require('express');
const http = require('http');
const path = require('path');

describe('WS/HTTP 客户端 IP 可信边界一致性（F-B43）', () => {
  const WebSocketService = require('../../services/websocketService');
  const {
    clientIpForSecurityDecision,
    isClientIpIdentityTrustworthy,
    isPrivateOrLoopback,
  } = require('../../utils/ipUtils');
  const { isIPAllowed } = require('../../utils/ipRange');

  const PUBLIC_PEER = '203.0.113.23'; // TEST-NET-3：文档用公网地址
  const FORGED = '10.0.0.5';

  /** 只归一 IPv4-in-IPv6 的文本表示（`::ffff:a.b.c.d` → `a.b.c.d`），不改变任何判定 */
  const toV4 = (addr) => String(addr).replace(/^::ffff:/, '');

  // 夹具前提自证：本用例用的"公网对端"在仓库自己的尺子下确实是公网。
  // 若哪天 isPrivateOrLoopback 的口径变了，下面"退回对端"的断言就失去了意义。
  test('夹具前提：TEST-NET 对端不可归为内网，回环可', () => {
    expect(isPrivateOrLoopback(PUBLIC_PEER)).toBe(false);
    expect(isPrivateOrLoopback('127.0.0.1')).toBe(true);
  });

  /**
   * 用真实 express 跑一次请求，同时取回 HTTP 侧结论与"同一次请求"的 handshake 形态。
   *
   * peerOverride 改写 `req.socket.remoteAddress`：本机无法真的从公网对端连进来，
   * 但 express 的 req.ip 是 getter（proxy-addr 惰性求值），只要**在首次读取之前**改写，
   * 这一侧看到的仍是"公网直连 + 携带 XFF"的真实组合，而不是我手工拼的 req.ip。
   *
   * 必须走 `Object.defineProperty` 而不是赋值：Node 24 把 `remoteAddress` 实现成
   * `net.Socket.prototype` 上**只有 getter** 的属性（实测
   * `Object.getOwnPropertyDescriptor(net.Socket.prototype, 'remoteAddress')` →
   * `{get: function, set: undefined}`），直接赋值在非严格模式下静默无效——
   * 表现是"改写成功了"但读回来仍是 `::ffff:127.0.0.1`，于是公网那一臂整体空跑，
   * 两侧都读到内网对端 ⇒ 可信边界恒成立 ⇒ 断言全绿却什么都没验证。
   */
  const probe = async ({ hops, xff, peerOverride }) => {
    const app = express();
    app.set('trust proxy', hops);
    let payload;
    app.get('/probe', (req, res) => {
      if (peerOverride) {
        Object.defineProperty(req.socket, 'remoteAddress', {
          value: peerOverride,
          configurable: true,
          writable: true,
        });
      }
      payload = {
        httpIP: clientIpForSecurityDecision(req),
        trustworthy: isClientIpIdentityTrustworthy(req),
        peer: req.socket.remoteAddress,
        headers: { ...req.headers },
      };
      res.json({ ok: true });
    });
    const server = app.listen(0);
    await new Promise((resolve) => server.once('listening', resolve));
    await new Promise((resolve, reject) => {
      const headers = xff === undefined ? {} : { 'X-Forwarded-For': xff };
      http
        .get(
          { host: '127.0.0.1', port: server.address().port, path: '/probe', headers },
          (res2) => {
            res2.resume();
            res2.on('end', resolve);
          }
        )
        .on('error', reject);
    });
    await new Promise((resolve) => server.close(resolve));
    return payload;
  };

  describe('1. 同一份流量，两侧得出同一个裁决地址', () => {
    test.each([
      ['未启用 trust proxy（hops=0），即使带着 XFF', 0, FORGED, undefined],
      ['trust proxy 开启但未携带 XFF', 1, undefined, undefined],
      ['trust proxy 开启 + 对端内网（经 nginx）', 1, '8.8.8.8', undefined],
      ['trust proxy 开启 + 对端公网 + 携带 XFF（可伪造臂）', 1, FORGED, PUBLIC_PEER],
      ['两跳 + 对端公网 + 携带 XFF', 2, `8.8.8.8, ${FORGED}`, PUBLIC_PEER],
      ['XFF 存在但为空串（express 也算"携带"）', 1, '', PUBLIC_PEER],
    ])('%s', async (_label, hops, xff, peerOverride) => {
      const { httpIP, peer, headers } = await probe({ hops, xff, peerOverride });
      // 夹具前提自证：对端改写真的生效了，否则"公网直连 + XFF"那一臂是空跑。
      // 本机回环在 Node 里是 IPv4 映射的 IPv6 文本（`::ffff:127.0.0.1`），
      // 这里只按表示法归一，不改判定语义——两侧拿到的仍是同一个字符串。
      expect(toV4(peer)).toBe(toV4(peerOverride || '127.0.0.1'));
      expect(httpIP).toBeTruthy();

      const wsIP = WebSocketService.resolveHandshakeIPForSecurityDecision(
        { address: peer, headers },
        hops
      );

      expect(String(wsIP)).toBe(String(httpIP));
    });

    test('可证伪：抹掉 WS 侧退回对端那一半，公网直连 + 伪造 XFF 就会与 HTTP 分叉', async () => {
      const { httpIP, peer, headers } = await probe({
        hops: 1,
        xff: FORGED,
        peerOverride: PUBLIC_PEER,
      });
      // 旧取址（= 本次改动前的 WS 行为）读的是伪造段
      const naive = WebSocketService.resolveHandshakeClientIP({ address: peer, headers }, 1);
      expect(String(naive)).toBe(FORGED);
      expect(String(httpIP)).toBe(PUBLIC_PEER);
      // 修好后两侧同值
      const fixed = WebSocketService.resolveHandshakeIPForSecurityDecision(
        { address: peer, headers },
        1
      );
      expect(String(fixed)).toBe(String(httpIP));
    });
  });

  describe('2. allowedIPs 闸的实际行为：伪造头买不到访问控制', () => {
    const makeSocket = (handshake) => {
      const socket = {
        id: 'trust-boundary-sock',
        handshake,
        emitted: [],
        connected: true,
        emit: (ev, data) => socket.emitted.push({ ev, data }),
        disconnect: () => {
          socket.connected = false;
        },
      };
      return socket;
    };

    const withHops = async (hops, fn) => {
      const original = process.env.TRUST_PROXY_HOPS;
      process.env.TRUST_PROXY_HOPS = String(hops);
      try {
        return await fn();
      } finally {
        if (original === undefined) delete process.env.TRUST_PROXY_HOPS;
        else process.env.TRUST_PROXY_HOPS = original;
      }
    };

    test('公网直连 + 伪造内网 XFF → 拒绝（此前放行，是 HTTP 收紧后剩下的半边门）', async () => {
      const allowedIPs = '10.0.0.0/8'; // 只允许内网：伪造头想冒充的目标范围
      const { peer, headers } = await probe({ hops: 1, xff: FORGED, peerOverride: PUBLIC_PEER });
      const socket = makeSocket({ address: peer, headers });
      // 前提自证：伪造段确实落在允许范围内（否则"拒绝"不能归因于可信边界）
      expect(isIPAllowed(FORGED, allowedIPs).allowed).toBe(true);
      expect(isIPAllowed(peer, allowedIPs).allowed).toBe(false);

      const denied = await withHops(1, () =>
        Object.create(WebSocketService.prototype)._assertHandshakeIpAllowed(socket, {
          allowedIPs,
          username: 'trust-boundary',
        })
      );

      expect(denied).toBe(true);
      expect(socket.connected).toBe(false);
      expect(
        socket.emitted.some((e) => e.ev === 'auth-error' && /IP 范围/.test(e.data.message))
      ).toBe(true);
    });

    test('反向对照：经 nginx 的正常流量照常放行（不得把闸做成恒拒绝）', async () => {
      const office = '198.51.100.77';
      const allowedIPs = '198.51.100.0/24';
      const { peer, headers } = await probe({ hops: 1, xff: office }); // 对端 127.0.0.1 = 内网
      const socket = makeSocket({ address: peer, headers });

      const denied = await withHops(1, () =>
        Object.create(WebSocketService.prototype)._assertHandshakeIpAllowed(socket, {
          allowedIPs,
          username: 'nginx-normal',
        })
      );

      expect(denied).toBe(false);
      expect(socket.connected).toBe(true);
    });

    test('未配 allowedIPs → 两条臂都不触发（本次改动不新增拒绝路径）', async () => {
      const { peer, headers } = await probe({ hops: 1, xff: FORGED, peerOverride: PUBLIC_PEER });
      const socket = makeSocket({ address: peer, headers });
      const denied = await withHops(1, () =>
        Object.create(WebSocketService.prototype)._assertHandshakeIpAllowed(socket, {
          allowedIPs: null,
          username: 'no-rules',
        })
      );
      expect(denied).toBe(false);
    });
  });

  describe('3. 封禁面与准入面同取安全裁决尺（#24 R1 后两处同柄）', () => {
    test('黑名单查询用的地址 = HTTP 侧 checkIPBlacklist 查询用的地址（#24 R1 后同取安全裁决尺）', async () => {
      const IPBlacklist = require(path.join(__dirname, '../../models/IPBlacklist'));
      const isBlocked = jest.spyOn(IPBlacklist, 'isBlocked').mockResolvedValue(true);
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
      const original = process.env.TRUST_PROXY_HOPS;
      process.env.TRUST_PROXY_HOPS = '1';
      try {
        const { peer, headers, httpIP } = await probe({
          hops: 1,
          xff: FORGED,
          peerOverride: PUBLIC_PEER,
        });
        const socket = {
          id: 'ban-arm',
          handshake: { address: peer, headers },
          emitted: [],
          connected: true,
          emit: (ev, data) => socket.emitted.push({ ev, data }),
          disconnect: () => {
            socket.connected = false;
          },
        };

        const rejected = await Object.create(
          WebSocketService.prototype
        )._assertHandshakeIpNotBanned(socket);

        // #24 R1：HTTP 侧与 WS 封禁闸同取 clientIpForSecurityDecision ⇒ 公网对端 + 伪造 XFF 都退到 socket 对端；WS 必须查同一个安全裁决地址。
        expect(isBlocked).toHaveBeenCalledTimes(1);
        // 前提自证：这把尺对"公网对端 + 伪造 XFF"确实退到不可伪造的 socket 对端
        expect(httpIP).toBe(PUBLIC_PEER);
        // WS 闸查的地址必须等于 HTTP 侧同一个安全裁决地址（两侧同址且同尺）
        expect(isBlocked.mock.calls[0][0]).toBe(httpIP);
        expect(isBlocked.mock.calls[0][0]).toBe(peer);
        expect(rejected).toBe(true);
        expect(socket.connected).toBe(false);
      } finally {
        if (original === undefined) delete process.env.TRUST_PROXY_HOPS;
        else process.env.TRUST_PROXY_HOPS = original;
        jest.restoreAllMocks();
      }
    });
  });
});

/**
 * 4. 配了 TRUSTED_PROXY_CIDRS 之后，WS 面必须跟着收紧（F-01 收尾，2026-10-18）
 *
 * 远端那份 F-01 实现只把 HTTP 侧接上了名单（`isClientIpIdentityTrustworthy` 读
 * `app.get('trusted proxy cidrs')`），WS 侧的第三臂仍写死 `isPrivateOrLoopback(peer)`。
 * 于是同一个伪造头在两侧再次分叉——只是这次的分界线从「HTTP / WS」换成了
 * 「HTTP 已收紧 / WS 没跟上」。第 1 组用例的注释里已经写过这个判断：
 * 把均匀缺陷修成不均匀缺陷比不修更危险，因为它让收紧看起来已经完成。
 *
 * 本组的口径与第 1 组一致：**不在测试里复述判据**，而是拿真实 express 的结论
 * 与 WS 函数比对；并配反向对照（名单含对端时正常反代路径不得被误伤）。
 */
describe('4. 配了 TRUSTED_PROXY_CIDRS 后 WS 与 HTTP 仍同侧（F-01 收尾）', () => {
  const trustedProxies = require('../../config/trustedProxies');
  const { parseTrustedProxyCidrs, toTrustedProxies } = trustedProxies;
  // 上面那个 describe 里的同名解构只在它自己的作用域内可见，这里重新取
  const {
    clientIpForSecurityDecision,
    isClientIpIdentityTrustworthy,
    isPrivateOrLoopback,
  } = require('../../utils/ipUtils');
  const WebSocketService = require('../../services/websocketService');
  const FORGED = '10.0.0.5';

  /**
   * WS 侧读的是 `resolveTrustedProxies()`（env + memoize），HTTP 侧读的是注入位。
   * 用例里两者必须来自**同一份**解析结果，故统一：env 由本函数设置，HTTP 侧用
   * 同一段 raw 直接构造 `proxies` 注入（避免依赖 app.js 的 createApp 全量装配）。
   */
  const withCidrs = async (raw, fn) => {
    const key = trustedProxies.ENV_KEY;
    const original = process.env[key];
    if (raw === undefined) delete process.env[key];
    else process.env[key] = raw;
    trustedProxies.resetTrustedProxyCache();
    try {
      return await fn();
    } finally {
      if (original === undefined) delete process.env[key];
      else process.env[key] = original;
      trustedProxies.resetTrustedProxyCache();
    }
  };

  /** 与既有 probe 同构，多一个"注入名单"的动作（对应 app.js 的 applyTrustedProxyPolicy） */
  const probeWithCidrs = async ({ hops, xff, cidrs }) => {
    const app = express();
    app.set('trust proxy', hops);
    app.set('trusted proxy cidrs', toTrustedProxies(parseTrustedProxyCidrs(cidrs)));
    let payload;
    app.get('/probe', (req, res) => {
      payload = {
        httpIP: clientIpForSecurityDecision(req),
        trustworthy: isClientIpIdentityTrustworthy(req),
        peer: req.socket.remoteAddress,
        headers: { ...req.headers },
      };
      res.json({ ok: true });
    });
    const server = app.listen(0);
    await new Promise((resolve) => server.once('listening', resolve));
    await new Promise((resolve, reject) => {
      const headers = xff === undefined ? {} : { 'X-Forwarded-For': xff };
      http
        .get(
          { host: '127.0.0.1', port: server.address().port, path: '/probe', headers },
          (res2) => {
            res2.resume();
            res2.on('end', resolve);
          }
        )
        .on('error', reject);
    });
    await new Promise((resolve) => server.close(resolve));
    return payload;
  };

  test('对端私网但不在名单内：WS 也退回 socket 对端（此前只有 HTTP 收紧）', async () => {
    const CIDRS = '203.0.113.0/24'; // 不含本机回环
    await withCidrs(CIDRS, async () => {
      const { httpIP, trustworthy, peer, headers } = await probeWithCidrs({
        hops: 1,
        xff: FORGED,
        cidrs: CIDRS,
      });

      // 前提自证：对端确实是「私网」，否则本用例钉不住"旧的私网判据会放行"这个缺陷
      expect(isPrivateOrLoopback(peer)).toBe(true);
      // 前提自证：HTTP 侧确实已经收紧（这是 F-01 主体做的）
      expect(trustworthy).toBe(false);

      const wsIP = WebSocketService.resolveHandshakeIPForSecurityDecision(
        { address: peer, headers },
        1
      );

      // 核心断言：两侧同址。旧实现在此处会返回 FORGED（对端是私网 ⇒ 认为 XFF 可信）
      expect(String(wsIP)).toBe(String(httpIP));
      expect(String(wsIP)).not.toBe(FORGED);
    });
  });

  test('反向对照：名单含对端所在网段 ⇒ WS 仍采信 XFF（正常反代路径不被误伤）', async () => {
    const CIDRS = '127.0.0.0/8';
    await withCidrs(CIDRS, async () => {
      const { httpIP, trustworthy, peer, headers } = await probeWithCidrs({
        hops: 1,
        xff: FORGED,
        cidrs: CIDRS,
      });

      expect(trustworthy).toBe(true);
      expect(String(httpIP)).toBe(FORGED);

      const wsIP = WebSocketService.resolveHandshakeIPForSecurityDecision(
        { address: peer, headers },
        1
      );
      expect(String(wsIP)).toBe(String(httpIP));
      expect(String(wsIP)).toBe(FORGED);
    });
  });

  test('未配置 ⇒ 兼容档不变：私网对端的 XFF 仍被采信（两侧同侧）', async () => {
    await withCidrs(undefined, async () => {
      const { httpIP, peer, headers } = await probeWithCidrs({
        hops: 1,
        xff: FORGED,
        cidrs: undefined,
      });
      const wsIP = WebSocketService.resolveHandshakeIPForSecurityDecision(
        { address: peer, headers },
        1
      );
      expect(String(wsIP)).toBe(String(httpIP));
      expect(String(wsIP)).toBe(FORGED);
    });
  });
});
