/**
 * WebSocket 认证范围校验（P0-2 修复锁定）
 *
 * 审计实证的绕过：同一个 JWT 在 HTTP 侧被拒（allowedIPs 不匹配 → 403
 * AUTH_IP_RANGE_DENIED；设备会话已吊销 → DEVICE_SESSION_REVOKED），
 * WS 侧却认证通过并绑定 socket.userId —— authenticateSocket 当时全文 0 处
 * 引用 sid / allowedIPs / sessionService。
 *
 * 本文件锁定修复后的两条防线，并额外锁定「WS 与 HTTP 得出同一个客户端 IP」
 * 这一前提：若两侧的 trust proxy 语义漂移，同一条 allowedIPs 规则会在两条
 * 通道上给出不同结论（表现为网页能开、实时推送连不上，或反之静默放宽）。
 * 一致性断言直接对比真实 express 的 req.ip，而不是复述实现。
 */

const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const express = require('express');

describe('WebSocket 认证范围校验（P0-2）', () => {
  let WebSocketService;
  let User;
  let Role;
  let UserSession;
  let roleId;
  const stamp = `x${String(Date.now()).slice(-8)}`;
  let counter = 0;

  /** 造一个用户：allowedIPs 为 null 表示不限制 */
  const makeUser = async (suffix, allowedIPs) => {
    const user = await User.create({
      username: `w${suffix}_${stamp}`,
      email: `w${suffix}-${stamp}@example.com`,
      password: `P@ssw0rd-${stamp}-${suffix}`,
      roles: [roleId],
      status: 'active',
      ...(allowedIPs ? { allowedIPs } : {}),
    });
    return user;
  };

  /** 签发访问令牌（sid 可选，模拟「会话已吊销」/「旧令牌无 sid」两种形态） */
  const signToken = (user, sid) =>
    jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        tokenVersion: user.tokenVersion ?? 0,
        jti: `jti-${++counter}`,
        ...(sid ? { sid } : {}),
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );

  /** 最小服务实例：authenticateSocket 只用到 clients / userConnections 两张表 */
  const makeService = () => {
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map();
    return svc;
  };

  /** 假 socket：记录 emit / disconnect / join，handshake 可注入 address 与 XFF */
  const makeSocket = (token, { address = null, xff = null } = {}) => {
    const socket = {
      id: `wsx-sock-${++counter}`,
      handshake: {
        auth: { token },
        address,
        headers: xff ? { 'x-forwarded-for': xff } : {},
      },
      authenticated: false,
      emitted: [],
      connected: true,
      rooms: new Set(),
      emit: (ev, data) => socket.emitted.push({ ev, data }),
      disconnect: () => {
        socket.connected = false;
      },
      join: (room) => socket.rooms.add(room),
    };
    return socket;
  };

  const authErrorOf = (socket) => socket.emitted.find((e) => e.ev === 'auth-error');

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    UserSession = require('../../models/UserSession');
    WebSocketService = require('../../services/websocketService');

    const role = await Role.findOneAndUpdate(
      { code: `WSX_${stamp.toUpperCase()}` },
      { $setOnInsert: { name: 'wsx-role', code: `WSX_${stamp.toUpperCase()}`, level: 5 } },
      { upsert: true, new: true }
    );
    roleId = role._id;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const users = await User.find({ username: new RegExp(`^w.*_${stamp}$`) }).select('_id');
      const ids = users.map((u) => u._id);
      await UserSession.deleteMany({ userId: { $in: ids } }).catch(() => {});
      await User.deleteMany({ _id: { $in: ids } }).catch(() => {});
      await Role.deleteOne({ code: `WSX_${stamp.toUpperCase()}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  describe('allowedIPs（对应 HTTP 侧 AUTH_IP_RANGE_DENIED）', () => {
    test('来源 IP 不在 allowedIPs 内 → 认证失败并断开', async () => {
      const user = await makeUser('ipd', '10.0.0.0/8');
      const socket = makeSocket(signToken(user), { address: '127.0.0.1' });
      const svc = makeService();

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(false);
      expect(socket.authenticated).toBe(false);
      expect(socket.connected).toBe(false);
      expect(authErrorOf(socket).data.message).toContain('IP');
      expect(svc.userConnections.size).toBe(0);
    });

    test('来源 IP 在 allowedIPs 内 → 认证通过', async () => {
      const user = await makeUser('ipa', '127.0.0.0/8');
      const svc = makeService();
      const socket = makeSocket(signToken(user), { address: '127.0.0.1' });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(true);
      expect(socket.userId).toBe(String(user._id));
      expect(svc.userConnections.get(String(user._id)).has(socket.id)).toBe(true);
    });

    test('allowedIPs 为空 → 不限制（与 HTTP 侧 no_rules 放行一致）', async () => {
      const user = await makeUser('ipn', null);
      const svc = makeService();
      const socket = makeSocket(signToken(user), { address: '203.0.113.9' });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(true);
    });

    test('allowedIPs 为非法文本 → fail-closed 拒绝（isIPAllowed 语义）', async () => {
      const user = await makeUser('ipb', '10.0.0.0/33');
      const svc = makeService();
      const socket = makeSocket(signToken(user), { address: '127.0.0.1' });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(false);
      expect(socket.connected).toBe(false);
    });
  });

  describe('设备会话状态（对应 HTTP 侧 DEVICE_SESSION_REVOKED）', () => {
    test('sid 对应会话已吊销 → 认证失败并断开', async () => {
      const user = await makeUser('srv', null);
      await UserSession.create({
        sid: `sid-revoked-${stamp}`,
        userId: user._id,
        status: 'revoked',
        ip: '127.0.0.1',
        userAgent: 'test',
        expiresAt: new Date(Date.now() + 86400000),
        revokedAt: new Date(),
        revokeReason: 'test',
      });
      const svc = makeService();
      const socket = makeSocket(signToken(user, `sid-revoked-${stamp}`), {
        address: '127.0.0.1',
      });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(false);
      expect(socket.connected).toBe(false);
      expect(authErrorOf(socket).data.message).toContain('会话');
    });

    test('sid 对应会话不存在（伪造 sid）→ 拒绝', async () => {
      const user = await makeUser('sgh', null);
      const svc = makeService();
      const socket = makeSocket(signToken(user, `sid-ghost-${stamp}`), { address: '127.0.0.1' });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(false);
    });

    test('sid 对应会话 active → 认证通过', async () => {
      const user = await makeUser('sac', null);
      await UserSession.create({
        sid: `sid-active-${stamp}`,
        userId: user._id,
        status: 'active',
        ip: '127.0.0.1',
        userAgent: 'test',
        expiresAt: new Date(Date.now() + 86400000),
      });
      const svc = makeService();
      const socket = makeSocket(signToken(user, `sid-active-${stamp}`), {
        address: '127.0.0.1',
      });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(true);
    });

    test('令牌未携带 sid（旧令牌/会话注册降级）→ 跳过会话校验而非拒绝', async () => {
      const user = await makeUser('sns', null);
      const svc = makeService();
      const socket = makeSocket(signToken(user), { address: '127.0.0.1' });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(true);
    });
  });

  describe('客户端 IP 取值与 HTTP 侧一致（trust proxy 语义）', () => {
    /**
     * 直接对比真实 express 的 req.ip：同一个 hops 取值下，
     * WS 侧 resolveHandshakeClientIP(handshake, hops) 必须等于 HTTP 侧 req.ip。
     * 断言走真实 HTTP 请求（XFF 头 + 真实 socket 对端地址），不复述实现细节。
     */
    const httpIpFor = async (hops, xff) => {
      const app = express();
      app.set('trust proxy', hops);
      app.get('/ip', (req, res) => res.json({ ip: req.ip }));
      const server = app.listen(0);
      await new Promise((r) => server.once('listening', r));
      const res = await new Promise((resolve) => {
        const headers = xff ? { 'X-Forwarded-For': xff } : {};
        require('http')
          .get({ host: '127.0.0.1', port: server.address().port, path: '/ip', headers }, (r2) => {
            let d = '';
            r2.on('data', (c) => (d += c));
            r2.on('end', () => resolve(JSON.parse(d)));
          })
          .on('error', () => resolve({ ip: null }));
      });
      server.close();
      return res.ip;
    };

    test.each([
      [1, '9.9.9.9, 1.1.1.1'],
      [2, '9.9.9.9, 1.1.1.1'],
      [3, '9.9.9.9, 8.8.8.8, 1.1.1.1'],
      [2, '9.9.9.9'],
      [1, null],
    ])('hops=%i XFF=%s → WS 与 HTTP 取值一致', async (hops, xff) => {
      // 通过真实 HTTP 请求取得 express 的 req.ip（对端为 127.0.0.1）
      const expected = await httpIpFor(hops, xff);
      expect(expected).not.toBeNull();

      // WS 侧：handshake.address 即 TCP 对端地址，与上一步同一个 127.0.0.1
      const socket = makeSocket(null, {
        address: '::ffff:127.0.0.1',
        xff,
      });
      const { resolveHandshakeClientIP } = require('../../services/websocketService');
      expect(typeof resolveHandshakeClientIP).toBe('function');
      const actual = resolveHandshakeClientIP(socket.handshake, hops);
      expect(String(actual)).toBe(String(expected));
    });
  });
});
