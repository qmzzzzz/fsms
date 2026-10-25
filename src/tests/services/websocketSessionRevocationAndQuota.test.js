/**
 * WebSocket 的两条防线：#2 设备会话吊销联动、#9 未认证连接按 IP 配额
 *
 * #2 的缺陷形状：HTTP 侧每个请求都复查 UserSession（middleware/auth.js 的
 * assertSessionUsable），WS 侧却只在**握手**时查一次。设备级吊销（「踢除该设备」）
 * 既不推进 tokenVersion 也不改 status，于是只复查这两项的周期清扫同样放行——
 * 被踢设备的长连接继续驻留 alarm / device-alert / role-management 直到自然断开。
 * 本文件锁三件事：
 *   ① 吊销发生在**本进程**时，sid 命中的连接立即断开（revokeSession/revokeOther/
 *      revokeAll 三条路径，含无 sid 旧令牌的按用户兜底）；
 *   ② 吊销落在其他实例时，周期清扫按库复查 UserSession 收敛（含过期/记录不存在）；
 *   ③ 入房复查（revalidateSocket）与握手使用同一条 sid 判据，且无 sid 的旧令牌不被误伤。
 *
 * #9 的缺陷形状：AUTH_TIMEOUT 只保证未认证连接不会永久占用名额，挡不住 30s 内
 * 灌入大量连接把单进程 1000 配额打满——无需任何凭据即可让已登录用户的重连全部失败。
 * 本文件锁：同 IP 第 MAX_UNAUTHENTICATED_PER_IP+1 条未认证连接被拒；认证成功与断开
 * 都会归还名额（含幂等）；取不到地址的连接不计数。
 */

const http = require('http');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const { MAX_UNAUTHENTICATED_PER_IP } = require('../../services/websocketService/shared');

describe('WebSocket 设备会话吊销与未认证配额', () => {
  let WebSocketService;
  let sessionService;
  let User;
  let Role;
  let UserSession;
  let roleId;
  const stamp = `r${String(Date.now()).slice(-8)}`;
  const createdUserIds = [];
  const services = [];
  let counter = 0;

  const sidOf = (label) => `wsrev-${stamp}-${label}-${++counter}`;

  const makeUser = async (label) => {
    const user = await User.create({
      username: `wsrev_${stamp}_${label}_${++counter}`,
      email: `wsrev-${stamp}-${label}-${counter}@example.com`,
      password: `P@ssw0rd-${stamp}-${label}`,
      roles: [roleId],
      status: 'active',
    });
    createdUserIds.push(user._id);
    return user;
  };

  const makeSession = async (userId, sid, extra = {}) =>
    UserSession.create({
      sid,
      userId,
      status: 'active',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      ...extra,
    });

  const signToken = (user, sid) =>
    jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        tokenVersion: user.tokenVersion ?? 0,
        jti: `jti-wsrev-${stamp}-${++counter}`,
        ...(sid ? { sid } : {}),
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '24h' }
    );

  /** 已认证假 socket；sid 为 null 表示功能上线前签发的无设备绑定令牌 */
  const makeSocket = ({ id, userId, sid = null }) => {
    const socket = {
      id: id || `wsrev-sock-${++counter}`,
      userId: userId ? String(userId) : null,
      sid,
      authenticated: true,
      connected: true,
      rooms: new Set(),
      emitted: [],
      handshake: { auth: {}, headers: {}, address: '198.51.100.42' },
      emit(ev, data) {
        socket.emitted.push({ ev, data });
      },
      disconnect() {
        socket.connected = false;
      },
      join(room) {
        socket.rooms.add(room);
      },
      leave(room) {
        socket.rooms.delete(room);
      },
      on: () => {},
    };
    return socket;
  };

  /** 真实门面实例：本文件的重点是构造器里的 onSessionRevoked 接线真的生效 */
  const makeRealService = () => {
    const svc = new WebSocketService(http.createServer());
    services.push(svc);
    return svc;
  };

  /** 把假 socket 挂进本服务的两张表（clients 记账 + io 连接表） */
  const attach = (svc, sockets) => {
    for (const socket of sockets) {
      svc.clients.set(socket.id, {
        id: socket.id,
        userId: socket.userId,
        rooms: new Set(),
        connectedAt: new Date(),
      });
      svc.io.sockets.sockets.set(socket.id, socket);
    }
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    UserSession = require('../../models/UserSession');
    WebSocketService = require('../../services/websocketService');
    sessionService = require('../../services/sessionService');

    const role = await Role.findOneAndUpdate(
      { code: `WSREV_${stamp.toUpperCase()}` },
      { $setOnInsert: { name: 'wsrev-role', code: `WSREV_${stamp.toUpperCase()}`, level: 5 } },
      { upsert: true, new: true }
    );
    roleId = role._id;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await UserSession.deleteMany({ userId: { $in: createdUserIds } }).catch(() => {});
      await User.deleteMany({ _id: { $in: createdUserIds } }).catch(() => {});
      await Role.deleteOne({ _id: roleId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  afterEach(() => {
    // 构造器登记了会话吊销监听：不 dispose 会让旧实例继续响应后续用例的吊销
    while (services.length > 0) services.pop().dispose();
    jest.restoreAllMocks();
  });

  describe('设备级吊销即时断开（#2）', () => {
    test('revokeSession 只断开被吊销 sid 的连接，其他设备与无 sid 旧令牌不受影响', async () => {
      const user = await makeUser('single');
      const sidA = sidOf('a');
      const sidB = sidOf('b');
      await makeSession(user._id, sidA);
      await makeSession(user._id, sidB);

      const svc = makeRealService();
      const socketA = makeSocket({ userId: user._id, sid: sidA });
      const socketB = makeSocket({ userId: user._id, sid: sidB });
      const legacy = makeSocket({ userId: user._id, sid: null });
      attach(svc, [socketA, socketB, legacy]);

      const revoked = await sessionService.revokeSession({
        sid: sidA,
        userId: String(user._id),
        reason: 'user_revoked',
      });

      expect(revoked).toBe(true);
      expect(socketA.connected).toBe(false);
      expect(socketA.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
      // 单设备吊销的核心价值：同一用户的其他设备不能被连带踢下线
      expect(socketB.connected).toBe(true);
      expect(legacy.connected).toBe(true);
    });

    test('revokeOtherSessions 按 sid 精确断开"除当前设备外"的连接', async () => {
      const user = await makeUser('others');
      const keepSid = sidOf('keep');
      const dropSid = sidOf('drop');
      await makeSession(user._id, keepSid);
      await makeSession(user._id, dropSid);

      const svc = makeRealService();
      const keep = makeSocket({ userId: user._id, sid: keepSid });
      const drop = makeSocket({ userId: user._id, sid: dropSid });
      attach(svc, [keep, drop]);

      const count = await sessionService.revokeOtherSessions({
        userId: String(user._id),
        exceptSid: keepSid,
        reason: 'user_revoked',
      });

      expect(count).toBe(1);
      expect(keep.connected).toBe(true);
      expect(drop.connected).toBe(false);
    });

    test('revokeAllSessions 按 userId 断开，含无 sid 的旧令牌连接', async () => {
      const user = await makeUser('all');
      const other = await makeUser('allother');
      const sid = sidOf('all');
      await makeSession(user._id, sid);

      const svc = makeRealService();
      const bound = makeSocket({ userId: user._id, sid });
      const legacy = makeSocket({ userId: user._id, sid: null });
      const unrelated = makeSocket({ userId: other._id, sid: null });
      attach(svc, [bound, legacy, unrelated]);

      const count = await sessionService.revokeAllSessions(String(user._id), 'password_changed');

      expect(count).toBe(1);
      expect(bound.connected).toBe(false);
      // 全局吊销的语义覆盖旧令牌：它们没有 sid 可匹配，必须按 userId 一并断开
      expect(legacy.connected).toBe(false);
      expect(unrelated.connected).toBe(true);
    });

    test('all=true 但缺少 userId 时不误踢任何连接（通知形态异常的安全阀）', () => {
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.io = { sockets: { sockets: new Map() } };
      const socket = makeSocket({ userId: 'u1', sid: null });
      attach(svc, [socket]);

      svc._handleSessionRevoked({ all: true, userId: null });

      expect(socket.connected).toBe(true);
    });
  });

  describe('周期清扫按库收敛（#2 跨实例兜底）', () => {
    const makeSweepService = () => {
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      return svc;
    };

    test('可用会话保留；已吊销/已过期/记录不存在的 sid 断开；无 sid 旧令牌跳过', async () => {
      const user = await makeUser('sweep');
      const activeSid = sidOf('active');
      const revokedSid = sidOf('revoked');
      const expiredSid = sidOf('expired');
      const missingSid = sidOf('missing');
      await makeSession(user._id, activeSid);
      await makeSession(user._id, revokedSid, { status: 'revoked' });
      await makeSession(user._id, expiredSid, { status: 'expired' });

      const svc = makeSweepService();
      const active = makeSocket({ userId: user._id, sid: activeSid });
      const revoked = makeSocket({ userId: user._id, sid: revokedSid });
      const expired = makeSocket({ userId: user._id, sid: expiredSid });
      const missing = makeSocket({ userId: user._id, sid: missingSid });
      const legacy = makeSocket({ userId: user._id, sid: null });

      const result = await svc._sweepRevokedSessions([active, revoked, expired, missing, legacy]);

      expect(result.kicked).toBe(3);
      expect(result.alive.map((s) => s.id)).toEqual([active.id, legacy.id]);
      expect(active.connected).toBe(true);
      expect(legacy.connected).toBe(true);
      for (const kicked of [revoked, expired, missing]) {
        expect(kicked.connected).toBe(false);
        expect(kicked.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
      }
    });

    test('DB 故障时 fail-open：本轮保留连接等下一轮，不清场在线会话', async () => {
      const svc = makeSweepService();
      const socket = makeSocket({ userId: 'u-dbdown', sid: sidOf('dbdown') });
      jest.spyOn(UserSession, 'find').mockImplementation(() => {
        throw new Error('db down');
      });

      const result = await svc._sweepRevokedSessions([socket]);

      expect(result.kicked).toBe(0);
      expect(result.alive).toEqual([socket]);
      expect(socket.connected).toBe(true);
    });
  });

  describe('入房复查的会话判据（#2）', () => {
    const makeRevalidateService = () => {
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      return svc;
    };

    test('设备会话仍可用 → 复查通过（不误伤正常连接）', async () => {
      const user = await makeUser('rok');
      const sid = sidOf('reval-ok');
      await makeSession(user._id, sid);

      const svc = makeRevalidateService();
      const socket = makeSocket({ userId: user._id, sid });
      svc.clients.set(socket.id, { id: socket.id, userId: socket.userId, rooms: new Set() });

      const result = await svc.revalidateSocket(socket);

      expect(result.ok).toBe(true);
      expect(socket.connected).toBe(true);
    });

    test('设备会话已吊销但 status/tokenVersion 未变 → 复查失败并断开', async () => {
      const user = await makeUser('rrev');
      const sid = sidOf('reval-revoked');
      await makeSession(user._id, sid, { status: 'revoked' });

      const svc = makeRevalidateService();
      const socket = makeSocket({ userId: user._id, sid });
      svc.clients.set(socket.id, { id: socket.id, userId: socket.userId, rooms: new Set() });

      const result = await svc.revalidateSocket(socket);

      // 前提自证：这条吊销没有推进 tokenVersion、也没有改 status，
      // 只有"复查 UserSession"这一条臂能拦住它
      expect(user.status).toBe('active');
      expect(socket.tokenVersion).toBeUndefined();
      expect(result.ok).toBe(false);
      expect(socket.connected).toBe(false);
      expect(socket.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
    });

    test('无 sid 的旧令牌跳过会话复查（与握手期同口径）', async () => {
      const user = await makeUser('rlegacy');
      const svc = makeRevalidateService();
      const socket = makeSocket({ userId: user._id, sid: null });
      socket.tokenVersion = user.tokenVersion ?? 0;

      const result = await svc.revalidateSocket(socket);

      expect(result.ok).toBe(true);
      expect(socket.connected).toBe(true);
    });
  });

  describe('未认证连接按 IP 配额（#9）', () => {
    const IP = '198.51.100.77';

    const makeQuotaService = () => {
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc.unauthConnectionsByIp = new Map();
      svc.io = {
        on: (ev, cb) => {
          if (ev === 'connection') svc.__connectionCb = cb;
        },
        sockets: { sockets: new Map(), adapter: { rooms: new Map() } },
        to: () => ({ emit: () => {} }),
      };
      svc.setupEventHandlers();
      return svc;
    };

    /** 走真实 connection 回调：配额占用、clients 登记、authTimer 全按生产形态建立 */
    const makeQuotaSocket = (ip = IP, token = null) => {
      const listeners = {};
      const socket = {
        id: `wsquota-${++counter}`,
        handshake: { auth: token ? { token } : {}, headers: {}, address: ip },
        authenticated: false,
        authing: false,
        connected: true,
        rooms: new Set(),
        emitted: [],
        emit(ev, data) {
          socket.emitted.push({ ev, data });
        },
        disconnect() {
          socket.connected = false;
        },
        join(room) {
          socket.rooms.add(room);
        },
        on(ev, cb) {
          listeners[ev] = cb;
        },
        __listeners: listeners,
      };
      return socket;
    };

    const connect = (svc, socket) => {
      svc.io.sockets.sockets.set(socket.id, socket);
      svc.__connectionCb(socket);
      return socket;
    };

    test('同一 IP 超出上限的第 N+1 条未认证连接被拒，其他 IP 不受影响', () => {
      const svc = makeQuotaService();
      const accepted = [];
      for (let i = 0; i < MAX_UNAUTHENTICATED_PER_IP; i++) {
        const socket = connect(svc, makeQuotaSocket());
        expect(socket.connected).toBe(true);
        accepted.push(socket);
      }
      expect(svc.unauthConnectionsByIp.get(IP)).toBe(MAX_UNAUTHENTICATED_PER_IP);

      const rejected = connect(svc, makeQuotaSocket());
      expect(rejected.connected).toBe(false);
      expect(rejected.emitted.some((e) => e.ev === 'error')).toBe(true);
      // 拒绝不得把计数继续抬高（否则一次越限会永久堵死该 IP）
      expect(svc.unauthConnectionsByIp.get(IP)).toBe(MAX_UNAUTHENTICATED_PER_IP);

      const otherIp = connect(svc, makeQuotaSocket('198.51.100.78'));
      expect(otherIp.connected).toBe(true);

      // 断开一条未认证连接 ⇒ 归还名额，下一条重连可进入
      accepted[0].__listeners.disconnect('client namespace disconnect');
      expect(svc.unauthConnectionsByIp.get(IP)).toBe(MAX_UNAUTHENTICATED_PER_IP - 1);
      expect(connect(svc, makeQuotaSocket()).connected).toBe(true);
    });

    test('认证成功立即归还名额（正常用户的累计登录次数不受配额影响）', async () => {
      const user = await makeUser('quota');
      const sid = sidOf('quota');
      await makeSession(user._id, sid);
      const token = signToken(user, sid);

      const svc = makeQuotaService();
      // 先有两条未认证连接占着同一 IP 的名额
      connect(svc, makeQuotaSocket());
      connect(svc, makeQuotaSocket());
      expect(svc.unauthConnectionsByIp.get(IP)).toBe(2);

      // 第三条不带 handshake token：本用例显式驱动认证链，
      // 避免 connection 回调里的握手认证与手动调用并发执行
      const socket = connect(svc, makeQuotaSocket());
      expect(svc.unauthConnectionsByIp.get(IP)).toBe(3);

      const ok = await svc.authenticateSocket(socket, token, null);

      expect(ok).toBe(true);
      expect(socket.authenticated).toBe(true);
      // 认证成功那条已归还，只剩两条未认证连接
      expect(svc.unauthConnectionsByIp.get(IP)).toBe(2);

      // 归还是幂等的：断开处理器再调一次不得把计数减成负数 / 误删他人名额
      svc._releaseUnauthenticatedSlot(socket);
      expect(svc.unauthConnectionsByIp.get(IP)).toBe(2);
    });

    test('取不到来源地址的连接不计数（无地址无从归属，强行记账只会误伤共享桶）', () => {
      const svc = makeQuotaService();
      const socket = connect(svc, makeQuotaSocket(null));
      expect(socket.connected).toBe(true);
      expect(svc.unauthConnectionsByIp.size).toBe(0);
    });
  });
});
