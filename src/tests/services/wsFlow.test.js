/**
 * WebSocket 全流程覆盖（冲 95% 批次 D2）
 *
 * 此前缺口：websocketService 语句 34.9%（连接/认证/房间/断开 29-316 未执行）。
 * 用「捕获 connection 回调 + 假 socket」驱动全流程，授权判定走真实 DB
 * （User/TokenBlacklist），覆盖认证各失败分支、受限房间入房、清理与统计。
 */

const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('WebSocket 全流程（批次 D2）', () => {
  let User;
  let Role;
  let Permission;
  let WebSocketService;
  let superUserId;
  let superUsername;
  let superRole;
  let superToken;
  const stamp = `ws${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  let counter = 0;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    WebSocketService = require('../../services/websocketService');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    const admin = await User.create({
      username: `wsadmin${stamp}`,
      email: `wsadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    superUserId = String(admin._id);
    superUsername = admin.username;
    superToken = jwt.sign(
      { userId: superUserId, username: superUsername, tokenVersion: 0, roles: ['SUPER_ADMIN'] },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteOne({ username: `wsadmin${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  /** 构造最小服务实例：捕获 connection 回调与 socket 注册表 */
  const makeService = () => {
    const svc = Object.create(WebSocketService.prototype);
    const state = { connectionCb: null, sent: [] };
    const socketRegistry = new Map();
    svc.clients = new Map();
    svc.userConnections = new Map();
    svc._sweepRunning = false;
    svc.io = {
      on: (ev, cb) => {
        if (ev === 'connection') state.connectionCb = cb;
      },
      sockets: { sockets: socketRegistry, adapter: { rooms: new Map() } },
      to: (target) => ({
        emit: (ev, data) => state.sent.push({ target, ev, data }),
      }),
    };
    svc.setupEventHandlers();
    return { svc, state, socketRegistry };
  };

  /** 假 socket：握手携带令牌，事件监听可捕获 */
  const makeSocket = (token, id) => {
    const socket = {
      id: id || `ws-${++counter}`,
      handshake: { auth: token ? { token } : {}, headers: {} },
      authenticated: false,
      authing: false,
      connected: true,
      rooms: new Set(),
      emitted: [],
      emit: (ev, data) => socket.emitted.push({ ev, data }),
      disconnect: () => {
        socket.connected = false;
      },
      on: () => {},
      join: (room) => socket.rooms.add(room),
      leave: (room) => socket.rooms.delete(room),
    };
    return socket;
  };

  const tick = () => new Promise((r) => setTimeout(r, 80));

  // 确定性等待：认证异步链受 DB 延迟影响，固定 sleep 偶发抖动
  const waitFor = async (cond, timeoutMs = 3000) => {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 20));
    }
    return cond();
  };

  test('握手认证成功 → 注册连接与用户映射', async () => {
    const { svc, state, socketRegistry } = makeService();
    const socket = makeSocket(superToken);
    socketRegistry.set(socket.id, socket);

    state.connectionCb(socket);
    await waitFor(() => socket.authenticated);

    expect(socket.authenticated).toBe(true);
    expect(socket.userId).toBe(superUserId);
    expect(svc.clients.get(socket.id).userId).toBe(superUserId);
    expect(svc.userConnections.get(superUserId).has(socket.id)).toBe(true);
    expect(socket.roleCodes).toContain('SUPER_ADMIN');
  });

  test('已拉黑令牌 → 认证失败断开', async () => {
    const { blacklistToken } = require('../../middleware/tokenBlacklist'); // jti 必须唯一：同 payload+iat+exp 会签出与 superToken 全等的 JWT（哈希相同），
    // 拉黑它等于拉黑 superToken 本身
    const deadToken = jwt.sign(
      {
        userId: superUserId,
        username: superUsername,
        tokenVersion: 0,
        roles: ['SUPER_ADMIN'],
        jti: `dead-${stamp}`,
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    await blacklistToken(deadToken, Math.floor(Date.now() / 1000) + 3600);

    const { state, socketRegistry } = makeService();
    const socket = makeSocket(deadToken);
    socketRegistry.set(socket.id, socket);

    state.connectionCb(socket);
    await waitFor(() => !socket.connected);

    expect(socket.authenticated).toBe(false);
    expect(socket.connected).toBe(false);
    expect(socket.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
  });

  test('tokenVersion 不匹配 / 用户不存在 → 断开', async () => {
    const { state, socketRegistry } = makeService();

    const badVersion = makeSocket(
      jwt.sign(
        { userId: superUserId, username: superUsername, tokenVersion: 99, roles: ['SUPER_ADMIN'] },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      )
    );
    socketRegistry.set(badVersion.id, badVersion);
    state.connectionCb(badVersion);
    await waitFor(() => !badVersion.connected);
    expect(badVersion.connected).toBe(false);

    const ghost = makeSocket(
      jwt.sign(
        { userId: String(new mongoose.Types.ObjectId()), username: 'ghost', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      )
    );
    socketRegistry.set(ghost.id, ghost);
    state.connectionCb(ghost);
    await waitFor(() => !ghost.connected);
    expect(ghost.connected).toBe(false);
  });

  test('受限房间：认证后可入，未认证/非法房间名被拒', async () => {
    const { state, socketRegistry } = makeService();
    const socket = makeSocket(superToken);
    socketRegistry.set(socket.id, socket);
    state.connectionCb(socket);
    await waitFor(() => socket.authenticated);
    if (!socket.authenticated) {
      console.error(
        'AUTH4_DEBUG',
        JSON.stringify({ emitted: socket.emitted, connected: socket.connected, id: socket.id })
      );
    }
    expect(socket.authenticated).toBe(true);

    // 捕获 join-room 监听器：setupEventHandlers 用 socket.on 注册，
    // 但假 socket 的 on 是空操作——直接重注册监听器捕获回调
    const roomListeners = {};
    socket.on = (ev, cb) => {
      roomListeners[ev] = cb;
    };
    // 重新走一遍注册（连接回调已注册过一次，假 socket.on 现在才捕获）
    // 为简化：直接调用 authenticate 后手动驱动 join-room 逻辑不现实——
    // 改为用带捕获的 socket 从头连接
    const socket2 = makeSocket(superToken);
    socket2.on = (ev, cb) => {
      roomListeners[ev] = cb;
    };
    socketRegistry.set(socket2.id, socket2);
    state.connectionCb(socket2);
    await waitFor(() => socket2.authenticated);
    expect(socket2.authenticated).toBe(true);

    await roomListeners['join-room']('role-management');
    if (!socket2.rooms.has('role-management')) {
      console.error(
        'JOIN_DEBUG',
        JSON.stringify({
          auth: socket2.authenticated,
          userId: socket2.userId,
          emitted: socket2.emitted,
          roleCodes: socket2.roleCodes,
          inMap: !!roomListeners['join-room'],
        })
      );
    }
    expect(socket2.rooms.has('role-management')).toBe(true);

    await roomListeners['join-room']('bogus-room');
    expect(
      socket2.emitted.some((e) => e.ev === 'error' && /无效的房间名/.test(e.data.message))
    ).toBe(true);

    await roomListeners['leave-room']('role-management');
    expect(socket2.rooms.has('role-management')).toBe(false);

    // 未认证连接 join-room 被拒
    const unauth = makeSocket(null);
    const unauthListeners = {};
    unauth.on = (ev, cb) => {
      unauthListeners[ev] = cb;
    };
    socketRegistry.set(unauth.id, unauth);
    state.connectionCb(unauth);
    await tick();
    await unauthListeners['join-room']('alarm');
    expect(unauth.emitted.some((e) => /请先完成认证/.test(e.data?.message || ''))).toBe(true);
  });

  test('disconnect 清理连接记录与用户映射', async () => {
    const { svc, state, socketRegistry } = makeService();
    const socket = makeSocket(superToken);
    const listeners = {};
    socket.on = (ev, cb) => {
      listeners[ev] = cb;
    };
    socketRegistry.set(socket.id, socket);
    state.connectionCb(socket);
    await waitFor(() => socket.authenticated);
    expect(svc.clients.has(socket.id)).toBe(true);

    listeners.disconnect('test');
    expect(svc.clients.has(socket.id)).toBe(false);
    expect(svc.userConnections.has(superUserId)).toBe(false);
  });

  test('getStats：总量与房间清单（不含明细）', async () => {
    const { svc } = makeService();
    const stats = svc.getStats();
    expect(stats.totalClients).toBe(0);
    expect(stats.maxConnections).toBe(1000);
    expect(Array.isArray(stats.rooms)).toBe(true);

    svc.clients.set('x', { id: 'x', rooms: new Set(['alarm']), connectedAt: new Date() });
    const detailed = svc.getStats({ includeClients: true });
    expect(detailed.clients).toHaveLength(1);
  });

  test('emitNotification：白名单房间放行、非白名单拒绝', () => {
    const { svc, state } = makeService();
    expect(svc.emitNotification('alarm', 'device_offline', '设备离线')).toBe(true);
    expect(state.sent[state.sent.length - 1].target).toBe('alarm');

    expect(svc.emitNotification('hacker-room', 'x', 'y')).toBe(false);
  });

  test('emitPermissionSync：重算失败降级为「仅通知」（无 permissionCodes 字段）', async () => {
    jest.doMock('../../models/User', () => ({
      getPermissions: async () => {
        throw new Error('db down');
      },
    }));
    const FreshService = require('../../services/websocketService');
    const svc = Object.create(FreshService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map([['u-fallback', new Set(['sid-fb'])]]);
    const sent = [];
    svc.io = {
      to: (t) => ({ emit: (ev, data) => sent.push({ target: t, ev, data }) }),
      sockets: { adapter: { rooms: new Map() } },
    };

    const result = await svc.emitPermissionSync(['u-fallback']);
    expect(result).toEqual({ notified: 1, offline: 0 });
    expect(sent).toHaveLength(1);
    expect(sent[0].ev).toBe('permission-sync');
    expect(sent[0].data.permissionCodes).toBeUndefined();

    jest.dontMock('../../models/User');
    jest.resetModules();
  });
});
