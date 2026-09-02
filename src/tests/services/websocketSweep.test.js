/**
 * WebSocket 周期清扫（R-2：会话期授权复查 + 踢出）测试
 *
 * 背景：P2-14 只封住「入房」面（受限房间 join-room 时 revalidateSocket）。
 * 已驻留在 role-management 房间的长连接，会话中被降级/停权/强制下线后
 * 不会被主动移出——runCleanupSweep 周期重查 status/tokenVersion 命中即断开。
 *
 * 复用 permissionHotReload.test.js 的最小实例模式（Object.create 原型），
 * 以 jest.doMock 替换 User 模型驱动 revalidateSocket 的三种判定分支。
 */

const path = require('path');

describe('WebSocket 周期清扫（R-2）', () => {
  /** 构造最小可测实例 + 注入假连接 */
  const makeService = ({ sockets = {}, clients = {} } = {}) => {
    const WebSocketService = require('../../services/websocketService');
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map(Object.entries(clients));
    svc._sweepRunning = false;
    svc.io = {
      sockets: { sockets: new Map(Object.entries(sockets)) },
      to: () => ({ emit: () => {} }),
      socketsAdapter: null,
    };
    return svc;
  };

  /** 构造假 socket：disconnect 置 connected=false（与 socket.io 同步语义一致） */
  const makeSocket = ({ id, userId, tokenVersion = 0, authenticated = true }) => {
    const socket = {
      id,
      userId,
      tokenVersion,
      authenticated,
      roleCodes: ['FIREFIGHTER'],
      connected: true,
      emitted: [],
      disconnect: jest.fn((force) => {
        socket.connected = false;
        socket.disconnectForced = force;
      }),
      emit: jest.fn((ev, data) => socket.emitted.push({ ev, data })),
    };
    return socket;
  };

  /** mock User 模型（revalidateSocket 内部惰性 require） */
  const mockUser = (userDoc) => {
    jest.doMock(path.join(__dirname, '../../models/User'), () => ({
      findById: jest.fn(() => ({
        select: () => ({
          populate: () => Promise.resolve(userDoc),
        }),
      })),
    }));
  };

  afterEach(() => {
    jest.resetModules();
    jest.dontMock(path.join(__dirname, '../../models/User'));
  });

  const clientEntry = (id, userId) => ({ id, userId, rooms: new Set(), connectedAt: new Date() });

  test('健康连接（active + tokenVersion 未变）不被踢出，快照被刷新', async () => {
    mockUser({ status: 'active', tokenVersion: 0, roles: [{ code: 'SECURITY_ADMIN' }] });
    const svc = makeService({
      sockets: { s1: makeSocket({ id: 's1', userId: 'u1' }) },
      clients: { s1: clientEntry('s1', 'u1') },
    });

    await svc.runCleanupSweep();

    const socket = svc.io.sockets.sockets.get('s1');
    expect(socket.disconnect).not.toHaveBeenCalled();
    expect(socket.connected).toBe(true);
    expect(socket.roleCodes).toEqual(['SECURITY_ADMIN']);
  });

  test('被停权用户（status≠active）的驻留连接被断开（auth-error + disconnect(true)）', async () => {
    mockUser({ status: 'inactive', tokenVersion: 0, roles: [{ code: 'SECURITY_ADMIN' }] });
    const svc = makeService({
      sockets: { s1: makeSocket({ id: 's1', userId: 'u1' }) },
      clients: { s1: clientEntry('s1', 'u1') },
    });

    await svc.runCleanupSweep();

    const socket = svc.io.sockets.sockets.get('s1');
    expect(socket.disconnect).toHaveBeenCalledWith(true);
    expect(socket.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
  });

  test('tokenVersion 被推进（改密/强制下线）的驻留连接被断开', async () => {
    mockUser({ status: 'active', tokenVersion: 5, roles: [] });
    const svc = makeService({
      sockets: { s1: makeSocket({ id: 's1', userId: 'u1', tokenVersion: 0 }) },
      clients: { s1: clientEntry('s1', 'u1') },
    });

    await svc.runCleanupSweep();

    const socket = svc.io.sockets.sockets.get('s1');
    expect(socket.disconnect).toHaveBeenCalledWith(true);
  });

  test('DB 瞬时故障路径：fail-closed 拒绝但不断开在线连接（等下一轮重试）', async () => {
    jest.doMock(path.join(__dirname, '../../models/User'), () => ({
      findById: jest.fn(() => {
        throw new Error('db down');
      }),
    }));
    const svc = makeService({
      sockets: { s1: makeSocket({ id: 's1', userId: 'u1' }) },
      clients: { s1: clientEntry('s1', 'u1') },
    });

    await svc.runCleanupSweep();

    const socket = svc.io.sockets.sockets.get('s1');
    expect(socket.disconnect).not.toHaveBeenCalled();
    expect(socket.connected).toBe(true);
  });

  test('未认证连接不参与授权复查（认证超时由 authTimer 负责）', async () => {
    const findById = jest.fn();
    jest.doMock(path.join(__dirname, '../../models/User'), () => ({ findById }));
    const svc = makeService({
      sockets: { s1: makeSocket({ id: 's1', userId: null, authenticated: false }) },
      clients: { s1: clientEntry('s1', null) },
    });

    await svc.runCleanupSweep();

    expect(findById).not.toHaveBeenCalled();
  });

  test('io.sockets 中已不存在的连接记录被清理（假死连接回收）', async () => {
    mockUser({ status: 'active', tokenVersion: 0, roles: [] });
    const svc = makeService({
      sockets: {}, // 无任何真实 socket
      clients: { stale: clientEntry('stale', 'u1') },
    });

    await svc.runCleanupSweep();

    expect(svc.clients.has('stale')).toBe(false);
  });
});
