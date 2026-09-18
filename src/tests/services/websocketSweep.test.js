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

  /**
   * mock User 模型（批量复查内部惰性 require）
   *
   * L-29 后清扫走 `User.find({_id:{$in:[...]}})` 单次批量查询，
   * 故这里 mock 的是 find 而非 findById；传入的 userDoc 缺 _id 时
   * 自动补一个与 socket.userId 对应的标识，便于按用户映射。
   */
  const mockUser = (userDoc, id = 'u1') => {
    jest.doMock(path.join(__dirname, '../../models/User'), () => ({
      find: jest.fn(() => ({
        select: () => ({
          populate: () => Promise.resolve(userDoc === null ? [] : [{ _id: id, ...userDoc }]),
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
    mockUser({ status: 'active', tokenVersion: 0, roles: [{ code: 'SECURITY_ADMIN' }] }, 'u1');
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
    mockUser({ status: 'inactive', tokenVersion: 0, roles: [{ code: 'SECURITY_ADMIN' }] }, 'u1');
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
    mockUser({ status: 'active', tokenVersion: 5, roles: [] }, 'u1');
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
      find: jest.fn(() => {
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
    const find = jest.fn();
    jest.doMock(path.join(__dirname, '../../models/User'), () => ({ find }));
    const svc = makeService({
      sockets: { s1: makeSocket({ id: 's1', userId: null, authenticated: false }) },
      clients: { s1: clientEntry('s1', null) },
    });

    await svc.runCleanupSweep();

    expect(find).not.toHaveBeenCalled();
  });

  test('L-29：一轮清扫只发起 1 次批量查询，且同一用户的多连接只查一次', async () => {
    // 3 个连接分属 2 个用户（u1 两个标签页）→ 期望 1 次 find + 2 个去重后的 _id
    const find = jest.fn(() => ({
      select: () => ({
        populate: () =>
          Promise.resolve([
            { _id: 'u1', status: 'active', tokenVersion: 0, roles: [{ code: 'FIREFIGHTER' }] },
            { _id: 'u2', status: 'active', tokenVersion: 0, roles: [{ code: 'FIREFIGHTER' }] },
          ]),
      }),
    }));
    jest.doMock(path.join(__dirname, '../../models/User'), () => ({ find }));
    const svc = makeService({
      sockets: {
        a: makeSocket({ id: 'a', userId: 'u1' }),
        b: makeSocket({ id: 'b', userId: 'u1' }),
        c: makeSocket({ id: 'c', userId: 'u2' }),
      },
      clients: {
        a: clientEntry('a', 'u1'),
        b: clientEntry('b', 'u1'),
        c: clientEntry('c', 'u2'),
      },
    });

    await svc.runCleanupSweep();

    expect(find).toHaveBeenCalledTimes(1);
    expect(find.mock.calls[0][0]._id.$in).toHaveLength(2);
    // 三个连接均未断开，且各自拿到角色快照
    for (const id of ['a', 'b', 'c']) {
      expect(svc.io.sockets.sockets.get(id).connected).toBe(true);
      expect(svc.io.sockets.sockets.get(id).roleCodes).toEqual(['FIREFIGHTER']);
    }
  });

  test('L-29：批量结果中缺失的用户（已删除）仍按 kick 处理', async () => {
    // 批量查询只返回 u1，u2 的文档已不存在 → u2 的连接被踢
    const find = jest.fn(() => ({
      select: () => ({
        populate: () =>
          Promise.resolve([{ _id: 'u1', status: 'active', tokenVersion: 0, roles: [] }]),
      }),
    }));
    jest.doMock(path.join(__dirname, '../../models/User'), () => ({ find }));
    const svc = makeService({
      sockets: {
        a: makeSocket({ id: 'a', userId: 'u1' }),
        b: makeSocket({ id: 'b', userId: 'u2' }),
      },
      clients: { a: clientEntry('a', 'u1'), b: clientEntry('b', 'u2') },
    });

    await svc.runCleanupSweep();

    expect(svc.io.sockets.sockets.get('a').connected).toBe(true);
    const removed = svc.io.sockets.sockets.get('b');
    expect(removed.disconnect).toHaveBeenCalledWith(true);
    expect(removed.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
  });

  test('io.sockets 中已不存在的连接记录被清理（假死连接回收）', async () => {
    mockUser({ status: 'active', tokenVersion: 0, roles: [] }, 'u1');
    const svc = makeService({
      sockets: {}, // 无任何真实 socket
      clients: { stale: clientEntry('stale', 'u1') },
    });

    await svc.runCleanupSweep();

    expect(svc.clients.has('stale')).toBe(false);
  });
});
