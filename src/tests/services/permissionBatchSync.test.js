/**
 * A-5：权限热生效推送的批量化
 *
 * 缺陷：emitPermissionSync 对每个受影响用户串行执行
 *   · `io.in(user:<id>).fetchSockets()`（Redis 模式，一次跨实例往返）
 *   · `User.getPermissions(id)`（一次三层 populate 查库）
 * 角色下挂几百人时，一次角色变更广播被拉成几百个串行往返。
 *
 * 修复口径：
 *   · 在线判定：一次 `io.in([user:a, user:b, ...]).fetchSockets()`，用每条连接的
 *     rooms 反查所属用户（RemoteSocket 不携带 socket.userId）；
 *   · 权限重算：一次 `User.find({_id: {$in: [...]}}).populate(...)`；
 *   · 缓存语义不变：命中跳过、不存在写 5 秒空结果、有文档写 30 秒、
 *     查库期间发生本地失效则整批不写回。
 *
 * 本套件同时钉住「只查在线用户」——离线用户不做无用的权限重算。
 */
'use strict';

const mongoose = require('mongoose');

const User = require('../../models/User');
const Role = require('../../models/Role');
const Permission = require('../../models/Permission');
const service = require('../../services/userPermissionService');
const sharedCache = require('../../services/sharedCache');

const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

describe('userPermissionService.getPermissionsForUsers（批量权限查询）', () => {
  let readPerm;
  let writePerm;
  let role;
  let userA;
  let userB;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const tag = Date.now().toString(36);
    readPerm = await Permission.create({
      name: '批量读',
      code: 'batchperm:read',
      type: 'api',
      module: 'batch',
    });
    writePerm = await Permission.create({
      name: '批量写',
      code: 'batchperm:write',
      type: 'api',
      module: 'batch',
    });
    role = await Role.create({
      code: `BATCH_ROLE_${tag.toUpperCase()}`,
      name: '批量测试角色',
      level: 3,
      permissions: [readPerm._id, writePerm._id],
    });
    userA = await User.create({
      username: `batch_a_${tag}`,
      email: `batch_a_${tag}@example.com`,
      password: 'Qz7#Lm42vTx9',
      roles: [role._id],
    });
    userB = await User.create({
      username: `batch_b_${tag}`,
      email: `batch_b_${tag}@example.com`,
      password: 'Qz7#Lm42vTx9',
      roles: [role._id],
    });
  });

  beforeEach(() => {
    service.invalidatePermissionCacheLocal();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('多个未命中用户合并为一次 $in 查询，返回逐用户权限集', async () => {
    const findSpy = jest.spyOn(User, 'find');
    const map = await service.getPermissionsForUsers([
      String(userA._id),
      userB._id,
      String(userA._id), // 去重
    ]);

    expect(findSpy).toHaveBeenCalledTimes(1);
    expect(findSpy.mock.calls[0][0]).toEqual({
      _id: { $in: [String(userA._id), String(userB._id)] },
    });
    expect(map.size).toBe(2);
    expect(map.get(String(userA._id)).sort()).toEqual([readPerm.code, writePerm.code].sort());
    expect(map.get(String(userB._id)).sort()).toEqual([readPerm.code, writePerm.code].sort());
  });

  test('第二次调用全部命中缓存，不再查库', async () => {
    await service.getPermissionsForUsers([String(userA._id), String(userB._id)]);
    const findSpy = jest.spyOn(User, 'find');
    const map = await service.getPermissionsForUsers([String(userA._id), String(userB._id)]);

    expect(findSpy).not.toHaveBeenCalled();
    expect(map.get(String(userA._id))).toContain(readPerm.code);
  });

  test('查不到的用户映射为空数组，并写 5 秒短 TTL', async () => {
    const missing = new mongoose.Types.ObjectId().toString();
    const base = 1_700_000_000_000;
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(base);
    const findSpy = jest.spyOn(User, 'find');

    const first = await service.getPermissionsForUsers([missing]);
    expect(first.get(missing)).toEqual([]);
    expect(findSpy).toHaveBeenCalledTimes(1);

    // 30 秒 TTL 内仍应命中缓存；越过 5 秒短 TTL 后必须重查
    nowSpy.mockReturnValue(base + 5001);
    await service.getPermissionsForUsers([missing]);
    expect(findSpy).toHaveBeenCalledTimes(2);
  });

  test('查库期间的本地失效 ⇒ 整批结果不得写回缓存', async () => {
    const q1 = deferred();
    jest.spyOn(User, 'find').mockReturnValue({ populate: () => q1.promise });

    const inflight = service.getPermissionsForUsers([String(userA._id)]);
    service.invalidatePermissionCacheLocal();
    q1.resolve([
      {
        _id: userA._id,
        roles: [{ permissions: [{ code: 'stale:perm' }] }],
      },
    ]);
    expect((await inflight).get(String(userA._id))).toEqual(['stale:perm']);

    // 失效之后的新读取必须重新查库，而不是命中刚被撤销的旧结果
    const q2 = deferred();
    const findSpy = jest.spyOn(User, 'find').mockReturnValue({ populate: () => q2.promise });
    findSpy.mockClear(); // 与第一趟的调用计数分开
    const after = service.getPermissionsForUsers([String(userA._id)]);
    expect(findSpy).toHaveBeenCalledTimes(1);
    q2.resolve([
      {
        _id: userA._id,
        roles: [{ permissions: [{ code: 'fresh:perm' }] }],
      },
    ]);
    expect((await after).get(String(userA._id))).toEqual(['fresh:perm']);
  });
});

describe('WebSocketService.emitPermissionSync（批量在线判定 + 批量重算）', () => {
  const WebSocketService = require('../../services/websocketService');

  let origIsRedisEnabled;

  const makeService = () => {
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map([
      ['u-a', new Set(['sid-a1', 'sid-a2'])],
      ['u-b', new Set(['sid-b1'])],
    ]);
    const emitted = [];
    svc.io = {
      in: jest.fn(),
      to: (target) => ({ emit: (ev, data) => emitted.push({ target, ev, data }) }),
    };
    return { svc, emitted };
  };

  beforeEach(() => {
    origIsRedisEnabled = sharedCache.isRedisEnabled;
  });

  afterEach(() => {
    sharedCache.isRedisEnabled = origIsRedisEnabled;
    jest.restoreAllMocks();
  });

  test('本地模式：只为在线用户做一次批量重算，离线用户直接计入 offline', async () => {
    sharedCache.isRedisEnabled = () => false;
    const { svc, emitted } = makeService();
    const batchSpy = jest.spyOn(service, 'getPermissionsForUsers').mockResolvedValue(
      new Map([
        ['u-a', ['a:read']],
        ['u-b', ['b:read']],
      ])
    );

    const result = await svc.emitPermissionSync(['u-a', 'u-b', 'u-offline'], {
      action: 'roles-assigned',
    });

    expect(result).toEqual({ notified: 2, offline: 1 });
    expect(batchSpy).toHaveBeenCalledTimes(1);
    expect(batchSpy).toHaveBeenCalledWith(['u-a', 'u-b']);
    expect(emitted.map((e) => e.target).sort()).toEqual(['sid-a1', 'sid-a2', 'sid-b1']);
    const byTarget = Object.fromEntries(emitted.map((e) => [e.target, e.data]));
    expect(byTarget['sid-a1'].permissionCodes).toEqual(['a:read']);
    expect(byTarget['sid-b1'].permissionCodes).toEqual(['b:read']);
  });

  test('Redis 模式：一次 fetchSockets 覆盖全部目标房间，用 rooms 反查在线用户', async () => {
    sharedCache.isRedisEnabled = () => true;
    const { svc, emitted } = makeService();
    svc.io.in = jest.fn(() => ({
      fetchSockets: async () => [
        { id: 'remote-1', rooms: ['user:u-a', 'remote-1'] },
        { id: 'remote-2', rooms: new Set(['user:u-b', 'remote-2']) },
        // 不相关的房间成员不应影响在线判定
        { id: 'remote-3', rooms: ['role-management', 'remote-3'] },
      ],
    }));
    const batchSpy = jest
      .spyOn(service, 'getPermissionsForUsers')
      .mockResolvedValue(new Map([['u-a', ['a:read']]]));

    const result = await svc.emitPermissionSync(['u-a', 'u-b', 'u-offline']);

    expect(result).toEqual({ notified: 2, offline: 1 });
    expect(svc.io.in).toHaveBeenCalledTimes(1);
    expect(svc.io.in).toHaveBeenCalledWith(['user:u-a', 'user:u-b', 'user:u-offline']);
    expect(batchSpy).toHaveBeenCalledTimes(1);
    expect(batchSpy).toHaveBeenCalledWith(['u-a', 'u-b']);
    expect(emitted.map((e) => e.target)).toEqual(['user:u-a', 'user:u-b']);
    expect(emitted[0].data.permissionCodes).toEqual(['a:read']);
    expect(emitted[1].data.permissionCodes).toBeUndefined();
  });

  test('批量重算失败 ⇒ 降级为「仅通知」，在线用户仍收到事件', async () => {
    sharedCache.isRedisEnabled = () => false;
    const { svc, emitted } = makeService();
    jest.spyOn(service, 'getPermissionsForUsers').mockRejectedValue(new Error('db down'));

    const result = await svc.emitPermissionSync(['u-a']);

    expect(result).toEqual({ notified: 1, offline: 0 });
    expect(emitted).toHaveLength(2);
    for (const e of emitted) {
      expect(e.data.permissionCodes).toBeUndefined();
      expect(e.data.type).toBe('permission-sync');
    }
  });
});
