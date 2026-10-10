/**
 * 权限热生效（免重登）后端侧测试
 *
 * 背景缺陷（本次改动实测发现，此前无人上报）：
 *  1. roleController.emitWebSocketEvent 接收 eventType 却从不使用，
 *     一律转发 emitRoleUpdate —— 前端 'permissions-updated' 监听从未触发；
 *  2. websocketService.emitPermissionUpdate 发的是单数 'permission-updated'，
 *     而前端监听复数 'permissions-updated'，两边永不相交（且因 1 从未被调用，
 *     这个错误的事件名一直没暴露）；
 *  3. 完全没有「按用户定向下发新权限」的能力：受影响用户多数无权进入
 *     role-management 房间，广播到不了他们 —— 这才是「必须重登」的根因。
 */

const path = require('path');

describe('权限热生效：WebSocket 定向推送', () => {
  /**
   * 构造最小可测实例，绕开真实 socket.io 服务器
   * @param {object} [opts]
   * @param {Map} [opts.userConnections] userId -> Set(socketId)
   */
  const makeService = ({ userConnections } = {}) => {
    const WebSocketService = require('../../services/websocketService');
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections =
      userConnections ||
      new Map([
        ['u-online', new Set(['sid-1', 'sid-2'])],
        ['u-other', new Set(['sid-9'])],
      ]);
    const emitted = [];
    svc.io = {
      to: (target) => ({ emit: (ev, data) => emitted.push({ target, ev, data }) }),
      sockets: { adapter: { rooms: new Map() } },
    };
    return { svc, emitted };
  };

  /** 用 jest.doMock 替换 User.getPermissions 的返回（emitPermissionSync 内部惰性 require） */
  const mockUserPermissions = (impl) => {
    jest.doMock(
      path.join(__dirname, '../../models/User'),
      () => ({
        getPermissions: impl,
      }),
      { virtual: false }
    );
  };

  afterEach(() => {
    jest.resetModules();
    jest.dontMock(path.join(__dirname, '../../models/User'));
  });

  test('emitPermissionUpdate 的事件名与前端监听一致（复数 permissions-updated）', () => {
    const { svc, emitted } = makeService();
    const data = svc.emitPermissionUpdate({ action: 'permissions-updated' });
    expect(data.type).toBe('permissions-updated');
    expect(emitted).toHaveLength(1);
    expect(emitted[0].ev).toBe('permissions-updated');
    expect(emitted[0].target).toBe('role-management');
  });

  test('emitPermissionSync 向在线用户的每条连接定向投递完整权限码集合', async () => {
    mockUserPermissions(async () => ['device:read', 'user:read']);
    const { svc, emitted } = makeService();

    const result = await svc.emitPermissionSync(['u-online'], { action: 'permissions-updated' });

    expect(result).toEqual({ notified: 1, offline: 0 });
    // 同一用户的两条连接各收一份（多标签页场景）
    expect(emitted).toHaveLength(2);
    expect(emitted.map((e) => e.target).sort()).toEqual(['sid-1', 'sid-2']);
    for (const e of emitted) {
      expect(e.ev).toBe('permission-sync');
      expect(e.data.permissionCodes).toEqual(['device:read', 'user:read']);
      expect(e.data.action).toBe('permissions-updated');
      expect(typeof e.data.timestamp).toBe('string');
    }
  });

  test('离线用户不重算也不投递（下次登录经 /auth/me 自然生效）', async () => {
    const getPermissions = jest.fn(async () => ['device:read']);
    mockUserPermissions(getPermissions);
    const { svc, emitted } = makeService();

    const result = await svc.emitPermissionSync(['u-offline-1', 'u-offline-2']);

    expect(result).toEqual({ notified: 0, offline: 2 });
    expect(emitted).toHaveLength(0);
    // 关键：不为离线用户做无用的权限重算（角色下挂几百人时这是实打实的开销）
    expect(getPermissions).not.toHaveBeenCalled();
  });

  test('userIds 去重且忽略空值（ObjectId 与字符串混入时不重复推送）', async () => {
    mockUserPermissions(async () => ['a:b']);
    const { svc, emitted } = makeService({
      userConnections: new Map([['u1', new Set(['s1'])]]),
    });

    const result = await svc.emitPermissionSync(['u1', 'u1', null, undefined, '']);

    expect(result.notified).toBe(1);
    expect(emitted).toHaveLength(1);
  });

  test('权限重算失败时降级为「仅通知」：不下发 permissionCodes', async () => {
    mockUserPermissions(async () => {
      throw new Error('db down');
    });
    const { svc, emitted } = makeService();

    const result = await svc.emitPermissionSync(['u-online']);

    expect(result.notified).toBe(1);
    expect(emitted).toHaveLength(2);
    for (const e of emitted) {
      // 字段缺失是前端「回退到主动拉 /auth/me」的信号，
      // 绝不能下发一份可能过期的集合去覆盖本地状态
      expect(e.data.permissionCodes).toBeUndefined();
      expect(e.data.type).toBe('permission-sync');
    }
  });

  test('空 userIds 列表为无操作（不抛错、不推送）', async () => {
    mockUserPermissions(async () => ['a:b']);
    const { svc, emitted } = makeService();
    await expect(svc.emitPermissionSync([])).resolves.toEqual({ notified: 0, offline: 0 });
    await expect(svc.emitPermissionSync()).resolves.toEqual({ notified: 0, offline: 0 });
    expect(emitted).toHaveLength(0);
  });
});

describe('控制器侧：事件分派与定向同步（真实 HTTP 驱动）', () => {
  const request = require('supertest');
  const jwt = require('jsonwebtoken');

  let app;
  let User;
  let Role;
  let Permission;
  let wsService;
  let admin; // 持 *:* 的操作者
  let adminToken;
  let target; // 被改权限/角色的普通用户
  let probeRole; // 非内置角色，用于 assignPermissions 全局模式
  let probePerm; // 探针权限（被授予）
  let otherPerm; // 探针权限（保持自身持有，避免越权拒绝）

  const PASSWORD = 'Qz7#Lm42vTx9';

  beforeAll(async () => {
    // 注意顺序：上一个 describe 的 afterEach 调用了 jest.resetModules()，
    // 模块注册表已是全新的。必须**先** require 模型（绑定到新 mongoose
    // 实例），**后** require mongoose 并在同一实例上 connect；否则模型绑定到实例 B
    // 而连接在实例 A，每个操作都会 buffering timeout。
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      {
        $setOnInsert: {
          name: '\u5168\u90e8\u6743\u9650',
          code: '*:*',
          type: 'api',
          module: 'system',
        },
      },
      { upsert: true, new: true }
    );
    probePerm = await Permission.findOneAndUpdate(
      { code: 'hotreload:read' },
      {
        $setOnInsert: {
          name: '\u70ed\u751f\u6548\u8bfb',
          code: 'hotreload:read',
          type: 'api',
          module: 'hotreload',
        },
      },
      { upsert: true, new: true }
    );
    otherPerm = await Permission.findOneAndUpdate(
      { code: 'hotreload:write' },
      {
        $setOnInsert: {
          name: '\u70ed\u751f\u6548\u5199',
          code: 'hotreload:write',
          type: 'api',
          module: 'hotreload',
        },
      },
      { upsert: true, new: true }
    );

    const adminRole = await Role.findOneAndUpdate(
      { code: 'HOTRELOAD_ADMIN_ROLE' },
      {
        $setOnInsert: {
          code: 'HOTRELOAD_ADMIN_ROLE',
          name: '\u70ed\u751f\u6548\u7ba1\u7406\u5458',
          level: 9,
          permissions: [wildcard._id, probePerm._id, otherPerm._id],
        },
      },
      { upsert: true, new: true }
    );
    probeRole = await Role.findOneAndUpdate(
      { code: 'HOTRELOAD_PROBE_ROLE' },
      {
        $setOnInsert: {
          code: 'HOTRELOAD_PROBE_ROLE',
          name: '\u70ed\u751f\u6548\u63a2\u9488\u89d2\u8272',
          level: 3,
          permissions: [probePerm._id],
        },
      },
      { upsert: true, new: true }
    );

    admin = await User.create({
      username: `hr_admin_${Date.now().toString(36)}`,
      email: `hr_admin_${Date.now().toString(36)}@example.com`,
      password: PASSWORD,
      roles: [adminRole._id],
    });
    target = await User.create({
      username: `hr_target_${Date.now().toString(36)}`,
      email: `hr_target_${Date.now().toString(36)}@example.com`,
      password: PASSWORD,
      roles: [probeRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();
    wsService = {
      emitRoleUpdate: jest.fn(),
      emitPermissionUpdate: jest.fn(),
      emitPermissionSync: jest.fn().mockResolvedValue({ notified: 0, offline: 0 }),
    };
    app.set('wsService', wsService);
  });

  afterAll(async () => {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    wsService.emitRoleUpdate.mockClear();
    wsService.emitPermissionUpdate.mockClear();
    wsService.emitPermissionSync.mockClear();
  });

  test('\u6309\u4e8b\u4ef6\u7c7b\u578b\u5206\u6d3e\uff1a\u6743\u9650\u53d8\u66f4\u8d70 emitPermissionUpdate\u3001\u89d2\u8272\u521b\u5efa\u8d70 emitRoleUpdate', async () => {
    // \u6743\u9650\u53d8\u66f4\uff1aPUT /api/roles/:id/permissions\uff08\u975e\u8d85\u7ba1\u89d2\u8272\u3001\u65e0 targetUserId\uff09
    const res = await request(app)
      .put(`/api/roles/${probeRole._id}/permissions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ permissions: [String(probePerm._id), String(otherPerm._id)] });
    expect(res.status).toBe(200);

    // \u539f\u7f3a\u9677\u5f62\u6001\uff1a\u6536\u4e0b eventType \u5374\u4e00\u5f8b\u8f6c\u53d1 emitRoleUpdate
    expect(wsService.emitPermissionUpdate).toHaveBeenCalledTimes(1);
    expect(wsService.emitRoleUpdate).not.toHaveBeenCalled();
    const payload = wsService.emitPermissionUpdate.mock.calls[0][0];
    expect(payload.type).toBe('permissions-updated');
    expect(payload.action).toBe('permissions-updated');
    expect(String(payload.roleId)).toBe(String(probeRole._id));

    // \u5bf9\u7167\uff1a\u89d2\u8272\u521b\u5efa\uff08role-created\uff09\u5fc5\u987b\u8d70 emitRoleUpdate
    const created = await request(app)
      .post('/api/roles')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: `\u5206\u6d3e\u63a2\u9488${Date.now().toString(36)}`,
        // 路由校验器要求 code 匹配 /^[A-Z_]+$/ —— 不能含数字/小写
        code: `HOTRELOAD_CREATED_${Date.now()
          .toString(36)
          .replace(/[0-9]/g, (d) => 'ABCDEFGHIJ'[Number(d)])
          .toUpperCase()}`,
        level: 3,
        permissions: [String(probePerm._id)],
      });
    expect(created.status).toBe(201);
    expect(wsService.emitRoleUpdate).toHaveBeenCalledTimes(1);
    expect(wsService.emitRoleUpdate.mock.calls[0][0].type).toBe('role-created');
    expect(wsService.emitPermissionUpdate).toHaveBeenCalledTimes(1); // \u4ecd\u4e3a\u4e0a\u6b21\u90a3\u4e00\u6b21
  });

  test('\u5168\u5c40\u6a21\u5f0f\uff1a\u5411\u6301\u6709\u8be5\u89d2\u8272\u7684\u5168\u90e8\u7528\u6237\u5b9a\u5411\u540c\u6b65\uff08\u4e0d\u662f\u5e7f\u64ad\uff09', async () => {
    const res = await request(app)
      .put(`/api/roles/${probeRole._id}/permissions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ permissions: [String(probePerm._id), String(otherPerm._id)] });
    expect(res.status).toBe(200);

    expect(wsService.emitPermissionSync).toHaveBeenCalledTimes(1);
    const [userIds, meta] = wsService.emitPermissionSync.mock.calls[0];
    expect(Array.isArray(userIds)).toBe(true);
    expect(userIds.map(String)).toContain(String(target._id));
    expect(meta).toMatchObject({ action: 'permissions-updated' });
  });

  test('\u514b\u9686\u6a21\u5f0f\uff1a\u53ea\u5411\u76ee\u6807\u7528\u6237\u5b9a\u5411\u540c\u6b65\uff08\u907f\u514d\u8bef\u4f24\u5176\u4ed6\u6301\u6709\u8005\uff09', async () => {
    // \u6784\u9020\u4e00\u4e2a\u5185\u7f6e\u89d2\u8272 + \u76ee\u6807\u7528\u6237\u6301\u6709\u5b83
    const builtin = await Role.findOneAndUpdate(
      { code: 'HOTRELOAD_BUILTIN_ROLE' },
      {
        $setOnInsert: {
          code: 'HOTRELOAD_BUILTIN_ROLE',
          name: '\u70ed\u751f\u6548\u5185\u7f6e\u89d2\u8272',
          level: 3,
          isBuiltIn: true,
          permissions: [probePerm._id],
        },
      },
      { upsert: true, new: true }
    );
    await User.findByIdAndUpdate(target._id, { $set: { roles: [builtin._id] } });

    const res = await request(app)
      .put(`/api/roles/${builtin._id}/permissions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        permissions: [String(probePerm._id), String(otherPerm._id)],
        targetUserId: String(target._id),
      });
    expect(res.status).toBe(200);

    expect(wsService.emitPermissionSync).toHaveBeenCalledTimes(1);
    const [userIds, meta] = wsService.emitPermissionSync.mock.calls[0];
    expect(userIds.map(String)).toEqual([String(target._id)]);
    expect(meta).toMatchObject({ action: 'permissions-cloned' });

    await User.findByIdAndUpdate(target._id, { $set: { roles: [probeRole._id] } });
  });

  test('\u7528\u6237\u89d2\u8272\u53d8\u66f4\uff08assignRoles\uff09\u540c\u6837\u89e6\u53d1\u5b9a\u5411\u540c\u6b65', async () => {
    const res = await request(app)
      .put(`/api/users/${target._id}/roles`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ roles: [String(probeRole._id)] });
    expect(res.status).toBe(200);

    expect(wsService.emitPermissionSync).toHaveBeenCalledTimes(1);
    const [userIds, meta] = wsService.emitPermissionSync.mock.calls[0];
    expect(userIds.map(String)).toEqual([String(target._id)]);
    expect(meta).toMatchObject({ action: 'roles-assigned' });
  });

  test('\u5b9a\u5411\u540c\u6b65\u53d1\u751f\u5728\u7f13\u5b58\u5931\u6548\u4e4b\u540e\uff08\u5426\u5219\u91cd\u7b97\u547d\u4e2d\u65e7\u7f13\u5b58\uff09', async () => {
    // \u884c\u4e3a\u5224\u636e\uff1a\u5728\u53d8\u66f4\u524d\u5148\u628a\u201c\u65e7\u6743\u9650\u96c6\u201d\u704c\u5165\u8fdb\u7a0b\u5185\u7f13\u5b58\uff0c
    // \u7136\u540e\u8d70 assignRoles \u628a\u76ee\u6807\u7528\u6237\u6362\u5230\u7a7a\u6743\u9650\u89d2\u8272\u3002\u82e5\u540c\u6b65\u53d1\u751f\u5728\u5931\u6548\u524d\uff0c
    // \u56de\u8c03\u91cc\u91cd\u7b97\u5f97\u5230\u7684\u5c06\u662f**\u65e7**\u96c6\u5408\uff1b\u53ea\u6709\u5728\u5931\u6548\u4e4b\u540e\uff0c\u91cd\u7b97\u624d\u80fd\u770b\u5230\u65b0\u96c6\u5408\u3002
    const userPermissionService = require('../../services/userPermissionService');
    const emptyRole = await Role.findOneAndUpdate(
      { code: 'HOTRELOAD_EMPTY_ROLE' },
      {
        $setOnInsert: {
          code: 'HOTRELOAD_EMPTY_ROLE',
          name: '\u70ed\u751f\u6548\u7a7a\u6743\u9650\u89d2\u8272',
          level: 3,
          permissions: [],
        },
      },
      { upsert: true, new: true }
    );

    await User.findByIdAndUpdate(target._id, { $set: { roles: [probeRole._id] } });
    userPermissionService.invalidatePermissionCacheLocal();
    // \u704c\u5165\u7f13\u5b58\uff1a\u6b64\u65f6\u76ee\u6807\u7528\u6237\u62e5\u6709 hotreload:read
    expect(await userPermissionService.getPermissions(target._id)).toContain('hotreload:read');

    // \u8ba9 emitPermissionSync \u771f\u5b9e\u91cd\u7b97\u5e76\u8bb0\u5f55\u7ed3\u679c\uff08\u800c\u4e0d\u662f\u76f4\u63a5\u8c03 User.getPermissions\uff09
    const seen = [];
    wsService.emitPermissionSync.mockImplementation(async (userIds) => {
      const ids = [...new Set((userIds || []).map((id) => String(id)).filter(Boolean))];
      for (const id of ids) {
        seen.push({ id, perms: await User.getPermissions(id) });
      }
      return { notified: ids.length, offline: 0 };
    });

    const res = await request(app)
      .put(`/api/users/${target._id}/roles`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ roles: [String(emptyRole._id)] });
    expect(res.status).toBe(200);

    // \u8c03\u7528\u65f6\u673a\u6b63\u786e\u7684\u8bc1\u636e\uff1a\u56de\u8c03\u91cc\u770b\u5230\u7684\u662f\u53d8\u66f4**\u540e**\u7684\u6743\u9650\u96c6\uff08\u7a7a\uff09\uff0c
    // \u82e5\u540c\u6b65\u53d1\u751f\u5728\u5931\u6548\u524d\uff0c\u8fd9\u91cc\u4f1a\u770b\u5230\u7f13\u5b58\u91cc\u7684 'hotreload:read'\u3002
    expect(seen).toHaveLength(1);
    expect(seen[0].id).toBe(String(target._id));
    expect(seen[0].perms).not.toContain('hotreload:read');

    // \u6062\u590d\uff1a\u76ee\u6807\u7528\u6237\u56de\u5230\u63a2\u9488\u89d2\u8272\uff0c\u6e05\u7f13\u5b58\u907f\u514d\u4e32\u6270\u540e\u7eed\u7528\u4f8b
    await User.findByIdAndUpdate(target._id, { $set: { roles: [probeRole._id] } });
    userPermissionService.invalidatePermissionCacheLocal();
  });
});
