/**
 * 权限热生效（免重登）后端侧测试
 *
 * 背景缺陷（本轮实测发现，此前无人上报）：
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

describe('roleController.emitWebSocketEvent 按事件类型正确分派', () => {
  /**
   * 直接从模块源码断言分派逻辑存在：控制器内部函数未导出，
   * 而端到端跑通需要完整 express+mongo 环境（已由集成测试覆盖），
   * 此处以静态不变量守住「eventType 被实际使用」这一点 ——
   * 这正是原缺陷的形态：参数收下了却没用。
   */
  const fs = require('fs');
  const source = fs.readFileSync(
    path.join(__dirname, '../../controllers/rolePermissionController.js'),
    'utf8'
  );

  test('emitWebSocketEvent 使用了 eventType 参数（原实现完全忽略）', () => {
    const fnStart = source.indexOf('const emitWebSocketEvent =');
    // 用行首的 '};' 定界，而非首个 '};'：函数体内的对象字面量
    // （const payload = { ...data, type: eventType };）会让后者提前截断
    const fnEnd = source.indexOf('\n};', fnStart);
    const body = source.slice(fnStart, fnEnd);
    expect(body).toContain('eventType');
    expect(body).toContain('emitPermissionUpdate');
    expect(body).toContain('emitRoleUpdate');
  });

  test('权限变更路径调用了定向同步 syncPermissionsToUsers', () => {
    expect(source).toContain('syncPermissionsToUsers');
    // 全局模式：对所有持有该角色的用户推送
    expect(source).toMatch(/syncPermissionsToUsers\(\s*req,\s*affectedUsers\.map/);
    // 克隆模式：只对目标用户推送
    expect(source).toMatch(/syncPermissionsToUsers\(\s*req,\s*\[targetUser\._id\]/);
  });

  test('用户角色变更也触发定向同步（此前完全没有任何通知）', () => {
    const userSource = fs.readFileSync(
      path.join(__dirname, '../../controllers/userController.js'),
      'utf8'
    );
    expect(userSource).toContain('syncPermissionsToUsers');
    expect(userSource).toMatch(/syncPermissionsToUsers\(\s*req,\s*\[user\._id\]/);
  });

  test('定向同步在 invalidateUserCache 之后调用（否则重算命中旧缓存）', () => {
    const userSource = fs.readFileSync(
      path.join(__dirname, '../../controllers/userController.js'),
      'utf8'
    );
    const cacheAt = userSource.indexOf('invalidateUserCache(user._id)');
    const syncAt = userSource.indexOf('syncPermissionsToUsers(req, [user._id]');
    expect(cacheAt).toBeGreaterThan(-1);
    expect(syncAt).toBeGreaterThan(cacheAt);
  });
});
