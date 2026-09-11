/**
 * WebSocket 服务分支补漏（覆盖率棘轮修复）
 *
 * 背景：并行开发新增了 CORS 构造校验、auth 事件防重入、密码修改失效等分支，
 * 但未补对应测试，导致 branches 从 62.9% 滑落到 59.55%，低于门槛 61%。
 * 本文件专补这些缺口，不重复 wsFlow / websocketSweep 已覆盖的路径。
 *
 * 策略：构造函数 CORS 分支需要真正 new WebSocketService(server)，
 * 不能用 Object.create(prototype) 跳过构造器；其余分支沿用假 socket 模式。
 */

const http = require('http');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const path = require('path');

describe('WebSocket 分支补漏', () => {
  // ========== 构造函数 CORS 分支 ==========
  describe('构造函数 CORS 校验', () => {
    const savedCors = process.env.CORS_ORIGIN;

    afterEach(() => {
      // 还原环境变量与模块缓存，避免污染后续用例
      if (savedCors === undefined) delete process.env.CORS_ORIGIN;
      else process.env.CORS_ORIGIN = savedCors;
      jest.resetModules();
    });

    test('CORS_ORIGIN="*" 时构造函数抛错拒绝启动', () => {
      // 通配符 '*' 在 Socket.IO cors.origin 下等于接受任意来源跨域请求，
      // 安全策略显式禁止——构造函数应抛出而非静默降级
      process.env.CORS_ORIGIN = '*';
      jest.resetModules();
      const WebSocketService = require('../../services/websocketService');
      const server = http.createServer();
      try {
        expect(() => new WebSocketService(server)).toThrow(/通配符/);
      } finally {
        server.close();
      }
    });

    test('未配置 CORS_ORIGIN 时回退本地开发白名单数组', () => {
      // 未配置时应回退到固定的 localhost/127.0.0.1 白名单，
      // 与 app.js HTTP CORS 保持一致（避免 WS/HTTP 同源策略漂移）
      delete process.env.CORS_ORIGIN;
      jest.resetModules();
      const WebSocketService = require('../../services/websocketService');
      const server = http.createServer();
      let svc;
      try {
        svc = new WebSocketService(server);
        // io.opts.cors.origin 应为包含 localhost:3001 等的数组
        const origin = svc.io.opts.cors.origin;
        expect(Array.isArray(origin)).toBe(true);
        expect(origin).toContain('http://localhost:3001');
        expect(origin).toContain('http://127.0.0.1:5173');
      } finally {
        if (svc) svc.dispose();
        server.close();
      }
    });

    test('配置了具体来源时按逗号分隔解析为数组', () => {
      // 生产环境通常配置多个来源（前端+管理端），需正确拆分并 trim
      process.env.CORS_ORIGIN = 'https://a.example.com , https://b.example.com';
      jest.resetModules();
      const WebSocketService = require('../../services/websocketService');
      const server = http.createServer();
      let svc;
      try {
        svc = new WebSocketService(server);
        const origin = svc.io.opts.cors.origin;
        expect(Array.isArray(origin)).toBe(true);
        expect(origin).toEqual(['https://a.example.com', 'https://b.example.com']);
      } finally {
        if (svc) svc.dispose();
        server.close();
      }
    });
  });

  // ========== dispose 清理分支 ==========
  describe('dispose 资源回收', () => {
    test('dispose 关闭 io 并清理全部连接', () => {
      // dispose 内部 io.close() 可能因状态异常抛错，不应阻断优雅关闭流程
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map([['s1', { id: 's1' }]]);
      svc.userConnections = new Map();
      svc._cleanupTimer = null;
      svc._adapterClients = [];
      const disconnected = [];
      svc.io = {
        sockets: {
          sockets: new Map([
            [
              's1',
              {
                disconnect: (force) => {
                  disconnected.push({ id: 's1', force });
                },
              },
            ],
          ]),
        },
        close: jest.fn(),
      };

      svc.dispose();

      expect(disconnected).toHaveLength(1);
      expect(disconnected[0].force).toBe(true);
      expect(svc.clients.size).toBe(0);
      expect(svc.io.close).toHaveBeenCalled();
    });

    test('dispose 中 io.close() 抛错时不向外传播', () => {
      // io.close() 失败仅告警，不阻断优雅关闭
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc._cleanupTimer = null;
      svc._adapterClients = [];
      svc.io = {
        sockets: { sockets: new Map() },
        close: () => {
          throw new Error('close failed');
        },
      };

      expect(() => svc.dispose()).not.toThrow();
    });

    test('dispose 回收 Redis adapter 专用连接', () => {
      // _adapterClients 中的每个 client 都应被 disconnect，
      // 即使某个 disconnect 抛错也不影响后续回收
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc._cleanupTimer = null;
      const dc1 = jest.fn();
      const dc2 = jest.fn(() => {
        throw new Error('already closed');
      });
      svc._adapterClients = [{ disconnect: dc1 }, { disconnect: dc2 }];
      svc.io = {
        sockets: { sockets: new Map() },
        close: jest.fn(),
      };

      svc.dispose();

      expect(dc1).toHaveBeenCalled();
      expect(dc2).toHaveBeenCalled();
      expect(svc._adapterClients).toEqual([]);
    });
  });

  // ========== extractHandshakeToken cookie 路径 ==========
  describe('extractHandshakeToken cookie 回退', () => {
    test('握手无 auth.token 但有 access_token cookie 时提取成功', () => {
      // I-01：浏览器同源场景下 cookie 自动携带，是 token 的第二来源
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      const socket = {
        handshake: {
          auth: {},
          headers: { cookie: 'access_token=cookie-jwt-value; other=val' },
        },
      };
      expect(svc.extractHandshakeToken(socket)).toBe('cookie-jwt-value');
    });

    test('既无 auth.token 也无 cookie 时返回 null', () => {
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      const socket = { handshake: { auth: {}, headers: {} } };
      expect(svc.extractHandshakeToken(socket)).toBeNull();
    });
  });

  // ========== emitRoleUpdate ==========
  describe('emitRoleUpdate', () => {
    test('向 role-management 房间广播并返回带时间戳的事件数据', () => {
      // emitRoleUpdate 是权限变更推送的核心方法，需确认事件结构与投递目标
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      const sent = [];
      svc.io = {
        to: (room) => ({
          emit: (ev, data) => sent.push({ room, ev, data }),
        }),
      };

      const result = svc.emitRoleUpdate({ roleId: 'r1', action: 'update' });

      expect(sent).toHaveLength(1);
      expect(sent[0].room).toBe('role-management');
      expect(sent[0].ev).toBe('role-updated');
      expect(result.type).toBe('role-updated');
      expect(result.timestamp).toBeTruthy();
      expect(result.roleId).toBe('r1');
    });
  });

  // ========== emitPermissionUpdate ==========
  describe('emitPermissionUpdate', () => {
    test('向 role-management 房间广播 permissions-updated 事件', () => {
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      const sent = [];
      svc.io = {
        to: (room) => ({
          emit: (ev, data) => sent.push({ room, ev, data }),
        }),
      };

      const result = svc.emitPermissionUpdate({ roleId: 'r2' });

      expect(sent).toHaveLength(1);
      expect(sent[0].ev).toBe('permissions-updated');
      expect(result.type).toBe('permissions-updated');
    });
  });

  // ========== authenticateSocket 失败分支（使用 mock 避免 DB 依赖） ==========
  describe('authenticateSocket 失败分支', () => {
    afterEach(() => {
      jest.dontMock(path.join(__dirname, '../../models/User'));
      jest.dontMock(path.join(__dirname, '../../middleware/tokenBlacklist'));
      jest.resetModules();
    });

    /** 构造最小 service 实例（跳过构造器） */
    const makeService = () => {
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc.io = { sockets: { sockets: new Map() } };
      return svc;
    };

    const makeSocket = (id) => {
      const socket = {
        id: id || 'sock-auth-fail',
        authenticated: false,
        emitted: [],
        connected: true,
        emit: (ev, data) => socket.emitted.push({ ev, data }),
        disconnect: () => {
          socket.connected = false;
        },
        join: () => {},
      };
      return socket;
    };

    test('用户状态非 active 时认证失败断开', async () => {
      // status !== 'active'（如 disabled/locked）的用户不应允许 WS 认证
      const fakeUserId = String(new mongoose.Types.ObjectId());
      jest.doMock(path.join(__dirname, '../../middleware/tokenBlacklist'), () => ({
        isTokenBlacklisted: async () => false,
      }));
      jest.doMock(path.join(__dirname, '../../models/User'), () => ({
        findById: jest.fn(() => ({
          select: () => ({
            populate: () =>
              Promise.resolve({
                username: 'disabled-user',
                status: 'disabled',
                tokenVersion: 0,
                passwordChangedAt: null,
                roles: [{ code: 'SUPER_ADMIN' }],
              }),
          }),
        })),
      }));
      jest.resetModules();

      const svc = makeService();
      const socket = makeSocket('sock-disabled');
      svc.clients.set(socket.id, {
        id: socket.id,
        userId: null,
        rooms: new Set(),
        connectedAt: new Date(),
      });
      const timer = setTimeout(() => {}, 60000);

      // 签发有效 JWT（userId 随意，mock 会返回固定用户）
      const token = jwt.sign(
        { userId: fakeUserId, username: 'disabled-user', tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      const result = await svc.authenticateSocket(socket, token, timer);
      clearTimeout(timer);

      expect(result).toBe(false);
      expect(socket.connected).toBe(false);
      expect(socket.emitted.some((e) => /禁用或锁定/.test(e.data?.message || ''))).toBe(true);
    });

    test('密码修改后旧 token 认证失败', async () => {
      // decoded.iat < passwordChangedAt 时令牌应失效
      const fakeUserId = String(new mongoose.Types.ObjectId());
      const oldIat = Math.floor(Date.now() / 1000) - 7200; // 2小时前
      jest.doMock(path.join(__dirname, '../../middleware/tokenBlacklist'), () => ({
        isTokenBlacklisted: async () => false,
      }));
      jest.doMock(path.join(__dirname, '../../models/User'), () => ({
        findById: jest.fn(() => ({
          select: () => ({
            populate: () =>
              Promise.resolve({
                username: 'pwd-user',
                status: 'active',
                tokenVersion: 0,
                // 密码在 1 小时前修改，晚于 token 的 iat（2小时前）
                passwordChangedAt: new Date(Date.now() - 3600000),
                roles: [{ code: 'FIREFIGHTER' }],
              }),
          }),
        })),
      }));
      jest.resetModules();

      const svc = makeService();
      const socket = makeSocket('sock-pwdchg');
      svc.clients.set(socket.id, {
        id: socket.id,
        userId: null,
        rooms: new Set(),
        connectedAt: new Date(),
      });
      const timer = setTimeout(() => {}, 60000);

      const token = jwt.sign(
        { userId: fakeUserId, username: 'pwd-user', tokenVersion: 0, iat: oldIat },
        process.env.JWT_SECRET,
        { expiresIn: '4h' }
      );

      const result = await svc.authenticateSocket(socket, token, timer);
      clearTimeout(timer);

      expect(result).toBe(false);
      expect(socket.connected).toBe(false);
      expect(socket.emitted.some((e) => /密码已修改/.test(e.data?.message || ''))).toBe(true);
    });

    test('JWT 校验异常（签名错误）走 catch 分支', async () => {
      // jwt.verify 抛错时应 emit auth-error 并断开
      const svc = makeService();
      const socket = makeSocket('sock-badjwt');
      svc.clients.set(socket.id, {
        id: socket.id,
        userId: null,
        rooms: new Set(),
        connectedAt: new Date(),
      });
      const timer = setTimeout(() => {}, 60000);

      const result = await svc.authenticateSocket(socket, 'invalid.jwt.token', timer);
      clearTimeout(timer);

      expect(result).toBe(false);
      expect(socket.connected).toBe(false);
      expect(socket.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
    });
  });

  // ========== revalidateSocket 用户不存在分支 ==========
  describe('revalidateSocket 边界', () => {
    afterEach(() => {
      jest.dontMock(path.join(__dirname, '../../models/User'));
      jest.resetModules();
    });

    test('用户已被删除时返回 ok:false 并断开连接', async () => {
      // revalidateSocket 复查发现用户不存在 → kick
      jest.doMock(path.join(__dirname, '../../models/User'), () => ({
        findById: jest.fn(() => ({
          select: () => ({
            populate: () => Promise.resolve(null),
          }),
        })),
      }));
      jest.resetModules();
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      const socket = {
        id: 'sock-ghost',
        userId: String(new mongoose.Types.ObjectId()),
        tokenVersion: 0,
        connected: true,
        emitted: [],
        emit: (ev, data) => socket.emitted.push({ ev, data }),
        disconnect: () => {
          socket.connected = false;
        },
      };

      const result = await svc.revalidateSocket(socket);

      expect(result.ok).toBe(false);
      expect(socket.connected).toBe(false);
      expect(socket.emitted.some((e) => e.ev === 'auth-error')).toBe(true);
    });
  });

  // ========== setupConnectionCleanup ==========
  describe('setupConnectionCleanup', () => {
    afterEach(() => {
      jest.useRealTimers();
    });

    test('创建周期定时器并在 _sweepRunning 时跳过本轮', () => {
      // 验证两件事：1) 定时器被创建并 unref；2) 防重入标志生效
      jest.useFakeTimers();
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc._sweepRunning = false;
      svc.runCleanupSweep = jest.fn().mockResolvedValue(undefined);
      svc.io = { sockets: { sockets: new Map() } };

      svc.setupConnectionCleanup();

      expect(svc._cleanupTimer).toBeTruthy();

      // 推进一个周期，runCleanupSweep 应被调用
      jest.advanceTimersByTime(30000);
      // 等待微任务队列 flush（runCleanupSweep 是 async）
      return Promise.resolve().then(() => {
        expect(svc.runCleanupSweep).toHaveBeenCalledTimes(1);

        // 设置防重入标志后再推进，不应再次调用
        svc._sweepRunning = true;
        svc.runCleanupSweep.mockClear();
        jest.advanceTimersByTime(30000);
        return Promise.resolve().then(() => {
          expect(svc.runCleanupSweep).not.toHaveBeenCalled();
          // 清理定时器防止泄漏
          clearInterval(svc._cleanupTimer);
        });
      });
    });
  });

  // ========== emitPermissionSync Redis 模式分支 ==========
  describe('emitPermissionSync Redis 模式', () => {
    test('Redis 模式下 fetchSockets 为空时计入 offline', async () => {
      // redisMode=true 且用户房间内无活跃连接 → offline++
      const sharedCache = require('../../services/sharedCache');
      const origIsRedisEnabled = sharedCache.isRedisEnabled;
      sharedCache.isRedisEnabled = () => true;

      try {
        const WebSocketService = require('../../services/websocketService');
        const svc = Object.create(WebSocketService.prototype);
        svc.clients = new Map();
        svc.userConnections = new Map();
        svc.io = {
          in: () => ({
            fetchSockets: async () => [],
          }),
          to: () => ({ emit: () => {} }),
        };

        const result = await svc.emitPermissionSync(['user-offline']);
        expect(result.offline).toBe(1);
        expect(result.notified).toBe(0);
      } finally {
        sharedCache.isRedisEnabled = origIsRedisEnabled;
      }
    });

    test('Redis 模式下有活跃连接时通过房间投递 permission-sync', async () => {
      // redisMode=true 且 fetchSockets 非空 → 经 io.to(userRoom).emit 投递
      // 先 mock User.getPermissions，再 resetModules，最后 patch sharedCache
      jest.doMock(path.join(__dirname, '../../models/User'), () => ({
        getPermissions: async () => ['read:device', 'write:alarm'],
      }));
      jest.resetModules();

      // resetModules 后重新加载 sharedCache 并 patch
      const sharedCache = require('../../services/sharedCache');
      const origIsRedisEnabled = sharedCache.isRedisEnabled;
      sharedCache.isRedisEnabled = () => true;

      try {
        const FreshWS = require('../../services/websocketService');
        const svc = Object.create(FreshWS.prototype);
        svc.clients = new Map();
        svc.userConnections = new Map();
        const sent = [];
        svc.io = {
          in: () => ({
            fetchSockets: async () => [{ id: 's1' }],
          }),
          to: (room) => ({
            emit: (ev, data) => sent.push({ room, ev, data }),
          }),
        };

        const result = await svc.emitPermissionSync(['u-online']);
        expect(result.notified).toBe(1);
        expect(result.offline).toBe(0);
        expect(sent).toHaveLength(1);
        expect(sent[0].ev).toBe('permission-sync');
        expect(sent[0].data.permissionCodes).toEqual(['read:device', 'write:alarm']);
      } finally {
        sharedCache.isRedisEnabled = origIsRedisEnabled;
        jest.dontMock(path.join(__dirname, '../../models/User'));
        jest.resetModules();
      }
    });
  });

  // ========== connection 回调中的 auth 事件防重入 ==========
  describe('auth 事件防重入', () => {
    test('已认证或认证进行中时忽略重复 auth 提交', async () => {
      // socket.authenticated=true 或 socket.authing=true 时，
      // 'auth' 事件处理器应立即返回，不重复执行 authenticateSocket
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc._sweepRunning = false;
      const listeners = {};
      svc.io = {
        on: (ev, cb) => {
          if (ev === 'connection') listeners.connection = cb;
        },
        sockets: { sockets: new Map([[`x`, {}]]) },
      };
      svc.setupEventHandlers();

      // 模拟一个已完成认证的 socket
      const socket = {
        id: 'sock-dup',
        handshake: { auth: {}, headers: {} },
        authenticated: true,
        authing: false,
        connected: true,
        emitted: [],
        emit: (ev, data) => socket.emitted.push({ ev, data }),
        disconnect: () => {
          socket.connected = false;
        },
        on: (ev, cb) => {
          listeners[`sock_${ev}`] = cb;
        },
        join: () => {},
        leave: () => {},
      };
      svc.io.sockets.sockets.set(socket.id, socket);
      svc.clients.set(socket.id, {
        id: socket.id,
        userId: 'u1',
        rooms: new Set(),
        connectedAt: new Date(),
      });

      listeners.connection(socket);

      // 触发 auth 事件：已认证状态下应被忽略
      const authHandler = listeners.sock_auth;
      expect(authHandler).toBeTruthy();
      // 不会抛错也不会改变状态
      await authHandler('some-token');
      expect(socket.authenticated).toBe(true);

      // authing=true 时也应被忽略
      socket.authenticated = false;
      socket.authing = true;
      await authHandler('some-token');
      // authing 应保持 true（未被 finally 重置，因为 authenticateSocket 未被调用）
      expect(socket.authing).toBe(true);
    });
  });

  // ========== join-room 受限房间复查失败分支 ==========
  describe('join-room 受限房间复查', () => {
    afterEach(() => {
      jest.dontMock(path.join(__dirname, '../../models/User'));
      jest.resetModules();
    });

    test('revalidateSocket 返回 ok:false 时中断入房', async () => {
      // 受限房间入房前复查失败 → 直接 return，不加入房间
      jest.doMock(path.join(__dirname, '../../models/User'), () => ({
        findById: jest.fn(() => ({
          select: () => ({
            populate: () => Promise.resolve(null), // 用户不存在
          }),
        })),
      }));
      jest.resetModules();

      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc._sweepRunning = false;
      const sockListeners = {};
      svc.io = {
        on: (ev, cb) => {
          if (ev === 'connection') {
            // 包装 connection 回调：捕获 socket.on 注册的监听器
            const origCb = cb;
            svc._connCb = (socket) => {
              const origOn = socket.on;
              socket.on = (evName, handler) => {
                sockListeners[evName] = handler;
                origOn.call(socket, evName, handler);
              };
              origCb(socket);
            };
          }
        },
        sockets: { sockets: new Map() },
      };
      svc.setupEventHandlers();

      const socket = {
        id: 'sock-reval-fail',
        handshake: { auth: {}, headers: {} },
        authenticated: true,
        authing: false,
        userId: 'u-ghost',
        roleCodes: ['SUPER_ADMIN'],
        tokenVersion: 0,
        connected: true,
        rooms: new Set(),
        emitted: [],
        emit: (ev, data) => socket.emitted.push({ ev, data }),
        disconnect: () => {
          socket.connected = false;
        },
        on: () => {},
        join: (room) => socket.rooms.add(room),
        leave: () => {},
      };
      svc.io.sockets.sockets.set(socket.id, socket);
      svc.clients.set(socket.id, {
        id: socket.id,
        userId: 'u-ghost',
        rooms: new Set(),
        connectedAt: new Date(),
      });

      svc._connCb(socket);

      // 尝试加入受限房间 role-management
      const joinHandler = sockListeners['join-room'];
      expect(joinHandler).toBeTruthy();
      await joinHandler('role-management');

      // revalidateSocket 应返回 ok:false，socket 不应加入房间
      expect(socket.rooms.has('role-management')).toBe(false);
    });

    test('角色不满足要求时拒绝入房但不断开连接', async () => {
      // revalidateSocket 成功但角色码不在 requiredRoles 中 → emit error，不 disconnect
      jest.doMock(path.join(__dirname, '../../models/User'), () => ({
        findById: jest.fn(() => ({
          select: () => ({
            populate: () =>
              Promise.resolve({
                status: 'active',
                tokenVersion: 0,
                roles: [{ code: 'FIREFIGHTER' }], // 非管理员角色
              }),
          }),
        })),
      }));
      jest.resetModules();

      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map();
      svc.userConnections = new Map();
      svc._sweepRunning = false;
      const sockListeners = {};
      svc.io = {
        on: (ev, cb) => {
          if (ev === 'connection') {
            svc._connCb = (socket) => {
              const origOn = socket.on;
              socket.on = (evName, handler) => {
                sockListeners[evName] = handler;
                origOn.call(socket, evName, handler);
              };
              cb(socket);
            };
          }
        },
        sockets: { sockets: new Map() },
      };
      svc.setupEventHandlers();

      const socket = {
        id: 'sock-no-role',
        handshake: { auth: {}, headers: {} },
        authenticated: true,
        authing: false,
        userId: 'u-firefighter',
        roleCodes: ['FIREFIGHTER'],
        tokenVersion: 0,
        connected: true,
        rooms: new Set(),
        emitted: [],
        emit: (ev, data) => socket.emitted.push({ ev, data }),
        disconnect: () => {
          socket.connected = false;
        },
        on: () => {},
        join: (room) => socket.rooms.add(room),
        leave: () => {},
      };
      svc.io.sockets.sockets.set(socket.id, socket);
      svc.clients.set(socket.id, {
        id: socket.id,
        userId: 'u-firefighter',
        rooms: new Set(),
        connectedAt: new Date(),
      });

      svc._connCb(socket);

      const joinHandler = sockListeners['join-room'];
      expect(joinHandler).toBeTruthy();
      await joinHandler('role-management');

      // 角色不匹配：不入房，发 error，但不断开
      expect(socket.rooms.has('role-management')).toBe(false);
      expect(socket.emitted.some((e) => /无权加入/.test(e.data?.message || ''))).toBe(true);
      expect(socket.connected).toBe(true);
    });
  });

  // ========== initSharedAdapter ==========
  describe('initSharedAdapter', () => {
    test('Redis 未启用时直接返回', async () => {
      // isRedisEnabled()=false 时不做任何操作
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc._adapterClients = [];
      svc.io = { adapter: jest.fn() };

      // sharedCache.isRedisEnabled 默认在测试环境返回 false
      await svc.initSharedAdapter();

      expect(svc.io.adapter).not.toHaveBeenCalled();
      expect(svc._adapterClients).toEqual([]);
    });
  });
});
