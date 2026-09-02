/**
 * 批次E 架构/性能类修复回归（P3-19/20/21/22/23/24/25）
 *
 * 这批缺陷的形态与前几批不同：它们不产生错误响应，只在特定负载或部署形态下
 * 才显现（多进程链分叉、高频用户内存峰值、未初始化配置的每请求打库）。
 * 因此断言重点是「机制存在且行为可观测」，而非某个接口的返回值。
 */

describe('批次E 架构与性能加固回归', () => {
  // ================= P3-19 单进程假设 =================
  describe('P3-19 运行时拓扑假设集中声明', () => {
    const load = () => {
      jest.resetModules();
      return require('../../constants/runtime');
    };

    const ENV_KEYS = ['instances', 'NODE_APP_INSTANCE', 'WEB_CONCURRENCY', 'CLUSTER_WORKERS'];
    const saved = {};

    beforeEach(() => {
      for (const k of ENV_KEYS) {
        saved[k] = process.env[k];
        delete process.env[k];
      }
    });

    afterEach(() => {
      for (const k of ENV_KEYS) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
      jest.resetModules();
    });

    test('依赖清单非空且每项都写明失效后果', () => {
      const { SINGLE_PROCESS_DEPENDENCIES } = load();
      expect(SINGLE_PROCESS_DEPENDENCIES.length).toBeGreaterThan(5);
      for (const d of SINGLE_PROCESS_DEPENDENCIES) {
        expect(d.module).toBeTruthy();
        expect(d.mechanism).toBeTruthy();
        // impact 必须具体到「会发生什么」，而非"可能有问题"
        expect(d.impact.length).toBeGreaterThan(5);
      }
    });

    test('清单涵盖最关键的审计链与限流', () => {
      const { SINGLE_PROCESS_DEPENDENCIES } = load();
      const modules = SINGLE_PROCESS_DEPENDENCIES.map((d) => d.module).join(',');
      expect(modules).toContain('auditChain');
      expect(modules).toContain('auditBuffer');
      expect(modules).toContain('rateLimit');
    });

    test('单进程环境下不报可疑', () => {
      const { detectMultiProcess } = load();
      expect(detectMultiProcess().suspected).toBe(false);
    });

    test.each([
      ['PM2 instances', 'instances', '4'],
      ['非首实例编号', 'NODE_APP_INSTANCE', '2'],
      ['WEB_CONCURRENCY', 'WEB_CONCURRENCY', '3'],
      ['CLUSTER_WORKERS', 'CLUSTER_WORKERS', '2'],
    ])('%s 被识别为多进程迹象', (_label, key, value) => {
      process.env[key] = value;
      const { detectMultiProcess } = load();
      const r = detectMultiProcess();
      expect(r.suspected).toBe(true);
      expect(r.reasons.join(' ')).toContain(key === 'instances' ? 'instances' : key);
    });

    test('NODE_APP_INSTANCE=0（首实例）不算多进程', () => {
      process.env.NODE_APP_INSTANCE = '0';
      const { detectMultiProcess } = load();
      expect(detectMultiProcess().suspected).toBe(false);
    });

    test('检测到多进程时输出失效清单且不抛错（不阻断启动）', () => {
      process.env.WEB_CONCURRENCY = '4';
      jest.resetModules();
      const logger = require('../../utils/logger');
      const spy = jest.spyOn(logger, 'error').mockImplementation(() => {});
      const { assertSingleProcessAssumptions } = require('../../constants/runtime');

      expect(() => assertSingleProcessAssumptions()).not.toThrow();
      expect(spy).toHaveBeenCalled();
      const msg = spy.mock.calls[0][0];
      expect(msg).toContain('WEB_CONCURRENCY=4');
      expect(msg).toContain('auditChain');
      spy.mockRestore();
    });
  });

  // ================= P3-19 审计链锁超时 =================
  describe('P3-19 审计链锁超时保护', () => {
    test('fn 悬挂时锁在超时后释放，后续调用不被永久阻塞', async () => {
      jest.resetModules();
      process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS = '80';
      const { withChainLock } = require('../../utils/auditChain');

      // 第一个持有者永不 settle（模拟 Mongo 无响应）
      const hung = withChainLock(() => new Promise(() => {})).catch((e) => e);

      // 第二个调用必须能在超时窗口后拿到锁并正常完成
      const started = Date.now();
      const result = await withChainLock(() => Promise.resolve('ok'));
      const waited = Date.now() - started;

      expect(result).toBe('ok');
      // 等待时间不应远超超时阈值（宽松上界，避免 CI 抖动误报）
      expect(waited).toBeLessThan(2000);

      const hungErr = await hung;
      expect(hungErr).toBeInstanceOf(Error);
      expect(hungErr.message).toContain('超时');

      delete process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS;
      jest.resetModules();
    });

    test('正常 fn 不受超时影响且串行化语义保持', async () => {
      jest.resetModules();
      const { withChainLock } = require('../../utils/auditChain');
      const order = [];
      await Promise.all([
        withChainLock(async () => {
          order.push('a-start');
          await new Promise((r) => setTimeout(r, 20));
          order.push('a-end');
        }),
        withChainLock(async () => {
          order.push('b-start');
          order.push('b-end');
        }),
      ]);
      // b 必须在 a 完成之后才开始（互斥语义）
      expect(order).toEqual(['a-start', 'a-end', 'b-start', 'b-end']);
    });
  });

  // ================= P3-22 SystemConfig 负缓存 =================
  describe('P3-22 SystemConfig 负缓存', () => {
    test('不存在的 key 只打库一次（第二次命中负缓存）', async () => {
      jest.resetModules();
      const SystemConfig = require('../../models/SystemConfig');
      const spy = jest.spyOn(SystemConfig, 'findOne').mockReturnValue({
        lean: () => Promise.resolve(null),
      });

      const key = `__absent_${Date.now()}`;
      const v1 = await SystemConfig.get(key, 'fallback');
      const v2 = await SystemConfig.get(key, 'fallback');

      expect(v1).toBe('fallback');
      expect(v2).toBe('fallback');
      // 关键断言：第二次不再查库
      expect(spy).toHaveBeenCalledTimes(1);
      spy.mockRestore();
    });

    test('负缓存不污染其他调用方的默认值', async () => {
      jest.resetModules();
      const SystemConfig = require('../../models/SystemConfig');
      const spy = jest.spyOn(SystemConfig, 'findOne').mockReturnValue({
        lean: () => Promise.resolve(null),
      });

      const key = `__absent2_${Date.now()}`;
      // 两个调用方传不同默认值：缓存的是「不存在」而非某个具体默认值
      expect(await SystemConfig.get(key, 'A')).toBe('A');
      expect(await SystemConfig.get(key, 'B')).toBe('B');
      expect(spy).toHaveBeenCalledTimes(1);
      spy.mockRestore();
    });
  });

  // ================= P3-23 statsCache 显式启动 =================
  describe('P3-23 statsCache 不在模块加载期启动定时器', () => {
    test('require 后无定时器，需显式 startCleanup', () => {
      jest.resetModules();
      const statsCache = require('../../services/statsCache');
      // 导出 startCleanup 供 index.js 显式调用（与其余后台任务口径一致）
      expect(typeof statsCache.startCleanup).toBe('function');
      expect(typeof statsCache.stopCleanup).toBe('function');
    });

    test('源码中不存在模块加载期的 startCleanup() 自调用', () => {
      const fs = require('fs');
      const path = require('path');
      const src = fs.readFileSync(path.join(__dirname, '../../services/statsCache.js'), 'utf8');
      // 去掉注释行后，顶层不应有裸的 startCleanup(); 调用
      const code = src
        .split('\n')
        .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
        .join('\n');
      expect(/^startCleanup\(\);/m.test(code)).toBe(false);
    });

    test('index.js 显式启动并在优雅关闭中停止', () => {
      const fs = require('fs');
      const path = require('path');
      const src = fs.readFileSync(path.join(__dirname, '../../index.js'), 'utf8');
      expect(src).toContain('statsCache.startCleanup()');
      expect(src).toContain('statsCache.stopCleanup()');
    });
  });

  // ================= P3-24 告警频控容量上限 =================
  describe('P3-24 告警频控表容量上限', () => {
    test('超过硬上限时清空，Map 不随攻击者可控的 key 无界增长', () => {
      jest.resetModules();
      process.env.ALERT_RATE_LIMIT_MAX = '50';
      const logger = require('../../utils/logger');
      const spy = jest.spyOn(logger, 'error').mockImplementation(() => {});
      const { shouldSendAlert } = require('../../services/securityAlert');

      // 模拟轮换用户名撞库：每次 alertKey 都不同且均未过期
      for (let i = 0; i < 200; i += 1) {
        shouldSendAlert(`brute_force_user_attacker_${i}`);
      }

      // 触发过清空告警（说明上限确实生效）
      expect(spy).toHaveBeenCalled();
      expect(spy.mock.calls[0][0]).toContain('硬上限');

      spy.mockRestore();
      delete process.env.ALERT_RATE_LIMIT_MAX;
      jest.resetModules();
    });

    test('频控语义未被破坏：同一 key 窗口内只放行一次', () => {
      jest.resetModules();
      const { shouldSendAlert } = require('../../services/securityAlert');
      const key = `dup_key_${Date.now()}`;
      expect(shouldSendAlert(key)).toBe(true);
      expect(shouldSendAlert(key)).toBe(false);
    });
  });

  // ================= P3-25 WebSocket 暴露面 =================
  describe('P3-25 WebSocket 统计与推送白名单', () => {
    /** 构造最小可测的 service 实例，绕开真实 socket.io 服务器 */
    const makeService = (roomNames = []) => {
      const WebSocketService = require('../../services/websocketService');
      const svc = Object.create(WebSocketService.prototype);
      svc.clients = new Map([
        [
          'sid-1',
          { id: 'sid-1', userId: 'u1', rooms: new Set(['alarm']), connectedAt: new Date() },
        ],
        [
          'sid-2',
          { id: 'sid-2', userId: 'u2', rooms: new Set(['notification']), connectedAt: new Date() },
        ],
      ]);
      svc.userConnections = new Map([
        ['u1', new Set(['sid-1'])],
        ['u2', new Set(['sid-2'])],
      ]);
      const emitted = [];
      svc.io = {
        to: (room) => ({ emit: (ev, data) => emitted.push({ room, ev, data }) }),
        sockets: { adapter: { rooms: new Map(roomNames.map((r) => [r, new Set()])) } },
      };
      return { svc, emitted };
    };

    test('getStats 默认不含逐连接明细（不泄露在线人员画像）', () => {
      const { svc } = makeService(['alarm']);
      const stats = svc.getStats();
      expect(stats.totalClients).toBe(2);
      expect(stats.totalUsers).toBe(2);
      expect(stats.clients).toBeUndefined();
    });

    test('显式 includeClients 时才返回明细', () => {
      const { svc } = makeService(['alarm']);
      const stats = svc.getStats({ includeClients: true });
      expect(Array.isArray(stats.clients)).toBe(true);
      expect(stats.clients).toHaveLength(2);
    });

    test('rooms 只回报白名单房间，socket.id 私有房间被过滤', () => {
      // adapter.rooms 同时包含白名单房间与以 socket.id 命名的私有房间
      const { svc } = makeService(['alarm', 'sid-1', 'sid-2', 'notification']);
      const stats = svc.getStats();
      expect(stats.rooms).toEqual(expect.arrayContaining(['alarm', 'notification']));
      expect(stats.rooms).not.toContain('sid-1');
      expect(stats.rooms).not.toContain('sid-2');
    });

    test('emitNotification 拒绝非白名单房间（含 socket.id 定向投递）', () => {
      const { svc, emitted } = makeService();
      expect(svc.emitNotification('sid-1', 'info', 'x')).toBe(false);
      expect(svc.emitNotification('../../etc', 'info', 'x')).toBe(false);
      expect(emitted).toHaveLength(0);
    });

    test('白名单房间正常推送', () => {
      const { svc, emitted } = makeService();
      expect(svc.emitNotification('alarm', 'info', 'hello')).toBe(true);
      expect(emitted).toHaveLength(1);
      expect(emitted[0].room).toBe('alarm');
      expect(emitted[0].data.message).toBe('hello');
    });
  });
});
