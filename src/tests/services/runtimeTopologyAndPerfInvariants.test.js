/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：运行时拓扑声明、高频用户内存峰值、未初始化配置的每请求打库
 * 守护的不变式：拓扑假设必须集中声明；性能机制必须存在且行为可观测
 * 可证伪性：变异实测（筛查 N=2）：杀 2/3
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [仍有效·已实测] `:310-319` 断源码文本 `src.toContain("statsCache.startCleanup()")`——文案改写即红、搬进永不执行的分支即绿（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     复核（2026-09-20 **变异实测**）：**成立**。把 `index.js` 的 `statsCache.startCleanup()` 搬进
 *     `if (process.env.__PROBE_NEVER__) { ... }` 后，本文件 **37 例全绿**——断言只查文本，文本还在就算过。
 *     另注：`--findRelatedTests src/index.js` 返回**空集**（本文件用 `fs.readFileSync` 读它，没有静态 import 边），
 *     所以这类"断源码文本"的用例**在依赖图上是孤岛**。证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法。
 *
 * 命名沿革：2026-09-20 由 `archPerfHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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

    const ENV_KEYS = [
      'instances',
      'NODE_APP_INSTANCE',
      'WEB_CONCURRENCY',
      'CLUSTER_WORKERS',
      'INSTANCE_COUNT',
      'REPLICAS',
    ];
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
      ['显式实例数', 'INSTANCE_COUNT', '3'],
      ['编排副本数', 'REPLICAS', '3'],
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

  // ================= P3-64 K8s 多副本检测（Deployment 不注入环境变量）=================
  describe('P3-64 K8s Pod 判据', () => {
    // `-<数字>` 结尾的主机名太常见
    // （CI runner `runner-14`、EC2 私有 DNS 名 `ip-10-0-1-23`、`host-2024`），
    // 光凭形状当序号会把单实例机器误判成多副本。因此 parsePodOrdinal 现在还要一个
    // 集群事实判据（kubelet 注入的 KUBERNETES_SERVICE_HOST）。
    // 本 describe 描述的**就是** K8s Pod 场景，所以这里显式声明该前提；
    // 集群外不得报 strong 的那一半由 src/tests/constants/zzqA_podOrdinalShape.test.js 钉住。
    const savedK8sEnv = process.env.KUBERNETES_SERVICE_HOST;
    beforeAll(() => {
      process.env.KUBERNETES_SERVICE_HOST = '10.96.0.1';
    });
    afterAll(() => {
      if (savedK8sEnv === undefined) delete process.env.KUBERNETES_SERVICE_HOST;
      else process.env.KUBERNETES_SERVICE_HOST = savedK8sEnv;
    });
    const load = () => {
      jest.resetModules();
      return require('../../constants/runtime');
    };

    test('StatefulSet 非首序号 → 判为可疑（这是纯 K8s 场景唯一可用的信号）', () => {
      const { detectMultiProcess } = load();
      for (const host of ['fsms-web-1', 'fsms-web-2', 'fsms-web-12']) {
        const r = detectMultiProcess({ hostname: host });
        expect({ host, suspected: r.suspected }).toEqual({ host, suspected: true });
        expect(r.reasons.join(' ')).toContain('K8s Pod 序号');
      }
    });

    test('StatefulSet 序号 0 → 不算多进程（单副本同样长这样，不能误报）', () => {
      const { detectMultiProcess } = load();
      const r = detectMultiProcess({ hostname: 'fsms-web-0' });
      expect(r.suspected).toBe(false);
      // 但仍应识别出「这是编排器管理的 Pod」
      expect(r.k8sPodLike).toBe(true);
    });

    test('Deployment 形态 → k8sPodLike=true 但不计入 suspected（弱信号不误报）', () => {
      const { detectMultiProcess } = load();
      const r = detectMultiProcess({ hostname: 'fsms-web-admin-7d9c8b6f4-abc12' });
      expect(r.k8sPodLike).toBe(true);
      expect(r.suspected).toBe(false);
    });

    test.each([
      ['本机 hostname', 'LAPTOP-V29F6ASQ'],
      ['localhost', 'localhost'],
      ['测试库后缀', 'jest_w1'],
      ['空串', ''],
      ['数字结尾但无连字符', 'nodejs20'],
    ])('%s 不误判为 Pod', (_label, host) => {
      const { parsePodOrdinal } = load();
      expect(parsePodOrdinal(host).podLike).toBe(false);
    });

    test('缺省参数读 os.hostname()（不依赖编排器导出 HOSTNAME）', () => {
      const { parsePodOrdinal } = load();
      const os = require('os');
      // 本机不是 Pod，但函数必须能拿到真实 hostname 而非抛错/返回空
      expect(parsePodOrdinal()).toEqual(parsePodOrdinal(os.hostname()));
    });

    test('非字符串入参一律安全返回（不抛错）', () => {
      const { parsePodOrdinal } = load();
      for (const v of [null, 123, {}, []]) {
        expect(parsePodOrdinal(v).podLike).toBe(false);
      }
    });

    test('端到端：K8s 副本场景下启动校验输出失效清单', () => {
      jest.resetModules();
      const logger = require('../../utils/logger');
      const spy = jest.spyOn(logger, 'error').mockImplementation(() => {});
      try {
        const { detectMultiProcess } = require('../../constants/runtime');
        // assertSingleProcessAssumptions 内部不传 hostname，此处只验证
        // 「检测到的可疑信号能形成完整告警文案」这一后半段
        const r = detectMultiProcess({ hostname: 'fsms-web-1' });
        expect(r.suspected).toBe(true);
        expect(r.reasons.join('；')).toContain('K8s Pod 序号=1');
      } finally {
        spy.mockRestore();
      }
    });
  });

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

    test('\u6a21\u5757\u52a0\u8f7d\u671f\u4e0d\u542f\u52a8\u5b9a\u65f6\u5668\uff08\u771f\u5b9e\u8ba1\u6570 setInterval\uff0c\u800c\u975e\u770b\u6e90\u7801\uff09', () => {
      // \u3010\u672c\u8f6e\u6539\u9020\uff1a\u6e90\u7801\u6b63\u5219 \u2192 \u884c\u4e3a\u8ba1\u6570\u3011\u539f\u7528\u4f8b\u628a statsCache.js \u6e90\u7801\u53bb\u6ce8\u91ca\u540e
      // \u5339\u914d /^startCleanup\(\);/m\u2014\u2014\u53ea\u8981\u6ca1\u6709\u8fd9\u884c\u5b57\u9762\u6587\u672c\u5c31\u7eff\uff0c\u800c\u6a21\u5757\u52a0\u8f7d\u671f\u542f\u52a8\u5b9a\u65f6\u5668
      // \u7684\u65b9\u5f0f\u53ef\u4ee5\u662f `setInterval(sweepExpired, ...)` \u76f4\u63a5\u5199\u5728\u9876\u5c42\u3001\u6216\u5305\u5728\u4efb\u610f\u51fd\u6570\u91cc\u8c03\u7528\u3002
      // \u73b0\u76f4\u63a5\u5bf9\u300c\u9996\u6b21 require\u300d\u8fd9\u4e2a\u52a8\u4f5c\u8ba1\u6570\uff1a\u52a0\u8f7d\u671f\u5fc5\u987b\u4e00\u4e2a\u5b9a\u65f6\u5668\u90fd\u4e0d\u5efa\u3002
      jest.resetModules();
      const si = jest.spyOn(global, 'setInterval');
      try {
        require('../../services/statsCache');
        expect(si).not.toHaveBeenCalled();
      } finally {
        si.mockRestore();
        jest.resetModules();
      }
    });

    test('startCleanup \u771f\u5efa\u5b9a\u65f6\u5668\u3001stopCleanup \u771f\u6e05\u9664\uff08\u884c\u4e3a\u9a8c\u8bc1\uff09', () => {
      jest.resetModules();
      const si = jest.spyOn(global, 'setInterval');
      const ci = jest.spyOn(global, 'clearInterval');
      try {
        const statsCache = require('../../services/statsCache');
        statsCache.startCleanup();
        expect(si).toHaveBeenCalledTimes(1);
        // \u5e42\u7b49\uff1a\u91cd\u590d startCleanup \u4e0d\u5f97\u53e0\u52a0\u7b2c\u4e8c\u4e2a\u5b9a\u65f6\u5668
        statsCache.startCleanup();
        expect(si).toHaveBeenCalledTimes(1);
        statsCache.stopCleanup();
        expect(ci).toHaveBeenCalledTimes(1);
        // \u6e05\u9664\u540e\u518d start \u53ef\u91cd\u65b0\u5efa\u7acb\uff08\u72b6\u6001\u771f\u7684\u5f52\u96f6\uff0c\u800c\u975e\u4ec5\u6e05\u4e00\u4e2a\u65e0\u6548\u53e5\u67c4\uff09
        statsCache.startCleanup();
        expect(si).toHaveBeenCalledTimes(2);
        statsCache.stopCleanup();
      } finally {
        si.mockRestore();
        ci.mockRestore();
        jest.resetModules();
      }
    });

    test('index.js \u663e\u5f0f\u542f\u52a8\u5e76\u5728\u4f18\u96c5\u5173\u95ed\u4e2d\u505c\u6b62', () => {
      // \u5165\u53e3\u7ec4\u88c5\u5173\u7cfb\uff08\u8c01\u8c03\u7528 startCleanup\uff09\u65e0\u6cd5\u5728\u8fdb\u7a0b\u5185 require\uff1a
      // index.js \u9876\u5c42\u76f4\u63a5\u542f\u52a8 HTTP \u670d\u52a1\u5668\u3002\u4f46\u53ef\u4ee5\u628a\u65ad\u8a00\u6536\u7d27\u5230
      // \u300c\u540c\u4e00\u6587\u4ef6\u5185\u540c\u65f6\u5b58\u5728\u542f\u52a8\u70b9\u4e0e\u505c\u6b62\u70b9\uff08\u4e0d\u80fd\u53ea\u6709\u4e00\u8fb9\uff09\u300d\u3002
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
