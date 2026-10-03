/**
 * 审计异常检测的「被检时间占比」与「单轮自锁」（F-125）
 *
 * 修复前的三个事实（本文件主证用例在修复前必红）：
 *
 * 1. 窗口与间隔解耦 ⇒ 调大间隔就是静默漏检。
 *    `runDetection()` 直调 `AuditLog.detectAnomalies()` 不带参数，窗口于是恒为
 *    模型默认值 5 分钟（auditLogQueryStatics.js 的 `windowMinutes = 5` 解构默认），而
 *    检测间隔可由 AUDIT_MONITOR_INTERVAL_MS 配成任意值。修复前 .env.example 把它写成
 *    "扫描间隔"，字面意思就是"每次扫描之间的全部数据都会被扫到"——恰恰相反
 *    （该注释已随本簇一并更正，说明窗口跟着间隔走 + 最小间隔）。
 *    运维为了减压把间隔调到 1 小时，实际只有 5/60 = 8.3% 的时间轴被看过，
 *    其余 91.7% 的审计记录**从来没有被任何检测读过**，而合规面板仍报
 *    `monitorRunning: true`。这与本仓刚修掉的 metrics_series_dropped「看起来在、
 *    实际断」是同一缺陷类：能力存在，占空比不在它声称的那个刻度上。
 *    现在窗口由**生效间隔**推导：window = interval + 重叠余量（余量=2×最小间隔，
 *    覆盖 setInterval 因事件循环滞后而后移的缝）。
 *
 * 2. 无重入保护。setInterval 不等待上一轮：一轮慢于间隔时第二轮照样进来得跑
 *    三条聚合 ⇒ 并发聚合互相挤压、把"减负"配置变成"加倍负载"的自 amplifying。
 *    现在上一轮未结束则本轮跳过，并把跳过次数暴露出来（skippedOverlaps 持续
 *    增长本身就是"检测跟不上节奏"的告警依据）。
 *
 * 3. 单轮失败只有日志。catch 写了 logger.error，但没有任何可查询状态，
 *    于是 isRunning()===true 与"连续 N 轮抛错"可以同时成立。现在 runDetection
 *    维护 runs/failures/consecutiveFailures/lastRunAt/lastFailureAt，
 *    并由 getHealth() 一次性读出——面板字段接线另议（见交接），本文件先把
 *    "失败必须可查询"这条不变量钉住。
 *
 * 4. 三路聚合无 maxTimeMS。挂死的聚合会把上面第 2 条的"跳过"变成永久跳过，
 *    所以本轮预算必须传到驱动层：interval 越大允许的轮次越长，但不低于 60s。
 *    模型侧对**不带 maxTimeMS 的调用方保持原行为**（HTTP 路径不变），
 *    由本文件最后几组用例分别钉住"传到位"与"不传就不限"。
 *    踩到的坑（也是本文件必须有一条真库用例的理由）：Mongoose 8 的 Aggregate
 *    实例上**没有** .maxTimeMS() 方法（聚合预算只能走 `aggregate(pipe, {maxTimeMS})`
 *    第二参），链式写法在替身下全绿、在真库下 TypeError 被 runDetection 的 catch
 *    吞掉——于是"修了个让检测彻底停摆的 bug 的 bugfix"自己也是静默失效。
 */

jest.mock('../../models/AuditLog', () => ({ detectAnomalies: jest.fn() }));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));
jest.mock('../../services/securityAlert', () => ({
  shouldSendAlert: jest.fn(() => true),
  sendNotification: jest.fn(async () => {}),
  THRESHOLDS: { alertRateLimitMs: 5 * 60 * 1000 },
}));

const AuditLog = require('../../models/AuditLog');
const securityAlert = require('../../services/securityAlert');
const logger = require('../../utils/logger');
const auditMonitor = require('../../services/auditMonitor');
const { applyQueryStatics } = require('../../models/auditLogQueryStatics');

const MINUTE = 60 * 1000;
const ANOMALY = {
  failedOperations: [{ _id: 'u1', count: 12 }],
  failedOperationsByIp: [],
  unusualTimeOperations: [],
};
const EMPTY = { failedOperations: [], failedOperationsByIp: [], unusualTimeOperations: [] };

/** 用「start 读 env → stop → 直调一轮」取回本轮实际参数，不依赖 fake timers */
const runOneRound = async (intervalEnv) => {
  if (intervalEnv === undefined) delete process.env.AUDIT_MONITOR_INTERVAL_MS;
  else process.env.AUDIT_MONITOR_INTERVAL_MS = String(intervalEnv);
  auditMonitor.start();
  auditMonitor.stop();
  await auditMonitor.runDetection();
  return AuditLog.detectAnomalies.mock.calls.at(-1)[0];
};

describe('auditMonitor 检测窗口占空比 / 重入 / 失败可见（F-125）', () => {
  const originalEnv = process.env.AUDIT_MONITOR_INTERVAL_MS;

  beforeEach(() => {
    auditMonitor.stop();
    auditMonitor.__resetForTest();
    AuditLog.detectAnomalies.mockReset();
    AuditLog.detectAnomalies.mockResolvedValue(ANOMALY);
    securityAlert.sendNotification.mockClear();
    securityAlert.shouldSendAlert.mockClear();
    logger.warn.mockClear();
    logger.error.mockClear();
  });

  afterEach(() => {
    auditMonitor.stop();
    if (originalEnv === undefined) delete process.env.AUDIT_MONITOR_INTERVAL_MS;
    else process.env.AUDIT_MONITOR_INTERVAL_MS = originalEnv;
  });

  describe('窗口必须覆盖间隔（占空比 = 1）', () => {
    test('主证：间隔配成 60 分钟时，检测窗口不得停留在 5 分钟', async () => {
      const opts = await runOneRound(60 * MINUTE);
      expect(opts).toBeDefined();
      expect(opts.windowMinutes * MINUTE).toBeGreaterThanOrEqual(60 * MINUTE);
    });

    test.each([[30 * 1000], [5 * MINUTE], [15 * MINUTE], [6 * 60 * MINUTE]])(
      '等式：间隔 %sms ⇒ 窗口严格大于间隔，且重叠余量不超过 2×最小间隔',
      async (intervalMs) => {
        const env = Math.max(intervalMs, auditMonitor.__MIN_INTERVAL_MS);
        const opts = await runOneRound(intervalMs);
        const windowMs = opts.windowMinutes * MINUTE;
        // 生效间隔本身必须是钳制**之后**的值：窗口若按钳制前的 env 推导，
        // "配 1s 间隔"就会推导出 1s 窗口而实际周期 30s——占空比又掉回 3%
        expect(auditMonitor.getHealth().intervalMs).toBe(env);
        // 下限＝不漏检；严格大于＝setInterval 触发点会因事件循环滞后整体后移，
        // 窗口恰好等于间隔会在两轮之间留下一条没人看的缝
        expect(windowMs).toBeGreaterThan(env);
        // 上限＝不失控（窗口远大于间隔会把每条历史反复计入，阈值语义随之失真，
        // 且聚合成本无界）
        expect(windowMs).toBeLessThanOrEqual(env + 2 * auditMonitor.__MIN_INTERVAL_MS);
      }
    );

    test('窗口必须随间隔变化，而不是被写死成一个大常数', async () => {
      const short = await runOneRound(5 * MINUTE);
      const long = await runOneRound(6 * 60 * MINUTE);
      expect(long.windowMinutes).toBeGreaterThan(short.windowMinutes);
    });

    test('反向保护：未 start 直调 runDetection 也必须带窗口（默认间隔口径）', async () => {
      delete process.env.AUDIT_MONITOR_INTERVAL_MS;
      await auditMonitor.runDetection();
      const opts = AuditLog.detectAnomalies.mock.calls[0][0];
      expect(opts).toBeDefined();
      expect(opts.windowMinutes).toBeGreaterThan(0);
    });

    test('低于最小间隔的配置被抬升后，窗口跟着抬升而不是变成 0/NaN', async () => {
      const opts = await runOneRound(1000);
      // 钳制必须发生在推导之前：读到 1000 说明窗口是按"没生效的间隔"算的
      expect(auditMonitor.getHealth().intervalMs).toBe(auditMonitor.__MIN_INTERVAL_MS);
      expect(Number.isFinite(opts.windowMinutes)).toBe(true);
      expect(opts.windowMinutes * MINUTE).toBeGreaterThan(auditMonitor.__MIN_INTERVAL_MS);
    });
  });

  describe('单轮预算必须传到驱动层（maxTimeMS）', () => {
    test('定时任务侧：带正数预算、有下限、且随间隔放大', async () => {
      const shortest = await runOneRound(30 * 1000);
      const fast = await runOneRound(5 * MINUTE);
      const slow = await runOneRound(6 * 60 * MINUTE);
      // 间隔配到最短合法值时，预算不得跟着缩成 30s：一轮聚合的正常耗时本来
      // 就可能超过半个周期，下限取 2×最小间隔
      expect(shortest.maxTimeMS).toBeGreaterThanOrEqual(2 * auditMonitor.__MIN_INTERVAL_MS);
      expect(fast.maxTimeMS).toBeGreaterThan(0);
      expect(slow.maxTimeMS).toBeGreaterThanOrEqual(fast.maxTimeMS);
    });

    // 间隔这个 env 没有 integer 校验（只要求正数），所以 90000.5 是合法配置；
    // 而服务端对小数 maxTimeMS 直接拒（真库实测，文案随版本而变）⇒ 预算必须是整数。
    // 不取整时三路聚合每轮都抛错、被 runDetection 的 catch 吞成 failures 恒增，
    // 检测静默停摆而 isRunning() 仍报 true——本仓反复声明要防的那一类。
    test('预算取整：小数间隔不得把小数 maxTimeMS 发给服务端', async () => {
      const fractional = await runOneRound(90000.5);
      expect(Number.isInteger(fractional.maxTimeMS)).toBe(true);
      expect(fractional.maxTimeMS).toBe(90000);
    });

    // 下面两条用替身，而替身"允许"任何 API：本仓 Mongoose 8 的 Aggregate 实例上
    // 根本没有 .maxTimeMS() 方法（链式写法在替身下全绿、在真库下抛 TypeError，
    // 又被 runDetection 的 catch 吞掉 ⇒ 检测静默停摆）。
    // 所以"预算传对了"必须由再下面那条真库用例来判，替身只负责"三路都传了"。
    const fakeModel = () => {
      const calls = [];
      const model = {
        aggregate: jest.fn((pipeline, options) => {
          calls.push({ pipeline, options });
          return Promise.resolve([]);
        }),
      };
      const schema = { statics: {} };
      applyQueryStatics(schema);
      return { calls, model, run: (opts) => schema.statics.detectAnomalies.call(model, opts) };
    };

    test('模型侧：maxTimeMS 以 aggregate 第二参传遍三路聚合', async () => {
      const { calls, model, run } = fakeModel();
      await run({ maxTimeMS: 4321 });

      expect(model.aggregate).toHaveBeenCalledTimes(3);
      expect(calls).toHaveLength(3);
      for (const call of calls) {
        expect(call.options).toEqual({ maxTimeMS: 4321 });
      }
    });

    test('模型侧反向：不传预算时保持单参调用（HTTP 路径调用面逐字不变）', async () => {
      const { calls, model, run } = fakeModel();
      await run({});

      expect(model.aggregate).toHaveBeenCalledTimes(3);
      for (const call of calls) {
        expect(call.options).toBeUndefined();
      }
    });

    test('真库判据：带预算与不带预算都必须正常返回三路结果', async () => {
      const mongoose = require('mongoose');
      const RealAuditLog = jest.requireActual('../../models/AuditLog');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }

      const budgeted = await RealAuditLog.detectAnomalies({ windowMinutes: 6, maxTimeMS: 60000 });
      expect(Array.isArray(budgeted.failedOperations)).toBe(true);
      expect(Array.isArray(budgeted.failedOperationsByIp)).toBe(true);
      expect(Array.isArray(budgeted.unusualTimeOperations)).toBe(true);

      const unbudgeted = await RealAuditLog.detectAnomalies({ windowMinutes: 6 });
      expect(unbudgeted.failedOperations).toEqual(budgeted.failedOperations);
    }, 20000);
  });

  describe('重入保护', () => {
    test('上一轮未结束时，本轮跳过且计入可查询状态', async () => {
      let release;
      AuditLog.detectAnomalies.mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            release = resolve;
          })
      );
      const first = auditMonitor.runDetection();
      await auditMonitor.runDetection();

      expect(AuditLog.detectAnomalies).toHaveBeenCalledTimes(1);
      const health = auditMonitor.getHealth();
      expect(health.skippedOverlaps).toBe(1);
      expect(health.runs).toBe(1);

      release(EMPTY);
      await first;
      expect(auditMonitor.getHealth().skippedOverlaps).toBe(1);
    });

    test('反向保护：上一轮 settle 后必须能继续跑（闸门不得变成永久停摆）', async () => {
      await auditMonitor.runDetection();
      await auditMonitor.runDetection();
      expect(AuditLog.detectAnomalies).toHaveBeenCalledTimes(2);
      expect(auditMonitor.getHealth().skippedOverlaps).toBe(0);
    });
  });

  describe('失败必须可查询（isRunning 不等于健康）', () => {
    test('抛错轮次：不向调用方传播，但 consecutiveFailures 递增且留下原因', async () => {
      AuditLog.detectAnomalies.mockRejectedValueOnce(new Error('db down'));
      await expect(auditMonitor.runDetection()).resolves.toBeUndefined();

      const health = auditMonitor.getHealth();
      expect(health.consecutiveFailures).toBe(1);
      expect(health.failures).toBe(1);
      expect(health.lastFailureMessage).toBe('db down');
      expect(health.lastFailureAt).toBeTruthy();
      expect(logger.error).toHaveBeenCalled();
      // 定时器仍在跑：这正是"面板说活着、实际每轮都失败"的形态，
      // 判健必须靠上面的计数，不能靠 isRunning()
      auditMonitor.start();
      expect(auditMonitor.isRunning()).toBe(true);
      auditMonitor.stop();
    });

    test('恢复后连续计数归零，累计计数不清零', async () => {
      AuditLog.detectAnomalies.mockRejectedValueOnce(new Error('blip'));
      await auditMonitor.runDetection();
      await auditMonitor.runDetection();

      const health = auditMonitor.getHealth();
      expect(health.consecutiveFailures).toBe(0);
      expect(health.failures).toBe(1);
      expect(health.runs).toBe(2);
      expect(health.lastRunAt).toBeTruthy();
    });

    test('推送异常同样计为失败（闭环断在告警侧也要可见）', async () => {
      securityAlert.sendNotification.mockRejectedValueOnce(new Error('webhook refused'));
      await auditMonitor.runDetection();
      expect(auditMonitor.getHealth().consecutiveFailures).toBe(1);
      expect(auditMonitor.getHealth().lastFailureMessage).toBe('webhook refused');
    });

    test('反向保护：无异常的一轮既不推送也不记失败（闸门没把正常路径改坏）', async () => {
      AuditLog.detectAnomalies.mockResolvedValue(EMPTY);
      await auditMonitor.runDetection();
      expect(securityAlert.sendNotification).not.toHaveBeenCalled();
      const health = auditMonitor.getHealth();
      expect(health.runs).toBe(1);
      expect(health.failures).toBe(0);
    });

    test('正常告警闭环仍然成立（窗口/锁/计数不得把检测改成哑巴）', async () => {
      await auditMonitor.runDetection();
      expect(securityAlert.sendNotification).toHaveBeenCalledTimes(1);
      expect(securityAlert.sendNotification.mock.calls[0][3].dimensions).toEqual(['高频失败']);
    });

    test('getHealth 返回副本：外部改动不回写内部状态', async () => {
      await auditMonitor.runDetection();
      const snapshot = auditMonitor.getHealth();
      snapshot.runs = 9999;
      snapshot.lastFailureMessage = 'injected';
      expect(auditMonitor.getHealth().runs).toBe(1);
      expect(auditMonitor.getHealth().lastFailureMessage).toBeNull();
    });

    test('测试钩子重置健康状态（否则三 seed 随机顺序下互相污染）', async () => {
      AuditLog.detectAnomalies.mockRejectedValueOnce(new Error('x'));
      await auditMonitor.runDetection();
      expect(auditMonitor.getHealth().failures).toBe(1);
      auditMonitor.__resetForTest();
      expect(auditMonitor.getHealth().failures).toBe(0);
      expect(auditMonitor.getHealth().skippedOverlaps).toBe(0);
    });
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
