/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：deviceReminder.js：并发互斥、全库/范围缓存隔离、调度器幂等与停止
 * 守护的不变式：带 scopeFilter 时**绝不可**返回全库缓存（H-1 数据边界）；调度器重复启动必须幂等
 * 可证伪性：变异实测（筛查 N=2）：杀 2/3
 *
 * 命名沿革：2026-09-20 由 `deviceReminderBranches.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * deviceReminder.js 分支补齐（branches 41% → 目标 85%+）
 *
 * 依据全量覆盖率的未覆盖分支：
 *  - scanDeviceReminders 并发互斥（L31-46）：带 scopeFilter 跳过（H-1 数据边界，
 *    绝不可返回全库缓存）、不带 scopeFilter 返回上次全库结果 / 空缓存兜底
 *  - 全库扫描写全局缓存（L106-109）与 getDeviceReminders 的
 *    scopeFilter 直扫绕过（L162-164）、TTL 命中（L167 真）/ 过期重扫（L167 假）
 *  - markOverdueInspections（L135-155）：modifiedCount 正常 / `?? 0` 兜底 / 异常吞掉
 *  - startReminderScheduler 重复启动幂等（L182-185）、firstTimer/interval 回调、
 *    interval 里 isScanning 跳过（L197-200）与扫描失败 .catch 分支
 *  - 2026-10-08 追加：**巡检标记臂**的两处 .catch（CI #13 的 functions 90% /
 *    branches 86.79% 即由此而来）。它们**不是**普通 DB 故障能驱动的——`markOverdueInspections`
 *    整段体在 try/catch 内、永不 reject，那两条箭头是**第二道防线**，只在第一道被破坏
 *    （内层 catch 体自身抛错）时才生效。故用例用"让内层 logger.error 抛错"来驱动，
 *    两种形态（Error / undefined）各一条，把 `${err?.message ?? err}` 的两条路径都走到。
 *  - stopReminderScheduler 句柄回退（L215）、target 判空（L217）、扫描等待循环（L222-226）
 *
 * 隔离策略（修复上一版跨用例泄漏导致的失败/挂起）：
 *  - 三个依赖（FireDevice / Inspection / logger）全部 factory mock，不触 DB、不开文件句柄
 *  - 每个用例经 jest.isolateModules 重新加载服务模块，模块级状态
 *    （isScanning / lastScanResult / lastScanAt / activeScheduler）彻底归零，
 *    用例之间不再互相污染
 *  - 互斥态构造：find 返回「链式 + 受控 pending」假 Query，首次扫描挂起使
 *    isScanning=true；用例结束前 drain 所有 pending，afterEach 兜底停调度器
 *  - 调度器时序用例使用 jest 假定时器，确定性触发 firstTimer/interval，秒级完成
 */

jest.mock('../../models/FireDevice', () => ({ find: jest.fn() }));
jest.mock('../../models/Inspection', () => ({ updateMany: jest.fn() }));
jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

describe('deviceReminder 分支补齐', () => {
  let service;
  let FireDevice;
  let Inspection;
  let logger;

  // 每个用例独立模块实例：模块级互斥/缓存/调度器状态互不干扰
  const loadFresh = () => {
    jest.isolateModules(() => {
      service = require('../../services/deviceReminder');
      FireDevice = require('../../models/FireDevice');
      logger = require('../../utils/logger');
    });
    // 注意：markOverdueInspections 内部的延迟 require 落在**主注册表**
    // （isolateModules 只隔离加载期顶层依赖），故 Inspection 取主注册表实例配置
    Inspection = require('../../models/Inspection');
    FireDevice.find.mockReturnValue(immediateChain([]));
    Inspection.updateMany.mockResolvedValue({ modifiedCount: 0 });
  };

  beforeEach(() => {
    loadFresh();
  });

  // ---- find 假 Query 构造 ----
  // 真实返回是 Query 链（.select().sort().limit()），mock 必须同时提供链方法与 thenable

  // 立即完成的链：await 后得到 value
  function immediateChain(value) {
    const chain = {
      select: () => chain,
      sort: () => chain,
      limit: () => chain,
      then: (res, rej) => Promise.resolve(value).then(res, rej),
    };
    return chain;
  }

  // 立即失败的链（覆盖扫描 .catch 分支用）
  const rejectChain = (err) => {
    const chain = {
      select: () => chain,
      sort: () => chain,
      limit: () => chain,
      then: (res, rej) => Promise.reject(err).then(res, rej),
    };
    return chain;
  };

  // 挂起链：resolve/reject 收进 pending，由用例按需释放
  let pending = [];
  const stallFind = () => {
    pending = [];
    FireDevice.find.mockImplementation(() => {
      let resolveFn;
      let rejectFn;
      const promise = new Promise((res, rej) => {
        resolveFn = res;
        rejectFn = rej;
      });
      pending.push({ resolve: resolveFn, reject: rejectFn });
      const chain = {
        select: () => chain,
        sort: () => chain,
        limit: () => chain,
        then: (...args) => promise.then(...args),
        catch: (...args) => promise.catch(...args),
      };
      return chain;
    });
  };

  // 微任务让位：不用 setImmediate——现代假定时器会把它一并 mock 掉，
  // 假定时器用例里会永远挂起；微任务不受假定时器影响，两种模式都安全
  const yieldNow = async () => {
    for (let i = 0; i < 20; i += 1) {
      await Promise.resolve();
    }
  };

  // 逐个释放挂起的 find：resolve 是同步的，但 await 续体（下一个 find）在微任务里
  // 推进，必须每次让出再查 pending，直到扫描推进完毕、isScanning 复位
  const drainPending = async (value = []) => {
    while (pending.length > 0) {
      pending.shift().resolve(value);
      await yieldNow();
    }
    await yieldNow(); // 确保最后一个 find 之后的收尾（结果组装/缓存写入）也完成
  };

  afterEach(async () => {
    // 兜底：放行残留挂起扫描（防 isScanning 卡死），再停掉残留调度器
    await drainPending();
    try {
      await service.stopReminderScheduler();
    } catch {
      /* 忽略：仅清理用途 */
    }
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  // ===== scanDeviceReminders：正常路径与缓存 =====

  test('全库扫描成功 → 结果写全局缓存，TTL 内 getDeviceReminders 命中缓存（L106-109/L167 真）', async () => {
    const first = await service.scanDeviceReminders();
    expect(first.summary).toEqual({
      expired: 0,
      expiringSoon: 0,
      needMaintenance: 0,
      needSchedule: 0,
      total: 0,
    });
    expect(first.expiringDays).toBe(30); // 默认窗口
    expect(first.scannedAt).toBeTruthy();

    // TTL 内命中缓存：同一对象直接返回，不再触发 DB 扫描
    const callsAfterScan = FireDevice.find.mock.calls.length;
    const cached = await service.getDeviceReminders({ intervalMs: 24 * 60 * 60 * 1000 });
    expect(cached).toBe(first);
    expect(FireDevice.find.mock.calls.length).toBe(callsAfterScan);
  });

  test('带 scopeFilter 的扫描不写全局缓存；无缓存时 getDeviceReminders 触发新扫描（L167 假）', async () => {
    const scoped = await service.scanDeviceReminders({ scopeFilter: { building: 'B1' } });
    expect(scoped.summary).toBeTruthy();

    // 缓存仍为空（scopeFilter 结果不可共享）→ getDeviceReminders 走重新扫描分支
    const callsBefore = FireDevice.find.mock.calls.length;
    const fresh = await service.getDeviceReminders();
    expect(fresh.scannedAt).toBeTruthy();
    expect(FireDevice.find.mock.calls.length).toBeGreaterThan(callsBefore);
  });

  test('getDeviceReminders 带 scopeFilter → 绕过缓存直扫（L162-164）', async () => {
    // 先写入全库缓存，证明带范围调用不会返回它
    const baseline = await service.scanDeviceReminders();
    expect(baseline.summary).toBeTruthy();

    const callsBefore = FireDevice.find.mock.calls.length;
    const scoped = await service.getDeviceReminders({ scopeFilter: { building: 'B2' } });
    expect(scoped).not.toBe(baseline);
    expect(FireDevice.find.mock.calls.length).toBeGreaterThan(callsBefore);
  });

  test('getDeviceReminders 缓存过期（intervalMs 为负）→ 重新扫描（L167 假）', async () => {
    const baseline = await service.scanDeviceReminders();
    const callsBefore = FireDevice.find.mock.calls.length;

    const renewed = await service.getDeviceReminders({ intervalMs: -1 });
    expect(renewed).not.toBe(baseline);
    expect(FireDevice.find.mock.calls.length).toBeGreaterThan(callsBefore);
  });

  // ===== scanDeviceReminders：并发互斥 =====

  test('并发互斥：带 scopeFilter 的调用直接跳过，绝不返回全库缓存（H-1，L34-37）', async () => {
    stallFind();
    const first = service.scanDeviceReminders(); // 挂起 → isScanning=true
    const second = await service.scanDeviceReminders({ scopeFilter: { building: 'B1' } });

    expect(second.skipped).toBe(true);
    expect(second.summary.total).toBe(0);
    expect(second.scannedAt).toBeTruthy();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('数据范围查询跳过'));

    await drainPending();
    await first; // 挂起扫描收尾，isScanning 复位
  });

  test('并发互斥：无 scopeFilter 且无历史缓存 → 返回空兜底（L40-45 null 分支）', async () => {
    stallFind();
    // 全新模块：从未扫描过，lastScanResult 为 null
    const first = service.scanDeviceReminders();
    const second = await service.scanDeviceReminders();

    expect(second.skipped).toBe(true);
    // 降级必须"形状完整 + 明确标注"：明细数组键缺失会让调用方把"没查"读成"没有待办"
    expect(second.summary).toEqual({
      expired: 0,
      expiringSoon: 0,
      needMaintenance: 0,
      needSchedule: 0,
      total: 0,
    });
    expect(second.partial).toBe(true);
    for (const key of ['expired', 'expiringSoon', 'needMaintenance', 'needSchedule']) {
      expect(Array.isArray(second[key])).toBe(true);
    }

    await drainPending();
    await first;
  });

  test('并发互斥：无 scopeFilter 且已有全库缓存 → 返回上次结果（同一 scannedAt）', async () => {
    const baseline = await service.scanDeviceReminders(); // 写入全局缓存

    stallFind();
    const first = service.scanDeviceReminders(); // 挂起，不覆盖缓存
    const second = await service.scanDeviceReminders();

    expect(second.skipped).toBeUndefined(); // 是缓存结果而非兜底
    expect(second).toBe(baseline);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('返回上次全库结果'));

    await drainPending();
    await first;
  });

  // ===== markOverdueInspections =====

  test('markOverdueInspections：有逾期 → 返回标记条数（L145-148）', async () => {
    Inspection.updateMany.mockResolvedValue({ modifiedCount: 3 });
    const n = await service.markOverdueInspections();
    expect(n).toBe(3);
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('巡检逾期标记完成'));
  });

  test('markOverdueInspections：结果缺 modifiedCount → `?? 0` 兜底（L145）', async () => {
    Inspection.updateMany.mockResolvedValue({}); // 无 modifiedCount 字段
    const n = await service.markOverdueInspections();
    expect(n).toBe(0);
  });

  test('markOverdueInspections：异常被吞掉返回 0，不影响提醒主流程（L150-154）', async () => {
    Inspection.updateMany.mockRejectedValue(new Error('db down'));
    const n = await service.markOverdueInspections();
    expect(n).toBe(0);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('巡检逾期标记失败'));
  });

  // ===== 调度器：幂等启动 / 回调分支 =====

  test('调度器重复启动幂等：返回同一句柄，不泄漏旧定时器（L182-185）', async () => {
    const first = service.startReminderScheduler(60 * 60 * 1000);
    const second = service.startReminderScheduler(60 * 60 * 1000);
    expect(second).toBe(first);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('忽略重复启动'));

    await service.stopReminderScheduler(first);
  });

  test('firstTimer/interval 回调：扫描挂起时 interval 命中 isScanning 跳过分支（L188-200）', async () => {
    jest.useFakeTimers();
    service.startReminderScheduler(60 * 1000);
    Inspection.updateMany.mockResolvedValue({ modifiedCount: 0 });

    stallFind();
    await jest.advanceTimersByTimeAsync(30 * 1000); // firstTimer 触发：扫描挂起 + 巡检标记
    expect(FireDevice.find).toHaveBeenCalledTimes(1); // 首个 find 挂起中

    await jest.advanceTimersByTimeAsync(60 * 1000); // interval 触发：isScanning=true → 跳过
    expect(FireDevice.find).toHaveBeenCalledTimes(1); // 未发起新扫描
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('跳过本次'));

    await drainPending(); // 收尾挂起扫描，isScanning 复位
    await service.stopReminderScheduler();
  });

  test('interval 正常扫描：上次已完成则发起新扫描并写缓存（L201）', async () => {
    jest.useFakeTimers();
    service.startReminderScheduler(60 * 1000);

    await jest.advanceTimersByTimeAsync(30 * 1000); // firstTimer 扫描（立即完成，写缓存）
    // 每档一次查询：expired / expiringSoon / needMaintenance / needSchedule。
    // needSchedule 是补上的第四档——没有排期的设备此前在四个出口里全部隐身
    expect(FireDevice.find).toHaveBeenCalledTimes(4);

    await jest.advanceTimersByTimeAsync(60 * 1000); // interval 扫描
    expect(FireDevice.find).toHaveBeenCalledTimes(8);

    await yieldNow(); // 等待最后一次扫描的微任务收尾，isScanning 复位后再停
    await service.stopReminderScheduler();
  });

  test('interval/首次扫描失败 → .catch 记录错误，互斥态正常复位（L189/L201 catch）', async () => {
    jest.useFakeTimers();
    FireDevice.find.mockReturnValue(rejectChain(new Error('db down')));
    service.startReminderScheduler(60 * 1000);

    await jest.advanceTimersByTimeAsync(30 * 1000); // firstTimer 扫描失败
    await jest.advanceTimersByTimeAsync(60 * 1000); // interval 扫描失败

    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('扫描失败'));
    // 失败后 isScanning 已复位：恢复立即成功的 find，再触发一次应正常执行
    FireDevice.find.mockReturnValue(immediateChain([]));
    await jest.advanceTimersByTimeAsync(60 * 1000);
    expect(logger.error).toHaveBeenCalledTimes(2); // 第三次未再失败

    await yieldNow(); // 等待最后一次扫描的微任务收尾，isScanning 复位后再停
    await service.stopReminderScheduler();
  });

  /**
   * 巡检标记臂的两处 .catch（firstTimer 的「首次巡检逾期标记失败」与 interval 的
   * 「巡检逾期标记调度失败」）。
   *
   * 关键前提（**实测得出，不是推测**）：`markOverdueInspections` 的函数体整段都在
   * try/catch 里，catch 体只调 logger.error 并 `return 0`——它**永不 reject**。上面三条
   * 调度器用例把它 mock 成 resolve 只是"没触发"，真相更硬：**普通 DB 故障驱动不了这两条箭头**。
   * 第一版用例正是这么写的，实测 logger.error 只收到内层 catch 自己那条
   * `巡检逾期标记失败：…`，两条箭头一次都没跑。
   *
   * ⇒ 这两条 `.catch` 是**第二道防线**：只有第一道被破坏（内层 catch 体自身抛错，
   *   例如观测函数故障）时才执行。要验证第二道防线，唯一正确的做法就是**把第一道打断**：
   *   让内层那一次 logger.error 抛错，使 markOverdueInspections 真的 reject，再看调度器接不接得住。
   *   这也解释了它们为何看起来像死代码——设计上就只在第一道失效时才生效。
   *
   * 两种形态都要测：抛 Error ⇒ 箭头走 `err?.message`；抛 undefined ⇒ 走 `?? err` 兜底。
   * 非 Error 形态正是这段代码要防的（`${err.message}` 形态会在 .catch 内再抛一次，
   * 变成第二个无人持有的拒绝 ⇒ 本仓 unhandledRejection 兜底 ⇒ process.exit(1)）。
   */
  test('巡检标记臂：内层「永不 reject」契约被破坏时，两条 .catch 必须接住（非 Error 形态）', async () => {
    jest.useFakeTimers();
    Inspection.updateMany.mockRejectedValue(undefined);
    service.startReminderScheduler(60 * 1000);

    // firstTimer：只让**内层**那一次 logger.error 抛——once 队列在箭头那次调用前就耗尽了，
    // 所以箭头自己的 logger.error 正常返回（否则它自己会变成第二个无人持有的拒绝）。
    logger.error.mockImplementationOnce(() => {
      throw undefined;
    });
    await jest.advanceTimersByTimeAsync(30 * 1000);
    expect(logger.error).toHaveBeenCalledWith('首次巡检逾期标记失败：undefined');

    // interval：同上，重新挂一次 once（上一次已在 firstTimer 轮消费掉）
    logger.error.mockImplementationOnce(() => {
      throw undefined;
    });
    await jest.advanceTimersByTimeAsync(60 * 1000);
    expect(logger.error).toHaveBeenCalledWith('巡检逾期标记调度失败：undefined');
    await yieldNow();

    // 前提自证：失败面只在巡检臂——扫描臂（find 立即成功）不得被误报，
    // 否则上面两条断言可能来自"整条调度都挂了"而不是这两条箭头。
    expect(logger.error).not.toHaveBeenCalledWith(expect.stringContaining('扫描失败'));

    await service.stopReminderScheduler();
  });

  test('巡检标记臂：内层抛 Error ⇒ 同一对箭头走 `err?.message` 一侧（补上另一半分支）', async () => {
    jest.useFakeTimers();
    Inspection.updateMany.mockRejectedValue(undefined);
    service.startReminderScheduler(60 * 1000);

    logger.error.mockImplementationOnce(() => {
      throw new Error('logger transport down');
    });
    await jest.advanceTimersByTimeAsync(30 * 1000);
    // 箭头拿到的被拒值是**内层抛出的那个** Error（不是 updateMany 的 undefined）
    expect(logger.error).toHaveBeenCalledWith('首次巡检逾期标记失败：logger transport down');

    logger.error.mockImplementationOnce(() => {
      throw new Error('logger transport down');
    });
    await jest.advanceTimersByTimeAsync(60 * 1000);
    expect(logger.error).toHaveBeenCalledWith('巡检逾期标记调度失败：logger transport down');
    await yieldNow();

    await service.stopReminderScheduler();
  });

  // ===== stopReminderScheduler =====

  test('stop 等待循环：扫描未完成时阻塞至其收尾再返回（L222-226）', async () => {
    const handle = service.startReminderScheduler(60 * 60 * 1000);

    stallFind();
    const ongoing = service.scanDeviceReminders(); // 制造「当前扫描未完成」

    const startedAt = Date.now();
    const stopping = service.stopReminderScheduler(handle);
    // 1.1 秒后放行挂起的扫描，stop 应至少等待一个 1 秒轮询周期
    setTimeout(() => drainPending(), 1100);
    await stopping;
    const waited = Date.now() - startedAt;

    expect(waited).toBeGreaterThanOrEqual(900);
    // stop 返回即代表互斥态已解除：恢复立即成功的 find 后再扫描，
    // 应正常执行而非进入互斥分支（stallFind 的挂起 mock 不能带到这里）
    FireDevice.find.mockReturnValue(immediateChain([]));
    const after = await service.scanDeviceReminders();
    expect(after.skipped).toBeUndefined();
    await ongoing;
  });

  test('stop 无参 → 回退 activeScheduler；重复停止安全返回（L215/L217）', async () => {
    service.startReminderScheduler(60 * 60 * 1000);

    await service.stopReminderScheduler(); // 使用模块内 activeScheduler
    // activeScheduler 已置空：再次停止走 target 判空分支，不抛错
    await expect(service.stopReminderScheduler()).resolves.toBeUndefined();
  });
});
