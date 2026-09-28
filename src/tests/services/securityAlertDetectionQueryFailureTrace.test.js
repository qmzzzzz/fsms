/**
 * 检测器"用来观测的那次查询"自己失败时，不得把检测整块静默关掉
 *
 * 三个安全告警检测器都做过"失败不冒泡"的收口（P1-23：审计落库挂 try/catch；
 * 投递走有留痕的 dispatchNotification）。但**入口处的计数查询一直是裸 await**：
 *
 *   - checkBruteForce：`Promise.all([countDocuments, countDocuments])`
 *   - checkPermissionAbuse：`countDocuments` 与随后的 `User.findById(...).select().lean()`
 *
 * 一旦这些查询抛（DB 瞬断、缓冲超时、CastError），函数就整体 reject，而所有调用方
 * 都是空 catch 形态：
 *   - `services/authService.js` 五处 `await checkBruteForce(...).catch(() => {})`
 *   - `middleware/rbac.js:77` `void checkPermissionAbuse(...).catch(() => {})`
 * ⇒ 结果是**渐进式封禁与权限滥用告警在 DB 抖动期整体失效，而日志里一行痕迹都没有**：
 * 运维看到的现象是"自动封禁怎么今天没动静"，代码看到的现象是"这里有 catch，应该没事"。
 * 已实测：把 `AuditLog.countDocuments` 换成 rejected 后调用 checkBruteForce，
 * 得到 `rawCallRejected: 'DB hiccup'` / 调用点 `silently-swallowed` / `logger` 零调用。
 *
 * 修法口径与本仓既有约定一致（utils/auditWriteFailure.js）：
 * **不改变业务语义**（计数拿不到就是不检测、不封禁），**但不再静默**（落 logger.error）。
 * 落点在**导出边界**（`guardDetection` 包一层）而不是逐处 try/catch：入口抛点会随检测器
 * 演进而增加，逐处包必然漏；且这样不必去动那些属于另一条线的调用方文件。
 * `checkBulkExport` 有意不包——它的计数来自调用方、写入与投递两处已各自收口，
 * 实测找不出可达抛点（写不出用例证明它需要这层壳），不做无据防御。
 *
 * 每条正例都配一条反向对照，防止"检测器一有风吹草动就无条件打 error"这种过修：
 * 未达阈值、用户确实不存在、以及计数正常且达标时走完整告警链路，三种健康路径
 * 必须**不**出现降级留痕。
 */

const mongoose = require('mongoose');

jest.mock('../../services/securityAlertDelivery', () => ({
  sendNotification: jest.fn(),
  isWebhookTargetAllowed: jest.fn(() => true),
}));

const AuditLog = require('../../models/AuditLog');
const User = require('../../models/User');
const logger = require('../../utils/logger');
const { sendNotification } = require('../../services/securityAlertDelivery');

// 只有"计数达标"那条正例会真的写审计/写封禁表（与 deliveryFailureTrace 同口径），
// 用户名统一带戳便于收尾清理
const stamp = `dqt${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

describe('检测器的观测查询失败必须留痕（不静默降级）', () => {
  let securityAlert;
  let THRESHOLDS;
  let errorSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    require('../../models/IPBlacklist');
    require('../../models/TokenBlacklist');
    securityAlert = require('../../services/securityAlert');
    THRESHOLDS = securityAlert.THRESHOLDS;
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
    const IPBlacklist = require('../../models/IPBlacklist');
    await IPBlacklist.deleteMany({ ip: '198.51.100.27' }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  beforeEach(() => {
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    sendNotification.mockReset();
  });

  afterEach(() => {
    errorSpy.mockRestore();
    jest.restoreAllMocks();
  });

  /** 只取"本轮不检测"这一族留痕，避免把无关 error 混进来当成通过 */
  const degradeTraces = () =>
    errorSpy.mock.calls
      .map((c) => String(c[0]))
      .filter((m) => m.includes('本轮不检测'))
      .join('\n');

  /** 模拟链式查询：`Model.findX().select().lean()` 的 reject / resolve 形态 */
  const chainQuery = (promise) => ({
    select: () => ({ lean: () => promise }),
  });

  describe('暴力破解检测', () => {
    test('计数查询抛错 ⇒ 不冒泡给调用方，但必须留下"本轮不检测"的痕迹', async () => {
      const spy = jest
        .spyOn(AuditLog, 'countDocuments')
        .mockRejectedValue(new Error('模拟计数查询失败'));

      await expect(
        securityAlert.checkBruteForce(`${stamp}_bf_db_down`, '198.51.100.21')
      ).resolves.toBeUndefined();

      expect(spy).toHaveBeenCalled();
      expect(degradeTraces()).toContain('暴力破解检测');
      expect(degradeTraces()).toContain('模拟计数查询失败');
      // 计数拿不到就不该有告警：投递入口必须一次都没被碰
      expect(sendNotification).not.toHaveBeenCalled();
    });

    test('反向对照：计数正常但未达阈值 ⇒ 不得出现降级痕迹', async () => {
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(0);

      await securityAlert.checkBruteForce(`${stamp}_bf_below_threshold`, '198.51.100.22');

      expect(degradeTraces()).toBe('');
      expect(sendNotification).not.toHaveBeenCalled();
    });

    test('反向对照：计数正常且达标 ⇒ 走完整告警链路而不是降级分支', async () => {
      sendNotification.mockResolvedValue(undefined);
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.bruteForceAttempts + 2);

      await securityAlert.checkBruteForce(`${stamp}_bf_reaches_alert`, '198.51.100.27');
      await new Promise((r) => setImmediate(r));

      expect(degradeTraces()).toBe('');
      expect(sendNotification).toHaveBeenCalled();
    });
  });

  describe('权限滥用检测', () => {
    test('计数查询抛错 ⇒ 不冒泡给 rbac 的空 catch，但必须留痕', async () => {
      jest.spyOn(AuditLog, 'countDocuments').mockRejectedValue(new Error('模拟权限计数失败'));

      await expect(
        securityAlert.checkPermissionAbuse(new mongoose.Types.ObjectId(), '198.51.100.23')
      ).resolves.toBeUndefined();

      expect(degradeTraces()).toContain('权限滥用');
      expect(degradeTraces()).toContain('模拟权限计数失败');
      expect(sendNotification).not.toHaveBeenCalled();
    });

    test('取用户名抛错 ⇒ 告警按既有语义跳过，但必须区分于"用户确实不存在"', async () => {
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.permissionFailures);
      jest
        .spyOn(User, 'findById')
        .mockReturnValue(chainQuery(Promise.reject(new Error('模拟读取用户失败'))));

      await expect(
        securityAlert.checkPermissionAbuse(new mongoose.Types.ObjectId(), '198.51.100.24')
      ).resolves.toBeUndefined();

      expect(degradeTraces()).toContain('模拟读取用户失败');
      expect(sendNotification).not.toHaveBeenCalled();
    });

    test('反向对照：用户确实不存在 ⇒ 静默 return 是既有语义，不得打降级 error', async () => {
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.permissionFailures);
      jest.spyOn(User, 'findById').mockReturnValue(chainQuery(Promise.resolve(null)));

      await securityAlert.checkPermissionAbuse(new mongoose.Types.ObjectId(), '198.51.100.25');

      expect(degradeTraces()).toBe('');
      expect(sendNotification).not.toHaveBeenCalled();
    });
  });
});
