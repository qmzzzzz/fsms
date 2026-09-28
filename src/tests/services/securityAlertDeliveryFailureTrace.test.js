/**
 * 安全告警的 fire-and-forget 投递：崩了必须留痕（dispatchNotification）
 *
 * 三个检测器都曾用 `void sendNotification(...).catch(() => {})`。那个空 catch 把两件
 * 不同的事混成一件：
 *   - "webhook 没送达"：sendNotification 内部已经重试过并 logger.warn 过，不用管；
 *   - "告警机器本身崩了"：它在写下 SECURITY_ALERT 那行之前就抛（计数/序列化/日志器
 *     不可用）——静默接住它等于这条告警从未存在过，而检测器已按"已告警"继续走下去。
 * 现在三处统一走 dispatchNotification，失败落 logger.error。
 *
 * 手法说明：securityAlert.js 在模块顶部就解构了
 * `const { sendNotification } = require('./securityAlertDelivery')`，
 * 因此 `jest.spyOn(投递模块, 'sendNotification')` 打不到那个局部绑定——
 * 必须在 require 被测模块之前用 jest.mock 把整个投递模块换掉（每个测试文件
 * 独立模块注册表，不影响其它套件）。
 *
 * 覆盖边界（诚实登记）：本文件证明的是"三处调用点都经过有留痕的入口"。
 * 若有人把某一处改回裸 `void sendNotification(...).catch(() => {})`，
 * 对应用例必须红——变异自检按三个点分别验证过。
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

const stamp = `sadt${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

describe('告警投递失败必须留痕（不静默）', () => {
  let securityAlert;
  let THRESHOLDS;
  // ALERT_TYPES 必须取自被测模块：投递模块在本文件里是 jest.mock 的替身，
  // 从它身上取枚举只会得到 undefined（断言退化成"包含 undefined"的假绿）。
  let ALERT_TYPES;
  let errorSpy;
  const users = new Map();

  // 每条用例一个独立用户：shouldSendAlert 的频控键是 `<类型>_<userId>`（进程内 Map），
  // 复用 id 会被第二次的频控闸挡在投递之前，用例就变成"什么都没测"的假绿。
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    require('../../models/IPBlacklist');
    require('../../models/TokenBlacklist');
    for (const slug of ['abuse', 'abuse_ok', 'export', 'export_ok', 'brute', 'brute_ok']) {
      users.set(
        slug,
        await User.create({
          username: `${stamp}_${slug}`,
          email: `${slug}.${stamp}@example.com`,
          password: 'Qz7#Lm42vTx9',
          roles: [],
        })
      );
    }
    securityAlert = require('../../services/securityAlert');
    THRESHOLDS = securityAlert.THRESHOLDS;
    ALERT_TYPES = securityAlert.ALERT_TYPES;
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  beforeEach(() => {
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    sendNotification.mockReset();
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  const deliveryErrors = () =>
    errorSpy.mock.calls
      .map((c) => String(c[0]))
      .filter((m) => m.includes('安全告警投递未能执行'))
      .join('\n');

  /** 让投递入口本身抛（模拟告警机器坏了，而不是 webhook 超时） */
  const deliveryExplodes = () => sendNotification.mockRejectedValue(new Error('模拟投递器崩溃'));

  describe('权限滥用', () => {
    test('投递器抛错 ⇒ logger.error 留痕，且不把异常冒给 fire-and-forget 的调用方', async () => {
      deliveryExplodes();
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.permissionFailures);

      await expect(
        securityAlert.checkPermissionAbuse(users.get('abuse')._id, '203.0.113.11')
      ).resolves.toBeUndefined();
      // 投递是 void 的：让被拒的 Promise 落地后再看日志
      await new Promise((r) => setImmediate(r));

      expect(deliveryErrors()).toContain(ALERT_TYPES.PERMISSION_ABUSE);
      expect(deliveryErrors()).toContain('模拟投递器崩溃');
    });

    test('反向对照：投递正常完成时不得出现投递失败痕迹', async () => {
      sendNotification.mockResolvedValue(undefined);
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.permissionFailures);

      await securityAlert.checkPermissionAbuse(users.get('abuse_ok')._id, '203.0.113.12');
      await new Promise((r) => setImmediate(r));

      expect(sendNotification).toHaveBeenCalled();
      expect(deliveryErrors()).toBe('');
    });
  });

  describe('批量导出', () => {
    test('投递器抛错不得把已成功的导出拖成异常，但必须留痕', async () => {
      deliveryExplodes();

      await expect(
        securityAlert.checkBulkExport(
          users.get('export')._id,
          users.get('export').username,
          THRESHOLDS.bulkExportThreshold,
          'audit_export'
        )
      ).resolves.toBeUndefined();
      await new Promise((r) => setImmediate(r));

      expect(deliveryErrors()).toContain(ALERT_TYPES.BULK_EXPORT);
      expect(deliveryErrors()).toContain('模拟投递器崩溃');
    });

    test('反向对照：投递正常完成时不得出现投递失败痕迹', async () => {
      sendNotification.mockResolvedValue(undefined);

      await securityAlert.checkBulkExport(
        users.get('export_ok')._id,
        users.get('export_ok').username,
        THRESHOLDS.bulkExportThreshold + 10,
        'report_export'
      );
      await new Promise((r) => setImmediate(r));

      expect(sendNotification).toHaveBeenCalled();
      expect(deliveryErrors()).toBe('');
    });
  });

  describe('暴力破解', () => {
    test('CRITICAL 告警的投递器抛错同样必须留痕（最高级别告警不许静默消失）', async () => {
      deliveryExplodes();
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.bruteForceAttempts + 3);

      const username = users.get('brute').username;
      await expect(
        securityAlert.checkBruteForce(username, '198.51.100.7')
      ).resolves.toBeUndefined();
      await new Promise((r) => setImmediate(r));

      expect(deliveryErrors()).toContain(ALERT_TYPES.BRUTE_FORCE);
      expect(deliveryErrors()).toContain('模拟投递器崩溃');
    });

    test('反向对照：投递正常完成时不得出现投递失败痕迹', async () => {
      sendNotification.mockResolvedValue(undefined);
      jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.bruteForceAttempts + 3);

      await securityAlert.checkBruteForce(users.get('brute_ok').username, '198.51.100.8');
      await new Promise((r) => setImmediate(r));

      expect(sendNotification).toHaveBeenCalled();
      expect(deliveryErrors()).toBe('');
    });
  });
});
