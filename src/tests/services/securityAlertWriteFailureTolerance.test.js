'use strict';

/**
 * 安全告警的"落库失败"必须是可观测失败，而不是消失
 *
 * 三个检测器（暴力破解 / 批量导出 / 权限滥用）都把告警写进 AuditLog，而调用方是
 * fire-and-forget 或 `await` 在业务主流程上：
 *   - `middleware/rbac.js` 对 checkPermissionAbuse 是 `void ….catch(() => {})`
 *     ⇒ 裸 `await AuditLog.create` 一抛，整条 HIGH 告警**无声消失**（既不进审计，
 *       也没有一行日志；权限滥用检测在掉链子这件事没有任何人看得见）；
 *   - 导出路径 `await` checkBulkExport ⇒ 一次 DB 瞬断会把已经成功的导出顶成 500。
 *
 * P1-23 给前两处挂了 try/catch + logger.error，本文件补的是"挂了 try/catch 却从未
 * 被测试钉住"这一格，同时把当初漏掉的第三处（checkPermissionAbuse）一并纳入同一
 * 条不变量：告警写不进去 ⇒ 必须留 error 痕迹，且不得把异常冒给调用方。
 * 反向对照钉住"不是改成无脑吞错"：写入成功时必须真的落库、且不打 error。
 */

const mongoose = require('mongoose');
const AuditLog = require('../../models/AuditLog');
const User = require('../../models/User');
const logger = require('../../utils/logger');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `sawf${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);

// 每个用例一个独立 userId：shouldSendAlert 的频控键是 `<类型>_<userId>`（进程内
// Map，5 分钟窗口），共用 id 会让第二个用例被频控闸直接挡下——表现为"没落库也没日志"
// 的假绿，杀掉的却是错误的东西。
const users = new Map();

describe('告警审计落库失败的处理', () => {
  let securityAlert;
  let THRESHOLDS;
  let errorSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    require('../../models/TokenBlacklist');
    for (const slug of ['abuse', 'export', 'ok']) {
      users.set(
        slug,
        await User.create({
          username: `${stamp}_${slug}`,
          email: `${slug}.${stamp}@example.com`,
          password: randomPassword(),
          roles: [],
        })
      );
    }
    securityAlert = require('../../services/securityAlert');
    THRESHOLDS = securityAlert.THRESHOLDS;
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ userId: { $in: [...users.values()].map((u) => u._id) } }).catch(
      () => {}
    );
    await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  beforeEach(() => {
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    jest.restoreAllMocks();
  });

  /** 权限滥用检测：403 计数走桩，避免为触发阈值真写 20 条审计 */
  const runAbuse = () => securityAlert.checkPermissionAbuse(users.get('abuse')._id, '203.0.113.9');

  test('权限滥用：审计落库失败必须留 error，且不得把异常抛给 fire-and-forget 的调用方', async () => {
    jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.permissionFailures);
    jest.spyOn(AuditLog, 'create').mockRejectedValue(new Error('模拟 DB 瞬断'));

    // 修复前这一句就红了：裸 await 抛错 → checkPermissionAbuse reject →
    // 调用方 rbac.js 的 .catch(() => {}) 把它咽掉，告警与错误一起消失。
    await expect(runAbuse()).resolves.toBeUndefined();

    const logged = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(logged).toContain('权限滥用告警审计落库失败');
    // 失败原因必须进日志（只写"失败了"等于让人去复现）
    expect(logged).toContain('模拟 DB 瞬断');
  });

  test('批量导出：同一格不变量（导出主流程不得被旁路告警拖成 500）', async () => {
    jest.spyOn(AuditLog, 'create').mockRejectedValue(new Error('模拟校验失败'));

    await expect(
      securityAlert.checkBulkExport(users.get('export')._id, `${stamp}_export`, 500, 'audit_export')
    ).resolves.toBeUndefined();

    const logged = errorSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(logged).toContain('批量导出告警审计落库失败');
    expect(logged).toContain('模拟校验失败');
  });

  test('反向对照：写入成功时不落 error 痕迹，且告警真的进了审计库', async () => {
    jest.spyOn(AuditLog, 'countDocuments').mockResolvedValue(THRESHOLDS.permissionFailures);
    // 封禁链路显式桩掉：本用例的命题是"审计写入成功 ⇒ 不打 error"，
    // 不该被"这个 IP 恰好能不能被封"污染（2026-09-30 起 checkPermissionAbuse
    // 会在审计之后封 IP，真实调用 addToBlacklist 时白名单/写库结果会让本断言变脆）。
    const security = require('../../middleware/security');
    const addSpy = jest
      .spyOn(security, 'addToBlacklist')
      .mockResolvedValue({ banned: true, normalizedIp: '203.0.113.10' });
    try {
      const okUser = users.get('ok');
      await securityAlert.checkPermissionAbuse(okUser._id, '203.0.113.10');

      const rows = await AuditLog.find({
        action: securityAlert.ALERT_TYPES.PERMISSION_ABUSE,
        userId: okUser._id,
      }).lean();
      expect(rows).toHaveLength(1);
      expect(rows[0].riskLevel).toBe(securityAlert.ALERT_LEVELS.HIGH);
      expect(rows[0].username).toBe(okUser.username);
      expect(errorSpy).not.toHaveBeenCalled();
      // 遏制确实执行了（这是本次新加的职责，不是"只告警"）
      expect(addSpy).toHaveBeenCalledWith(
        '203.0.113.10',
        expect.any(Number),
        expect.stringContaining('permission_abuse_auto_ban_tier'),
        'auto'
      );
    } finally {
      addSpy.mockRestore();
    }
  });
});
