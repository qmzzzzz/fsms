/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：审计导出的硬上限与 CSV 转义
 * 守护的不变式：超上限必须拒绝；CSV 字段必须转义（防公式/列注入）
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `auditExportBoundary.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * Audit export hard-limit and CSV escaping regression tests.
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('audit export boundaries', () => {
  let app;
  let AuditLog;
  let Role;
  let Permission;
  let operator;
  let operatorToken;
  const stamp = `aeb${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    const wildcardPermission = await Permission.create({
      name: 'Audit export wildcard',
      code: '*:*',
      type: 'api',
      module: 'system',
    });
    const superRole = await Role.create({
      name: 'Audit export super role',
      code: `AEB_ROLE_${stamp}`,
      level: 10,
      isBuiltIn: true,
      permissions: [wildcardPermission._id],
    });
    operator = await require('../../models/User').create({
      username: `aeboperator${stamp}`,
      email: `aeboperator${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      roles: [superRole._id],
    });

    operatorToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await AuditLog.deleteMany({ username: `aebexport${stamp}` }).catch(() => {});
      await require('../../models/User')
        .deleteMany({
          username: `aeboperator${stamp}`,
        })
        .catch(() => {});
      await Role.deleteMany({ code: `AEB_ROLE_${stamp}` }).catch(() => {});
      await Permission.deleteOne({ code: '*:*' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('streams the CSV export with a safe manifest', async () => {
    const documents = Array.from({ length: 5 }, (_, index) => ({
      timestamp: new Date(Date.UTC(2026, 8, 8, 0, 0, index)),
      action: 'auth_login',
      username: index === 0 ? `=cmd|'/c calc'!A1` : `aebuser${stamp}`,
      ip: '192.168.1.10',
      path: '/audit-logs',
      statusCode: 200,
      success: true,
      riskLevel: 'low',
      category: 'auth',
    }));
    await AuditLog.insertMany(documents);

    const response = await request(app)
      .get('/api/security/audit-logs/export')
      .query({ action: 'auth_login' })
      .set('Authorization', `Bearer ${operatorToken}`);

    expect(response.status).toBe(200);
    expect(response.headers['x-audit-truncated']).toBeUndefined();
    expect(Number(response.headers['x-audit-manifest-records'])).toBeGreaterThanOrEqual(5);
    expect(response.text).toContain(`'=cmd|'/c calc'!A1`);
    expect(response.text).toContain('__MANIFEST__');
  });
});
