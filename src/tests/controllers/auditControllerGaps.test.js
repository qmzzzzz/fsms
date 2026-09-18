/**
 * auditController 未覆盖路径补充（2026-09-18）
 *
 * 补的是 lcov 显示零覆盖、但属真实契约的分支：
 *  - exportAuditLogs 的 buildAuditQuery 失败出口（auditController.js:28-32）：
 *    筛选参数非法时必须 400 + 原始中文原因，而不是 500；
 *  - exportAuditLogs 的 catch 出口（auditController.js:60-68）：
 *    流中途失败时头已发出，只能 res.end() 收尾；头未发出则回 AUDIT_EXPORT_FAILED；
 *  - verifyAuditChainIntegrity 的断链出口（auditController.js:97-125）：
 *    断裂属安全事件——必须 error 日志 + 写 high 风险审计，而不是只回一次普通查询。
 *
 * 关于断链用例的取舍：**检测**（篡改能否被发现）已由 backgroundJobs.test.js 与
 * auditChainVerify.test.js 用真实篡改覆盖；本文件只覆盖**控制器对断裂报告的反应**，
 * 故把 verifyAuditChain 替换为返回固定报告的替身。这样既不重复覆盖，也避免
 * 在全局共享的内存库里留下「被篡改的链内记录」污染其他套件（真实教训：
 * 链式审计的破坏是全局可见的，随手的 $set 会让别的套件随机转红）。
 * 除该服务外一律真实：真实 HTTP 路由、真实库写入、真实响应对象。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const logger = require('../../utils/logger');

// 控制器内是 inline require，jest.mock 的工厂对 inline require 同样生效
const mockVerifyAuditChain = jest.fn();
jest.mock('../../services/auditChainVerify', () => ({
  verifyAuditChain: (...args) => mockVerifyAuditChain(...args),
  DEFAULT_MAX_RECORDS: 20000,
}));

describe('auditController 导出失败与断链审计', () => {
  let app;
  let AuditLog;
  let Role;
  let Permission;
  let operator;
  let operatorToken;
  const stamp = `acg${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    const wildcard = await Permission.create({
      name: 'Audit controller gap wildcard',
      code: '*:*',
      type: 'api',
      module: 'system',
    });
    const role = await Role.create({
      name: 'Audit controller gap role',
      code: `ACG_ROLE_${stamp}`,
      level: 10,
      isBuiltIn: true,
      permissions: [wildcard._id],
    });
    operator = await require('../../models/User').create({
      username: `acgoperator${stamp}`,
      email: `acgoperator${stamp}@example.com`,
      password: `Aa1!${stamp}Test`,
      roles: [role._id],
    });
    operatorToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      // 本文件写入的审计留痕全部清掉（链式集合用 collection 绕过 append-only 钩子）
      await AuditLog.collection
        .deleteMany({ action: 'audit_chain_verify', userId: operator._id })
        .catch(() => {});
      await require('../../models/User')
        .deleteMany({ username: `acgoperator${stamp}` })
        .catch(() => {});
      await Role.deleteMany({ code: `ACG_ROLE_${stamp}` }).catch(() => {});
      await Permission.deleteOne({ code: '*:*' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    mockVerifyAuditChain.mockReset();
  });

  const authed = (url) => request(app).get(url).set('Authorization', `Bearer ${operatorToken}`);

  describe('导出筛选参数非法 → 400（auditController.js:28-32）', () => {
    test('startDate 非法 → 400 且回显「开始日期格式错误」（不得 500）', async () => {
      const res = await authed('/api/security/audit-logs/export?startDate=not-a-date');
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('开始日期格式错误');
    });

    test('endDate 非法 → 400 且回显「结束日期格式错误」', async () => {
      // 中文日期必须 encodeURIComponent：superagent 拒绝未转义的非 ASCII 路径（实测 TypeError）
      const res = await authed(
        '/api/security/audit-logs/export?endDate=' + encodeURIComponent('13月45日')
      );
      expect(res.status).toBe(400);
      expect(res.body.message).toBe('结束日期格式错误');
    });

    test('action 不在白名单 → 400，且校验发生在任何 CSV 响应头之前', async () => {
      const res = await authed('/api/security/audit-logs/export?action=definitely_not_an_action');
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      // 关键：必须在发送任何 CSV 头之前失败，否则下游只能拿到半截文件
      expect(res.headers['content-disposition']).toBeUndefined();
      expect(res.headers['x-audit-manifest-records']).toBeUndefined();
    });
  });

  describe('断链出口：安全事件必须留痕（auditController.js:97-125）', () => {
    const brokenReport = {
      intact: false,
      total: 42,
      breaks: 3,
      byType: { hash_mismatch: 2, hmac_missing: 0, hmac_mismatch: 1, chain_break: 0 },
    };
    const intactReport = {
      intact: true,
      total: 42,
      breaks: 0,
      byType: { hash_mismatch: 0, hmac_missing: 0, hmac_mismatch: 0, chain_break: 0 },
    };

    beforeEach(async () => {
      // 清掉上一条留痕，避免两条用例互相取到对方的记录
      await AuditLog.collection.deleteMany({
        action: 'audit_chain_verify',
        userId: operator._id,
      });
    });

    test('intact=false → 200 + 报告透传 + error 日志（含断裂计数与操作者）+ high 风险审计', async () => {
      mockVerifyAuditChain.mockResolvedValue(brokenReport);
      const errorSpy = jest.spyOn(logger, 'error');
      try {
        const res = await authed('/api/security/audit-logs/verify?limit=500');
        expect(res.status).toBe(200);
        // 响应体是报告本身，断裂信息必须完整透出（前端据此展示明细）
        expect(res.body.data).toEqual(brokenReport);
        expect(res.body.message).toBe('审计链存在断裂');

        // 可检索的告警日志：必须点名操作者与各断裂类型计数
        const alert = errorSpy.mock.calls
          .map((c) => String(c[0]))
          .find((m) => m.includes('审计链完整性校验发现'));
        expect(alert).toBeDefined();
        expect(alert).toContain(operator.username);
        expect(alert).toContain('3 处断裂');
        expect(alert).toContain('hash_mismatch=2');
        expect(alert).toContain('hmac_mismatch=1');
      } finally {
        errorSpy.mockRestore();
      }

      // 留痕：high 风险 + 只记摘要（不记 samples 的 hash 明文）
      const written = await AuditLog.collection.findOne({
        action: 'audit_chain_verify',
        userId: operator._id,
      });
      expect(written).not.toBeNull();
      expect(written.riskLevel).toBe('high');
      expect(written.body).toEqual({ total: 42, breaks: 3, byType: brokenReport.byType });
      expect(written.success).toBe(true);
    });

    test('intact=true → 同一接口写 low 风险审计（与断裂路径形成对照，防 riskLevel 写死）', async () => {
      mockVerifyAuditChain.mockResolvedValue(intactReport);
      const res = await authed('/api/security/audit-logs/verify?limit=500');
      expect(res.status).toBe(200);
      expect(res.body.data.intact).toBe(true);
      expect(res.body.message).toBe('审计链完整');

      const written = await AuditLog.collection.findOne({
        action: 'audit_chain_verify',
        userId: operator._id,
      });
      expect(written).not.toBeNull();
      expect(written.riskLevel).toBe('low');
      expect(written.success).toBe(true);
    });

    test('limit 与 from 非法 → 400，且不得调用校验服务（参数校验先于扫描）', async () => {
      const badLimit = await authed('/api/security/audit-logs/verify?limit=latest');
      expect(badLimit.status).toBe(400);
      expect(badLimit.body.errors.errorCode).toBe('LIMIT_MUST_BE_POSITIVE_INT');
      const badFrom = await authed('/api/security/audit-logs/verify?from=newest');
      expect(badFrom.status).toBe(400);
      expect(badFrom.body.errors.errorCode).toBe('FROM_MUST_BE_LATEST_OR_EARLIEST');
      // 参数非法时扫描整个链是纯浪费（且会掩盖真正的参数错误）
      expect(mockVerifyAuditChain).not.toHaveBeenCalled();
    });

    test('扫描参数透传：limit 解析为数字，from=earliest → fromLatest=false', async () => {
      mockVerifyAuditChain.mockResolvedValue(intactReport);
      await authed('/api/security/audit-logs/verify?limit=123&from=earliest');
      expect(mockVerifyAuditChain).toHaveBeenCalledTimes(1);
      const [model, opts] = mockVerifyAuditChain.mock.calls[0];
      expect(model).toBe(AuditLog);
      expect(opts).toEqual({ maxRecords: 123, fromLatest: false });

      mockVerifyAuditChain.mockClear();
      await authed('/api/security/audit-logs/verify');
      const [, defaultOpts] = mockVerifyAuditChain.mock.calls[0];
      // 未传 limit 时走服务的默认上限，而不是 NaN/undefined
      expect(defaultOpts).toEqual({ maxRecords: 20000, fromLatest: true });
    });
  });
});
