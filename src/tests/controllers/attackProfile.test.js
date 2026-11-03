/**
 * GET /api/security/attack-profile —— 单 IP 攻击行为画像
 *
 * 画像接口是「普通用户只输入 IP」的唯一读口，因此这里不测内部函数，而是从
 * HTTP 边界验证三件客户实际会依赖的事：
 *   ① 输入只有一个 IP：缺省/非法/歧义写法都必须回 400 IP_SINGLE_REQUIRED，
 *      不能把「参数写错」变成一份看起来正常的空画像；
 *   ② 输出是一份可读的结论：分类、评分、建议、证据与时间线来自同一批审计行，
 *      已封禁的攻击源不重复建议封禁，受限数据范围必须显式标注并追加 verify_scope；
 *   ③ 证据最小化：画像只投影判定字段，请求/响应正文与头袋不得从聚合读口批量流出。
 *
 * 取数范围不 mock：真实 HTTP + 内存 MongoDB，数据范围由角色 level 照实推导。
 */

'use strict';

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { reauthHeaders } = require('../helpers/reauthTicket');

const ATTACKER_IP = '203.0.113.234';
const BLOCKED_IP = '203.0.113.235';
const CLEAN_IP = '203.0.113.236';
const OLD_IP = '203.0.113.237';
const SELF_ONLY_IP = '203.0.113.238';

const NOW = Date.now();
const minutesAgo = (minutes) => new Date(NOW - minutes * 60 * 1000);

describe('GET /api/security/attack-profile 单 IP 攻击行为画像', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let IPBlacklist;
  let admin;
  let adminToken;
  let selfUser;
  let selfToken;
  let noPermToken;

  const suffix = Date.now().toString(36);
  const tokenFor = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '6h' }
    );

  const getProfile = (query, token = adminToken, withTicket = true) => {
    const req = request(app)
      .get('/api/security/attack-profile')
      .query(query)
      .set('Authorization', `Bearer ${token}`);
    if (withTicket) req.set(reauthHeaders(token));
    return req;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');
    IPBlacklist = require('../../models/IPBlacklist');

    const auditPerm = await Permission.findOneAndUpdate(
      { code: 'security:audit' },
      {
        $setOnInsert: { name: '审计日志', code: 'security:audit', type: 'api', module: 'security' },
      },
      { upsert: true, new: true }
    );

    const adminRole = await Role.create({
      name: `攻击画像超管_${suffix}`,
      code: `ATTACK_PROFILE_ADMIN_${suffix}`,
      level: 10,
      permissions: [auditPerm._id],
    });
    admin = await User.create({
      username: `attack_profile_admin_${suffix}`,
      email: `attack_profile_admin_${suffix}@example.com`,
      password: 'Test@1234567',
      roles: [adminRole._id],
    });
    adminToken = tokenFor(admin);

    // level 4 ⇒ self 数据范围：画像只能聚合到自己的审计行
    const selfRole = await Role.create({
      name: `攻击画像自查_${suffix}`,
      code: `ATTACK_PROFILE_SELF_${suffix}`,
      level: 4,
      permissions: [auditPerm._id],
    });
    selfUser = await User.create({
      username: `attack_profile_self_${suffix}`,
      email: `attack_profile_self_${suffix}@example.com`,
      password: 'Test@1234567',
      roles: [selfRole._id],
    });
    selfToken = tokenFor(selfUser);

    const noPermRole = await Role.create({
      name: `攻击画像无权限_${suffix}`,
      code: `ATTACK_PROFILE_NO_PERM_${suffix}`,
      level: 4,
      permissions: [],
    });
    const noPermUser = await User.create({
      username: `attack_profile_noperm_${suffix}`,
      email: `attack_profile_noperm_${suffix}@example.com`,
      password: 'Test@1234567',
      roles: [noPermRole._id],
    });
    noPermToken = tokenFor(noPermUser);

    const base = {
      ip: ATTACKER_IP,
      category: 'security',
      success: false,
      statusCode: 401,
      method: 'POST',
      path: '/api/auth/login',
      username: 'alice',
      userAgent: 'curl/8.0',
      riskLevel: 'low',
      timestamp: minutesAgo(5),
    };

    await AuditLog.collection.insertMany([
      {
        ...base,
        action: 'honeypot_login',
        path: '/admin/login',
        statusCode: 200,
        userAgent: 'sqlmap/1.0',
        riskLevel: 'critical',
        timestamp: minutesAgo(1),
      },
      { ...base, action: 'login_failed', username: 'alpha', timestamp: minutesAgo(2) },
      { ...base, action: 'login_failed', username: 'beta', timestamp: minutesAgo(3) },
      { ...base, action: 'login_failed', username: 'gamma', timestamp: minutesAgo(4) },
      {
        ...base,
        action: 'report_export',
        path: '/api/reports/export',
        success: true,
        statusCode: 200,
        username: 'admin',
        userAgent: 'Mozilla/5.0',
        riskLevel: 'high',
        timestamp: minutesAgo(5),
      },
      {
        ...base,
        action: 'query_param_rejected',
        path: '/api/devices',
        statusCode: 400,
        userAgent: 'sqlmap/1.0',
        timestamp: minutesAgo(6),
      },
      {
        ...base,
        action: 'malformed_request_blocked',
        path: '/wp-login.php',
        statusCode: 404,
        userAgent: 'nmap',
        timestamp: minutesAgo(7),
      },
      {
        ...base,
        action: 'rate_limit_abuse',
        statusCode: 429,
        timestamp: minutesAgo(8),
      },
      {
        ...base,
        action: 'canary_username_attempt',
        username: 'canary',
        timestamp: minutesAgo(9),
      },
      {
        ...base,
        action: 'permission_abuse',
        path: '/api/users',
        statusCode: 403,
        refusalReason: 'PERMISSION_DENIED',
        userAgent: 'Mozilla/5.0',
        timestamp: minutesAgo(10),
      },
      {
        ...base,
        action: 'suspicious_ip_activity',
        path: '/api/dashboard',
        success: true,
        statusCode: 200,
        riskLevel: 'high',
        userAgent: 'Mozilla/5.0',
        timestamp: minutesAgo(11),
      },
      {
        ...base,
        action: 'ip_blacklist_blocked',
        path: '/api/devices',
        statusCode: 403,
        userAgent: 'nmap',
        timestamp: minutesAgo(12),
      },
      {
        // 敏感载荷诱饵：画像只做判定投影，这些字段不得随聚合结果离开服务端
        ...base,
        action: 'user_delete',
        category: 'user',
        path: '/api/users/x',
        success: true,
        statusCode: 200,
        username: 'admin',
        userAgent: 'Mozilla/5.0',
        timestamp: minutesAgo(13),
        body: { password: 'MARKER_BODY' },
        params: { id: 'MARKER_PARAMS' },
        query: { token: 'MARKER_QUERY' },
        requestHeaders: { authorization: 'MARKER_REQUEST_HEADER' },
        responseHeaders: { 'set-cookie': 'MARKER_RESPONSE_HEADER' },
        responseBody: { secret: 'MARKER_RESPONSE_BODY' },
        clientInfo: { browser: 'MARKER_CLIENT_INFO' },
      },
      {
        ...base,
        ip: OLD_IP,
        action: 'login_failed',
        timestamp: new Date(NOW - 8 * 24 * 60 * 60 * 1000),
      },
      {
        ...base,
        ip: SELF_ONLY_IP,
        userId: selfUser._id,
        username: selfUser.username,
        action: 'login_failed',
        timestamp: minutesAgo(14),
      },
      {
        ...base,
        ip: SELF_ONLY_IP,
        userId: admin._id,
        username: admin.username,
        action: 'honeypot_login',
        statusCode: 200,
        riskLevel: 'critical',
        timestamp: minutesAgo(15),
      },
    ]);

    await IPBlacklist.create({
      ip: BLOCKED_IP,
      type: 'black',
      reason: '画像测试封禁',
      source: 'manual',
    });
    IPBlacklist.invalidateSnapshot('black');
    await AuditLog.collection.insertMany([
      {
        ...base,
        ip: BLOCKED_IP,
        action: 'honeypot_login',
        statusCode: 200,
        riskLevel: 'critical',
        timestamp: minutesAgo(16),
      },
    ]);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('攻击源：分类/评分/建议/证据/时间线同源，敏感载荷不出现在聚合结果', async () => {
    const res = await getProfile({ ip: ATTACKER_IP });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const data = res.body.data;
    expect(data).toMatchObject({
      ip: ATTACKER_IP,
      total: 13,
      analyzed: 13,
      truncated: false,
      score: 100,
      verdict: 'attack',
      riskLevel: 'high',
      isPrivate: false,
      scopeLimited: false,
    });
    expect(data.window.hours).toBe(168);
    expect(new Date(data.window.since).getTime()).toBeLessThan(
      new Date(data.window.until).getTime()
    );

    const byCode = Object.fromEntries(data.categories.map((item) => [item.code, item]));
    expect(Object.keys(byCode).sort()).toEqual([
      'account_enumeration',
      'credential_stuffing',
      'data_exfiltration',
      'honeypot',
      'injection_probe',
      'path_scanning',
      'rate_limit_abuse',
      'suspicious_activity',
      'unauthorized_access',
    ]);
    expect(byCode.credential_stuffing).toMatchObject({
      count: 3,
      blockedCount: 3,
      successCount: 0,
      severity: 'high',
    });
    expect(byCode.honeypot).toMatchObject({ count: 1, severity: 'critical' });
    expect(byCode.data_exfiltration).toMatchObject({
      count: 1,
      successCount: 1,
      severity: 'high',
    });
    expect(byCode.path_scanning).toMatchObject({ count: 1, severity: 'low' });
    // 黑名单命中是处置结果，不是新增的行为分类
    expect(byCode.ip_blacklist_blocked).toBeUndefined();

    expect(data.stats).toMatchObject({
      failedRequests: 10,
      // E9② 改名钉值：口径是「未被拦截的请求」（blocked/403 行不计），不再叫 successfulRequests
      nonBlockedRequests: 3,
      failedLogins: 3,
      successfulLogins: 0,
      distinctAccountsTried: 3,
      distinctUserAgents: 4,
      criticalRows: 1,
      peakBucketRequests: 13,
      successAfterFailure: false,
      suspiciousSuccessAt: null,
    });
    expect(typeof data.stats.peakBucketStart).toBe('string');
    expect(data.stats.firstFailedLoginAt).toEqual(minutesAgo(4).toISOString());
    expect(data.stats.lastFailedLoginAt).toEqual(minutesAgo(2).toISOString());

    expect(data.suggestions).toEqual(
      expect.arrayContaining([
        'monitor',
        'enable_mfa',
        'review_exports',
        'review_honeypot',
        'review_accounts',
        'review_access_control',
        'review_rate_limits',
        'block_ip',
      ])
    );
    expect(data.suggestions).not.toContain('verify_scope');

    expect(data.topPaths[0]).toEqual({ value: '/api/auth/login', count: 5 });
    expect(data.topActions[0]).toEqual({ value: 'login_failed', count: 3 });
    expect(data.topTargetAccounts).toEqual(
      expect.arrayContaining([
        { value: 'alpha', count: 1 },
        { value: 'beta', count: 1 },
        { value: 'gamma', count: 1 },
      ])
    );
    expect(data.topUserAgents[0]).toEqual({ value: 'curl/8.0', count: 5 });

    // 默认 7 天窗口用天桶（≤48 小时才切小时桶，见分类聚合层用例）
    expect(data.timeline.unit).toBe('day');
    expect(data.timeline.buckets).toHaveLength(1);
    expect(data.timeline.buckets[0]).toMatchObject({ total: 13, blocked: 10 });
    expect(data.timeline.buckets[0].categories).toHaveLength(9);

    expect(data.containment).toEqual({
      degraded: false,
      blacklisted: false,
      whitelisted: false,
      entries: [],
    });

    // 证据只带判定字段；请求/响应正文与头袋不得进入画像
    const evidence = data.categories.flatMap((item) => item.evidence);
    const allowedKeys = [
      'action',
      'category',
      'logId',
      'method',
      'path',
      'reason',
      'refusalReason',
      'riskFactors',
      'riskLevel',
      'statusCode',
      'success',
      'timestamp',
      'username',
    ];
    for (const item of evidence) {
      expect(Object.keys(item).every((key) => allowedKeys.includes(key))).toBe(true);
      expect(item).toEqual(
        expect.objectContaining({
          timestamp: expect.anything(),
          path: expect.anything(),
          statusCode: expect.anything(),
        })
      );
      // 证据行必须能回指原始审计记录，否则客户拿到的只是无法核对的摘要
      expect(item.logId).toMatch(/^[a-f0-9]{24}$/i);
    }

    // 未归类的行（黑名单处置、普通业务操作）仍作为证据返回；它们不进分类，但不得消失
    expect(data.uncategorized.count).toBe(2);
    expect(data.uncategorized.evidence).toHaveLength(2);
    expect(data.uncategorized.evidence.map((item) => item.action).sort()).toEqual([
      'ip_blacklist_blocked',
      'user_delete',
    ]);
    for (const item of data.uncategorized.evidence) {
      expect(item.logId).toMatch(/^[a-f0-9]{24}$/i);
      expect(Object.keys(item).every((key) => allowedKeys.includes(key))).toBe(true);
    }

    const text = JSON.stringify(res.body);
    expect(text).not.toContain('MARKER_BODY');
    expect(text).not.toContain('MARKER_PARAMS');
    expect(text).not.toContain('MARKER_QUERY');
    expect(text).not.toContain('MARKER_REQUEST_HEADER');
    expect(text).not.toContain('MARKER_RESPONSE_HEADER');
    expect(text).not.toContain('MARKER_RESPONSE_BODY');
    expect(text).not.toContain('MARKER_CLIENT_INFO');
  });

  test('已封禁的攻击源：containment 如实标注，不重复建议封禁', async () => {
    const res = await getProfile({ ip: BLOCKED_IP });
    expect(res.status).toBe(200);
    const data = res.body.data;
    expect(data.verdict).toBe('attack');
    expect(data.containment.blacklisted).toBe(true);
    expect(data.containment.degraded).toBe(false);
    expect(data.containment.entries).toEqual([
      expect.objectContaining({ listType: 'black', ip: BLOCKED_IP }),
    ]);
    expect(data.suggestions).not.toContain('block_ip');
    expect(data.suggestions).toContain('review_honeypot');
  });

  test('IP 缺省/非法/歧义写法：400 IP_SINGLE_REQUIRED（不返回一份空画像）', async () => {
    for (const query of [{}, { ip: '999.999.999.999' }, { ip: '0177.0.0.1' }]) {
      const res = await getProfile(query);
      expect(res.status).toBe(400);
      expect(res.body.errors?.errorCode).toBe('IP_SINGLE_REQUIRED');
    }
  });

  test('无数据：200 + no_data，零分且无建议（与「参数错误」可区分）', async () => {
    const res = await getProfile({ ip: CLEAN_IP });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      ip: CLEAN_IP,
      total: 0,
      analyzed: 0,
      score: 0,
      verdict: 'no_data',
      riskLevel: 'none',
      categories: [],
      suggestions: [],
      isPrivate: false,
    });
    expect(res.body.data.timeline.buckets).toEqual([]);
    expect(res.body.data.uncategorized).toEqual({ count: 0, evidence: [] });
    expect(res.body.data.containment.degraded).toBe(false);
  });

  test('内网/回环地址带 isPrivate 标记（报告据此提示「来源不可路由」）', async () => {
    const res = await getProfile({ ip: '10.123.45.67' });
    expect(res.status).toBe(200);
    expect(res.body.data.isPrivate).toBe(true);
  });

  test('时间窗：缺省 7 天、上限 30 天、下界 1 小时；坏值回落默认', async () => {
    const cases = [
      [{ ip: CLEAN_IP }, 168],
      [{ ip: CLEAN_IP, hours: 9999 }, 720],
      [{ ip: CLEAN_IP, hours: 0 }, 1],
      [{ ip: CLEAN_IP, hours: 'abc' }, 168],
    ];
    for (const [query, expectedHours] of cases) {
      const res = await getProfile(query);
      expect(res.status).toBe(200);
      expect(res.body.data.window.hours).toBe(expectedHours);
    }
  });

  test('窗口边界真实生效：8 天前的行在默认 7 天窗口外，扩到 30 天才可见', async () => {
    const shorter = await getProfile({ ip: OLD_IP });
    expect(shorter.status).toBe(200);
    expect(shorter.body.data.total).toBe(0);
    expect(shorter.body.data.verdict).toBe('no_data');

    const longer = await getProfile({ ip: OLD_IP, hours: 720 });
    expect(longer.status).toBe(200);
    expect(longer.body.data.total).toBe(1);
    expect(longer.body.data.categories[0].code).toBe('brute_force');
  });

  test('self 数据范围：只聚合自己的审计行，并显式标注 scopeLimited', async () => {
    const res = await getProfile({ ip: SELF_ONLY_IP }, selfToken);
    expect(res.status).toBe(200);
    const data = res.body.data;
    expect(data.total).toBe(1);
    expect(data.analyzed).toBe(1);
    expect(data.scopeLimited).toBe(true);
    expect(data.categories).toHaveLength(1);
    expect(data.categories[0]).toMatchObject({ code: 'brute_force', count: 1 });
    // 同 IP 的蜜罐行属于另一个账号，不能被 self 档看到
    expect(data.categories.some((item) => item.code === 'honeypot')).toBe(false);
    expect(data.uncategorized).toEqual({ count: 0, evidence: [] });
    expect(data.suggestions).toEqual(expect.arrayContaining(['monitor', 'verify_scope']));
    expect(data.suggestions).not.toContain('block_ip');
  });

  test('缺二次验证：401 REAUTH_TICKET_REQUIRED（在权限码之后判定）', async () => {
    const res = await getProfile({ ip: CLEAN_IP }, adminToken, false);
    expect(res.status).toBe(401);
    expect(res.body.errors?.errorCode).toBe('REAUTH_TICKET_REQUIRED');
  });

  test('无 security:audit 权限：403 PERMISSION_DENIED', async () => {
    const res = await getProfile({ ip: CLEAN_IP }, noPermToken);
    expect(res.status).toBe(403);
    expect(res.body.errors?.errorCode).toBe('PERMISSION_DENIED');
  });
});
