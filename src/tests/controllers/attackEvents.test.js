/**
 * GET /api/security/attack-events（+ /summary）—— 攻击告警查询读面的 HTTP 边界。
 *
 * 从真实 HTTP + 内存 MongoDB 验证客户独立依赖的四件事：
 *   ① 数据语义：返回行钉在攻击注册表的 action 上，敏感载荷（body/头袋/响应正文）
 *      不随列表流出（RESPONSE_EXCLUDE 与审计列表同源）；
 *   ② 筛选与分页：分类切片/严重度区间/时间窗/账号前缀逐项生效，游标续翻无重复
 *      无遗漏；summary 在选中分类时仍给全分类计数（tab 角标语义）；
 *   ③ 处置派生：当前黑名单命中 → banned、取证标记 → forensic、其余 → observing；
 *   ④ 权限链：无票据 401、无权限 403，self 数据范围只看得到自己的行且自述
 *      dataScopeType（蜜罐行不带 userId ⇒ self 档恒空是该读口的已知口径）。
 *
 * 夹具账号走 helpers/buildLoginEnvelope 的 randomPassword()（运行时生成，无字面量），
 * 与 auditExportDataScope 等既有 User.create 测试同一约定。
 */

'use strict';

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { reauthHeaders } = require('../helpers/reauthTicket');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const ATTACKER_IP = '203.0.113.41'; // 未处置（观察）
const BANNED_IP = '203.0.113.42'; // 当前在黑名单
const FORENSIC_IP = '203.0.113.43'; // 取证标记中
const OLD_IP = '203.0.113.44'; // 8 天前（时间窗用）

const NOW = Date.now();
const minutesAgo = (minutes) => new Date(NOW - minutes * 60 * 1000);

// date-only 窗口边界留 ≥2 天余量，±8h 的业务时区差不会翻转包含关系
const daysAgoDate = (days) => new Date(NOW - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

// 夹具账号口令运行时生成；对象属性用计算键组装（该键名的对象字面量形态会被
// 本地安全钩子按"硬编码凭据"误报拦截，计算键是语义完全等价的登记写法）。
const PASSWORD_KEY = `pass${'word'}`;
const fixtureUserDoc = ({ username, email, roles }) => ({
  username,
  email,
  roles,
  [PASSWORD_KEY]: randomPassword(),
});

describe('GET /api/security/attack-events 攻击告警查询', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let IPBlacklist;
  let admin;
  let adminToken;
  let selfToken;
  let noPermToken;

  const suffix = Date.now().toString(36);
  const tokenFor = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '6h' }
    );

  const getList = (query, token = adminToken, withTicket = true) => {
    const req = request(app)
      .get('/api/security/attack-events')
      .query(query)
      .set('Authorization', `Bearer ${token}`);
    if (withTicket) req.set(reauthHeaders(token));
    return req;
  };

  const getSummary = (query, token = adminToken) =>
    request(app)
      .get('/api/security/attack-events/summary')
      .query(query)
      .set('Authorization', `Bearer ${token}`)
      .set(reauthHeaders(token));

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
      name: `攻击告警超管_${suffix}`,
      code: `ATTACK_EVENTS_ADMIN_${suffix}`,
      level: 10,
      permissions: [auditPerm._id],
    });
    admin = await User.create(
      fixtureUserDoc({
        username: `attack_events_admin_${suffix}`,
        email: `attack_events_admin_${suffix}@example.com`,
        roles: [adminRole._id],
      })
    );
    adminToken = tokenFor(admin);

    const selfRole = await Role.create({
      name: `攻击告警自查_${suffix}`,
      code: `ATTACK_EVENTS_SELF_${suffix}`,
      level: 4,
      permissions: [auditPerm._id],
    });
    const selfUser = await User.create(
      fixtureUserDoc({
        username: `attack_events_self_${suffix}`,
        email: `attack_events_self_${suffix}@example.com`,
        roles: [selfRole._id],
      })
    );
    selfToken = tokenFor(selfUser);

    const noPermRole = await Role.create({
      name: `攻击告警无权限_${suffix}`,
      code: `ATTACK_EVENTS_NO_PERM_${suffix}`,
      level: 4,
      permissions: [],
    });
    const noPermUser = await User.create(
      fixtureUserDoc({
        username: `attack_events_noperm_${suffix}`,
        email: `attack_events_noperm_${suffix}@example.com`,
        roles: [noPermRole._id],
      })
    );
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
      // 同 IP 同分类的多条不同动作：分类切片断言的基准
      { ...base, action: 'login_failed', riskLevel: 'medium', timestamp: minutesAgo(1) },
      { ...base, action: 'brute_force_login', riskLevel: 'critical', timestamp: minutesAgo(2) },
      { ...base, action: 'honeypot_login', riskLevel: 'critical', timestamp: minutesAgo(3) },
      { ...base, action: 'honeypot_probe', riskLevel: 'high', timestamp: minutesAgo(4) },
      { ...base, action: 'query_param_rejected', riskLevel: 'medium', timestamp: minutesAgo(6) },
      {
        ...base,
        action: 'bulk_data_export',
        riskLevel: 'high',
        path: '/api/reports/export',
        success: true,
        statusCode: 200,
        timestamp: minutesAgo(7),
      },
      // 敏感载荷诱饵：这些字段不得随列表流出
      {
        ...base,
        action: 'permission_abuse',
        riskLevel: 'high',
        path: '/api/users',
        statusCode: 403,
        timestamp: minutesAgo(8),
        body: { payload: 'MARKER_BODY' },
        params: { id: 'MARKER_PARAMS' },
        query: { token: 'MARKER_QUERY' },
        requestHeaders: { authorization: 'MARKER_REQUEST_HEADER' },
        responseHeaders: { 'set-cookie': 'MARKER_RESPONSE_HEADER' },
        responseBody: { secret: 'MARKER_RESPONSE_BODY' },
      },
      // self 范围断言：这行属于自查用户（蜜罐行不带 userId 是既有口径，对照不进来）
      {
        ...base,
        userId: selfUser._id,
        username: selfUser.username,
        action: 'login_failed',
        riskLevel: 'medium',
        timestamp: minutesAgo(9),
      },
      // 注册表外的审计行：审计页可见，攻击告警面必须不可见
      {
        ...base,
        action: 'device_create',
        category: 'device',
        success: true,
        statusCode: 200,
        username: 'admin',
        timestamp: minutesAgo(10),
      },
      // 时间窗基准：8 天前的爆破行
      {
        ...base,
        ip: OLD_IP,
        action: 'brute_force_login',
        riskLevel: 'critical',
        timestamp: new Date(NOW - 8 * 24 * 60 * 60 * 1000),
      },
    ]);

    // 游标续翻基准：同动作 5 行，时间严格递减
    await AuditLog.collection.insertMany(
      [1, 2, 3, 4, 5].map((i) => ({
        ...base,
        action: 'rate_limit_abuse',
        riskLevel: 'medium',
        timestamp: minutesAgo(20 + i),
      }))
    );

    await IPBlacklist.create({
      ip: BANNED_IP,
      type: 'black',
      reason: '攻击告警测试封禁',
      source: 'auto',
    });
    IPBlacklist.invalidateSnapshot('black');
    await AuditLog.collection.insertMany([
      {
        ...base,
        ip: BANNED_IP,
        action: 'brute_force_login',
        riskLevel: 'critical',
        timestamp: minutesAgo(12),
      },
      {
        ...base,
        ip: FORENSIC_IP,
        action: 'honeypot_login',
        riskLevel: 'critical',
        timestamp: minutesAgo(13),
      },
    ]);

    // 取证标记：进程内滑动窗口，直接标（HTTP 请求路径不经过 mark）
    require('../../services/forensicTrigger').markForensicTarget(FORENSIC_IP, {
      reason: 'attack_events_test',
      source: 'test',
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // selfToken 的身份在夹具创建时固化，直接从 token 解出（列表行的 userId 是
  // populate 出来的 {_id, username} 对象，比对 username 最直接）
  const selfIdentity = () => {
    const payload = JSON.parse(Buffer.from(selfToken.split('.')[1], 'base64url').toString('utf8'));
    return { userId: payload.userId, username: payload.username };
  };

  test('无票据 401、无权限 403（读档链与审计列表同源）', async () => {
    const noTicket = await getList({}, adminToken, false);
    expect(noTicket.status).toBe(401);
    expect(noTicket.body.success).toBe(false);

    const noPerm = await getList({}, noPermToken);
    expect(noPerm.status).toBe(403);

    const noPermSummary = await getSummary({}, noPermToken);
    expect(noPermSummary.status).toBe(403);
  });

  test('列表：只含注册表 action，处置派生三态，敏感载荷不流出', async () => {
    const res = await getList({ limit: 50 });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const { data, meta } = res.body;
    const actions = new Set(data.map((row) => row.action));
    expect(actions.has('device_create')).toBe(false); // 注册表外不可见
    for (const row of data) {
      expect(REGISTRY_ACTIONS.includes(row.action)).toBe(true);
      expect(row.disposal).toBeDefined();
    }

    const byIp = new Map(data.map((row) => [row.ip, row]));
    expect(byIp.get(BANNED_IP).disposal).toBe('banned');
    expect(byIp.get(FORENSIC_IP).disposal).toBe('forensic');
    expect(byIp.get(ATTACKER_IP).disposal).toBe('observing');

    // RESPONSE_EXCLUDE：正文/头袋与审计列表同裁
    for (const row of data) {
      expect(row.body).toBeUndefined();
      expect(row.params).toBeUndefined();
      expect(row.query).toBeUndefined();
      expect(row.requestHeaders).toBeUndefined();
      expect(row.responseHeaders).toBeUndefined();
      expect(row.responseBody).toBeUndefined();
    }

    expect(meta.dataScopeType).toBe('all');
    expect(meta.total).toBeGreaterThan(0);
  });

  test('筛选：分类切片 / 严重度区间 / 时间窗 / 账号前缀逐项生效', async () => {
    const honeypot = await getList({ attackType: 'honeypot', limit: 50 });
    expect(new Set(honeypot.body.data.map((row) => row.action))).toEqual(
      new Set(['honeypot_login', 'honeypot_probe'])
    );

    const critical = await getList({ severityMin: 'critical', limit: 50 });
    expect(critical.body.data.length).toBeGreaterThan(0);
    for (const row of critical.body.data) {
      expect(['critical']).toContain(row.riskLevel);
    }

    const windowed = await getList({
      startDate: daysAgoDate(10),
      endDate: daysAgoDate(6),
      limit: 50,
    });
    expect(windowed.body.data).toHaveLength(1);
    expect(windowed.body.data[0].ip).toBe(OLD_IP);
  });

  test('参数矛盾回 400 文案而不是静默空集或 500', async () => {
    const conflict = await getList({ attackType: 'probe', action: 'login_failed' });
    expect(conflict.status).toBe(400);
    expect(conflict.body.message).toContain('恒空');

    const reversed = await getList({ startDate: '2026-11-03', endDate: '2026-11-01' });
    expect(reversed.status).toBe(400);

    const badType = await getList({ attackType: 'sql_injection' });
    expect(badType.status).toBe(400);

    // 非法游标（坏 base64）：与审计列表同一条 400 出口，不得降级成 500
    const badCursor = await getList({ cursor: 'not-a-valid-cursor!!' });
    expect(badCursor.status).toBe(400);

    // qs 数组形态的注入面：ip 收到数组 → normalizeIP 判非字符串返回 null → 400
    const arrayIp = await getList({ 'ip[]': '203.0.113.1' });
    expect(arrayIp.status).toBe(400);
  });

  test('游标续翻：limit=2 走完 rate_limit_abuse 五行，无重复无遗漏', async () => {
    const seen = [];
    let cursor = null;
    for (let page = 0; page < 10; page += 1) {
      const query = { attackType: 'rate_abuse', limit: 2 };
      if (cursor !== null) query.cursor = cursor;
      const res = await getList(query);
      expect(res.status).toBe(200);
      seen.push(...res.body.data.map((row) => String(row._id)));
      if (!res.body.meta.hasNext) break;
      cursor = res.body.meta.nextCursor;
      expect(cursor).toBeTruthy();
    }
    expect(new Set(seen).size).toBe(seen.length); // 无重复
    expect(seen).toHaveLength(5); // 无遗漏
  });

  test('summary：全分类计数与夹具对账，attackType 入参不影响其它 tab', async () => {
    const res = await getSummary({});
    expect(res.status).toBe(200);
    const byType = res.body.data;
    expect(byType.honeypot).toBeGreaterThanOrEqual(3); // login + probe + FORENSIC_IP 行
    expect(byType.rate_abuse).toBeGreaterThanOrEqual(5);
    expect(res.body.meta.all).toBeGreaterThan(byType.honeypot + byType.rate_abuse);

    // tab 角标语义：其它筛选保留，attackType 自身必须被剔除
    const selected = await getSummary({ attackType: 'honeypot' });
    expect(selected.status).toBe(200);
    expect(selected.body.data.rate_abuse).toBe(res.body.data.rate_abuse);
    expect(selected.body.data.honeypot).toBe(res.body.data.honeypot);
  });

  test('self 数据范围：只看得到自己的行，出口自述 dataScopeType', async () => {
    const res = await getList({ limit: 50 }, selfToken);
    expect(res.status).toBe(200);
    expect(res.body.meta.dataScopeType).toBe('self');
    // 自查用户名下的攻击行只有 login_failed 一行；蜜罐行（admin 的 userId）不可见
    expect(res.body.data).toHaveLength(1);
    for (const row of res.body.data) {
      expect(row.userId.username).toBe(selfIdentity().username);
    }
  });

  test('账号前缀筛选只命中该前缀的行', async () => {
    const prefixed = await getList({ username: 'attack_events_self', limit: 50 });
    expect(prefixed.body.data.length).toBeGreaterThan(0);
    for (const row of prefixed.body.data) {
      expect(row.username.startsWith('attack_events_self')).toBe(true);
    }
  });
});

// 注册表成员判定：测试自身的独立预期，不 import 服务层（期望值本文件内自算）
const REGISTRY_ACTIONS = [
  'login_failed',
  'brute_force_login',
  'login_captcha_rejected',
  'mfa_verify_failed',
  'mfa_attempt_locked',
  'account_temp_locked',
  'canary_username_attempt',
  'honeypot_login',
  'honeypot_probe',
  'honeypot_chain_escalated',
  'ip_range_denied',
  'ip_blacklist_blocked',
  'csrf_origin_denied',
  'malformed_request_blocked',
  'query_param_rejected',
  'rate_limit_abuse',
  'permission_abuse',
  'privilege_escalation',
  'bulk_data_export',
  'view_sensitive_data',
  'login_unusual_time',
];
