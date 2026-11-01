/**
 * 拒绝原因码必须落进审计（H4）——红线用例
 *
 * 缺口本体：ip-list 的三类写拒绝走同一个响应码 IP_SEGMENT_WRITE_REFUSED，原因码只在
 * **HTTP 响应体** errors.reason 里；全局审计中间件只写「400 + low + riskFactors:[]」的通用行。
 * 于是事后无法区分「操作者想封自己所在的网段」（攻击/自伤信号）与「没打字确认」（正常手滑）：
 * 两者在 SQL/日志里长得一模一样，按原因码统计与告警都做不了。
 *
 * 本文件钉三件事，缺一就会退化成「字段加了但没真的分开」：
 *   ① 三类拒绝（operator_inside / live_traffic_inside / typed_confirmation_required）各自的
 *      审计行里 refusalReason 必须等于自己的原因码，且**两两不同**；
 *   ② 反空自证：成功请求（200）的审计行**不得**带 refusalReason——否则「全都写同一个值」
 *      也能让 ① 的三个非空断言变绿；
 *   ③ FULL_RANGE_FORBIDDEN 那条既有的 privilege_escalation 行不受影响（riskLevel=critical、
 *      riskFactors=[full_range_cidr_attempt]、reason 是中文散文），证明本次改动没有覆盖/污染它。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { waitFor } = require('../helpers/waitFor');

const WAIT_MS = 3000;

describe('拒绝原因码落审计（H4）', () => {
  let app;
  let AuditLog;
  let IPBlacklist;
  let token;
  let auditBuffer;
  const createdUserIds = [];
  const createdRoleIds = [];
  const createdPermIds = [];
  const PASSWORD = randomPassword();
  const stamp = 'h4r' + Date.now().toString(36);

  const post = (body) =>
    request(app)
      .post('/api/security/ip-list')
      .set('Authorization', 'Bearer ' + token)
      .send(body);

  /**
   * 条件轮询而不是固定睡眠：等的是「这一行真的落库」，超时错误里带 label。
   * 原写法 `await new Promise(r => setTimeout(r, 100))` 是固定睡眠——机器快时白等、
   * 慢时照样超时，且等不到时只留下一个 null 让断言去猜原因（noFixedSleepRatchet 禁）。
   */
  const waitRow = async (query, label) => {
    let row = null;
    await waitFor(
      async () => {
        row = await query();
        return Boolean(row);
      },
      { timeoutMs: WAIT_MS, label }
    );
    return row;
  };

  /** 等审计缓冲（FLUSH_INTERVAL_MS=2000）落库后按 action 取该请求的通用行 */
  const refusalRowOf = (ip) =>
    waitRow(() => {
      const q = { action: 'security_ip-list', 'body.ip': ip, statusCode: 400 };
      return AuditLog.findOne(q).sort({ timestamp: -1 });
    }, `拒绝审计行 body.ip=${ip}`);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');
    IPBlacklist = require('../../models/IPBlacklist');
    auditBuffer = require('../../services/auditBuffer');
    const { createApp } = require('../../app');
    app = createApp();
    // 审计行由缓冲异步落库：不启动定时器，本用例就永远读到 0 行（会把「没落库」误判成「没写字段」）
    auditBuffer.start();

    const perm = await Permission.findOneAndUpdate(
      { code: 'security:config' },
      {
        $setOnInsert: {
          code: 'security:config',
          name: '安全配置',
          type: 'api',
          module: 'security',
        },
      },
      { upsert: true, new: true }
    );
    createdPermIds.push(String(perm._id));
    const role = await Role.create({
      name: 'H4 安全员 ' + stamp,
      code: 'H4SEC_' + stamp,
      level: 5,
      permissions: [perm._id],
    });
    createdRoleIds.push(String(role._id));
    const user = await User.create({
      username: 'h4sec' + stamp,
      email: 'h4sec' + stamp + '@example.com',
      password: PASSWORD,
      roles: [role._id],
    });
    createdUserIds.push(String(user._id));
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
  });

  afterAll(async () => {
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    auditBuffer.stop();
    await IPBlacklist.deleteMany({});
    IPBlacklist.invalidateSnapshot();
    if (createdUserIds.length) await User.deleteMany({ _id: { $in: createdUserIds } });
    if (createdRoleIds.length) await Role.deleteMany({ _id: { $in: createdRoleIds } });
    if (createdPermIds.length) await Permission.deleteMany({ _id: { $in: createdPermIds } });
    // 本套件自建连接自己关（mongooseTeardownLedger：漏关会让 jest-worker 强杀并吞输出）
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    await IPBlacklist.deleteMany({});
    IPBlacklist.invalidateSnapshot();
  });

  test('三类拒绝在审计行里可分辨（refusalReason 各不相同）', async () => {
    // ① 没打字确认：/24 加黑但不带 typedConfirm
    const typed = await post({ ip: '203.0.113.0/24', type: 'black', reason: 'H4-typed' });
    expect(typed.status).toBe(400);
    expect(typed.body.errors.reason).toBe('typed_confirmation_required');

    // ② 操作者自己在该网段内：127.0.0.0/24 罩住本机回环地址
    const inside = await post({
      ip: '127.0.0.0/24',
      type: 'black',
      reason: 'H4-inside',
      typedConfirm: '127.0.0.0/24',
    });
    expect(inside.status).toBe(400);
    expect(inside.body.errors.reason).toBe('operator_inside');

    // ③ 网段内最近仍有真实业务请求：先造一条带 ip 的活动审计行
    await AuditLog.create({
      action: 'device_read',
      category: 'device',
      username: 'h4live' + stamp,
      method: 'GET',
      path: '/api/devices',
      ip: '198.51.100.7',
      statusCode: 200,
      success: true,
      riskLevel: 'low',
    });
    const live = await post({
      ip: '198.51.100.0/24',
      type: 'black',
      reason: 'H4-live',
      typedConfirm: '198.51.100.0/24',
    });
    expect(live.status).toBe(400);
    expect(live.body.errors.reason).toBe('live_traffic_inside');

    const [r1, r2, r3] = await Promise.all([
      refusalRowOf('203.0.113.0/24'),
      refusalRowOf('127.0.0.0/24'),
      refusalRowOf('198.51.100.0/24'),
    ]);
    // 三行必须都真的落库了（否则下面的 undefined 断言会以「没有行」冒充「没有字段」）
    expect([r1 && r1._id, r2 && r2._id, r3 && r3._id].filter(Boolean)).toHaveLength(3);

    const reasons = [r1.refusalReason, r2.refusalReason, r3.refusalReason];
    expect(reasons).toEqual([
      'typed_confirmation_required',
      'operator_inside',
      'live_traffic_inside',
    ]);
    expect(new Set(reasons).size).toBe(3);
  });

  test('反空自证：成功写入的审计行不得带 refusalReason（字段不是恒填）', async () => {
    const ok = await post({ ip: '203.0.113.9', type: 'black', reason: 'H4-ok' });
    expect(ok.status).toBe(200);

    // 成功路径由控制器手写（recordDurably），action 是 ip_blacklist_added 而非路由派生的
    // security_ip-list——按 action 精确取，避免把别的请求的行当成自己这一条
    const row = await waitRow(
      () => AuditLog.findOne({ action: 'ip_blacklist_added', 'body.ip': '203.0.113.9' }),
      '成功写入的 ip_blacklist_added 行'
    );
    expect(Boolean(row)).toBe(true);
    expect(row.success).toBe(true);
    expect(row.refusalReason).toBeUndefined();
    // 同一次成功请求也不得留下「被拒」痕迹（否则字段可以从别的行蹭出来而断言仍绿）
    expect(
      await AuditLog.countDocuments({ action: 'security_ip-list', 'body.ip': '203.0.113.9' })
    ).toBe(0);
  });

  test('FULL_RANGE_FORBIDDEN 的 privilege_escalation 行不受影响', async () => {
    const res = await post({ ip: '0.0.0.0/0', type: 'black', reason: 'H4-full' });
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');

    const escalation = await waitRow(() => {
      const q = { action: 'privilege_escalation', 'body.ip': '0.0.0.0/0' };
      return AuditLog.findOne(q).sort({ timestamp: -1 });
    }, 'privilege_escalation 危险事件行');
    expect(Boolean(escalation)).toBe(true);
    // 这一行是控制器手写的高危事件：等级、因素、中文原因都必须一字不动
    expect(escalation.riskLevel).toBe('critical');
    expect(escalation.riskFactors).toEqual(['full_range_cidr_attempt']);
    expect(escalation.reason).toContain('0.0.0.0/0');
    expect(escalation.success).toBe(false);
  });
});
