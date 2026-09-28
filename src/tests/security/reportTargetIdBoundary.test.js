/**
 * POST /api/security/report 的 targetId 入参边界
 *
 * 判据分工：
 * 1. 基线正向：合法举报 200，AuditLog 落库的 riskLevel/targetId 与写入意图一致。
 * 2. targetId 超长：必须落在 400 的**校验明细**里（path=targetId）。
 *    状态码 400 本身不是判据——schema 的 maxlength:100 也会给 400，
 *    但 errorHandler 对 Mongoose ValidationError 在生产环境刻意抹掉字段明细，
 *    所以「响应里有没有 fieldErrors」才等价于「闸装在路由层还是漏到 DB 层」。
 * 3. targetId 为对象/数组：必须 400 拒绝，不得带着非字符串进入审计写入。
 * 4. 缺省 targetId：合法（举报"系统级异常"时没有具体对象），必须仍 200。
 * 5. 反向对照：三条非法用例都不得留下审计行（否则"报错但仍落库"）。
 * 6. riskLevel 由服务端常量决定，客户端传值不得改写（举报人人可发，
 *    能压低级别就等于能把高危举报刷成没人看的低危行）。
 * 7. 路由上限与 schema maxlength 同值：100 放行 / 101 拒绝的双向边界。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('POST /api/security/report：targetId 入参边界', () => {
  let app;
  let User;
  let AuditLog;
  let token;
  let userId;
  const stamp = `rtb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = 'Aa1!b2@c3#d4';

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    require('../../models/Role');
    require('../../models/Permission');
    require('../../models/TokenBlacklist');
    AuditLog = require('../../models/AuditLog');

    const user = await User.create({
      username: `rtbuser${stamp}`,
      email: `rtbuser${stamp}@example.com`,
      password: PASSWORD,
    });
    userId = String(user._id);
    token = jwt.sign({ userId, username: user.username, tokenVersion: 0 }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: `rtbuser${stamp}` }).catch(() => {});
      await AuditLog.deleteMany({ userId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const post = (body) =>
    request(app).post('/api/security/report').set('Authorization', `Bearer ${token}`).send(body);

  // extra 用于把计数收窄到"本用例自己写的那一行"：兄弟用例 4/6/7 同为该 userId 落库，
  // 按 userId 计数就变成了**用例顺序的函数**（--randomize 下 5 个 seed 里红 4 个）。
  // 收窄是等价且更强的判据：落库 targetId 与写入意图不一致 ⇒ 查不到行 ⇒ 照样红。
  const reportRows = (extra = {}) =>
    AuditLog.find({ action: 'suspicious_report', userId, ...extra }).lean();

  test('1 基线正向：合法举报 200 且按写入意图落库', async () => {
    const res = await post({
      targetType: 'device',
      targetId: `dev-${stamp}`,
      reason: `越界设备_${stamp}`,
      description: 'targetId 边界用例的基线正向',
    });
    expect(res.status).toBe(200);

    const rows = await reportRows({ targetId: `dev-${stamp}` });
    expect(rows).toHaveLength(1);
    // 风险级别由服务端常量决定：客户端传 riskLevel 不得改变落库值（见用例 6）
    expect(rows[0].riskLevel).toBe('high');
  });

  test('2 targetId 超长：400 且校验明细落在 targetId', async () => {
    const res = await post({
      targetType: 'device',
      targetId: 'x'.repeat(5000),
      reason: `超长目标_${stamp}`,
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
  });

  test('3 targetId 为对象：400 拒绝而不是进入审计写入', async () => {
    const res = await post({
      targetType: 'device',
      targetId: { $ne: null },
      reason: `对象目标_${stamp}`,
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
  });

  test('4 缺省 targetId：仍 200（系统级举报没有具体对象）', async () => {
    const res = await post({ targetType: 'system', reason: `系统级举报_${stamp}` });
    expect(res.status).toBe(200);
  });

  test('5 反向对照：三条非法用例都不留审计行', async () => {
    const before = await reportRows();
    await post({ targetType: 'device', targetId: 'y'.repeat(5000), reason: `对照A_${stamp}` });
    await post({ targetType: 'device', targetId: { $ne: null }, reason: `对照B_${stamp}` });
    await post({ targetType: 'bogus', targetId: 'ok', reason: `对照C_${stamp}` });
    expect(await reportRows()).toHaveLength(before.length);
  });

  test('6 客户端 riskLevel 不得改写服务端常量', async () => {
    const reason = `注入风险级别_${stamp}`;
    const res = await post({ targetType: 'system', reason, riskLevel: 'low' });
    expect(res.status).toBe(200);
    const rows = await AuditLog.find({ action: 'suspicious_report', userId, reason }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0].riskLevel).toBe('high');
  });

  // 路由上限必须与 schema 的 maxlength:100 **同值**：
  // 路由更松 ⇒ 走到 DB 层才报错，又退化成没有 fieldErrors 的 400；
  // 路由更紧 ⇒ 合法长度被拒（前端 100 字节的设备 ID 直接不能用）。
  test('7 边界：恰好 100 字符放行，101 字符在路由层拒绝', async () => {
    const okRes = await post({
      targetType: 'device',
      targetId: 'z'.repeat(100),
      reason: `边界100_${stamp}`,
    });
    expect(okRes.status).toBe(200);

    const overRes = await post({
      targetType: 'device',
      targetId: 'z'.repeat(101),
      reason: `边界101_${stamp}`,
    });
    expect(overRes.status).toBe(400);
    expect(overRes.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
  });
});
