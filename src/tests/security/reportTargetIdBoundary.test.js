/**
 * POST /api/security/report 的 targetId 入参边界
 *
 * 判据分工：
 * 1. 基线正向：合法举报 200，AuditLog 落库的 riskLevel/targetId 与写入意图一致。
 * 2. targetId 超长/非 ID：必须落在 400 的**校验明细**里（path=targetId）。
 *    状态码 400 本身不是判据——schema 的 maxlength:100 也会给 400，
 *    但 errorHandler 对 Mongoose ValidationError 在生产环境刻意抹掉字段明细，
 *    所以「响应里有没有 fieldErrors」才等价于「闸装在路由层还是漏到 DB 层」。
 * 3. targetId 为对象/数组：必须 400 拒绝，不得带着非字符串进入审计写入。
 * 4. 缺省 targetId：仅 system 型合法（举报"系统级异常"时没有具体对象），必须仍 200。
 * 5. 反向对照：三条非法用例都不得留下审计行（否则"报错但仍落库"）。
 * 6. riskLevel 由服务端常量决定，客户端传值不得改写（举报人人可发，
 *    能压低级别就等于能把高危举报刷成没人看的低危行）。
 * 7. targetId 的格式边界：24 位十六进制放行，短一位 / 长一位 / 含非 hex 字符
 *    三种都必须在路由层 400 并点名 targetId，且不得留下审计行。
 *
 * 契约变更（2026-10-01，判据 7 的原形态被替换）：本文件原测「路由 isLength 上限与
 * schema maxlength:100 **同值**」的双向边界（100 放行 / 101 拒绝）。拍板
 * 「校 ID + 存在性 + 限流」后，记录型的 targetId 必须是真实记录的 ObjectId，
 * 100 字符自由串不再是合法值 ⇒ 长度同值判据失去对象，替换为格式判据；
 * schema 的 maxlength:100 作为防御性上限保留（见 models/AuditLog.js 字段注释）。
 * 存在性（404）、数据范围（403）与账号维度限流由
 * reportTargetScopeAndLimiter.test.js 覆盖，本文件只管入参形状。
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

    // 夹具账户**刻意不带角色**：dataScope 因此是 none，任何记录型举报都会在
    // 「存在性」这一步就 404（范围闸在其后）。本文件只管入参形状，
    // 形状判据要的正是"非法形状 400 / 合法形状走到下一层"，与范围无关。
    // 范围与存在性的正向用例见 reportTargetScopeAndLimiter.test.js。
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

  const post = async (body) => {
    const res = await request(app)
      .post('/api/security/report')
      .set('Authorization', `Bearer ${token}`)
      .send(body);
    // 本文件全部用例共用一个账户：账号维度限流（securityReportUserLimiter，
    // 配额 20 次/15 分钟，见 rateLimit.js）一旦触顶，后面的用例就会拿到 429 而不是
    // 被测判据的答案——那种红极难归因。这里把它就地说明。
    if (res.status === 429) {
      throw new Error(
        '账号维度限流已触发：本文件的请求数超过了 securityReportUserLimiter 的配额，' +
          '请为新用例开一个独立账户或提高配额（不是被测判据失败）'
      );
    }
    return res;
  };

  // extra 用于把计数收窄到"本用例自己写的那一行"：兄弟用例 4/6/7 同为该 userId 落库，
  // 按 userId 计数就变成了**用例顺序的函数**（--randomize 下 5 个 seed 里红 4 个）。
  // 收窄是等价且更强的判据：落库 targetId 与写入意图不一致 ⇒ 查不到行 ⇒ 照样红。
  const reportRows = (extra = {}) =>
    AuditLog.find({ action: 'suspicious_report', userId, ...extra }).lean();

  test('1 基线正向：合法举报 200 且按写入意图落库', async () => {
    // 基线用 system 型：夹具账户无角色（dataScope=none），记录型一律 404/403，
    // 而本用例要钉的是"成功路径真的写了那一行"，与目标核验无关。
    const res = await post({
      targetType: 'system',
      reason: `系统级基线_${stamp}`,
      description: 'targetId 边界用例的基线正向',
    });
    expect(res.status).toBe(200);

    const rows = await reportRows({ reason: `系统级基线_${stamp}` });
    expect(rows).toHaveLength(1);
    expect(rows[0].targetType).toBe('system');
    // 风险级别由服务端常量决定：客户端传 riskLevel 不得改变落库值（见用例 6）
    expect(rows[0].riskLevel).toBe('high');
  });

  test('2 targetId 超长（非 ID 字符串）：400 且校验明细落在 targetId', async () => {
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

  test('4 缺省 targetId：system 型 200，记录型 400 且点名 targetId', async () => {
    const sys = await post({ targetType: 'system', reason: `系统级举报_${stamp}` });
    expect(sys.status).toBe(200);

    // 记录型没有对象可指 ⇒ 必须是 400，不能退化成"没有对象的系统级举报"
    const rec = await post({ targetType: 'device', reason: `缺目标ID_${stamp}` });
    expect(rec.status).toBe(400);
    expect(rec.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
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

  // 判据 7（2026-10-01 替换原「路由上限 == schema maxlength:100」的长度判据，
  // 替换理由见文件头）：记录型的 targetId 形状必须是 24 位十六进制。
  // 三个反例都在**路由层**拒绝并点名 targetId（不是 DB 的 CastError 通用文案）；
  // 最后一条正向反证形状与存在性两道判据没有串线：合法形状 + 不存在的对象
  // 必须走到下一层拿到 404，而不是被形状闸当成 400。
  test('7 格式边界：23 位 / 25 位 / 含非 hex 字符一律 400，合法形状的不存在 ID 走 404', async () => {
    const hex24 = new mongoose.Types.ObjectId().toHexString();
    const malformed = [
      ['23位', hex24.slice(0, 23)],
      ['25位', `${hex24}a`],
      ['非hex', 'g'.repeat(24)],
    ];
    const before = await reportRows();
    for (const [label, value] of malformed) {
      const res = await post({
        targetType: 'device',
        targetId: value,
        reason: `格式边界_${label}_${stamp}`,
      });
      expect(res.status).toBe(400);
      expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('targetId');
    }
    expect(await reportRows()).toHaveLength(before.length);

    const notFound = await post({
      targetType: 'device',
      targetId: hex24,
      reason: `格式合法但不存在_${stamp}`,
    });
    expect(notFound.status).toBe(404);
    expect(notFound.body.errors.errorCode).toBe('DEVICE_NOT_FOUND');
    expect(await reportRows()).toHaveLength(before.length);
  });
});
