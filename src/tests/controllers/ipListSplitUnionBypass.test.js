'use strict';

/**
 * 分片拼满（非 /0，但并集覆盖整族）不得绕过 /0 的判据
 *
 * 第 23 轮探针 work/lead/_b4probe.js、_b5probe.js 实测真值表（操作者来源是 IPv4 回环）：
 *
 *   1) IPv4 先写 128.0.0.0/1（不含操作者）→ 200；再写 0.0.0.0/1（含操作者）→ 400 no_rescue_path，
 *      STATE persisted=["128.0.0.0/1"] union4={ipv4:false}   —— 第二片被并集守卫拦下，没落地
 *   2) 反过来先写 0.0.0.0/1 → 400 operator_inside（含调用者自己，自伤判据先命中）
 *   3) IPv6 先写 ::/1 → 200；再写 8000::/1 → 400 no_rescue_path；persisted 仅 1 条，union6=false
 *   4) 直接写 ::/0 带确认但无救援路径 → 400 no_rescue_path，不落库（对照，证明判据不是"只拦分片"）
 *
 * 判据要害：**"这一条本身是 /0"与"并集铺满整族"是两条不同判据**。前者的豁免（自伤/活跃流量对 /0
 * 恒真是同义反复）不能推广到后者；后者恰恰更需要看并集，因为分片可以绕过"单条含 /0"的检查。
 * 若把两者混用，就会出现"是否被拦取决于名单里已有什么"的自相矛盾判据。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { cidrUnionCoversAll } = require('../../utils/cidrCoverage');

describe('分片拼满整族不得绕过全网段判据', () => {
  let app;
  let IPBlacklist;
  let superToken;
  const stamp = `spl${Date.now()}`.replace(/\d/g, (d) => `abcdefghij`[Number(d)]);
  const PASSWORD = randomPassword();
  const V4_HALVES = ['0.0.0.0/1', '128.0.0.0/1'];
  const V6_HALVES = ['::/1', '8000::/1'];
  const ALL = V4_HALVES.concat(V6_HALVES, ['0.0.0.0/0', '::/0']);

  const post = (body) =>
    request(app)
      .post('/api/security/ip-list')
      .set('Authorization', `Bearer ${superToken}`)
      .send(body);

  const wipe = () => IPBlacklist.deleteMany({ ip: { $in: ALL } });
  const familyOf = async (ips) => {
    const rows = await IPBlacklist.find({ ip: { $in: ips } }).lean();
    const texts = rows.map((r) => r.ip);
    return cidrUnionCoversAll(texts, ips === V6_HALVES ? 'ipv6' : 'ipv4');
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    IPBlacklist = require('../../models/IPBlacklist');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const u = await User.create({
      username: `splsuper${stamp}`,
      email: `splsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    superToken = jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const { createApp } = require('../../app');
    app = createApp();
  });

  beforeEach(wipe);
  afterEach(wipe);

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      await User.deleteMany({ username: new RegExp(`^splsuper${stamp}$`) }).catch(() => {});
      await wipe().catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('IPv4 两片拼满：第二片被拦，并集始终不覆盖整族', async () => {
    const first = await post({
      ip: '128.0.0.0/1',
      type: 'black',
      reason: '分片-甲',
      typedConfirm: '128.0.0.0/1',
    });
    expect(first.status).toBe(200);
    expect((await familyOf(V4_HALVES)).ipv4).toBe(false);

    const second = await post({
      ip: '0.0.0.0/1',
      type: 'black',
      reason: '分片-乙',
      typedConfirm: '0.0.0.0/1',
    });
    expect(second.status).toBe(400);
    expect(second.body.errors.errorCode).toBe('IP_SEGMENT_WRITE_REFUSED');
    // 原因必须是缺救援路径（不是缺确认串）：用户已经敲对了确认串
    expect(second.body.errors.reason).toBe('no_rescue_path');
    const after = await familyOf(V4_HALVES);
    expect(after.ipv4).toBe(false);
    expect(await IPBlacklist.countDocuments({ ip: { $in: V4_HALVES } })).toBe(1);
    const health = await request(app).get('/health');
    expect(health.status).toBe(200);
  });

  test('IPv6 两片拼满：同样被拦（两片都不含 IPv4 操作者，但并集等价 /0）', async () => {
    const first = await post({
      ip: '::/1',
      type: 'black',
      reason: '分片-v6甲',
      typedConfirm: '::/1',
    });
    expect(first.status).toBe(200);
    const second = await post({
      ip: '8000::/1',
      type: 'black',
      reason: '分片-v6乙',
      typedConfirm: '8000::/1',
    });
    expect(second.status).toBe(400);
    expect(second.body.errors.reason).toBe('no_rescue_path');
    expect((await familyOf(V6_HALVES)).ipv6).toBe(false);
    expect(await IPBlacklist.countDocuments({ ip: { $in: V6_HALVES } })).toBe(1);
  });

  test('反向对照：单条 /0 直接写同样被拦（判据不是只拦分片）', async () => {
    const res = await post({
      ip: '::/0',
      type: 'black',
      reason: '分片-对照',
      typedConfirm: '::/0',
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe('no_rescue_path');
    expect(await IPBlacklist.countDocuments({ ip: '::/0' })).toBe(0);
  });

  test('反向对照：小于阈值的段照常放行（判据不是恒拒）', async () => {
    // HIGH_IMPACT_HOSTS=256：/24 恰好 256 台 ⇒ 需要逐字确认；/28 是 16 台 ⇒ 不需要。
    // 这条用 /28 才在测"并集判据不是恒拒"；/24 测到的是阈值判据（两回事，别混）。
    const res = await post({ ip: '198.51.100.0/28', type: 'black', reason: '分片-普通段' });
    expect(res.status).toBe(200);
    await IPBlacklist.deleteMany({ ip: '198.51.100.0/28' });
  });

  test('含操作者自己的一半先被自伤判据拦下（不落到救援路径判据）', async () => {
    const res = await post({
      ip: '0.0.0.0/1',
      type: 'black',
      reason: '分片-自伤',
      typedConfirm: '0.0.0.0/1',
    });
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe('operator_inside');
    expect(await IPBlacklist.countDocuments({ ip: { $in: V4_HALVES } })).toBe(0);
  });
});
