'use strict';

/**
 * 取证溯源接口契约（T5/T6）：走真 HTTP，钉住「错误要说清是哪一种」而不是只说失败。
 *
 * 为什么不能只留服务层单测：服务层单测绕过路由，看不见三件只有在真实请求上才成立的事——
 * · 401 必须早于参数校验，否则未鉴权的人能靠「参数错」探出端点存在与字段名；
 * · 判据不可用（地址根本解析不出来）必须是 400，不能是 200 + 空数组。空结果读起来就是
 *   「这个 IP 很干净」，而这恰恰是溯源时最危险的假阴性；
 * · 封段被拒时必须带 errors.reason。只回「操作失败」，操作者唯一能做的就是换个网段重试，
 *   于是把 full_range_cidr / operator_inside 这类「再试也没用」的护栏当成偶发失败。
 *
 * 票据一次性只在 HTTP 上验得了：同一张票第二次必须落空，这条是「跳过确认直接封」的唯一拦路。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const stamp = `zfrc${Date.now()}`.slice(-10);
const BASE = '/api/security/forensic';

describe('取证溯源接口契约（T5/T6）', () => {
  let app;
  let token;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    require('../../models/ForensicCapture');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `ZFRC_ALL${stamp}`,
      code: `ZFRC_ALL${stamp}`,
      level: 10,
      permissions: [wildcard._id],
    });
    const user = await User.create({
      username: `zfrc_all${stamp}`.toLowerCase(),
      email: `zfrc_all${stamp}@example.com`,
      password: 'Test@1234567',
      department: `ZFRC-D-${stamp}`,
      roles: [role._id],
    });
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 客户端身份判据只在开着 trust proxy 时才认 XFF（test 环境默认 hops=0 ⇒ req.ip 恒为 socket 对端）。
    // 8d/8e 要造"取票与确认来自两个不同来源 IP"，必须先把代理拓扑声明成生产形态（反代 1 跳）。
    process.env.TRUST_PROXY_HOPS = '1';
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteMany({ username: `zfrc_all${stamp}`.toLowerCase() }).catch(() => {});
      await Role.deleteMany({ code: `ZFRC_ALL${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const get = (p, q) =>
    request(app)
      .get(BASE + p)
      .set('Authorization', `Bearer ${token}`)
      .query(q || {});
  const post = (p, b) =>
    request(app)
      .post(BASE + p)
      .set('Authorization', `Bearer ${token}`)
      .send(b);
  const postFrom = (p, b, ip) =>
    request(app)
      .post(BASE + p)
      .set({ Authorization: `Bearer ${token}`, 'x-forwarded-for': ip })
      .send(b);

  test('1 未鉴权一律 401，且 401 早于参数校验（不泄露端点与字段名）', async () => {
    for (const p of ['/trace', '/clusters']) {
      const res = await request(app).get(BASE + p);
      expect(res.status).toBe(401);
    }
    const bad = await request(app)
      .post(BASE + '/pool-ban/request')
      .send({ cidr: '0.0.0.0/0' });
    expect(bad.status).toBe(401);
    expect(bad.body.errors && bad.body.errors.errorCode).not.toBe('VALIDATION_FAILED');
  });

  test('2 三个维度都不给 → 400，不能靠「查全部」绕过判据', async () => {
    const res = await get('/trace');
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('FORENSIC_NO_CRITERIA');
  });

  test('3 地址不可解析按「判据不可用」拒绝，不返回空结果（假阴性来源）', async () => {
    const res = await get('/trace', { ip: '999.999.999.999' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('FORENSIC_NO_CRITERIA');
  });

  test('4 合法 IP 查不到任何记录也是 200：没记录是正常结论，不是错误', async () => {
    const res = await get('/trace', { ip: '203.0.113.77' });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data.timeline)).toBe(true);
    expect(res.body.data.count).toBe(0);
    // truncated 必须显式给出：空结果与「被 limit 截断后的空」不能长得一样
    expect(res.body.data.truncated).toBe(false);
    expect(typeof res.body.data.triggers).toBe('object');
    expect(res.body.data.timeline.length).toBe(0);
  });

  test('5 聚类：窗口越界在路由层就被拒，合法窗口的时间跨度逐字对上', async () => {
    const tooWide = await get('/clusters', { windowHours: 99999 });
    expect(tooWide.status).toBe(400);
    expect(tooWide.body.errors.errorCode).toBe('VALIDATION_FAILED');

    const res = await get('/clusters', { windowHours: 48 });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data.segments)).toBe(true);
    expect(Array.isArray(res.body.data.recommended)).toBe(true);
    const span = new Date(res.body.data.until).getTime() - new Date(res.body.data.since).getTime();
    expect(span).toBe(48 * 3600 * 1000);
  });

  test('6 request 缺 reason 在路由层就被拒（reason_required 走不到 HTTP 面）', async () => {
    const res = await post('/pool-ban/request', { cidr: '198.51.100.0/24' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    expect(res.body.errors.fieldErrors.map((e) => e.path)).toContain('reason');
  });

  test('7 0.0.0.0/0 被拒，且 reason 具体到「再试也没用」', async () => {
    const res = await post('/pool-ban/request', { cidr: '0.0.0.0/0', reason: '全封' });
    expect(res.status).toBe(400);
    expect(res.body.errors.errorCode).toBe('FORENSIC_POOL_BAN_REFUSED');
    expect(res.body.errors.reason).toBe('full_range_cidr');
  });

  test('8 两步确认：票据只能用一次，重放必须落空', async () => {
    const issued = await post('/pool-ban/request', {
      cidr: '198.51.100.0/24',
      reason: `契约测试 ${stamp}`,
    });
    expect(issued.status).toBe(200);
    expect(typeof issued.body.data.token).toBe('string');
    const tokenStr = issued.body.data.token;

    // /24 的主机数正好等于 HIGH_IMPACT_HOSTS(256) ⇒ 票据必带 needTypedConfirm，
    // 不带 typedConfirm 落库会被拒（这是"两侧都必须实现"的后端一侧，见 ADR-018 ③）。
    expect(issued.body.data.needTypedConfirm).toBe(true);

    const first = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.100.0/24',
    });
    expect(first.status).toBe(200);
    expect(typeof first.body.data.bannedCount).toBe('number');

    // 重放：票据已被消耗（一次性），带不带 typedConfirm 都必须是 unknown_token
    const replay = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.100.0/24',
    });
    expect(replay.status).toBe(400);
    expect(replay.body.errors.errorCode).toBe('FORENSIC_POOL_BAN_REFUSED');
    expect(replay.body.errors.reason).toBe('unknown_token');
  });

  test('8b 需要打字确认的段：缺 typedConfirm 或打字不匹配一律拒，且票据不被消耗', async () => {
    const issued = await post('/pool-ban/request', {
      cidr: '198.51.100.0/24',
      reason: `契约测试 ${stamp}`,
    });
    expect(issued.status).toBe(200);
    const tokenStr = issued.body.data.token;

    const missing = await post('/pool-ban/confirm', { token: tokenStr, durationHours: 1 });
    expect(missing.status).toBe(400);
    expect(missing.body.errors.reason).toBe('typed_confirmation_required');

    const wrong = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.101.0/24',
    });
    expect(wrong.status).toBe(400);
    expect(wrong.body.errors.reason).toBe('typed_confirmation_required');

    // 打错字不消耗票据：改对了同一张票仍然能用（ADR-018「让人多走一步」而不是"重来一遍"）
    const right = await post('/pool-ban/confirm', {
      token: tokenStr,
      durationHours: 1,
      typedConfirm: '198.51.100.0/24',
    });
    expect(right.status).toBe(200);
  });

  test('8c 空字符串时长不得折成永久封禁（审计 2026-11-02 F-2：漏填即 24h 兜底）', async () => {
    // 攻击场景：路由校验 optional({values:'falsy'}) 对 ''/null/false 整体放行，旧折算
    // 「解析不出正数且字段传了 ⇒ 永久」会把前端某次重构序列化出的空输入落成
    // expiresAt=null 的永久封段。判据直接查库：expiresAt 必须非 null（≈24h 兜底）。
    const IPBlacklist = require('../../models/IPBlacklist');
    const issued = await post('/pool-ban/request', {
      cidr: '198.51.100.8/30', // 4 主机 < HIGH_IMPACT_HOSTS(256)，无需打字确认
      reason: `空时长兜底 ${stamp}`,
    });
    expect(issued.status).toBe(200);
    expect(issued.body.data.needTypedConfirm).toBe(false);

    const res = await post('/pool-ban/confirm', {
      token: issued.body.data.token,
      durationHours: '',
    });
    expect(res.status).toBe(200);
    expect(res.body.data.bannedCount).toBeGreaterThan(0);

    // blockIP 的入参就是票据里的 CIDR 串，名单条目按原样存（不展开成单 IP）
    const doc = await IPBlacklist.findOne({ ip: '198.51.100.8/30' }).lean();
    expect(doc).toBeTruthy();
    expect(doc.expiresAt).not.toBeNull();
    // 24h 兜底：落在 23h~25h 窗口内（容忍测试执行耗时）
    const hours = (new Date(doc.expiresAt).getTime() - Date.now()) / 3600000;
    expect(hours).toBeGreaterThan(23);
    expect(hours).toBeLessThan(25);
    // 清理：不给其它用例留下真实黑名单记录
    await IPBlacklist.deleteMany({ ip: '198.51.100.8/30' });
  });

  test('8d 落库时刻必须复核操作者位置：取票时在段外、确认时在段内 ⇒ operator_inside 且零落库', async () => {
    // 判据位在**写入时刻**（ip-list 侧一直在写入时刻现取 operatorIp，pool-ban 先前只在取票时刻判一次）。
    // 不复核的后果：取票→确认之间换个网（或把票交给同事）就能把自己/对方挡在门外，且不需要 /0、不需要并集铺满。
    const IPBlacklist = require('../../models/IPBlacklist');
    const HALF = '128.0.0.0/1';
    const issued = await postFrom('/pool-ban/request', { cidr: HALF, reason: `位置复核 ${stamp}` }, '10.0.0.5');
    expect(issued.status).toBe(200);

    // 确认时换到 192.0.2.7：它落在 128.0.0.0/1 里（该段覆盖 128.0.0.0–255.255.255.255）
    const confirmed = await postFrom(
      '/pool-ban/confirm',
      { token: issued.body.data.token, durationHours: 1, typedConfirm: HALF },
      '192.0.2.7'
    );
    const rows = await IPBlacklist.find({ ip: HALF }).lean();
    expect({
      status: confirmed.status,
      reason: confirmed.body.errors && confirmed.body.errors.reason,
      rows: rows.length,
    }).toEqual({ status: 400, reason: 'operator_inside', rows: 0 });

    // 反向对照：两侧都在段外的段照常落库（判据不是恒拒）
    const CIDR = '203.0.113.0/24';
    const ok = await postFrom('/pool-ban/request', { cidr: CIDR, reason: `对照 ${stamp}` }, '192.0.2.7');
    const okConfirm = await postFrom(
      '/pool-ban/confirm',
      { token: ok.body.data.token, durationHours: 1, typedConfirm: CIDR },
      '192.0.2.7'
    );
    const okRows = await IPBlacklist.find({ ip: CIDR }).lean();
    expect({ status: okConfirm.status, rows: okRows.length }).toEqual({ status: 200, rows: 1 });
    await IPBlacklist.deleteMany({ ip: { $in: [HALF, CIDR] } });
  });

  test('8e 并集复核拒绝必须留 critical 痕迹：AuditLog 增量 = 1（不是"函数被调用过"）', async () => {
    const IPBlacklist = require('../../models/IPBlacklist');
    const AuditLog = require('../../models/AuditLog');
    const V6 = ['::/1', '8000::/1'];
    const a = await postFrom('/pool-ban/request', { cidr: V6[0], reason: `痕迹甲 ${stamp}` }, '192.0.2.7');
    const b = await postFrom('/pool-ban/request', { cidr: V6[1], reason: `痕迹乙 ${stamp}` }, '192.0.2.7');
    expect([a.status, b.status]).toEqual([200, 200]);
    // 两种时刻共用一个可对账的事件：写入前拦下（prewrite）与写完才发现并发补齐（rollback）
    const filter = { riskFactors: { $in: ['full_range_cidr_pool_ban_union_prewrite', 'full_range_cidr_pool_ban_union_rollback'] } };
    const first = await postFrom('/pool-ban/confirm', { token: a.body.data.token, durationHours: 1, typedConfirm: V6[0] }, '192.0.2.7');
    expect(first.status).toBe(200);
    const before = await AuditLog.countDocuments(filter); // 正常落库不留痕：这条同时是"不是恒记"的对照
    const rolled = await postFrom('/pool-ban/confirm', { token: b.body.data.token, durationHours: 1, typedConfirm: V6[1] }, '192.0.2.7');
    const after = await AuditLog.countDocuments(filter);
    const doc = await AuditLog.findOne(filter).sort({ _id: -1 }).lean();
    // 判据是**增量**而不是"函数被调用过"：写失败被静默吞掉时增量会是 0，这条就会红
    expect({
      status: rolled.status,
      reason: rolled.body.errors && rolled.body.errors.reason,
      before,
      delta: after - before,
      riskLevel: doc && doc.riskLevel,
      action: doc && doc.action,
      success: doc && doc.success,
      factor: doc && doc.riskFactors && doc.riskFactors[0],
      rolledBack: doc && doc.body && doc.body.rolledBack,
    }).toEqual({
      status: 400,
      reason: 'union_covers_family',
      before: 0,
      delta: 1,
      riskLevel: 'critical',
      action: 'privilege_escalation',
      success: false,
      factor: 'full_range_cidr_pool_ban_union_prewrite',
      rolledBack: 0,
    });
    await IPBlacklist.deleteMany({ ip: { $in: V6 } });
  });

  test('9 无导出密钥时拒绝，不产出未签名包', async () => {
    const savedExport = process.env.FORENSIC_EXPORT_SECRET;
    const savedHmac = process.env.AUDIT_HMAC_SECRET;
    delete process.env.FORENSIC_EXPORT_SECRET;
    delete process.env.AUDIT_HMAC_SECRET;
    try {
      const res = await post('/export', { ip: '203.0.113.77' });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('FORENSIC_EXPORT_NO_SECRET');
      expect(res.body.data).toBeUndefined();
    } finally {
      if (savedExport !== undefined) process.env.FORENSIC_EXPORT_SECRET = savedExport;
      if (savedHmac !== undefined) process.env.AUDIT_HMAC_SECRET = savedHmac;
    }
  });
});
