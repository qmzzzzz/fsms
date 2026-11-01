'use strict';

/**
 * GET /api/security/stuffing-profile 读口的判据（ADR-013「P2 情报 · 读侧出口（已落地）」）
 *
 * 分工（缺一条就留假绿空间）：
 *  1. 读档：无票据 ⇒ 401、有票据但无 security:audit ⇒ 403——与 /alerts、/audit-logs 同档，不新增权限码；
 *  2. 正向现算：all 档看到自己来源段的条目，每个字段当场由**种子行**算出来对拍，不抄一份期望值；
 *  3. 反证：诱饵放行落的那条 login_success **不算**成功率（否则诱饵自己把成功率抬到 100%）；
 *  4. 同源收口：部门档看到的蜜罐行集恒为空（蜜罐行不带 userId，而 department 档的谓词按 userId 过滤），
 *     出口回传调用者自己的 dataScopeType ⇒ 空表可解释、不许冒充「没有攻击」；
 *  5. 参数判死：坏形状与空串都回 400 DATE_PARAM_INVALID，只有整个参数缺席才是「今天」；
 *  6. 零泄漏：响应里不得出现陷阱账号名，也不得出现种子行的 body 原样内容。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { reauthHeaders } = require('../helpers/reauthTicket');
const { ipSegment } = require('../../utils/fingerprint');
const { businessDayBounds, businessDateParts } = require('../../constants/timezone');
const { MIN_SAMPLES } = require('../../constants/stuffingProfile');
const { parseHoneypotUsernames } = require('../../constants/honeypotAccounts');

const URL = '/api/security/stuffing-profile';
const stamp = `zsp${Date.now()}`.slice(-12);
const PASSWORD = 'Zz!pTg7mKq9xLd4nBv2Rf8sY';
const DEPT_A = `ZZSP-A-${stamp}`;
const SEGMENT_IP = '198.51.100.7';
const SHAPE_MAJOR = { credentialStemHits: 1, lengthBucket: 'lt8', charsetClass: 'digits' };
const SHAPE_MINOR = { credentialStemHits: 0, lengthBucket: 'gte8', charsetClass: 'mixed' };
const SEED = Object.freeze({ major: 20, minor: 12, accounts: 5 });
// 现算：期望值全部由上面的种子定义与常量推出，不抄一份字面量（抄两份口径迟早分叉）
const EXPECT = Object.freeze({
  attempts: SEED.major + SEED.minor,
  stemHits:
    SEED.major * SHAPE_MAJOR.credentialStemHits + SEED.minor * SHAPE_MINOR.credentialStemHits,
  lengthBucket: SEED.major > SEED.minor ? SHAPE_MAJOR.lengthBucket : SHAPE_MINOR.lengthBucket,
  charsetClass: SEED.major > SEED.minor ? SHAPE_MAJOR.charsetClass : SHAPE_MINOR.charsetClass,
  successes: 1,
  // 账号基数把两条 login_success 也数进去（真实成功一条 + 诱饵放行一条）：它数的是「这一段碰过几个账号」，
  // 不是「几个账号试成功了」——所以是 SEED.accounts + 2，抄成 SEED.accounts 会把口径抄错一次
  accountCardinality: SEED.accounts + 2,
});
const LURE = parseHoneypotUsernames().names[0];
const BODY_MARK = `sp-body-${stamp}`;
const seedRows = () => {
  const now = new Date();
  const rows = [];
  for (let i = 0; i < EXPECT.attempts; i += 1) {
    rows.push({
      action: 'honeypot_login',
      category: 'security',
      riskLevel: 'high',
      username: `zzspacct${i % SEED.accounts}${stamp}`,
      ip: SEGMENT_IP,
      success: false,
      timestamp: now,
      body: { credentialShape: i < SEED.major ? SHAPE_MAJOR : SHAPE_MINOR, zzProbe: BODY_MARK },
    });
  }
  rows.push({
    action: 'login_success',
    category: 'security',
    riskLevel: 'low',
    username: `zzspreal${stamp}`,
    ip: SEGMENT_IP,
    success: true,
    timestamp: now,
    body: {},
  });
  rows.push({
    action: 'login_success', // 诱饵会话签发时也会落一条 login_success：它不是「真实登录成功」
    category: 'security',
    riskLevel: 'high',
    username: LURE,
    ip: SEGMENT_IP,
    success: true,
    timestamp: now,
    body: {},
  });
  return rows;
};

describe('GET /api/security/stuffing-profile 读口判据', () => {
  let app;
  let AuditLog;
  let allToken;
  let deptToken;
  let noDeptToken;
  let plainToken;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

    const upsertPerm = (code, module) =>
      Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { name: code, code, type: 'api', module } },
        { upsert: true, new: true }
      );
    const wildcard = await upsertPerm('*:*', 'system');
    const auditPerm = await upsertPerm('security:audit', 'security');
    const mkRole = (suffix, level, permissions) =>
      Role.findOneAndUpdate(
        { code: `ZZSP${suffix}${stamp}` },
        {
          $setOnInsert: {
            name: `sp-${suffix}${stamp}`,
            code: `ZZSP${suffix}${stamp}`,
            level,
            permissions,
          },
        },
        { upsert: true, new: true }
      );
    const superRole = await mkRole('SUP', 10, [wildcard._id]);
    const secRole = await mkRole('SEC', 8, [auditPerm._id]);
    const plainRole = await mkRole('PLAIN', 1, []);

    const mkUser = (name, extra = {}) =>
      User.create({
        username: `${name}${stamp}`,
        email: `${name}${stamp}@example.com`,
        password: PASSWORD,
        ...extra,
      });
    const tokenFor = (user) =>
      jwt.sign(
        { userId: String(user._id), username: user.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

    const root = await mkUser('zzsproot', { roles: [superRole._id] });
    const secA = await mkUser('zzspseca', { roles: [secRole._id], department: DEPT_A });
    const secNone = await mkUser('zzspsecn', { roles: [secRole._id] });
    const plain = await mkUser('zzspplain', { roles: [plainRole._id] });
    allToken = tokenFor(root);
    deptToken = tokenFor(secA);
    noDeptToken = tokenFor(secNone);
    plainToken = tokenFor(plain);

    await AuditLog.insertMany(seedRows());
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0 && AuditLog) {
      await AuditLog.deleteMany({ ip: SEGMENT_IP }, { bypassAppendOnly: true }).catch(() => {});
      const User = require('../../models/User');
      await User.deleteMany({ username: new RegExp(String(stamp)) }).catch(() => {});
    }
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const authGet = (token, query = '') =>
    request(app)
      .get(URL + query)
      .set('Authorization', `Bearer ${token}`)
      .set(reauthHeaders(token));

  const entryForSegment = (body) =>
    (body.data || []).find((row) => row.sourceKey === ipSegment(SEGMENT_IP));

  test('读档：无票据 401、有票据但无 security:audit 403；all 档同票据 200（反证不是一律拒绝）', async () => {
    const noTicket = await request(app).get(URL).set('Authorization', `Bearer ${allToken}`);
    expect(noTicket.status).toBe(401);
    expect((await authGet(plainToken)).status).toBe(403);
    expect((await authGet(allToken)).status).toBe(200);
  });

  test('正向现算：all 档的每个字段由种子行算出来对拍，不抄期望值', async () => {
    const res = await authGet(allToken);
    expect(res.status).toBe(200);
    const day = businessDateParts().dateStr;
    const bounds = businessDayBounds(day);
    const meta = res.body.meta;
    expect(meta.businessDay).toBe(day);
    expect(meta.windowEnd).toBe(bounds.end.toISOString());
    expect(meta.windowStart).toBe(bounds.start.toISOString());
    expect(meta.expired).toBe(false);
    expect(meta.minSamples).toBe(MIN_SAMPLES);
    expect(meta.dataScopeType).toBe('all');
    expect(meta.count).toBe(res.body.data.length);
    const row = entryForSegment(res.body);
    expect(row).toBeTruthy();
    expect(row.attempts).toBe(EXPECT.attempts);
    expect(row.successes).toBe(EXPECT.successes);
    expect(row.accountCardinality).toBe(EXPECT.accountCardinality);
    expect(row.credentialStemHits).toBe(EXPECT.stemHits);
    expect(row.lengthBucket).toBe(EXPECT.lengthBucket);
    expect(row.charsetClass).toBe(EXPECT.charsetClass);
    expect(row.businessDay).toBe(day);
    expect(row.windowStart).toBe(meta.windowStart);
    expect(row.windowEnd).toBe(meta.windowEnd);
    for (const item of res.body.data) expect(item.attempts).toBeGreaterThanOrEqual(MIN_SAMPLES);
  });

  test('反证：诱饵放行的那条 login_success 确实在库里，但不算成功率', async () => {
    const seeded = await AuditLog.countDocuments({ ip: SEGMENT_IP, action: 'login_success' });
    expect(seeded).toBe(2); // 一条真实成功 + 一条诱饵放行
    const row = entryForSegment((await authGet(allToken)).body);
    expect(row.successes).toBe(EXPECT.successes);
    expect(row.attempts).toBe(EXPECT.attempts); // 成功行不计入 attempts
  });

  test('同源收口：部门档看不到蜜罐行（蜜罐行无 userId）；部门档却没有部门 ⇒ fail-closed 403', async () => {
    const withDept = await authGet(deptToken);
    expect(withDept.status).toBe(200);
    expect(withDept.body.meta.dataScopeType).toBe('department');
    expect(entryForSegment(withDept.body)).toBeUndefined();
    // 部门档却没有部门：与 auditScopeFilter 的 deny 口径同向，不许退化成「看全部」或「看自己」
    const withoutDept = await authGet(noDeptToken);
    expect(withoutDept.status).toBe(403);
    expect(withoutDept.body.errors.errorCode).toBe('DATA_SCOPE_DENIED');
    // 反证：同一份种子在 all 档可见——否则「看不到」可能只是种子根本没落库
    expect(entryForSegment((await authGet(allToken)).body)).toBeTruthy();
  });

  test('参数判死：坏形状、空串与数组形态都 400；不存在的日历日沿用本仓既有的 clamp 收口', async () => {
    const bad = [
      '?businessDay=2026-2-3',
      '?businessDay=abc',
      '?businessDay=',
      '?businessDay=20260801',
    ];
    for (const query of bad) {
      const res = await authGet(allToken, query);
      expect({ query, status: res.status }).toEqual({ query, status: 400 });
      expect(res.body.errors.errorCode).toBe('DATE_PARAM_INVALID');
    }
    // 数组形态在更上游就被标量闸拦下（QUERY_PARAM_MUST_BE_SCALAR）：控制器里那条 typeof 判据是第二道，
    // 不当它是唯一防线，所以这里只钉「不落到取数、不 200」。
    const scalar = await authGet(allToken, '?businessDay=a&businessDay=b');
    expect(scalar.status).toBe(400);
    expect(scalar.body.errors.errorCode).toBe('QUERY_PARAM_MUST_BE_SCALAR');
    // 2026-02-30 这类不存在的日历日**故意**留给 constants/timezone 的 clampToRealCalendarDay 收口
    // （isValidDateParam 的注释点明了该收口点）。期望值由 businessDayBounds 现算，不在这里另立一套。
    const illegal = '2026-02-30';
    const clamped = await authGet(allToken, `?businessDay=${illegal}`);
    expect(clamped.status).toBe(200);
    expect(clamped.body.meta.businessDay).toBe(businessDayBounds(illegal).dateStr);
    const res = await authGet(allToken);
    expect(res.body.meta.businessDay).toBe(businessDateParts().dateStr);
  });

  test('零泄漏：响应里没有陷阱账号名，也没有种子行的 body 原样内容', async () => {
    const text = JSON.stringify((await authGet(allToken)).body);
    expect(text).not.toContain(LURE);
    expect(text).not.toContain('zzspacct');
    expect(text).not.toContain(BODY_MARK);
    expect(text).not.toContain('credentialShape');
  });
});
