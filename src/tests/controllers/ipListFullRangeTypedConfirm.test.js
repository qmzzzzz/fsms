'use strict';

/**
 * 全网段（/0）写入：超管也必须逐字确认，且放行要留 critical 痕迹
 *
 * 第 20 轮审计实测的两处缺口（ADR-018 ③/④ 只落在池封禁一侧）：
 *   ①  `POST /api/security/ip-list` 的 /0 分支只查"是不是生效超管"，**不查确认串**——
 *       一次点击即写入"全站拒服且管理员自己也无法登录解除"的条目，而池封禁侧同规模的
 *       段必须逐字敲网段才能落库。同一个权限位两个入口各用一把尺子（ADR-018 踩坑③）。
 *   ②  超管放行 /0 时只有 `logger.warn`，**没有可检索的审计行**：事后复盘只能说"日志里
 *       好像有"，且拒绝侧是 critical 而允许侧连 riskFactors 都没有——最该留痕的结局留白。
 *
 * 判据（每条都可证伪）：
 *   1. 超管、无确认串 ⇒ 400 + errors.reason=typed_confirmation_required，且**不落库**；
 *   2. 确认串与归一化后的网段不一致 ⇒ 同 1（打错字不是确认）；
 *   3. 确认串精确一致 ⇒ 200 + 落库 + 一条 success:true 的 critical 审计行；
 *   4. 加白 /0 与加黑 /0 同一口径（加白使黑名单与限流整体失效，不比加黑轻）；
 *   5. 两侧边界：/24（256 主机）需确认、/25（128 主机）不需要——门槛是后端算的 256，
 *      不是"凡是带斜杠就要确认"；
 *   6. 非超管仍先被 403 拦住（本改动不得放宽原有收口）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { waitFor } = require('../helpers/waitFor');

describe('全网段写入：超管打字确认 + 放行留痕', () => {
  let app;
  let IPBlacklist;
  let AuditLog;
  let superToken;
  let secToken;
  let superUserId;
  const stamp = `frq${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const FULL_RANGE = '0.0.0.0/0';
  // 原因码取值来自后端常量，测试也不抄字面量（抄一份漂一份）
  const TYPED_CONFIRM = require('../../constants/banRefusalReason').CODES
    .typed_confirmation_required;
  const typed_confirmation_required_expected = TYPED_CONFIRM;

  const post = (token, body) =>
    request(app).post('/api/security/ip-list').set('Authorization', `Bearer ${token}`).send(body);

  /** 放行侧的 critical 痕迹：按 body.ip 精确认领，避免命中拒绝侧同名策略的旧行 */
  const findAllowAudit = async (ip) => {
    let doc = null;
    await waitFor(
      async () => {
        doc = await AuditLog.findOne({
          action: 'privilege_escalation',
          'body.ip': ip,
          success: true,
        })
          .sort({ _id: -1 })
          .lean();
        return !!doc;
      },
      { label: `放行侧 critical 审计落库（body.ip=${ip}）` }
    );
    return doc;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    IPBlacklist = require('../../models/IPBlacklist');
    AuditLog = require('../../models/AuditLog');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const superUser = await User.create({
      username: `frqsuper${stamp}`,
      email: `frqsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superUserId = String(superUser._id);
    superToken = jwt.sign(
      { userId: superUserId, username: superUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const configPerm = await Permission.findOneAndUpdate(
      { code: 'security:config' },
      { $setOnInsert: { name: '安全配置', code: 'security:config', type: 'api', module: 'security' } },
      { upsert: true, new: true }
    );
    const secRole = await Role.create({
      name: `安全员_${stamp}`,
      code: `FRQ_SEC_${stamp}`,
      level: 5,
      permissions: [configPerm._id],
    });
    const secUser = await User.create({
      username: `frqsec${stamp}`,
      email: `frqsec${stamp}@example.com`,
      password: PASSWORD,
      roles: [secRole._id],
    });
    secToken = jwt.sign(
      { userId: String(secUser._id), username: secUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 回环白名单：加黑 /0 一旦落库，后续任何来源（含 supertest 的本机请求）都会被
    // checkIPBlacklist 拦成 IP_BLOCKED，白名单优先级更高才能继续验后面的分支。
    // durationMs=0（永久）：救援路径判据只认永不过期的白名单（临时白 = 一小时后二次自锁）
    await IPBlacklist.blockIP('127.0.0.0/8', {
      type: 'white',
      reason: '全网段确认-回环豁免前置',
      source: 'manual',
      durationMs: 0,
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterEach(async () => {
    // 每条用例后立即收回 /0 条目：留到下一次会把请求判成 IP_BLOCKED（失败原因错位）
    await IPBlacklist.deleteMany({ ip: FULL_RANGE });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      await User.deleteMany({ username: new RegExp(`^frq(super|sec)${stamp}$`) }).catch(() => {});
      await IPBlacklist.deleteMany({
        $or: [{ ip: { $in: [FULL_RANGE, '127.0.0.0/8'] } }, { reason: /全网段确认/ }],
      }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('前提自证：操作者确实是生效内置超管（否则下面每条"被拒"都可能只是权限不足）', async () => {
    const User = require('../../models/User');
    const me = await User.findById(superUserId)
      .populate({ path: 'roles', select: 'code isBuiltIn', match: { status: 'active' } })
      .lean();
    expect((me.roles || []).map((r) => r.code)).toContain('SUPER_ADMIN');
    // 同一操作者写一个无风险的普通条目必须成功：证明权限链、校验链都通
    const ok = await post(superToken, { ip: '198.51.100.9', type: 'white', reason: '前提自证' });
    expect(ok.status).toBe(200);
    await IPBlacklist.deleteMany({ ip: '198.51.100.9' });
  });

  test('超管加黑 /0 不带确认串 → 400 typed_confirmation_required，且不落库', async () => {
    const res = await post(superToken, { ip: FULL_RANGE, type: 'black', reason: '手滑' });
    expect(res.status).toBe(400);
    // 判据用 reason 而不是笼统 errorCode：换一条判据（如并集）也能给出同一个码，
    // 只有 reason 能证明"被拦的理由是没确认"
    expect(res.body.errors.errorCode).toBe('IP_SEGMENT_WRITE_REFUSED');
    expect(res.body.errors.reason).toBe(TYPED_CONFIRM);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);
  });

  test('确认串对不上就不算确认：少一组、少了掩码、多打一位都拒；首尾空白是归一化不是失真', async () => {
    for (const typed of ['0.0.0.0/1', '0.0.0.0', '0.0.0.00/0', '00.0.0.0/0']) {
      const res = await post(superToken, {
        ip: FULL_RANGE,
        type: 'black',
        reason: '确认串不符',
        typedConfirm: typed,
      });
      expect({ typed, status: res.status }).toEqual({ typed, status: 400 });
      expect(res.body.errors.reason).toBe(typed_confirmation_required_expected);
    }
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);

    // 首尾空白：`typedConfirmMatches` 里 trim 后比较（与池封禁 applyBan 同一实现）。
    // 这里钉住"归一化不改变判据"：同一实现换到 ip-list 侧不得变成"带空格也算一次手滑"
    const padded = await post(superToken, {
      ip: FULL_RANGE,
      type: 'black',
      reason: '首尾空白',
      typedConfirm: '  0.0.0.0/0\t',
    });
    expect(padded.status).toBe(200);
  });

  test('确认串精确一致 → 200、落库、并留一条 success:true 的 critical 审计（加黑 /0）', async () => {
    const res = await post(superToken, {
      ip: FULL_RANGE,
      type: 'black',
      reason: '全网段确认-加黑成功路径',
      typedConfirm: FULL_RANGE,
    });
    expect(res.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE, type: 'black' })).toBe(1);

    const audit = await findAllowAudit(FULL_RANGE);
    expect({
      userId: String(audit.userId),
      category: audit.category,
      riskLevel: audit.riskLevel,
      riskFactors: audit.riskFactors,
      success: audit.success,
      path: audit.path,
      method: audit.method,
      body: audit.body,
      type: audit.body?.type,
    }).toEqual({
      userId: superUserId,
      category: 'security',
      riskLevel: 'critical',
      riskFactors: ['full_range_cidr_super_admin_grant'],
      success: true,
      path: '/api/security/ip-list',
      method: 'POST',
      body: { ip: FULL_RANGE, type: 'black' },
      type: 'black',
    });
    // 审计的 reason 必须说清"允许了什么"，不能是一句"超管操作"
    expect(typeof audit.reason === 'string' && audit.reason.length > 8).toBe(true);
  });

  test('加白 /0 与加黑 /0 同一口径：不带确认串同样 400 且不落库', async () => {
    const res = await post(superToken, { ip: FULL_RANGE, type: 'white', reason: '全放行' });
    expect(res.status).toBe(400);
    expect(res.body.errors.reason).toBe(TYPED_CONFIRM);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);
  });

  test('加白 /0 带确认串 → 200，且放行痕迹不区分黑白（同一条 riskFactors，type 在 body 里）', async () => {
    const res = await post(superToken, {
      ip: FULL_RANGE,
      type: 'white',
      reason: '全网段确认-加白成功路径',
      typedConfirm: FULL_RANGE,
    });
    if (res.status !== 200) console.log('WHITE500', JSON.stringify(res.body));
    expect(res.status).toBe(200);
    const audit = await findAllowAudit(FULL_RANGE);
    expect({ riskLevel: audit.riskLevel, body: audit.body }).toEqual({
      riskLevel: 'critical',
      body: { ip: FULL_RANGE, type: 'white' },
    });
  });

  test('两侧边界：门槛是后端算的 256 主机，不是"带斜杠就要确认"', async () => {
    // 黑名单侧的门槛在 segmentWriteRefusal（与池封禁同一函数）：/24=256 台 ⇒ 要确认
    const at = await post(superToken, { ip: '198.51.100.0/24', type: 'black', reason: '边界-256' });
    expect(at.status).toBe(400);
    expect(at.body.errors.reason).toBe(typed_confirmation_required_expected);

    // /25=128 台 ⇒ 不需要确认，也不该被"凡斜杠皆拦"误伤
    const under = await post(superToken, {
      ip: '198.51.100.0/25',
      type: 'black',
      reason: '边界-128',
    });
    expect(under.status).toBe(200);

    // 256 台以上带对确认串 ⇒ 放行（证明上面那次 400 只缺确认串）
    const okAt = await post(superToken, {
      ip: '198.51.100.0/24',
      type: 'black',
      reason: '边界-256',
      typedConfirm: '198.51.100.0/24',
    });
    expect(okAt.status).toBe(200);

    await IPBlacklist.deleteMany({ ip: { $in: ['198.51.100.0/24', '198.51.100.0/25'] } });
  });

  test('非超管加黑 /0 仍先被 403 拦住（本改动不得放宽原有收口，且不因缺确认串而改口）', async () => {
    const res = await post(secToken, { ip: FULL_RANGE, type: 'black', reason: '越权尝试' });
    expect(res.status).toBe(403);
    // 权限先于确认：否则非超管会先收到"请逐字确认"，等于告诉对方"确认了就能成"
    expect(res.body.errors.errorCode).toBe('FULL_RANGE_FORBIDDEN');
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE })).toBe(0);
  });
});
