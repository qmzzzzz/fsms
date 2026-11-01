'use strict';

/**
 * 全网段写入的**痕迹时序**与**救援路径对称性**（第 22 轮 audit-ops 报的两条高危）
 *
 * ① 痕迹写在落库**之前**：guardFullRangeCIDR 的允许侧先记 success:true 的越权痕迹，再回控制器 blockIP。
 *    于是护栏之后的任何拒绝（白名单已覆盖 / 段护栏 / 并发回滚）都会留下一句“超级管理员已将 0.0.0.0/0 加入黑名单”
 *    ——事后复盘会以为那道防线已经架上了。痕迹必须晚于落库：没有条目，就没有“已加入”。
 *
 * ② 删除侧不保护救援路径：/0 黑名单落库后，唯一能自救的是覆盖操作者的那条永久白；
 *    DELETE 侧只保护“并集是否仍铺满整族”，不保护“救援路径是否仍在”。实测低阶 security:config 一次 DELETE
 *    删掉唯一救援白即得 200、零越权痕迹，随后所有请求（含超管）403 IP_BLOCKED，只能直连数据库恢复。
 *    门可以被无痕拆掉时，门上的锁等于没装。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('全网段写入：痕迹晚于落库 + 删除侧守护救援路径', () => {
  let app;
  let IPBlacklist;
  let AuditLog;
  let superToken;
  let secToken;
  let auditBuffer;
  const stamp = 'grs' + Date.now().toString(36);
  const PASSWORD = randomPassword();
  const FULL_RANGE = '0.0.0.0/0';
  const RESCUE_WHITE = '127.0.0.0/8';
  const createdIds = [];

  const post = (body) =>
    request(app)
      .post('/api/security/ip-list')
      .set('Authorization', 'Bearer ' + superToken)
      .send(body);

  /** “已授权”痕迹条数（riskFactors 含 grant 的那一类） */
  const grantTraces = () =>
    AuditLog.countDocuments({ riskFactors: 'full_range_cidr_super_admin_grant' });

  /** 重播救援白：beforeEach 会清库，不重播则每条用例都退化成“无救援路径”，② 的对照会失真 */
  const seedRescue = () =>
    IPBlacklist.blockIP(RESCUE_WHITE, {
      type: 'white',
      reason: '救援对称-前置永久白',
      source: 'manual',
      durationMs: 0,
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    IPBlacklist = require('../../models/IPBlacklist');
    AuditLog = require('../../models/AuditLog');
    require('../../models/ForensicCapture');
    auditBuffer = require('../../services/auditBuffer');
    auditBuffer.start();
    const { createApp } = require('../../app');
    app = createApp();

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
    const configPerm = await Permission.findOneAndUpdate(
      { code: 'security:config' },
      {
        $setOnInsert: {
          name: '安全配置',
          code: 'security:config',
          type: 'api',
          module: 'security',
        },
      },
      { upsert: true, new: true }
    );
    const secRole = await Role.create({
      name: '救援对称安全员' + stamp,
      code: 'GRS_SEC_' + stamp,
      level: 5,
      permissions: [configPerm._id],
    });
    createdIds.push(String(secRole._id));

    const uSuper = await User.create({
      username: 'grssuper' + stamp,
      email: 'grssuper' + stamp + '@e.com',
      password: PASSWORD,
      roles: [superRole._id],
    });
    const uSec = await User.create({
      username: 'grssec' + stamp,
      email: 'grssec' + stamp + '@e.com',
      password: PASSWORD,
      roles: [secRole._id],
    });
    createdIds.push(String(uSuper._id), String(uSec._id));
    const sign = (u) =>
      jwt.sign(
        { userId: String(u._id), username: u.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
    superToken = sign(uSuper);
    secToken = sign(uSec);
  });

  beforeEach(async () => {
    await IPBlacklist.deleteMany({});
    IPBlacklist.invalidateSnapshot();
    // 审计是 append-only：清理必须显式声明旁路（该旁路只在 NODE_ENV=test 生效）
    await AuditLog.deleteMany({ action: 'privilege_escalation' }, { bypassAppendOnly: true });
    await seedRescue();
  });

  afterAll(async () => {
    auditBuffer.stop();
    if (mongoose.connection.readyState !== 0) {
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await IPBlacklist.deleteMany({}).catch(() => {});
      await User.deleteMany({ _id: { $in: createdIds.slice(0, 2) } }).catch(() => {});
      await Role.deleteMany({ _id: { $in: createdIds.slice(2) } }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('① 被后续护栏拒绝时不得留下“已加入”痕迹（白 /0 已覆盖 ⇒ 加黑 400 且无新痕迹）', async () => {
    const white = await post({
      ip: FULL_RANGE,
      type: 'white',
      reason: '痕迹时序-白覆盖前置',
      typedConfirm: FULL_RANGE,
    });
    expect(white.status).toBe(200);
    const before = await grantTraces();

    const black = await post({
      ip: FULL_RANGE,
      type: 'black',
      reason: '痕迹时序-应被白名单拒',
      typedConfirm: FULL_RANGE,
    });
    expect(black.status).toBe(400);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE, type: 'black' })).toBe(0);
    // 没有落库，就不得新增“已授权”痕迹
    expect(await grantTraces()).toBe(before);
  });

  test('① 正面对照：真正落库的 /0 必须留下 granted 痕迹（判据不是恒无痕迹）', async () => {
    const before = await grantTraces();
    const ok = await post({
      ip: FULL_RANGE,
      type: 'black',
      reason: '痕迹时序-正面',
      typedConfirm: FULL_RANGE,
    });
    expect(ok.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ ip: FULL_RANGE, type: 'black' })).toBe(1);
    expect(await grantTraces()).toBe(before + 1);
  });

  test('② 删除唯一救援白 ⇒ 403 + critical 痕迹，条目必须还在', async () => {
    const black = await post({
      ip: FULL_RANGE,
      type: 'black',
      reason: '救援对称-黑前置',
      typedConfirm: FULL_RANGE,
    });
    expect(black.status).toBe(200);
    const rescueDoc = await IPBlacklist.findOne({ ip: RESCUE_WHITE, type: 'white' });
    expect(rescueDoc).toBeTruthy();

    const del = await request(app)
      .delete('/api/security/ip-list/' + rescueDoc._id)
      .set('Authorization', 'Bearer ' + secToken);
    expect(del.status).toBe(403);
    expect(await IPBlacklist.countDocuments({ _id: rescueDoc._id })).toBe(1);
    const trace = await AuditLog.findOne({
      riskFactors: 'full_range_cidr_rescue_removal_attempt',
    }).lean();
    expect(trace).toBeTruthy();
    expect(trace.riskLevel).toBe('critical');
  });

  test('② 对照：先撤掉 /0 黑名单后，同一条救援白可以正常删除（判据不是恒拒）', async () => {
    const black = await post({
      ip: FULL_RANGE,
      type: 'black',
      reason: '救援对称-对照',
      typedConfirm: FULL_RANGE,
    });
    expect(black.status).toBe(200);
    const blackDoc = await IPBlacklist.findOne({ ip: FULL_RANGE, type: 'black' });
    const delBlack = await request(app)
      .delete('/api/security/ip-list/' + blackDoc._id)
      .set('Authorization', 'Bearer ' + superToken);
    expect(delBlack.status).toBe(200);

    const rescueDoc = await IPBlacklist.findOne({ ip: RESCUE_WHITE, type: 'white' });
    const delWhite = await request(app)
      .delete('/api/security/ip-list/' + rescueDoc._id)
      .set('Authorization', 'Bearer ' + secToken);
    expect(delWhite.status).toBe(200);
    expect(await IPBlacklist.countDocuments({ _id: rescueDoc._id })).toBe(0);
  });

  test('③ 确认串不匹配时回带 errors.expected，且它真的是通关口令', async () => {
    const first = await post({
      ip: '2001:DB8::/64',
      type: 'black',
      reason: '确认回带',
      typedConfirm: '2001:DB8::/64',
    });
    expect(first.status).toBe(400);
    expect(first.body.errors.errorCode).toBe('IP_SEGMENT_WRITE_REFUSED');
    expect(first.body.errors.reason).toBe('typed_confirmation_required');
    expect(first.body.errors.expected).toBe('2001:db8::/64');

    const second = await post({
      ip: '2001:DB8::/64',
      type: 'black',
      reason: '确认回带',
      typedConfirm: first.body.errors.expected,
    });
    expect(second.status).toBe(200);
  });
});
