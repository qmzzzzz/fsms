'use strict';

/**
 * 审计导出的参数错误口径：xlsx 与 CSV 两条导出链必须回同一个 400 + 同一条文案
 *
 * 两条链共用 `utils/auditQuery.js` 的判据（`参数 userId 必须是合法的用户 ID` /
 * `参数 ip 必须是合法的 IPv4/IPv6 地址`），但只有 CSV 侧（`auditController.js:27-31`）
 * 把 `buildAuditQuery` 的抛错兜成 400；xlsx 侧（`/api/reports/export?type=audit`）
 * 让 `buildExportQuery` 的抛错一路穿到全局错误处理器 ⇒ **同一个 URL 参数**，
 * CSV 回 400 + 人话，xlsx 回 500。用户看到的是"服务器错误"，而不是"你的 userId 写错了"。
 *
 * 本用例把"两条链同口径"直接写成断言：同一入参各发一次，
 * 状态码与 message 必须逐字相同。任何一侧单独改文案/改状态码都会红。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { AUDIT_CATEGORIES } = require('../../constants/audit');

const stamp = `zzpp${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

describe('审计导出参数错误：xlsx 与 CSV 同口径', () => {
  let app;
  let AuditLog;
  let token;
  let realUserId;

  /** 两条导出链：同一份 query 参数各发一次 */
  const viaXlsx = (params) =>
    request(app)
      .get('/api/reports/export')
      .query({ type: 'audit', ...params })
      .set('Authorization', `Bearer ${token}`);
  const viaCsv = (params) =>
    request(app)
      .get('/api/security/audit-logs/export')
      .query(params)
      .set('Authorization', `Bearer ${token}`);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let role = await Role.findOne({ code: `${stamp}_ALL` });
    if (!role) {
      role = await Role.create({
        name: `${stamp} 全量`,
        code: `${stamp}_ALL`,
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const op = await User.create({
      username: `${stamp}_op`,
      email: `${stamp}_op@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    const target = await User.create({
      username: `${stamp}_tgt`,
      email: `${stamp}_tgt@example.com`,
      password: randomPassword(),
    });
    realUserId = String(target._id);
    token = jwt.sign(
      { userId: String(op._id), username: op.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    await AuditLog.create({
      action: 'login',
      category: AUDIT_CATEGORIES[0],
      userId: target._id,
      username: target.username,
      ip: '10.0.0.9',
      success: true,
      timestamp: new Date(),
    });

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    const User = require('../../models/User');
    await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
    await AuditLog.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test.each([
    { label: 'userId', params: { userId: 'not-an-objectid' } },
    { label: 'userId 过短', params: { userId: '123' } },
    { label: 'ip', params: { ip: '999.999.999.999' } },
    { label: 'ip 非地址', params: { ip: 'just-a-string' } },
  ])('$label 非法 ⇒ xlsx 与 CSV 回同一个 400 + 同一条文案', async ({ params }) => {
    const [xlsx, csv] = await Promise.all([viaXlsx(params), viaCsv(params)]);

    expect(csv.status).toBe(400);
    expect(xlsx.status).toBe(400);
    // 逐字相同：任何一侧偷偷换文案/换状态码，这里就红
    expect(xlsx.body.message).toBe(csv.body.message);
    expect(typeof xlsx.body.message).toBe('string');
    expect(xlsx.body.message).not.toBe('');
    // 不得是"服务器内部错误"那类兜底文案（500 换皮成 400 也算红）
    expect(xlsx.body.message).toMatch(/ userId | ip |参数/);
  });

  test('反向前提：合法参数两条链都必须真的出文件（否则上面的全 400 也会"通过"）', async () => {
    const xlsx = await request(app)
      .get('/api/reports/export')
      .query({ type: 'audit', userId: realUserId })
      .set('Authorization', `Bearer ${token}`)
      .responseType('blob');
    expect(xlsx.status).toBe(200);
    // 非空字节流：200 + 空 body 不算出文件
    expect(Buffer.isBuffer(xlsx.body)).toBe(true);
    expect(xlsx.body.length).toBeGreaterThan(0);

    const csv = await viaCsv({ userId: realUserId });
    expect(csv.status).toBe(200);
    expect(csv.text).toContain('10.0.0.9');
  });

  test('兄弟契约不能被新加的 try/catch 吞掉：未知 type 与未知 format 各自回专属码', async () => {
    // buildExportQuery 对未知 type 返回 null（不是抛错）——把它一起包进 try/catch 之后，
    // 这条 null 分支必须仍然走到 REPORT_TYPE_UNSUPPORTED。
    const badType = await request(app)
      .get('/api/reports/export')
      .query({ type: 'not-a-report-type' })
      .set('Authorization', `Bearer ${token}`);
    expect(badType.status).toBe(400);
    expect(badType.body.errors.errorCode).toBe('REPORT_TYPE_UNSUPPORTED');

    const badFormat = await viaXlsx({ format: 'csv' });
    expect(badFormat.status).toBe(400);
    expect(badFormat.body.errors.errorCode).toBe('EXPORT_FORMAT_UNSUPPORTED');
  });
});
