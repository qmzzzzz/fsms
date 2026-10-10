/**
 * xlsx 审计导出必须与列表/CSV 导出同样受数据范围约束
 *
 * 修复前只有权限码闸门（security:audit），没有 dataScope：
 * `/api/security/audit-logs`（auditController.js:43）与审计列表
 * （auditQueryService.js:320）都调用 `applyAuditDataScope`，
 * 而 `/api/reports/export?type=audit` 直接跳过它。⇒ level 7（department 档）的运维
 * 列表里只看得到本部门成员的行为记录，xlsx 却导出**全库所有人**的 IP/路径/操作。
 * 导出集比可见集宽，等于把范围闸从后门拆掉。
 */
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const ExcelJS = require('exceljs');

const { randomPassword } = require('./helpers/buildLoginEnvelope');
const { AUDIT_CATEGORIES } = require('../constants/audit');

const DEPT_A = 'ZZEX-A';
const DEPT_B = 'ZZEX-B';
const stamp = `zzex${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 8);

describe('GET /api/reports/export?type=audit 的数据范围', () => {
  let app;
  let AuditLog;
  let deptToken;
  let allToken;

  const rowOf = async (token) => {
    const res = await request(app)
      .get('/api/reports/export')
      .query({ type: 'audit' })
      .set('Authorization', `Bearer ${token}`)
      .responseType('blob');
    expect(res.status).toBe(200);
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(res.body);
    const ws = wb.worksheets[0];
    // 第 1 行是表头
    return ws.rowCount - 1;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    const User = require('../models/User');
    const Role = require('../models/Role');
    const Permission = require('../models/Permission');
    AuditLog = require('../models/AuditLog');
    require('../models/FireAlarm');
    require('../models/TokenBlacklist');

    const [exp, audit, wildcard] = await Permission.create([
      { name: '导出报表', code: 'report:export', type: 'api', module: 'report' },
      { name: '读审计', code: 'security:audit', type: 'api', module: 'security' },
      { name: '全部权限', code: '*:*', type: 'api', module: 'system' },
    ]);
    const mkRole = (code, level, permissions) =>
      Role.create({ name: `${stamp} ${code}`, code: `${stamp}_${code}`, level, permissions });
    const deptRole = await mkRole('DEPT', 7, [exp._id, audit._id]);
    const allRole = await mkRole('ALL', 10, [wildcard._id]);

    const mkUser = (username, roles, department) =>
      User.create({
        username,
        email: `${username}@example.com`,
        password: randomPassword(),
        department,
        roles,
      });
    const opA = await mkUser(`${stamp}_op`, [deptRole._id], DEPT_A);
    await mkUser(`${stamp}_all`, [allRole._id], DEPT_A);
    const memberA = await mkUser(`${stamp}_ma`, [], DEPT_A);
    const memberB = await mkUser(`${stamp}_mb`, [], DEPT_B);

    const sign = (u) =>
      jwt.sign(
        { userId: String(u._id), username: u.username, tokenVersion: u.tokenVersion ?? 0 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
    deptToken = sign(opA);
    allToken = sign(await User.findOne({ username: `${stamp}_all` }));

    const mkLog = (user, n) =>
      AuditLog.create({
        action: `${stamp}_act_${n}`,
        category: AUDIT_CATEGORIES[0],
        username: user.username,
        userId: user._id,
        ip: '10.0.0.9',
        success: true,
        timestamp: new Date(),
      });
    // 本部门 3 条、他部门 2 条：导出集若等于 5 就说明范围闸被跳过
    await mkLog(memberA, 1);
    await mkLog(memberA, 2);
    await mkLog(memberA, 3);
    await mkLog(memberB, 4);
    await mkLog(memberB, 5);

    const { createApp } = require('../app');
    app = createApp();
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ action: new RegExp(`^${stamp}`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('department 档只导出本部门成员的审计行', async () => {
    expect(await rowOf(deptToken)).toBe(3);
  });

  test('反向对照：all 档仍是全量（不得把导出一律收成空表）', async () => {
    expect(await rowOf(allToken)).toBe(5);
  });
});
