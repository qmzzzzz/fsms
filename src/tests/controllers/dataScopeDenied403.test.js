/**
 * ──────────────────────────────────────────────────────────────────────────
 * 数据范围不可用 ⇒ HTTP 403 DATA_SCOPE_DENIED（待办 #12 选项①）
 *
 * 被测对象：所有"按调用者数据范围取数"的读出口。
 * 守护的不变式：范围不可用（department 档但未分配部门 / self 档取不到 userId /
 *   type='none' / 未知档）时，响应必须是 403 + errors.errorCode='DATA_SCOPE_DENIED'，
 *   而不是 HTTP 200 + 一份看起来正常的空结果。
 *
 * 为什么 200 + 空集不够（本轮改动的全部理由）：
 *   空集让调用方分不清「这个部门今天没有数据」与「这个账号没有可见范围」，
 *   而这两件事的后续动作相反——前者继续等/换筛选条件，后者去找管理员开权限。
 *   与"宁声明勿假装完整"同族：导出截断要喊（X-Export-Truncated），范围不可用也要喊。
 *
 * 为什么必须到 HTTP 层：服务层用例（dataScopeDenyParity / dataScopeConvergence /
 *   statsScopeFailClosed）证明的是"函数会抛"。本文件证明的是"抛得出的 403 真的
 *   抵达客户端"——中间任何一层 catch 把它折算成 400/404/500 都会让客户端拿到一个
 *   错的语义。实测这类折算真实存在过两处（本轮已修）：
 *     · securityController.getRecentAlerts 的 catch 把 403 包成 500 RECENT_ALERTS_QUERY_FAILED
 *     · reportController.exportReport 的 catch 把 403 包成 400（err.message 原样回）
 *   另有一处死分支（exportReport 里 `dataScope.type === 'none'` ⇒ 回空文件）随之删除。
 *
 * 取证方式：真实 HTTP（supertest）+ 真实 mongod（mongodb-memory-server），
 *   不 mock 数据范围轴——getDataScope 照实从角色 level + user.department 推导。
 *   三个夹具用户分别落在 all / department(有部门) / department(无部门) 三档，
 *   后两档只差 user.department 一个字段，用来证明"拒的是范围，不是人"。
 *
 * 变异验证记录（2026-10-10，逐条改实现 → 跑本套件 → 还原；未变异基线 22 条全绿）：
 *   M1 删掉 applyDataScopeToQuery 里的 `if (isDataScopeDenied) throw` ⇒ 6 红 / 16 绿。
 *      红的 6 条（devices、alarms、alarms/stats、inspections、inspections/stats、users）
 *      正是只靠这一处拦的出口；其余 14 条另有 auditScopeFilter / scopeFilterFor 的
 *      独立预检所以没红——判据抄三处，漏一处只漏一批，不会全站失守。
 *   M2 isDataScopeDenied 对 type:'all' 也返回 true（白名单漏 'all'）⇒ 2 红 / 20 绿：
 *      红的是两条负前提，20 条正向仍绿。这个漏子第一版真实踩到过（rbac.js 有留痕）。
 *   M3 反向：保留 applyDataScopeToQuery 的抛错，摘掉 auditScopeFilter 与
 *      scopeFilterFor 两处预检 ⇒ 14 红 / 8 绿，与 M1 的 6 条正好互补（6+14=20）。
 *      两条负前提在 M1/M3 下都始终绿——它们不依赖任何一处 deny 判据。
 *   M4 errorHandler 丢回 err.code ⇒ 20 红 / 2 绿：statusCode 断言仍过，全部卡在
 *      res.body.errors.errorCode 读不到（客户端回退显示后端中文 message）。
 *   M5 securityController / reportController 的 catch 重新吞掉 ApiError ⇒ 3 红 / 19 绿，
 *      正是 /api/security/alerts 与两条 /api/reports/export。auditController 的那处
 *      catch 不在本次变异范围内，故 /api/security/audit-logs/export 仍绿。
 * ──────────────────────────────────────────────────────────────────────────
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

// 唯一前缀：夹具设备与用户都带它，别的套件的行进不了本次查询结果集
const PREFIX = 'zzdsc';
const stamp = `zzds${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const DEPT = `ZZDSC-A-${stamp}`;
const OTHER_DEPT = `ZZDSC-B-${stamp}`;
const PASSWORD = randomPassword();

/**
 * 全部"按调用者数据范围取数"的读出口。
 * 收口处分布：applyDataScopeToQuery（列表/统计）、scopeFilterFor（报表/设备统计/用户统计）、
 * applyAuditDataScope（审计列表/导出/告警/安全统计）——三处判据同源，落点必须同一形状。
 */
const DENIED_ENDPOINTS = [
  '/api/devices',
  '/api/devices/stats',
  '/api/devices/expiring',
  '/api/devices/reminders',
  '/api/alarms',
  '/api/alarms/stats',
  '/api/inspections',
  '/api/inspections/stats',
  '/api/users',
  '/api/users/stats',
  '/api/reports/dashboard',
  '/api/reports/alarms',
  '/api/reports/devices',
  '/api/reports/inspections',
  '/api/reports/export?type=devices&format=xlsx',
  '/api/reports/export?type=alarms&format=xlsx',
  '/api/security/audit-logs',
  '/api/security/audit-logs/export',
  '/api/security/alerts',
  '/api/security/stats',
];

describe('数据范围不可用的每一条读出口都必须回 403 DATA_SCOPE_DENIED（#12）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let FireDevice;
  let deptUser;
  let noDeptUser;
  let superUser;
  let deptToken;
  let noDeptToken;
  let superToken;

  const sign = (user) =>
    jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');

    // 一个通配权限码覆盖全部读出口：本文件要验的是"数据范围"这一根轴，
    // 不是权限轴。少任何一个码，请求会在 checkPermission 就被 403 拦下，
    // 于是拿到的是一个与数据范围无关的 403（假绿）。
    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );

    const superRole = await Role.create({
      name: `口径deny超管_${stamp}`,
      code: `DSC_SUPER_${stamp}`,
      level: 10,
      permissions: [wildcard._id],
    });
    // level 7 = department 档。两个用户只差 department 一个字段：
    // 有部门的必须照常放行，没部门的必须 403。
    const deptRole = await Role.create({
      name: `口径deny部门_${stamp}`,
      code: `DSC_DEPT_${stamp}`,
      level: 7,
      permissions: [wildcard._id],
    });

    const mk = (name, roleId, department) =>
      User.create({
        username: `${PREFIX}${name}${stamp}`,
        email: `${PREFIX}${name}${stamp}@example.com`,
        password: PASSWORD,
        roles: [roleId],
        tokenVersion: 0,
        ...(department ? { department } : {}),
      });

    superUser = await mk('super', superRole._id);
    deptUser = await mk('dept', deptRole._id, DEPT);
    noDeptUser = await mk('nodept', deptRole._id);
    superToken = sign(superUser);
    deptToken = sign(deptUser);
    noDeptToken = sign(noDeptUser);

    // 两台设备：一台在本部门楼栋、一台在别部门楼栋。
    // 没有它们，"有部门用户照常放行"就只能靠状态码 200 断言，
    // 而 200 + 全零在 deny 修复过度收紧时同样成立（假绿）。
    await FireDevice.create({
      deviceCode: `${PREFIX}-in-${stamp}`,
      deviceName: '烟感_本部门',
      deviceType: 'smoke_detector',
      installDate: new Date('2025-01-01'),
      location: { building: DEPT },
      createdBy: deptUser._id,
    });
    await FireDevice.create({
      deviceCode: `${PREFIX}-out-${stamp}`,
      deviceName: '烟感_别部门',
      deviceType: 'smoke_detector',
      installDate: new Date('2025-01-01'),
      location: { building: OTHER_DEPT },
    });

    app = require('../../app').createApp();
  });

  afterAll(async () => {
    await FireDevice.deleteMany({ deviceCode: new RegExp(`^${PREFIX}-`) }).catch(() => {});
    await User.deleteMany({ username: new RegExp(`^${PREFIX}.*${stamp}$`) }).catch(() => {});
    await Role.deleteMany({ code: new RegExp(`^DSC_.*_${stamp}$`) }).catch(() => {});
    await Permission.deleteOne({ code: '*:*' }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const get = (token, path) => request(app).get(path).set('Authorization', `Bearer ${token}`);

  // ===== 正向：无部门的管理员，每条出口都必须 403 + errorCode =====
  test.each(DENIED_ENDPOINTS)('%s ⇒ 403 DATA_SCOPE_DENIED', async (path) => {
    const res = await get(noDeptToken, path);
    // 状态码与错误码分两条断言：折算成 400/404/500 的任何一层 catch 都会在第一条红，
    // 而 errorHandler 丢掉 err.code 时只有第二条红（M4 的指纹正是如此）。
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.errors.errorCode).toBe('DATA_SCOPE_DENIED');
  });

  // ===== 负前提 1：同一个人补上 department 就必须照常放行 =====
  // 少了这一条，"一律 403"也能让上面全部变绿。
  test('负前提：补上 department 后同一些出口必须 200，且只见本部门设备', async () => {
    const { getDataScope } = require('../../middleware/rbac');
    // 前提自证：两个夹具用户确实只差 department 一个字段
    expect((await getDataScope(String(noDeptUser._id))).type).toBe('department');
    expect((await getDataScope(String(deptUser._id))).department).toBe(DEPT);

    for (const path of ['/api/devices', '/api/devices/stats', '/api/users/stats']) {
      const res = await get(deptToken, path);
      expect(res.status).toBe(200);
    }

    // 200 还不够：必须真的是"本部门的可见集"，不是空集也不是全组织。
    // 序列化后比对，不写死信封形状——信封不是本文件的判据。
    // 用楼栋名而不是 deviceCode 断言：模型上的 deviceCode 有大写化 setter，
    // 拿夹具原值去比会对不上（与判据无关的一次假红）。
    const list = await get(deptToken, '/api/devices');
    expect(JSON.stringify(list.body)).toContain(DEPT);
    expect(JSON.stringify(list.body)).not.toContain(OTHER_DEPT);
  });

  // ===== 负前提 2：all 档（level 10）不得被误伤 =====
  // 这一条专门盯 isDataScopeDenied 的白名单必须含 'all'——
  // 第一版实现漏了它，超管被一律 403，是本轮真实踩到并修掉的漏子。
  test('负前提：all 档超管在同一些出口上必须 200 且看得见两台设备', async () => {
    const { getDataScope } = require('../../middleware/rbac');
    expect((await getDataScope(String(superUser._id))).type).toBe('all');

    for (const path of [
      '/api/devices',
      '/api/devices/stats',
      '/api/users/stats',
      '/api/reports/export?type=devices&format=xlsx',
      '/api/security/audit-logs',
    ]) {
      const res = await get(superToken, path);
      expect(res.status).toBe(200);
    }

    const list = await get(superToken, '/api/devices');
    expect(JSON.stringify(list.body)).toContain(DEPT);
    expect(JSON.stringify(list.body)).toContain(OTHER_DEPT);
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，不关的套件会让
// jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀，强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件自己的
// afterAll 之后才跑（与 reportExportTruncationHeader.test.js 同款）。
afterAll(async () => {
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
