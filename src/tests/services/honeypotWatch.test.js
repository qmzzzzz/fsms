/**
 * 蜜罐账户端到端：物化 → 诱饵登录放行 → 审计/告警留痕 → 枚举面排除 → 哨兵对账口径
 *
 * 与既有测试的分工：
 *  - tests/constants/honeypotAccounts.test.js 测名单与判据（不连库）；
 *  - tests/ci/honeypotExclusionLedger.test.js 静态钉住「枚举面必须排除」的接线；
 *  - 本文件测**行为**：真实库里的诱饵账户、loginUser 主流程的接线、审计行与告警、
 *    以及哨兵遮蔽对账在「蜜罐占用哨兵名」下的口径（那是有意接管，不是遮蔽）。
 *
 * 边界覆盖：
 *  - 诱饵名已被真实账户占用 ⇒ 拒绝接管（绝不把真实账户打标成蜜罐）；
 *  - 重复 init 幂等（不重复建号）；
 *  - 非诱饵口令走**既有**失败路径（计数/审计/401 口径不变），不留 honeypot_login 审计；
 *  - 总开关关闭 ⇒ 即使库里有标志位账户也不放行（fail-closed，不是 fail-open）；
 *  - 开了 MFA 的标志位账户不走诱饵旁路（不制造绕过二段的路径）。
 */

'use strict';

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { DECOY_PERMISSIONS, DECOY_ROLE_CODES } = require('../../constants/honeypotDecoy');
const { DECOY_SELF_EMAIL_DOMAIN } = require('../../constants/honeypotDecoySelf');
const { PERSONA_DEPARTMENTS } = require('../../constants/honeypotPersonas');

describe('蜜罐账户（honeypot）：物化、诱饵登录与枚举面排除', () => {
  const stamp = ('hpt' + Date.now()).replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const honeypotName = stamp + 'trap';
  const secondDecoy = stamp + 'trap2';
  const realName = stamp + 'real';
  const saved = {};

  let User;
  let AuditLog;
  let honeypotWatch;
  let securityAlert;
  let authService;
  let userService;
  let canaryWatch;
  let dispatchSpy;

  const ctx = (ip) => ({
    ip,
    userAgent: 'test-agent',
    fingerprint: 'fp-honeypot',
    method: 'POST',
    path: '/api/auth/login',
    req: { headers: { 'user-agent': 'test-agent' }, ip, connection: {} },
  });

  const setEnv = (key, value) => {
    if (!(key in saved)) saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  };

  const honeypotAuditRows = (name) =>
    AuditLog.countDocuments({ action: 'honeypot_login', username: name });
  const honeypotDispatches = () =>
    dispatchSpy.mock.calls.filter((call) => call[0] === 'honeypot_login');

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    require('../../models/User');
    require('../../models/TokenBlacklist');
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    honeypotWatch = require('../../services/honeypotWatch');
    securityAlert = require('../../services/securityAlert');
    authService = require('../../services/authService');
    userService = require('../../services/userService');
    canaryWatch = require('../../services/canaryWatch');
    setEnv('HONEYPOT_ENABLED', 'true');
    setEnv('HONEYPOT_USERNAMES', honeypotName);
  });

  afterAll(async () => {
    await mongoose.connection
      .collection('auditlogs')
      .deleteMany({ action: 'honeypot_login' })
      .catch(() => {});
    await mongoose.connection
      .collection('auditlogs')
      .deleteMany({ username: new RegExp('^' + stamp) })
      .catch(() => {});
    const created = await User.find({ username: new RegExp('^' + stamp) })
      .select('_id')
      .lean()
      .catch(() => []);
    if (created.length > 0) {
      const ids = created.map((doc) => doc._id);
      await mongoose.connection
        .collection('usersessions')
        .deleteMany({ userId: { $in: ids } })
        .catch(() => {});
    }
    await User.deleteMany({ username: new RegExp('^' + stamp) }).catch(() => {});
    for (const [key, value] of Object.entries(saved)) setEnv(key, value);
    honeypotWatch.__resetForTest();
    canaryWatch.__resetForTest();
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  beforeEach(() => {
    dispatchSpy = jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
  });

  afterEach(() => {
    dispatchSpy.mockRestore();
  });

  test('init 物化诱饵账户：标志位 true、零角色、active、口令无人知晓', async () => {
    honeypotWatch.__resetForTest();
    await honeypotWatch.init();
    const doc = await User.findByUsername(honeypotName).select('+password');
    expect(doc).toBeTruthy();
    expect(doc.isHoneypot).toBe(true);
    expect(doc.status).toBe('active');
    expect(doc.roles).toEqual([]);
    expect(doc.phone).toBeFalsy();
    expect(doc.mustChangePassword).toBe(false);
    expect(doc.mfaEnabled).toBe(false);
    expect(doc.password).toBeTruthy(); // 存了一份真随机口令，诱饵判据不看它
    // 画像差异化（P1e）：物化时写入派生画像，不再是全员同一个「运维管理员」
    expect(doc.realName).not.toBe('运维管理员');
    expect(doc.realName).toBeTruthy();
    expect(doc.department).toBeTruthy();
    expect(PERSONA_DEPARTMENTS).toContain(doc.department);
    expect(doc.email).toBe(honeypotName + '@honeypot.invalid'); // 域名不变：保留「导出/备份一眼可辨」的声明面
    const status = honeypotWatch.getStatus();
    expect(status).toMatchObject({ enabled: true, checked: true, fromEnv: true, nameCount: 1 });
    expect(status.provisioned).toContain(honeypotName);
    expect(status.configErrors).toEqual([]);
  });

  test('重复 init 幂等：第二次是「沿用已存在」，不重复建号', async () => {
    honeypotWatch.__resetForTest();
    await honeypotWatch.init();
    expect(await User.countDocuments({ username: honeypotName, isHoneypot: true })).toBe(1);
    const status = honeypotWatch.getStatus();
    expect(status.skipped).toContain(honeypotName);
    expect(status.provisioned).not.toContain(honeypotName);
  });

  test('画像差异化：两个诱饵互不撞名，重复 init 不改名（同名恒同画像）', async () => {
    setEnv('HONEYPOT_USERNAMES', honeypotName + ',' + secondDecoy);
    honeypotWatch.__resetForTest();
    await honeypotWatch.init();
    const first = await User.findByUsername(honeypotName);
    const second = await User.findByUsername(secondDecoy);
    expect(second).toBeTruthy();
    expect(second.isHoneypot).toBe(true);
    expect(second.realName).not.toBe(first.realName);
    expect(second.department).toBeTruthy();
    const before = first.realName + '|' + first.department;
    honeypotWatch.__resetForTest();
    await honeypotWatch.init();
    const again = await User.findByUsername(honeypotName);
    expect(again.realName + '|' + again.department).toBe(before);
    await User.deleteMany({ username: secondDecoy }); // 后面的计数用例要求库里只剩本套件的 1 个诱饵账户
    setEnv('HONEYPOT_USERNAMES', honeypotName);
    honeypotWatch.__resetForTest();
  });

  test('诱饵名被真实账户占用：拒绝接管并报错，真实账户不得被打标', async () => {
    await User.create({
      username: realName,
      email: realName + '@example.com',
      password: 'Zz9!kLm3#Tuv7',
      realName: '真实用户',
      roles: [],
    });
    setEnv('HONEYPOT_USERNAMES', realName);
    honeypotWatch.__resetForTest();
    await honeypotWatch.init();
    const status = honeypotWatch.getStatus();
    expect(status.configErrors.join(' ')).toContain('已被真实账户占用');
    expect(status.provisioned).toEqual([]);
    const occupied = await User.findByUsername(realName);
    expect(occupied.isHoneypot).not.toBe(true);
    setEnv('HONEYPOT_USERNAMES', honeypotName);
  });

  test('诱饵口令命中：按成功路径放行（零角色会话）+ 审计 + 告警一次；重复登录审计逐条、告警仍一次', async () => {
    const result = await authService.loginUser(
      { username: honeypotName, password: 'admin@123456' },
      ctx('10.30.0.1')
    );
    expect(result.outcome).toBe('OK');
    expect(result.token).toBeTruthy();
    expect(result.user.roles).toEqual([...DECOY_ROLE_CODES]);
    expect(result.user.permissions).toEqual([...DECOY_PERMISSIONS]);

    const row = await AuditLog.findOne({ action: 'honeypot_login', username: honeypotName }).lean();
    expect(row).toBeTruthy();
    expect(row.category).toBe('auth');
    expect(row.riskLevel).toBe('critical');
    expect(row.success).toBe(true);
    expect(row.ip).toBe('10.30.0.1');
    expect(row.body.honeypot).toBe(honeypotName);
    expect(honeypotDispatches()).toHaveLength(1);
    expect(honeypotDispatches()[0][1]).toBe('critical');
    expect(honeypotDispatches()[0][3].honeypot).toBe(honeypotName);

    await authService.loginUser({ username: honeypotName, password: 'P@ssw0rd' }, ctx('10.30.0.2'));
    expect(await honeypotAuditRows(honeypotName)).toBe(2);
    expect(honeypotDispatches()).toHaveLength(1);
  });

  test('签署声明：令牌载荷里的 email/roles 是呈现层那份（登录与续期两条签发点同一口径）', async () => {
    const login = await authService.loginUser(
      { username: honeypotName, password: 'admin@123456' },
      ctx('10.30.0.5')
    );
    expect(login.outcome).toBe('OK');
    const access = jwt.decode(login.token);
    // 载荷可被客户端解码：@honeypot.invalid 与零角色等于在令牌里自报家门
    expect(access.email).toBe(honeypotName + '@' + DECOY_SELF_EMAIL_DOMAIN);
    expect(access.roles).toEqual([...DECOY_ROLE_CODES]);

    const refreshed = await authService.refreshSession(login.refreshToken, ctx('10.30.0.6'));
    expect(refreshed.outcome).toBe('OK');
    const rotated = jwt.decode(refreshed.token);
    expect(rotated.email).toBe(honeypotName + '@' + DECOY_SELF_EMAIL_DOMAIN); // 续期不重签呈现声明 ⇒ 一次刷新就退回 honeypot.invalid
    expect(rotated.roles).toEqual([...DECOY_ROLE_CODES]);
    expect(rotated.sid).toBe(access.sid); // 轮换继承同一个 sid（呈现层不改变可吊销性）

    const plainName = stamp + 'plain'; // 与"诱饵名被真实账户占用"那条用例的真实账户区分开（那条的账户留在库里给计数用例当底数）
    const real = await User.create({
      username: plainName,
      email: plainName + '@example.com',
      password: 'Zz9!kLm3#Tuv7',
      realName: '真实用户',
      roles: [],
    });
    const realLogin = await authService.loginUser(
      { username: real.username, password: 'Zz9!kLm3#Tuv7' },
      ctx('10.30.0.7')
    );
    expect(realLogin.outcome).toBe('OK');
    const realAccess = jwt.decode(realLogin.token);
    expect(realAccess.email).toBe(real.email); // 非诱饵会话原样透传：呈现层不得改动真实账户
    expect(realAccess.roles).toEqual([]);
    await User.deleteOne({ _id: real._id });
  });

  test('非诱饵口令：走既有失败路径（401 口径不变），且不留 honeypot_login 审计', async () => {
    const before = await honeypotAuditRows(honeypotName);
    const result = await authService.loginUser(
      { username: honeypotName, password: 'Zz9!kLm3#Tuv7' },
      ctx('10.30.0.3')
    );
    expect(result.outcome).toBe('INVALID_CREDENTIALS');
    expect(result.token).toBeUndefined();
    expect(await honeypotAuditRows(honeypotName)).toBe(before);
  });

  test('总开关关闭：库里有标志位账户也不放行（fail-closed）', async () => {
    setEnv('HONEYPOT_ENABLED', 'false');
    const result = await authService.loginUser(
      { username: honeypotName, password: 'admin@123456' },
      ctx('10.30.0.4')
    );
    expect(result.outcome).toBe('INVALID_CREDENTIALS');
    setEnv('HONEYPOT_ENABLED', 'true');
  });

  test('诱饵旁路不覆盖 MFA：开了二段的标志位账户不会被口令直接放行', () => {
    const account = { isHoneypot: true, mfaEnabled: true };
    expect(honeypotWatch.isLureLogin(account, 'admin@123456')).toBe(false);
    expect(honeypotWatch.isLureLogin({ isHoneypot: true }, 'admin@123456')).toBe(true);
    expect(honeypotWatch.isLureLogin({ isHoneypot: false }, 'admin@123456')).toBe(false);
    expect(honeypotWatch.isLureLogin(undefined, 'admin@123456')).toBe(false);
    expect(honeypotWatch.isLureLogin({ isHoneypot: true }, 'Zz9!kLm3#Tuv7')).toBe(false);
  });

  test('枚举面排除：用户列表、计数与统计聚合都看不到诱饵账户', async () => {
    const { roleFound, query } = await userService.buildListQuery(
      { search: stamp },
      { type: 'all' }
    );
    expect(roleFound).toBe(true);
    const { users, count } = await userService.listUsers(query, { createdAt: -1 }, 1, 50);
    expect(users.map((u) => u.username)).not.toContain(honeypotName);
    expect(users.map((u) => u.username)).toContain(realName);
    const expected = await User.countDocuments({
      username: new RegExp('^' + stamp),
      isHoneypot: { $ne: true },
    });
    expect(count).toBe(expected);
    expect(await User.countDocuments({ username: new RegExp('^' + stamp) })).toBe(expected + 1);

    const stats = await userService.aggregateStats([
      { $match: { username: new RegExp('^' + stamp) } },
      { $count: 'count' },
    ]);
    expect(stats).toHaveLength(1);
    expect(stats[0].count).toBe(expected);
  });

  test('哨兵对账口径：蜜罐占用哨兵名不算遮蔽，真实账户占用才算', async () => {
    setEnv('CANARY_USERNAMES', honeypotName);
    canaryWatch.__resetForTest();
    await canaryWatch.init();
    expect(canaryWatch.getStatus().shadowed).toEqual([]);

    setEnv('CANARY_USERNAMES', realName);
    canaryWatch.__resetForTest();
    await canaryWatch.init();
    expect(canaryWatch.getStatus().shadowed).toEqual([realName]);
    setEnv('CANARY_USERNAMES', saved.CANARY_USERNAMES);
    canaryWatch.__resetForTest();
  });
});
