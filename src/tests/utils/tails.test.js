/**
 * 尾差覆盖（冲 95% 批次 F）
 *
 * 纯函数与模型直驱：rbac 数据范围分支、helpers/ipUtils/ipRange/totp/mfaSecret/
 * cookie/fingerprint 尾差、apiResponse.codeError、User/SystemConfig/Role/
 * FireDevice/IPBlacklist/AuditLog 模型尾差、loginCipher 自动生成路径、
 * httpPostJson 非法 URL、wellKnown 路由。
 */

const request = require('supertest');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('尾差覆盖（批次 F）', () => {
  let User;
  let Role;
  let Permission;
  let FireDevice;
  let IPBlacklist;
  let AuditLog;
  let adminUserId;
  const stamp = `f${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    FireDevice = require('../../models/FireDevice');
    IPBlacklist = require('../../models/IPBlacklist');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_批次F',
      code: `SUPER_ADMIN_F_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `fadmin${stamp}`,
      email: `fadmin${stamp}@example.com`,
      password: PASSWORD,
      roles: [superRole._id],
    });
    adminUserId = String(admin._id);

    const { createApp } = require('../../app');
    global.__fapp = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteOne({ username: `fadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_F_${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `RB_${stamp}` }).catch(() => {});
      await FireDevice.deleteMany({ deviceCode: new RegExp(`^F-${stamp}`) }).catch(() => {});
      await IPBlacklist.deleteMany({ ip: '203.0.113.77' }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  // ================= rbac 数据范围分支 =================

  test('rbac：applyDataScopeToQuery 全分支（直驱，返回布尔+原地改写 query）', () => {
    const { applyDataScopeToQuery } = require('../../middleware/rbac');
    const FIELDS = { ownerField: 'createdBy', departmentField: 'department' };

    // all：true 且不加过滤
    const qAll = {};
    expect(applyDataScopeToQuery(qAll, { type: 'all' }, FIELDS)).toBe(true);
    expect(qAll).toEqual({});

    // department / self：true 且注入过滤
    const qDept = {};
    expect(applyDataScopeToQuery(qDept, { type: 'department', department: '安保部' }, FIELDS)).toBe(
      true
    );
    expect(JSON.stringify(qDept)).toContain('安保部');

    const qSelf = {};
    expect(applyDataScopeToQuery(qSelf, { type: 'self', userId: 'u1' }, FIELDS)).toBe(true);
    expect(JSON.stringify(qSelf)).toContain('u1');

    // deny 分支：false
    expect(applyDataScopeToQuery({}, { type: 'none' }, FIELDS)).toBe(false);
    expect(applyDataScopeToQuery({}, { type: 'mystery' }, FIELDS)).toBe(false);
    expect(applyDataScopeToQuery({}, { type: 'department', department: '' }, FIELDS)).toBe(false);
    expect(applyDataScopeToQuery({}, { type: 'self' }, FIELDS)).toBe(false);
    expect(applyDataScopeToQuery({}, null, FIELDS)).toBe(false);
  });

  // ================= helpers 尾差 =================

  test('helpers：escapeHtml / sanitizeSpreadsheetCell / normalizePagination / validateEnum', () => {
    const helpers = require('../../utils/helpers');

    expect(helpers.escapeHtml('<img src=x>')).toContain('&lt;img');

    expect(helpers.sanitizeSpreadsheetCell('=cmd')).toBe("'=cmd");
    expect(helpers.sanitizeSpreadsheetCell('+1')).toBe("'+1");
    expect(helpers.sanitizeSpreadsheetCell('-1')).toBe("'-1");
    expect(helpers.sanitizeSpreadsheetCell('@x')).toBe("'@x");
    expect(helpers.sanitizeSpreadsheetCell('normal')).toBe('normal');
    expect(helpers.sanitizeSpreadsheetCell(null)).toBeNull();

    const p1 = helpers.normalizePagination('0', '99999');
    expect(p1.page).toBe(1);
    expect(p1.limit).toBeLessThanOrEqual(500);

    expect(helpers.validateEnum('a', ['a', 'b'])).toBe('a');
    // 非法枚举是抛错语义（err.status=400），不是返回哨兵值
    expect(() => helpers.validateEnum('c', ['a', 'b'])).toThrow();

    expect(helpers.isBreachedPassword(randomPassword())).toBe(false);
  });

  // ================= totp / mfaSecret / cookie / fingerprint 尾差 =================

  test('totp：base32Decode 空串抛错', () => {
    const { base32Decode } = require('../../utils/totp');
    expect(() => base32Decode('')).toThrow();
    expect(() => base32Decode(null)).toThrow();
  });

  test('cookie：parseCookies 边界', () => {
    const { parseCookies } = require('../../utils/cookie');
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies('garbage')).toEqual({});
    expect(parseCookies('a=1; b=%E4%B8%AD')).toEqual({ a: '1', b: '中' });
    expect(parseCookies('=novalue; x=2')).toEqual({ x: '2' });
  });

  test('fingerprint：computeFingerprint 对同输入稳定', () => {
    const { computeFingerprint } = require('../../utils/fingerprint');
    const req = { headers: { 'user-agent': 'UA-1', 'accept-language': 'zh-CN' }, ip: '1.2.3.4' };
    expect(computeFingerprint(req)).toBe(computeFingerprint(req));
  });

  // ================= 模型尾差 =================

  test('User：comparePassword 非字符串收敛为 false', async () => {
    const u = await User.findById(adminUserId).select('+password');
    expect(await u.comparePassword(12345)).toBe(false);
    expect(await u.comparePassword(null)).toBe(false);
    expect(await u.comparePassword(PASSWORD)).toBe(true);
  });

  test('Role：内置角色 findOneAndDelete 保护（模型层）', async () => {
    // ADMIN 码触发 pre-save 强制 isBuiltIn（unique 索引下先查后建）
    let adminRole = await Role.findOne({ code: 'ADMIN' });
    if (!adminRole) {
      adminRole = await Role.create({ name: '管理员', code: 'ADMIN', level: 8 });
    }
    await expect(Role.findOneAndDelete({ _id: adminRole._id })).rejects.toThrow();
  });

  test('FireDevice：transitionTo 状态机（合法迁移 + 非法回退拒绝）+ 报废后维护拒绝', async () => {
    const now = Date.now();
    const dev = await FireDevice.create({
      deviceCode: `F-${stamp}-T1`,
      deviceName: '迁移测试',
      deviceType: 'hydrant',
      status: 'normal',
      installDate: new Date(now),
      location: { building: 'F栋' },
      lifecycleStage: 'installed',
    });
    // lifecycleStage 迁移表：installed → in_use 合法；回退 installed 非法
    // （transitionTo 为同步校验，非法迁移同步抛错）
    await dev.transitionTo('in_use');
    expect(dev.lifecycleStage).toBe('in_use');
    expect(() => dev.transitionTo('installed')).toThrow();

    // in_use → scrapped 后无出口迁移
    await dev.transitionTo('scrapped');
    expect(() => dev.transitionTo('in_use')).toThrow();
  });

  test('IPBlacklist：blockIP/unblockIP/isWhitelisted', async () => {
    const block = await IPBlacklist.blockIP('203.0.113.77', {
      durationMs: 3600000,
      reason: '批次F测试',
      source: 'manual',
      type: 'black',
    });
    expect(block).toBeTruthy();
    expect(await IPBlacklist.isBlocked('203.0.113.77')).toBe(true);
    expect(await IPBlacklist.isWhitelisted('203.0.113.77')).toBe(false);

    // 解封后立即不再拦截
    await IPBlacklist.unblockIP('203.0.113.77', 'black');
    expect(await IPBlacklist.isBlocked('203.0.113.77')).toBe(false);
  });

  test('AuditLog：getUserActivity 返回脱敏结构（不含 hmac）', async () => {
    await AuditLog.create({
      action: 'login_success',
      category: 'auth',
      username: `fadmin${stamp}`,
      userId: adminUserId,
      ip: '203.0.113.250',
      success: true,
      hmac: 'should-not-leak',
    });
    const logs = await AuditLog.getUserActivity(adminUserId, 10);
    expect(Array.isArray(logs)).toBe(true);
    for (const log of logs) {
      expect(log.hmac).toBeUndefined();
    }
  });

  // ================= loginCipher / httpPostJson 尾差 =================

  test('loginCipher：未配置密钥时自动生成临时密钥对（test 环境）', () => {
    const cipher = require('../../utils/loginCipher');
    const saved = process.env.LOGIN_ECDH_PRIVATE_KEY;
    delete process.env.LOGIN_ECDH_PRIVATE_KEY;
    cipher._resetForTests();
    const info = cipher.getPublicKeyInfo();
    expect(info.publicKey).toMatch(/BEGIN PUBLIC KEY/);
    expect(info.curve).toBe('P-256');
    cipher._resetForTests();
    if (saved !== undefined) process.env.LOGIN_ECDH_PRIVATE_KEY = saved;
    else delete process.env.LOGIN_ECDH_PRIVATE_KEY;
  });

  test('httpPostJson：非法 URL 拒绝', async () => {
    const { postJson } = require('../../utils/httpPostJson');
    await expect(postJson('not-a-url', {}, '{}')).rejects.toThrow();
  });

  // ================= wellKnown 路由尾差 =================

  test('well-known：security.txt 端点', async () => {
    const app = global.__fapp;
    const txt = await request(app).get('/.well-known/security.txt');
    expect(txt.status).toBe(200);
    expect(txt.text).toContain('Contact');
  });
});
