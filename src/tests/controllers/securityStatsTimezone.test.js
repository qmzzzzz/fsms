/**
 * getSecurityStats「今日」起点口径回归测试（时区分叉修复）
 *
 * 修复背景：今日统计起点此前用 new Date(now.setHours(0,0,0,0))
 * （服务器本地时区零点，容器 TZ=Asia/Shanghai 时碰巧正确，裸跑/改 TZ
 * 即漂移），与 P3-18 业务时区声明存在分叉隐患。现统一为
 * businessDayBounds().start，与仪表盘/报表/告警频控的「今日」同源。
 *
 * 锁定方式：把 businessDayBounds mock 为已知窗口（北京 2026-09-02 00:00
 * 对应的 UTC 瞬间），在窗口边界各插一条登录记录——
 *   - timestamp === start（业务时区今日零点整）→ 必须计入
 *   - timestamp === start - 1ms（业务时区昨日最后一毫秒）→ 必须排除
 * 若回退为本地/UTC 零点口径（CI 默认 UTC 时区），下界会错位一天，
 * 今日计数变成 0 或 2，本测试即红。
 */

jest.mock('../../constants/timezone', () => ({
  ...jest.requireActual('../../constants/timezone'),
  businessDayBounds: jest.fn(),
}));

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const timezone = require('../../constants/timezone');

// 业务时区（Asia/Shanghai）2026-09-02 00:00:00.000 对应的 UTC 瞬间
const BUSINESS_DAY_START = new Date('2026-09-01T16:00:00.000Z');

describe('getSecurityStats 今日起点口径（时区分叉修复回归）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let AuditLog;
  let superToken;
  const stamp = `tz${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();
  const USERNAME = `tzsuper${stamp}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    AuditLog = require('../../models/AuditLog');

    // 把「今日」固定为已知业务时区窗口（真实实现依赖当前时钟，无法稳定构造边界）
    timezone.businessDayBounds.mockReturnValue({
      start: BUSINESS_DAY_START,
      end: new Date(BUSINESS_DAY_START.getTime() + 24 * 60 * 60 * 1000 - 1),
      dateStr: '2026-09-02',
    });

    const wildcardPerm = await Permission.findOneAndUpdate(
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
        permissions: [wildcardPerm._id],
      });
    }
    const superUser = await User.create({
      username: USERNAME,
      email: `${USERNAME}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superToken = jwt.sign(
      { userId: String(superUser._id), username: superUser.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    const { createApp } = require('../../app');
    app = createApp();

    // 今日窗口边界各插一条成功登录（文件级独立空库，无其他 login_success 干扰）
    const actorId = String(superUser._id);
    await AuditLog.insertMany([
      {
        action: 'login_success',
        category: 'auth',
        username: USERNAME,
        userId: actorId,
        ip: '203.0.113.77',
        success: true,
        riskLevel: 'low',
        timestamp: new Date(BUSINESS_DAY_START.getTime()), // 业务时区今日零点整 → 计入
      },
      {
        action: 'login_success',
        category: 'auth',
        username: USERNAME,
        userId: actorId,
        ip: '203.0.113.77',
        success: true,
        riskLevel: 'low',
        timestamp: new Date(BUSINESS_DAY_START.getTime() - 1), // 昨日最后一毫秒 → 排除
      },
    ]);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: USERNAME }).catch(() => {});
      await AuditLog.deleteMany({ username: USERNAME }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('今日登录统计的查询下界精确等于业务时区零点（含 start、排除昨日末毫秒）', async () => {
    const res = await request(app)
      .get('/api/security/stats')
      .set('Authorization', `Bearer ${superToken}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // 接线验证：统计必须经 businessDayBounds 取今日起点（而非本地 setHours）。
    // 断言放在请求之后——调用发生在 handler 执行期。
    expect(timezone.businessDayBounds).toHaveBeenCalled();

    // 两条边界记录只有「今日零点整」一条落入窗口；
    // 回退旧口径（CI 的 UTC 时区下）会把下界错位一天，计数变 0 或 2
    expect(res.body.data.overview.todayLogins).toBe(1);
  });
});
