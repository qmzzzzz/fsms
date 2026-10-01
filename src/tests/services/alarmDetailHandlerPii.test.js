/**
 * 报警详情不得回吐处置人手机号（2026-10-01 审计 D-3）
 *
 * 缺陷形状：`AlarmService.getAlarmById` 的 handler populate 比两条列表分支多带一个
 * `phone`，而 `User.phone` 的 getter 会把密文解成明文（models/User.js）——
 * 于是 `GET /api/alarms/:id` 把处置人的**完整手机号**交给任何持 `alarm:read`
 * 且落在该条数据范围内的账号：无二次验证、无 `system:read`、也不写
 * `view_sensitive_data` 审计。而仓里专门为此建的合规通道
 * （POST /api/security/view-sensitive）挂着 reauthLimiter + requireReAuthentication
 * 与层级闸，被这个多出来的 select 整个架空。
 *
 * 本文件的可证伪对：同一条查询、同一个 populate 路径，**只有 select 列表不同**——
 * 带 phone 时确实拿得到明文（证明"详情里没有 phone"是 select 收窄的结果，
 * 而不是 populate 静默丢字段、或夹具根本没写手机号）。
 */

const mongoose = require('mongoose');

describe('报警详情的处置人字段口径', () => {
  let FireAlarm;
  let User;
  let service;
  let alarmId;
  let handler;
  const stamp = `adhp${String(Date.now()).slice(-8)}`;
  const HANDLER_PHONE = '13800138000';

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../../models/FireAlarm');
    User = require('../../models/User');
    service = require('../../services/AlarmService');

    handler = await User.create({
      username: `h_${stamp}`,
      email: `h-${stamp}@example.com`,
      password: `P@ssw0rd-${stamp}`,
      realName: '处置员甲',
      phone: HANDLER_PHONE,
      status: 'active',
      roles: [],
    });

    const alarm = await FireAlarm.create({
      alarmType: 'smoke',
      description: `${stamp} 地下室烟感报警`,
      reporter: { userId: new mongoose.Types.ObjectId() },
      handler: handler._id,
    });
    alarmId = String(alarm._id);
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await User.deleteMany({ username: new RegExp(`^h_${stamp}$`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('夹具自证：手机号确实写进去了，且带 phone 选择时详情查询会给出明文', async () => {
    // 这条是"对侧"证据：没有它，下面的 not.toContain 可能只是因为
    // populate 根本没生效、或手机号压根没入库。
    const withPhone = await FireAlarm.findById(alarmId).populate({
      path: 'handler',
      select: 'username realName phone',
    });
    expect(String(withPhone.handler.phone)).toBe(HANDLER_PHONE);
    expect(JSON.stringify(withPhone.toJSON())).toContain(HANDLER_PHONE);
  });

  test('详情：handler 只有 username/realName，序列化后全文不含手机号', async () => {
    const detail = await service.getAlarmById(alarmId);
    const json = JSON.stringify(detail.toJSON());

    expect(detail.handler.username).toBe(handler.username);
    expect(detail.handler.realName).toBe('处置员甲');
    expect(detail.handler.phone).toBeUndefined();
    expect(json).not.toContain(HANDLER_PHONE);
  });

  test('列表与详情同口径（两条分支都不该多带 PII）', async () => {
    const { alarms } = await service.getAlarms({
      page: 1,
      limit: 50,
      search: stamp,
      dataScope: { type: 'all' },
    });
    expect(alarms.length).toBeGreaterThan(0);
    for (const alarm of alarms) {
      if (String(alarm._id) !== alarmId) continue;
      expect(alarm.handler.phone).toBeUndefined();
      expect(JSON.stringify(alarm.toJSON())).not.toContain(HANDLER_PHONE);
    }
  });

  test('游标分页分支同样不带手机号（列表有两条分支，只修一条等于没修）', async () => {
    const first = await service.getAlarms({
      page: 1,
      limit: 1,
      dataScope: { type: 'all' },
      search: stamp,
    });
    const cursor = first.nextCursor || null;
    const next = await service.getAlarms({
      cursor,
      limit: 5,
      dataScope: { type: 'all' },
      search: stamp,
    });
    const all = [...first.alarms, ...next.alarms].filter(
      (a) =>
        String(a._id) === alarmId || String(a.handler?._id || a.handler) === String(handler._id)
    );
    expect(all.length).toBeGreaterThan(0);
    for (const alarm of all) expect(alarm.handler.phone).toBeUndefined();
  });

  test('源码文本闸：AlarmService 里 handler 的 select 只许一处口径', () => {
    // 判据落在源码而非只有一次运行结果：将来谁再把 phone 加回**其中一条**分支，
    // 上面三条用例可能因为都恰好走了另一条分支而全绿，这条不会。
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(
      path.join(__dirname, '..', '..', 'services', 'AlarmService.js'),
      'utf8'
    );
    const selects = [...src.matchAll(/path:\s*'handler',\s*select:\s*'([^']+)'/g)].map((m) => m[1]);
    expect(selects.length).toBeGreaterThanOrEqual(3); // 两条列表分支 + 详情
    for (const s of selects) expect(s).not.toMatch(/\bphone\b/);
  });
});
