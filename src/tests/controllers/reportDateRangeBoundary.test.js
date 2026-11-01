/**
 * 报表/列表日期参数的三个边界：反向区间、趋势窗口、数字形态串
 *
 * 三条缺陷都是"返回 200 + 看起来正常的结果"，没有任何错误信号：
 *  1) 反向区间（startDate > endDate）：控制器只校验单值格式，不校验先后 ⇒
 *     \$gte 晚于 \$lte 恒不命中，五个出口一律 200 + 空集（导出则是 2 字节的空表）。
 *     本仓既有判例在 utils/auditQuery.js：同一形状必须显式拒绝。
 *  2) 报警报表的 byDay 分支丢了 matchStage 且没有上界 ⇒ 选了日期区间后趋势图仍是
 *     "近 30 天"，且未来时刻的记录会进趋势图（仪表盘「今日」同病：只 \$gte 不 \$lte）。
 *  3) isValidDateParam 的"纯数字串"闸门只认 ^\d+\$ ⇒ '-1' / '+2026' / '1.5' / '.5'
 *     被 Date 解析成 2000/2001 年的窄窗口，报表出口静默返回空表。
 *
 * 判据形态：每条都做**内容级**断言（分组结果 / 精确计数 / 状态码+错误码成对），
 * 只断 200 无法证伪——把过滤器删掉同样返回 200。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { businessDayBounds, businessDateParts } = require('../../constants/timezone');
const { isValidDateParam, isDateRangeReversed } = require('../../utils/helpers');

const DAY_MS = 24 * 60 * 60 * 1000;

describe('日期参数边界：反向区间 / 趋势窗口 / 数字形态串', () => {
  let app;
  let FireAlarm;
  let token;
  let adminId;
  const stamp = `drb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const createdIds = [];

  const as = (method, url) => request(app)[method](url).set('Authorization', `Bearer ${token}`);
  const get = (url) => as('get', url);
  const errorCodeOf = (res) => res.body?.errors?.errorCode || null;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    FireAlarm = require('../../models/FireAlarm');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const role = await Role.create({
      name: `日期边界超管_${stamp}`,
      code: `DATE_BOUND_SUPER_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcard._id],
    });
    const admin = await User.create({
      username: `datebound${stamp}`,
      email: `datebound${stamp}@example.com`,
      password: randomPassword(),
      roles: [role._id],
    });
    adminId = String(admin._id);
    token = jwt.sign(
      { userId: adminId, username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    // 数据范围 all：三个用例都要读全库计数，不能只看自己那条种子
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    for (const id of createdIds) {
      await FireAlarm.deleteOne({ _id: id }).catch(() => {});
    }
    const User = require('../../models/User');
    const Role = require('../../models/Role');
    await User.deleteOne({ _id: adminId }).catch(() => {});
    await Role.deleteOne({ code: `DATE_BOUND_SUPER_${stamp}` }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const seedAlarm = async (occurredAt, note) => {
    const doc = await FireAlarm.create({
      alarmType: 'other',
      level: 'warning',
      description: `日期边界_${note}_${stamp}`,
      status: 'resolved',
      occurredAt,
      receivedAt: occurredAt,
      reporter: { name: `rb${stamp}` },
      processLog: [{ time: occurredAt, action: 'alarm_received', remark: 'x' }],
    });
    createdIds.push(doc._id);
    return doc;
  };

  // ==================== ① 反向区间 ====================

  describe('① startDate > endDate 必须显式 400（不得静默返回空集）', () => {
    // 五个控制器出口 + 导出：每行都是"之前 200 + 空结果"的真实形状
    const REVERSED = 'startDate=2026-01-31&endDate=2026-01-01';
    const FORWARD = 'startDate=2026-01-01&endDate=2026-01-31';
    const sites = [
      ['报警报表', '/api/reports/alarms'],
      ['设备报表', '/api/reports/devices'],
      ['巡检报表', '/api/reports/inspections'],
      ['报警列表', '/api/alarms'],
      ['报警统计', '/api/alarms/stats'],
      ['巡检列表', '/api/inspections'],
      ['巡检统计', '/api/inspections/stats'],
      ['报表导出', '/api/reports/export?type=alarms'],
    ];

    test.each(sites)(
      '%s：反向 400 + DATE_RANGE_INVALID，正向仍 200（防"一律 400"）',
      async (_n, url) => {
        const sep = url.includes('?') ? '&' : '?';
        const bad = await get(`${url}${sep}${REVERSED}`);
        expect({ status: bad.status, code: errorCodeOf(bad) }).toEqual({
          status: 400,
          code: 'DATE_RANGE_INVALID',
        });
        const ok = await get(`${url}${sep}${FORWARD}`);
        expect(ok.status).toBe(200);
      }
    );

    test('只给一侧时不做先后比较（单边筛选是合法用法）', async () => {
      for (const q of ['startDate=2026-01-31', 'endDate=2026-01-01']) {
        expect((await get(`/api/reports/alarms?${q}`)).status).toBe(200);
        expect((await get(`/api/alarms?${q}`)).status).toBe(200);
      }
    });

    test('判据本身：同日不算反向，跨日才算；缺一侧恒 false', () => {
      expect(isDateRangeReversed('2026-01-31', '2026-01-31')).toBe(false);
      expect(isDateRangeReversed('2026-01-31', '2026-01-01')).toBe(true);
      expect(isDateRangeReversed('2026-01-01', '2026-01-31')).toBe(false);
      expect(isDateRangeReversed('2026-01-31', undefined)).toBe(false);
      expect(isDateRangeReversed(undefined, '2026-01-01')).toBe(false);
      // 同日带时间的边界：结束当天 00:00 早于开始当天 23:59 才算反向
      expect(isDateRangeReversed('2026-01-01T23:00', '2026-01-01T01:00')).toBe(true);
      expect(isDateRangeReversed('2026-01-01T01:00', '2026-01-01T23:00')).toBe(false);
    });
  });

  // ==================== ② 趋势窗口 ====================

  describe('② byDay 必须跟随请求区间并封上界；仪表盘「今日」必须有下界+上界', () => {
    // 区间内 / 区间外但在近 30 天内 / 未来 40 天（旧实现会把后者数进趋势图）
    const inWindow = new Date('2026-01-15T03:00:00.000Z');
    const outsideWindow = new Date();
    const future = new Date(Date.now() + 40 * DAY_MS);

    beforeAll(async () => {
      await seedAlarm(inWindow, '窗口内');
      await seedAlarm(outsideWindow, '窗口外');
      await seedAlarm(future, '未来');
    });

    test('按天趋势只含请求区间内的日期（旧实现丢了 matchStage）', async () => {
      const res = await get('/api/reports/alarms?startDate=2026-01-01&endDate=2026-01-31');
      expect(res.status).toBe(200);
      const days = res.body.data.byDay.map((d) => d._id);
      expect(days).toEqual(['2026-01-15']);
      // 反向对照：区间外的"今天"不得混进来（它落在近 30 天内，正是旧实现的口径）
      expect(days).not.toContain(businessDateParts(outsideWindow).dateStr);
    });

    test('不传日期时仍是近 30 天趋势，但未来时刻的记录不得入桶', async () => {
      const res = await get('/api/reports/alarms');
      expect(res.status).toBe(200);
      const days = res.body.data.byDay.map((d) => d._id);
      expect(days).toContain(businessDateParts(outsideWindow).dateStr);
      expect(days).not.toContain(businessDateParts(future).dateStr);
      expect(days).not.toContain('2026-01-15');
    });

    test('仪表盘「今日」报警数与业务日窗口的精确计数一致（未来记录不得计入）', async () => {
      const { start, end } = businessDayBounds();
      const expected = await FireAlarm.countDocuments({ occurredAt: { $gte: start, $lte: end } });
      const res = await get('/api/reports/dashboard');
      expect(res.status).toBe(200);
      expect(res.body.data.alarms.today).toBe(expected);
      // 自证：种子里确实有一条"今天之外"的报警，否则上一条无法区分"有上界"与"库里没有未来数据"
      expect(await FireAlarm.countDocuments({ occurredAt: { $gt: end } })).toBeGreaterThan(0);
    });
  });

  // ==================== ③ 数字形态串 ====================

  describe('③ 数字形态串（正负号/小数点/千分位）一律判非法', () => {
    test.each([
      '123',
      '20260801',
      '-1',
      '+1',
      '-0',
      '+0',
      '-2026',
      '+2026',
      '--1',
      '++1',
      '+-1',
      '1.5',
      '-1.5',
      '.5',
      '-.5',
      '1,5',
      ' 1 ',
    ])('%s 判非法', (value) => {
      expect(isValidDateParam(value)).toBe(false);
    });

    test('合法形态与"未传"不受影响（反向对照）', () => {
      for (const ok of [
        undefined,
        null,
        '',
        '2026-08-01',
        '2026-8-1',
        '2026-08-01T05:00:00Z',
        '2026-04-31',
      ]) {
        expect(isValidDateParam(ok)).toBe(true);
      }
      for (const bad of [20260801, 0, false, true, {}, [], 'not-a-date', ' ']) {
        expect(isValidDateParam(bad)).toBe(false);
      }
    });

    test('HTTP：报表出口对 -1 / +2026 不再返回 200 + 空表', async () => {
      for (const q of ['startDate=-1', 'endDate=+2026', 'startDate=.5']) {
        const res = await get(`/api/reports/alarms?${q}`);
        expect({ q, status: res.status, code: errorCodeOf(res) }).toEqual({
          q,
          status: 400,
          code: 'DATE_PARAM_INVALID',
        });
      }
    });
  });
});
