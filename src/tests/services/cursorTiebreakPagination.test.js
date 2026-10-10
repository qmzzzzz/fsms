/**
 * 排序键取值重复时的游标连续性（等值键必须被次级排序键裁决）
 *
 * 缺陷本体：游标续翻条件形如
 *   (f < v) OR (f == v AND _id < id)          // 降序
 * 这是对 `_id` 做的平局裁决；但调用点的 `.sort()` 只排主键 `{f:-1}`。
 * 单字段索引下的隐式平局序是 (key, RecordId **升序**)，与续翻条件的 `_id < id`
 * **方向相反** ⇒ 每页吃进的是同一个等值块里**最旧**的一小截，而游标却宣称
 * "_id 比它小的都翻过了" ⇒ 同块剩余记录永久不可达，且 hasMore 提前为假。
 *
 * 本机实测（5000 条 / 100 个取值 × 50 / 每页 20）：
 *   .sort({ts:-1})         ⇒ 重复 950、漏 3950（79% never reachable）、第 101 页就 hasMore:false
 *   .sort({ts:-1,_id:-1})  ⇒ 重复 0、漏 0、251 页遍历完
 *
 * 为什么既有套件没发现：`controllers/cursorPagination.test.js` 的夹具每条记录
 * 相差 1 分钟——排序键**无重复**，正好绕开这条缺陷。本文件把等值键造出来。
 *
 * 断言取向：
 *  · 「无遗漏/无重复/hasMore 只在末页为假」= 缺陷本身；
 *  · 「等值块内按 _id 降序」= 不是审美，是续翻子句 `{f:v,_id:{$lt:id}}` 唯一自洽的方向；
 *    若有人改成升序修复，必须连 `applyCursorCondition` 的比较符一起翻，否则本文件照样红。
 *
 * 造数形态警告（改动夹具插入次序前必读）：漂移是否发生**与块内插入次序有关**。
 * 本机 2×2×2 矩阵（2000 条 / 40 组 × 50 / 每页 20）：块内按 seq 正序插入时
 * 「单字段索引 + 只排主键」这一格重复 380、漏 1580；把同一批夹具改成组内**反序**
 * 插入，四格全绿——因为单字段索引的隐式块内序是 (key, RecordId 升序)，反序插入
 * 恰好让它与 `_id` 降序同向。所以：本文件的 create() 顺序（seq 递增 ⇒ _id 递增
 * 且 RecordId 递增）是缺陷可复现的前提，别把它打乱；同理，"这条查询没漂"从来
 * 不是证据，漂不漂要按方向断言（上面第二条）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { TEST_CLIENT_IP } = require('../fixtures');

// 每页 5 条 × 24 条夹具 ⇒ 5 页（5/5/5/5/4）
const PAGE_SIZE = 5;
const GROUPS = [
  { name: '较新一组', offsetMs: 0, count: 12 },
  { name: '较旧一组', offsetMs: 60 * 60 * 1000, count: 12 },
];
const TOTAL = GROUPS.reduce((sum, g) => sum + g.count, 0);
const EXPECTED_PAGES = Math.ceil(TOTAL / PAGE_SIZE);

describe('等值排序键的游标连续性', () => {
  let app;
  let FireAlarm;
  let Inspection;
  let AuditLog;
  let adminToken;
  const stamp = `tb${Date.now()}`.replace(/\d/g, (d) => 'wxyzabcdef'[Number(d)]);
  const auditSeedUser = `tiebreak_seed_${stamp}`;
  const baseTime = new Date('2026-09-01T12:00:00.000Z');

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    const User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');
    FireAlarm = require('../../models/FireAlarm');
    Inspection = require('../../models/Inspection');
    AuditLog = require('../../models/AuditLog');
    require('../../models/TokenBlacklist');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    const superRole = await Role.create({
      name: '超管_等值游标',
      code: `SUPER_ADMIN_TB_${stamp}`,
      level: 10,
      isBuiltIn: false,
      permissions: [wildcardPerm._id],
    });
    const admin = await User.create({
      username: `tbadmin${stamp}`,
      email: `tbadmin${stamp}@example.com`,
      password: randomPassword(),
      roles: [superRole._id],
    });
    adminToken = jwt.sign(
      { userId: String(admin._id), username: admin.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { createApp } = require('../../app');
    app = createApp();

    // ===== 造数：同组内排序键**完全相同**（等值块），块大小 > 每页条数 =====
    const flatten = GROUPS.flatMap((group, gi) =>
      Array.from({ length: group.count }, (_, i) => ({ group: gi, seq: i }))
    );

    await FireAlarm.create(
      flatten.map((doc) => ({
        alarmType: 'smoke',
        description: `等值游标报警 ${stamp}-${doc.group}-${doc.seq}`,
        occurredAt: new Date(baseTime.getTime() - doc.group * 60 * 60 * 1000),
        location: { building: `等值栋${stamp}` },
      }))
    );

    await Inspection.create(
      flatten.map((doc) => ({
        inspectionType: 'daily',
        title: `等值游标巡检 ${stamp}-${doc.group}-${doc.seq}`,
        planStartTime: new Date(baseTime.getTime() - doc.group * 60 * 60 * 1000),
      }))
    );

    await AuditLog.create(
      flatten.map((doc) => ({
        action: 'login_success',
        category: 'auth',
        username: auditSeedUser,
        success: true,
        riskLevel: 'low',
        ip: TEST_CLIENT_IP,
        timestamp: new Date(baseTime.getTime() - doc.group * 60 * 60 * 1000),
      }))
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await Inspection.deleteMany({ title: new RegExp(stamp) }).catch(() => {});
      await AuditLog.deleteMany({ username: auditSeedUser }).catch(() => {});
      const User = require('../../models/User');
      const Role = require('../../models/Role');
      await User.deleteOne({ username: `tbadmin${stamp}` }).catch(() => {});
      await Role.deleteOne({ code: `SUPER_ADMIN_TB_${stamp}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const authed = (url) => request(app).get(url).set('Authorization', `Bearer ${adminToken}`);

  /**
   * 逐页消费 nextCursor；记录每页的 hasMore，用于证明"提前收敛"。
   * 首页走 offset（真实客户端形态：首屏带 total，之后可切游标续翻），
   * offset 口径本就不给 hasMore，所以该断言只钉游标页。
   */
  const walk = async (urlPrefix, { itemsOf, cursorOf, hasMoreOf }) => {
    const flat = [];
    const hasMoreFlags = [];
    let cursor = null;
    let pages = 0;
    let guard = 0;
    do {
      const url = cursor
        ? `${urlPrefix}&limit=${PAGE_SIZE}&cursor=${encodeURIComponent(cursor)}`
        : `${urlPrefix}&limit=${PAGE_SIZE}`;
      const res = await authed(url);
      expect(res.status).toBe(200);
      flat.push(...itemsOf(res.body));
      pages += 1;
      if (cursor) {
        // 游标页必须给出 hasMore；缺位即"响应口径变了"，不能当成 false 混过去
        expect(hasMoreOf(res.body)).toBeDefined();
        hasMoreFlags.push(hasMoreOf(res.body));
      }
      cursor = cursorOf(res.body);
      guard += 1;
      if (guard > 50) throw new Error('游标遍历超过 50 页，疑似死循环');
    } while (cursor);
    return { pages, flat, hasMoreFlags };
  };

  const paginated = {
    itemsOf: (body) => body.data,
    cursorOf: (body) => body.pagination.nextCursor,
    hasMoreOf: (body) => body.pagination.hasMore,
  };
  const auditShape = {
    itemsOf: (body) => body.data.data,
    cursorOf: (body) => body.data.meta.nextCursor,
    // 审计接口的续翻标志叫 hasNext（其余三个列表叫 hasMore），此处按各自口径取
    hasMoreOf: (body) => body.data.meta.hasNext,
  };

  /**
   * 通用不变量：把整块链走完必须**不多不少**拿到全部夹具，且顺序是
   * (排序键降序, _id 降序)——后者是续翻子句 `{f:v,_id:{$lt:id}}` 的唯一自洽方向。
   */
  const assertCursorWalk = ({ flat, pages, hasMoreFlags, keyOf, expectedIds }) => {
    const ids = flat.map((doc) => String(doc._id));
    // 无重复：同一条不得跨页出现两次
    expect(new Set(ids).size).toBe(ids.length);
    // 无遗漏：块内 79% 不可达就是死在这一格
    expect(ids.slice().sort()).toEqual(expectedIds.slice().sort());
    // hasMore 只能在最后一页为假
    expect(hasMoreFlags.filter((flag) => flag === false)).toHaveLength(1);
    expect(hasMoreFlags[hasMoreFlags.length - 1]).toBe(false);
    expect(pages).toBe(EXPECTED_PAGES);
    // 排序键整体降序
    const keys = flat.map((doc) => new Date(keyOf(doc)).getTime());
    expect(keys).toEqual([...keys].sort((a, b) => b - a));
    // 等值块内 _id 降序（同键相邻两条必须 _id 更大者在前）
    for (let i = 1; i < flat.length; i += 1) {
      if (keys[i] !== keys[i - 1]) continue;
      expect(ids[i] < ids[i - 1]).toBe(true);
    }
  };

  const runCase = async ({ urlPrefix, shape, keyOf, model, filter }) => {
    const expectedIds = await model
      .find(filter)
      .select('_id')
      .lean()
      .then((docs) => docs.map((doc) => String(doc._id)));
    expect(expectedIds).toHaveLength(TOTAL);
    const walked = await walk(urlPrefix, shape);
    return { ...walked, keyOf, expectedIds };
  };

  test('前提自证：夹具确实是等值块（块大小 > 每页条数）', async () => {
    const alarms = await FireAlarm.find({ description: new RegExp(stamp) })
      .select('occurredAt')
      .lean();
    const distinctKeys = new Set(alarms.map((doc) => doc.occurredAt.getTime()));
    expect(alarms).toHaveLength(TOTAL);
    expect(distinctKeys.size).toBe(GROUPS.length);
    // 块大小 > 每页条数 ⇒ 每个等值块必然跨页边界
    expect(GROUPS[0].count).toBeGreaterThan(PAGE_SIZE);
  });

  test('报警列表：同一 occurredAt 跨页边界不重复、不遗漏', async () => {
    const args = await runCase({
      urlPrefix: `/api/alarms?search=${stamp}`,
      shape: paginated,
      keyOf: (doc) => doc.occurredAt,
      model: FireAlarm,
      filter: { description: new RegExp(stamp) },
    });
    assertCursorWalk(args);
  });

  test('巡检列表：同一 planStartTime 跨页边界不重复、不遗漏', async () => {
    const args = await runCase({
      urlPrefix: `/api/inspections?search=${stamp}`,
      shape: paginated,
      keyOf: (doc) => doc.planStartTime,
      model: Inspection,
      filter: { title: new RegExp(stamp) },
    });
    assertCursorWalk(args);
  });

  test('审计日志：同一 timestamp 跨页边界不重复、不遗漏', async () => {
    const args = await runCase({
      urlPrefix: `/api/security/audit-logs?username=${auditSeedUser}`,
      shape: auditShape,
      keyOf: (doc) => doc.timestamp,
      model: AuditLog,
      filter: { username: auditSeedUser },
    });
    assertCursorWalk(args);
  });
});
