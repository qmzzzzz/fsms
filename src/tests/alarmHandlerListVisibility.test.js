/**
 * 报警列表与详情的属主口径必须一致，且 search 不得吃掉数据范围条件
 *
 * 两条各管一半：
 *  A. 「凡单条可操作者必在列表可见」——只打通详情/操作（canOperateAlarm）而列表仍按
 *     reporter 过滤的话，被派单的消防员面对的是"界面上根本没有这一行"，
 *     操作权等于零；这条实测成立，已一并收口。
 *  B. 把 ownerField 改成数组会新引入一个**极其隐蔽的越权**：数组属主 ⇒ self 范围的
 *     条件形态是 `{$or:[{reporter.userId},{handler}]}`，而 getAlarms 的 search 分支
 *     原本写的是 `query.$or = [...]`（赋值）。顺序是"先范围、后搜索"，
 *     于是带 search 参数时**整条范围条件被替换掉** ⇒ 任何人带个关键词就能搜到全组织报警。
 *     不带 search 完全正常，所以最容易被漏测。DeviceService 早就为设备修过同一形态，
 *     这次把三处收敛成同一个合并器（utils/scopeCast.js 的 applySearchCondition）。
 */
const mongoose = require('mongoose');

const { applySearchCondition } = require('../utils/scopeCast');

const stamp = `zzlv${Date.now()}`.replace(/[^a-z0-9]/g, '').slice(0, 10);

describe('applySearchCondition：范围条件必须活到最后', () => {
  test('已有 $or（数据范围）时用 $and 取交集并让出 $or 位置', () => {
    const scopeOr = [{ 'reporter.userId': 'aaa' }, { handler: 'aaa' }];
    const q = { $or: scopeOr };
    applySearchCondition(q, { $or: [{ description: /冒烟/ }] });
    expect(q.$or).toBeUndefined();
    expect(q.$and).toHaveLength(2);
    expect(q.$and[0]).toEqual({ $or: scopeOr });
    expect(q.$and[1]).toEqual({ $or: [{ description: /冒烟/ }] });
  });

  test('没有范围 $or 时直接落 $or，不无谓地套一层 $and', () => {
    const q = { status: 'pending' };
    applySearchCondition(q, { $or: [{ description: /冒烟/ }] });
    expect(q.$and).toBeUndefined();
    expect(q.$or).toEqual([{ description: /冒烟/ }]);
  });

  test('已有 $and 时追加而不是覆盖（多条同字段冲突要取交集）', () => {
    const q = { $or: [{ handler: 'a' }], $and: [{ level: 'critical' }] };
    applySearchCondition(q, { $or: [{ description: /x/ }] });
    expect(q.$and).toHaveLength(3);
    expect(q.$and[0]).toEqual({ level: 'critical' });
  });
});

describe('报警列表：被派单者看得见、局外人搜不到', () => {
  let FireAlarm;
  let service;
  let reporter;
  let handler;
  let stranger;
  let mineId;
  let theirsId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../models/FireAlarm');
    service = require('../services/AlarmService');
    [reporter, handler, stranger] = Array.from({ length: 3 }, () => new mongoose.Types.ObjectId());

    const mine = await FireAlarm.create({
      alarmType: 'smoke',
      description: `${stamp} 三层井道冒烟（派给我）`,
      reporter: { userId: reporter },
      handler,
    });
    const theirs = await FireAlarm.create({
      alarmType: 'smoke',
      description: `${stamp} 只有别人看得到的一条`,
      reporter: { userId: stranger },
      handler: stranger,
    });
    mineId = String(mine._id);
    theirsId = String(theirs._id);
  });

  afterAll(async () => {
    await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const listFor = (userId, search) =>
    service.getAlarms({ page: 1, limit: 50, search, dataScope: { type: 'self', userId } });

  test('夹具形态确认：两条都属于别人，只有第一条的 handler 是我', async () => {
    expect(await FireAlarm.countDocuments({ description: new RegExp(stamp) })).toBe(2);
  });

  test('self(handler) 无 search：被派单的那条必须在列表里（列表↔详情同口径）', async () => {
    const { alarms } = await listFor(handler.toString());
    expect(alarms.map((a) => String(a._id))).toContain(mineId);
    expect(alarms.map((a) => String(a._id))).not.toContain(theirsId);
  });

  test('反向：无关用户既看不到别人的处置单，也看不到自己没参与的', async () => {
    const { alarms } = await listFor(new mongoose.Types.ObjectId().toString());
    const ids = alarms.map((a) => String(a._id));
    expect(ids).not.toContain(mineId);
    expect(ids).not.toContain(theirsId);
  });

  test('★ self + search 命中别人的关键词时必须返回 0 行（search 不得吃掉范围）', async () => {
    // 这正是把 ownerField 改成数组后会新引入的越权：
    // 如果 search 分支用赋值覆盖范围条件，这一条会返回别人的那条报警。
    const { alarms, count } = await listFor(handler.toString(), '只有别人看得到');
    expect(alarms.map((a) => String(a._id))).not.toContain(theirsId);
    expect(count).toBe(0);
  });

  test('反向保护：search 与范围同时成立时必须命中（不得把 search 做成恒不匹配）', async () => {
    const { alarms, count } = await listFor(handler.toString(), '三层井道');
    expect(alarms.map((a) => String(a._id))).toContain(mineId);
    expect(count).toBe(1);
  });

  test('列表与统计同口径：handler 的 self 列表 count 与其 self 统计 total 相等', async () => {
    const { count } = await listFor(handler.toString());
    const stats = await service.getAlarmStats(undefined, undefined, {
      type: 'self',
      userId: handler.toString(),
    });
    expect(stats.total).toBe(count);
  });
});
