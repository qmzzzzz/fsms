/**
 * 报警的所有读出路径不得回吐 `reporter.phone`（2026-10-02 审计线 lane-B #1）
 *
 * 缺陷形状：`FireAlarm.reporter.phone` 是明文存的第三方手机号（不属于
 * models/User.js 那套「getter 解密 + POST /api/security/view-sensitive step-up +
 * view_sensitive_data 审计」通道），而报警的读出路径原本**一条根文档投影都没有**，
 * 于是任何持 `alarm:read` 且落在该条范围内的账号都能整页批量读到它：
 * 无二次验证、无 `system:read`、无留痕。同一 model 上的 `handler.phone` 正因同样
 * 理由被收窄过（见同目录 alarmDetailHandlerPii.test.js），这是同一列的邻接漏点。
 *
 * 为什么判据要覆盖五个处置接口而不只列表/详情：`dispatch/arrive/resolve/
 * false-alarm/cancel` 都把 `findOneAndUpdate` 的 `updated` 文档原样回给客户。
 * 只给列表与详情加投影，同一列就从这五个口整块漏出去——而 CI 仍全绿，
 * 因为那五个响应体本来就没有用例读过它。这正是本仓反复强调的「绿但不设防」。
 *
 * 可证伪对（每条都配反向证据，避免"其实是被 populate/夹具吞了"）：
 *   · 夹具自证：不过滤的裸查询确实能拿到明文并出现在序列化结果里；
 *   · reporter.name 仍在：证明排除的是那一列，不是整个子文档；
 *   · 源码文本闸：逐个 FireAlarm 读调用点必须带投影（运行用例只走一条分支，
 *     源码闸才钉得住"三条列表/详情分支 + 五个处置口"这个整体形状）。
 */

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const REPORTER_PHONE = '13900139000';
const REPORTER_NAME = '上报人乙';

describe('报警读出路径的 reporter.phone 口径', () => {
  let FireAlarm;
  let User;
  let service;
  let operator;
  const stamp = `arp${String(Date.now()).slice(-8)}`;
  let alarmCancel;
  let alarmFalse;
  let alarmChain;

  const expectNoPhone = (doc, label) => {
    const json = JSON.stringify(doc.toJSON ? doc.toJSON() : doc);
    expect(`${label}:${json}`).not.toContain(REPORTER_PHONE);
    expect(doc.reporter?.phone).toBeUndefined();
    // 反向证据：同一条里 reporter.name 必须还在
    expect(doc.reporter?.name).toBe(REPORTER_NAME);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../../models/FireAlarm');
    User = require('../../models/User');
    service = require('../../services/AlarmService');

    operator = await User.create({
      username: `op_${stamp}`,
      email: `op-${stamp}@example.com`,
      password: `P@ssw0rd-${stamp}`,
      realName: '处置员甲',
      status: 'active',
      roles: [],
    });

    const mk = (suffix) =>
      FireAlarm.create({
        alarmType: 'smoke',
        description: `${stamp} 楼-${suffix} 烟感报警`,
        reporter: { name: REPORTER_NAME, phone: REPORTER_PHONE },
        location: { building: `${stamp}号楼` },
      });
    alarmCancel = await mk('c');
    alarmFalse = await mk('f');
    alarmChain = await mk('h');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await User.deleteMany({ username: new RegExp(`^op_${stamp}$`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('夹具自证：号码确实明文入库，裸查询能整块读出（否则下面的 not.toContain 是空的）', async () => {
    const raw = await FireAlarm.findById(alarmCancel._id);
    expect(raw.reporter.phone).toBe(REPORTER_PHONE);
    expect(JSON.stringify(raw.toJSON())).toContain(REPORTER_PHONE);
  });

  test('详情：getAlarmById 排除该列，reporter.name 保留', async () => {
    const detail = await service.getAlarmById(String(alarmCancel._id));
    expectNoPhone(detail, 'detail');
  });

  test('列表（offset 分支）：整页都不含该列', async () => {
    const { alarms } = await service.getAlarms({
      page: 1,
      limit: 50,
      search: stamp,
      dataScope: { type: 'all' },
    });
    expect(alarms.length).toBe(3);
    for (const alarm of alarms) expectNoPhone(alarm, 'offset');
  });

  test('列表（游标分支）：与 offset 分支同口径（只修一条等于没修）', async () => {
    const first = await service.getAlarms({
      page: 1,
      limit: 1,
      search: stamp,
      dataScope: { type: 'all' },
    });
    expect(first.alarms).toHaveLength(1);
    const next = await service.getAlarms({
      cursor: first.nextCursor,
      limit: 5,
      search: stamp,
      dataScope: { type: 'all' },
    });
    const all = [...first.alarms, ...next.alarms];
    expect(all.length).toBeGreaterThanOrEqual(2);
    for (const alarm of all) expectNoPhone(alarm, 'cursor');
  });

  test('五个处置接口的回显同样不带该列（updated 文档也是读出路径）', async () => {
    const scope = { dataScope: { type: 'all' } };
    const op = operator._id;

    const dispatched = await service.dispatchAlarm(
      String(alarmChain._id),
      String(op),
      String(op),
      scope
    );
    expectNoPhone(dispatched, 'dispatch');

    const arrived = await service.arriveAtScene(String(alarmChain._id), String(op));
    expectNoPhone(arrived, 'arrive');

    const resolved = await service.resolveAlarm(
      String(alarmChain._id),
      { handleResult: '已现场确认并扑灭' },
      String(op)
    );
    expectNoPhone(resolved, 'resolve');

    const cancelled = await service.cancelAlarm(String(alarmCancel._id), '重复上报', String(op));
    expectNoPhone(cancelled, 'cancel');

    const falsified = await service.markAsFalseAlarm(
      String(alarmFalse._id),
      '设备自检误触发',
      String(op)
    );
    expectNoPhone(falsified, 'false-alarm');
  });

  test('状态机前提自证：五个接口真的各自命中并返回了文档（不是 null 让断言空过）', async () => {
    const [chain, cancelled, falsified] = await Promise.all(
      [alarmChain, alarmCancel, alarmFalse].map((d) => FireAlarm.findById(d._id))
    );
    expect(chain.status).toBe('resolved');
    expect(cancelled.status).toBe('cancelled');
    expect(falsified.status).toBe('false_alarm');
  });

  test('源码文本闸：AlarmService 每个 FireAlarm 文档读调用点都必须带投影', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', '..', 'services', 'AlarmService.js'),
      'utf8'
    );
    const callSites = [...src.matchAll(/FireAlarm\.(find|findById|findOneAndUpdate)\s*\(/g)];
    // 基线自证：3 条读路径（游标/offset/详情）+ 5 个处置口 = 8；
    // 零命中或命中数下跌会被下面这条先拦住，不会出现"扫描没匹配到 ⇒ 全绿"。
    expect(callSites.length).toBeGreaterThanOrEqual(8);

    // 窗口取「到下一个调用点为止」而不是固定字数：resolveAlarm 的 $push 文案块就
    // 比 420 字符长，固定窗口会把它的 options 尾巴截在外面，闸对着正确的代码报红。
    const starts = callSites.map((m) => m.index);
    const chunks = starts.map((start, i) =>
      src.slice(start, i + 1 < starts.length ? starts[i + 1] : start + 900)
    );
    const offender = chunks.find((chunk) => {
      const hasShared = chunk.includes('ALARM_READ_SELECT');
      const hasInclusion = /\.select\(\s*'(?![^']*reporter(?:\.phone)?[^']*\bphone\b)/.test(chunk);
      const hasProjectionOption = /projection:/.test(chunk);
      return !(hasShared || hasInclusion || hasProjectionOption);
    });
    expect(offender).toBeUndefined();

    // 反向自查：证明这套匹配不是恒真的——把共享常量换成不存在的写法，闸必须变红
    expect(/ALARM_READ_SELECT/.test(src)).toBe(true);
    expect(src.match(/ALARM_READ_SELECT/g)).toHaveLength(9);
  });
});
