/**
 * 设备更新对 `location` 必须按子字段合并（F-170）
 *
 * 缺陷本体：`DeviceService.updateDevice` 把 `updates.location` 整个赋给文档，
 * 于是 `{location:{floor:'3F'}}` 这种**能过更新路由校验**的请求（location 只声明
 * `.optional().isObject()`，子字段各自 optional）会把 `location.building` 一起抹掉。
 * 而 building 是设备的部门数据范围键（`DATA_SCOPE_FIELDS.device.departmentField`）
 * ⇒ 一次"只改楼层"的合法编辑，让设备从所有按楼栋授权的人的列表/统计/导出里消失，
 * 接口还回 200。表单不维护的 `location.coordinates`（GPS 定位）同理会丢。
 *
 * 用真实模型而不是 mock：mock 只能证明"赋值怎么写的"，证明不了
 * Mongoose 的嵌套路径在 `{...current, ...patch}` 形态下真的把未提及的键带上去了，
 * 也证明不了改完之后范围查询还看得见这台设备——后者才是这个字段的业务后果。
 */

const mongoose = require('mongoose');

const FireDevice = require('../../models/FireDevice');
const DeviceService = require('../../services/DeviceService');

const TAG = 'ZZLOC';
const BUILDING = `${TAG}栋`;

const makeCode = (suffix) => `${TAG}-${suffix}`;

const create = (suffix, location) =>
  FireDevice.create({
    deviceCode: makeCode(suffix),
    deviceName: `${TAG} 灭火器`,
    deviceType: 'extinguisher',
    installDate: new Date('2026-01-01'),
    location: { building: BUILDING, ...location },
  });

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  await FireDevice.deleteMany({ deviceCode: new RegExp(`^${TAG}`) });
});

afterAll(async () => {
  await FireDevice.deleteMany({ deviceCode: new RegExp(`^${TAG}`) });
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});

const reload = async (id) => {
  const doc = await FireDevice.findById(id).lean();
  expect(doc).not.toBeNull();
  return doc;
};

describe('location 的更新语义：发哪个键只改哪个键', () => {
  test('只改 floor：未提及的 building/room/coordinates 原样留在库里', async () => {
    const device = await create('FLOOR', {
      floor: '原层',
      room: '101',
      coordinates: { lat: 30.1, lng: 120.2 },
    });
    await DeviceService.updateDevice(device, { location: { floor: '新层' } });
    const stored = await reload(device._id);
    expect(stored.location.floor).toBe('新层');
    expect(stored.location.building).toBe(BUILDING);
    expect(stored.location.room).toBe('101');
    expect(stored.location.coordinates).toMatchObject({ lat: 30.1, lng: 120.2 });
  });

  test('范围后果（端到端）：改完楼层后，按楼栋授权的人仍然查得到这台设备', async () => {
    const device = await create('SCOPE', { floor: '原层' });
    await DeviceService.updateDevice(device, { location: { detail: '新增详细位置' } });

    const mine = await DeviceService.getDevices({
      page: 1,
      limit: 20,
      search: TAG,
      dataScope: { type: 'department', department: BUILDING },
    });
    expect(mine.devices.map((d) => d.deviceCode)).toContain(makeCode('SCOPE'));

    // 鉴别力对照：department 档确实按楼栋筛，上一条不是一句"根本没过滤"的假绿
    const elsewhere = await DeviceService.getDevices({
      page: 1,
      limit: 20,
      search: TAG,
      dataScope: { type: 'department', department: `${TAG}别的栋` },
    });
    expect(elsewhere.devices).toHaveLength(0);
  });

  test('空 patch 不动任何东西（合并不得退化成"传了 location 就重置"）', async () => {
    const device = await create('EMPTY', { floor: '保持', room: '202' });
    await DeviceService.updateDevice(device, { location: {} });
    const stored = await reload(device._id);
    expect(stored.location).toMatchObject({ building: BUILDING, floor: '保持', room: '202' });
  });

  /**
   * 「清空」在合并语义下必须有一条出路，否则字段只进不出。
   *
   * 判据与 PUT /api/auth/profile 的空值分档同源（profileFieldClearability.test.js 把这条
   * 口径写成了注释）：**空串＝显式清空，未提及＝保持原值**。
   * 用例统一先过一遍 JSON 往返，因为真实链路上的"清空"是用户把输入框删空后提交，
   * 表单值可能是 `''` 也可能是 `undefined`；后者在传输层就被 JSON.stringify 丢掉键，
   * 服务端看到的是"没提这个字段"。前端若发 undefined，清空就整条链表达不出来 ——
   * 这正是本文件把更新语义从"整对象替换"收成"按键合并"之后必须同时改掉的地方
   * （DeviceView.vue 的 detail 现在发空串，由 web-admin 的 deviceView.test.js 钉住）。
   */
  const overTheWire = (payload) => JSON.parse(JSON.stringify(payload));

  test('清空要发空串：显式空串清得掉，未提及/undefined 都保持原值', async () => {
    const device = await create('CLEAR', { floor: '原层', detail: '靠东侧消防箱内' });

    await DeviceService.updateDevice(device, overTheWire({ location: { detail: '' } }));
    let stored = await reload(device._id);
    expect(stored.location.detail).toBe('');
    // 只清 detail：同级的 room/floor 与部门范围键 building 一个都不能少
    expect(stored.location).toMatchObject({ building: BUILDING, floor: '原层' });

    await DeviceService.updateDevice(device, overTheWire({ location: { detail: '又写上了' } }));
    // ① 经传输层的 undefined ＝ 键不存在
    await DeviceService.updateDevice(device, overTheWire({ location: { detail: undefined } }));
    expect((await reload(device._id)).location.detail).toBe('又写上了');
    // ② 不经传输层的裸 undefined 走同一口径（服务内调用方不得多出一种"看起来会清空"的写法）
    await DeviceService.updateDevice(device, { location: { detail: undefined } });
    expect((await reload(device._id)).location.detail).toBe('又写上了');
  });

  test('顶层空串同样清得掉（顶层与嵌套是两条写入通道，口径必须一致）', async () => {
    const device = await create('TOPCLEAR', { room: '404' });
    await DeviceService.updateDevice(device, { building: '', location: { room: '' } });
    const stored = await reload(device._id);
    expect(stored.location.building).toBe('');
    expect(stored.location.room).toBe('');
    // 未被点名的 floor 保持原值——清空不是"顺手重置没提的键"
    expect(stored.location.floor).toBeUndefined();
  });

  test('顶层 building/floor/room 兑现可更新（路由校验了它们，Service 不能丢），且嵌套值优先', async () => {
    const device = await create('TOP', { floor: '原层', room: '303' });
    await DeviceService.updateDevice(device, { building: `${TAG}新栋` });
    let stored = await reload(device._id);
    expect(stored.location.building).toBe(`${TAG}新栋`);
    // 顶层只动 building，兄弟键不受影响
    expect(stored.location.floor).toBe('原层');
    expect(stored.location.room).toBe('303');

    // 两种形态同时出现时以嵌套为准——与创建路径（deviceController 的 createDevice）同一口径
    await DeviceService.updateDevice(device, {
      building: `${TAG}栋`,
      location: { building: `${TAG}为准` },
    });
    stored = await reload(device._id);
    expect(stored.location.building).toBe(`${TAG}为准`);
  });

  test('反向保护：白名单外的键仍然写不进去（合并不能变成来者不拒）', async () => {
    const device = await create('GUARD', { floor: '原层' });
    await DeviceService.updateDevice(device, {
      deviceCode: 'HACKED-0001',
      location: { createdBy: 'nobody' },
    });
    const stored = await reload(device._id);
    expect(stored.deviceCode).toBe(makeCode('GUARD'));
    // location 是嵌套路径，schema 之外的子键由 Mongoose strict 模式丢弃
    expect(stored.location.createdBy).toBeUndefined();
    expect(stored.location.floor).toBe('原层');
  });
});
