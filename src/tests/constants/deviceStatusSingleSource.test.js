/**
 * 设备状态清单的单一来源对账（F-165）
 *
 * 对方 2026-09-25 的待办里这一条写的是「DEVICE_STATUS 有 5 份私有拷贝」。逐处比对后的
 * 实际形状不是「5 份副本」，而是「4 份副本 + 1 处别字段」，且副本分两类：
 *   - 全集 6 档：models/FireDevice.js 的 schema enum、deviceRoutes 的 update 校验器、
 *     docs/generate.js 的 query 参数（三处，内容当时相同）；DeviceService.VALID_STATUSES
 *     与 deviceRoutes 的 list query 早就引用 constants，不在此列；
 *   - 可写子集 5 档：deviceRoutes 的 updateDeviceStatusValidation 与 generate.js 的
 *     requestBody enum——**少一档是设计**（scrapped 必须走 /scrap 推进生命周期），
 *     抄的却是这条规则的结果而不是规则本身。
 *   （FireDevice.js 的 lifecycleStage 也有五个值，那是另一套枚举，不是本文件的副本，
 *     下面的 B 组用负对照钉住"别把它一起接过来"。）
 *
 * 于是本文件要防的是两种不同的分叉，各有一组用例：
 *   加一档而只改 model ⇒ 路由 400 掉新档（A/D 红）；
 *   加一档而只改 constants ⇒ 文档继续宣称旧清单，调用方照文档传值得到 400（E 红）。
 * 口径照搬 alarmEnumSingleSource.test.js（F-142/158）与 permissionStatusSingleSource
 * （F-137/138/141）：运行时内容对账 + 引用点数量对账 + **已提交产物**也要对账，
 * 外加 D 组的正对照（防空集恒绿）。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

/**
 * 代码视图：去掉**整行注释**。对账"某处不该再有字面量副本"必须先过这一层，否则
 * 本文件头注释里复述的旧写法会把自己判红——那种红改措辞就能消掉，等于把用例绑在文案上。
 * 口径同 F-128 与 permission/alarm 两个套件。
 */
const codeOnly = (src) =>
  src
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');

/** 整行注释与行尾注释都去掉后压掉换行/缩进：副本可能写成一行，也可能 prettier 拆成多行 */
const flatCode = (src) =>
  codeOnly(src)
    .replace(/\/\/[^\n]*/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

// 字面量副本的探测串：只取「normal 开头、offline 在中间」这段共性——
// 6 档与 5 档两种抄法都含它，因此一条判据能同时抓两类回退
const LITERAL = "'normal', 'warning', 'fault', 'offline', 'maintenance'";

const { DEVICE_STATUS } = require('../../utils/constants');
const { DEVICE_STATUS_VALUES, DEVICE_STATUS_WRITABLE } = require('../../constants/deviceStatus');
const spec = require('../../docs/openapi.json');

describe('派生视图本身：不是第二份值，也不是一句把清单清空的 filter', () => {
  it('全集就是 utils/constants 的 values（同值同序，文档与下拉依赖此序）', () => {
    expect([...DEVICE_STATUS_VALUES]).toEqual(Object.values(DEVICE_STATUS));
    // 防空集：filter/map 写错成常量表为空时，下面所有"等于派生视图"的用例会同色通过
    expect(DEVICE_STATUS_VALUES.length).toBeGreaterThanOrEqual(4);
  });

  it('可写子集 = 全集减 scrapped，且只减掉 scrapped 这一档', () => {
    expect(DEVICE_STATUS_WRITABLE).toEqual(DEVICE_STATUS_VALUES.filter((s) => s !== 'scrapped'));
    expect(DEVICE_STATUS_WRITABLE).not.toContain(DEVICE_STATUS.SCRAPPED);
    expect(DEVICE_STATUS_WRITABLE.length).toBe(DEVICE_STATUS_VALUES.length - 1);
  });
});

describe('运行时 schema 与全集同源', () => {
  const FireDevice = require('../../models/FireDevice');
  const enumOf = (field) => FireDevice.schema.path(field).enumValues;

  it('status 的 schema 合法值 == DEVICE_STATUS_VALUES（窄于 schema 的那族失效在此现形）', () => {
    expect([...enumOf('status')]).toEqual([...DEVICE_STATUS_VALUES]);
  });

  it('负对照：lifecycleStage 是另一套枚举，不许被顺手接到 DEVICE_STATUS 上', () => {
    expect(enumOf('lifecycleStage').length).toBe(5);
    expect([...enumOf('lifecycleStage')]).not.toEqual([...DEVICE_STATUS_VALUES]);
    // 它既不含 warning/fault/offline，又含 status 没有的 installed/retired
    expect(enumOf('lifecycleStage')).toEqual(
      expect.arrayContaining(['installed', 'retired', 'scrapped'])
    );
    expect(enumOf('lifecycleStage')).not.toContain('fault');
  });
});

describe('服务层真跑：可写子集里每一档都收，scrapped 一律 400', () => {
  const deviceService = require('../../services/DeviceService');

  // 只造 updateDeviceStatus 用到的那几个成员：两条写路径分别是 save() 与 transitionTo()，
  // 各计数一次，用于断言"这一档确实落库了"而不是"没抛错"
  const fakeDevice = (over = {}) => ({
    deviceCode: 'FA-TEST-1',
    status: 'normal',
    lifecycleStage: 'in_use',
    saved: 0,
    transitioned: 0,
    async transitionTo(stage) {
      this.transitioned += 1;
      this.lifecycleStage = stage;
    },
    async save() {
      this.saved += 1;
    },
    ...over,
  });

  test.each(DEVICE_STATUS_WRITABLE.map((s) => [s]))(
    'PUT /api/devices/:id/status 的合法档 %s 落到写库',
    async (status) => {
      const device = fakeDevice();
      await deviceService.updateDeviceStatus(device, status);
      expect(device.status).toBe(status);
      // normal/maintenance 走 transitionTo（内部已 save），其余档直接 save()：
      // 两条路径都必须有一次写库，否则就是"改了内存对象就返回"
      expect(device.saved + device.transitioned).toBeGreaterThanOrEqual(1);
    }
  );

  it('scrapped 不在可写子集里：服务层显式拒绝，不静默放行', async () => {
    expect(DEVICE_STATUS_WRITABLE).not.toContain('scrapped');
    await expect(deviceService.updateDeviceStatus(fakeDevice(), 'scrapped')).rejects.toThrow(
      /报废/
    );
  });

  it('派生视图若被写成空数组，本组用例会一条不跑（用数量自证它非空）', () => {
    expect(DEVICE_STATUS_WRITABLE.length).toBeGreaterThan(0);
  });
});

describe('引用点数量对账：原副本位置不许再手写字面量', () => {
  it.each([
    ['src/routes/deviceRoutes.js', 0],
    ['src/docs/generate.js', 0],
  ])('%s 的 code 视图里不再出现状态字面量', (file, expect0) => {
    const hits = (flatCode(read(file)).match(/'normal', 'warning', 'fault', 'offline'/g) || [])
      .length;
    expect(hits).toBe(expect0);
  });

  it('两个校验器各自引用同一来源（引用点掉 1 说明有人把手抄清单接了回来）', () => {
    const src = codeOnly(read('src/routes/deviceRoutes.js'));
    expect((src.match(/isIn\(DEVICE_STATUS_VALUES\)/g) || []).length).toBe(2);
    expect((src.match(/isIn\(DEVICE_STATUS_WRITABLE\)/g) || []).length).toBe(1);
  });

  it('正对照：探测串确实抓得到被抄回的写法（防恒绿）', () => {
    const regressed = `body('status').isIn([${LITERAL}, 'scrapped'])`;
    expect(flatCode(regressed)).toContain(LITERAL);
    expect(
      (flatCode(regressed).match(/'normal', 'warning', 'fault', 'offline'/g) || []).length
    ).toBe(1);
    // 而"引用派生视图"的写法必须判为干净，否则上面的 0 只是把一切一红旗
    expect(flatCode("body('status').isIn(DEVICE_STATUS_WRITABLE)")).not.toContain(LITERAL);
  });
});

describe('已提交产物的枚举 == 派生视图（产物才是对外交付的那一份）', () => {
  const queryStatusEnum = () => {
    const params = spec.paths['/api/devices'].get.parameters;
    const item = params.find((p) => p.name === 'status');
    return item && item.schema ? item.schema.enum : undefined;
  };
  const bodyStatusEnum = () =>
    spec.paths['/api/devices/{id}/status'].put.requestBody.content['application/json'].schema
      .properties.status.enum;

  it('列表 query 的 status 枚举 = 全集', () => {
    expect(queryStatusEnum()).toEqual([...DEVICE_STATUS_VALUES]);
  });

  it('状态变更 requestBody 的 status 枚举 = 可写子集（文档不许比运行时宽）', () => {
    expect(bodyStatusEnum()).toEqual([...DEVICE_STATUS_WRITABLE]);
  });
});
