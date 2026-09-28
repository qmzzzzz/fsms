/**
 * 设备「更新」链路的字段口径对账
 *
 * 三层各自成立、合起来说谎的形态：
 *   路由  deviceRoutes.updateDeviceValidation 校验 `body('deviceType').isIn(...)`
 *   服务  DeviceService.updateDevice 的 updatableFields **白名单里没有它**
 *   前端  DeviceView.vue 的 submitForm 是新建/编辑共用，编辑时总会带上 deviceType
 * ⇒ 用户改设备类型、看到绿色"更新成功"，库里没变。这与本仓 P3-14 明令禁止的
 *   "校验存在暗示可更新，行为必须兑现"是同一类缺陷（installDate 当初也是这个形态）。
 *
 * 因此两层都测：
 *  ① 行为层：deviceType 真的写进文档；非白名单键（deviceCode）仍然不写；status 仍显式拒绝。
 *  ② 对账层：把更新路由校验过的字段名与服务白名单求差集，**任何新出现的"只校验不可写"
 *     字段都会让本文件转红**——单点修好一个字段不等于口径不再漂。
 */

const fs = require('fs');
const path = require('path');

const DeviceService = require('../services/DeviceService');

const makeDevice = (overrides = {}) => ({
  deviceCode: 'SMK-0001',
  deviceName: '一层烟感',
  deviceType: 'smoke_detector',
  status: 'normal',
  location: { building: 'A栋' },
  save: jest.fn(async function save() {
    return this;
  }),
  ...overrides,
});

describe('设备更新字段口径：校验过的字段必须真的可写', () => {
  describe('① 行为层', () => {
    test('deviceType 变更确实落库（此前被白名单静默丢弃 → 前端假成功）', async () => {
      const device = makeDevice();
      await DeviceService.updateDevice(device, { deviceType: 'extinguisher' });
      expect(device.deviceType).toBe('extinguisher');
      expect(device.save).toHaveBeenCalledTimes(1);
    });

    test('对照：不在白名单的键仍然不写（白名单不能退化成"来者不拒"）', async () => {
      const device = makeDevice();
      await DeviceService.updateDevice(device, { deviceCode: 'HACK-9999', unknownField: 1 });
      expect(device.deviceCode).toBe('SMK-0001');
      expect(device.unknownField).toBeUndefined();
    });

    test('对照：status 依旧是显式报错而不是静默忽略（与 deviceType 的处置方向不同，须各自成立）', async () => {
      const device = makeDevice();
      await expect(DeviceService.updateDevice(device, { status: 'scrapped' })).rejects.toThrow(
        /不能通过本接口修改/
      );
      expect(device.status).toBe('normal');
    });

    test('deviceType 与其它字段同批提交时一起生效（前端编辑就是整表提交）', async () => {
      const device = makeDevice();
      await DeviceService.updateDevice(device, {
        deviceName: '二层烟感',
        deviceType: 'sprinkler',
        remark: '改造后',
      });
      expect(device.deviceName).toBe('二层烟感');
      expect(device.deviceType).toBe('sprinkler');
      expect(device.remark).toBe('改造后');
    });
  });

  describe('② 对账层：更新路由校验字段 ⊆ 服务可写字段 ∪ 显式拒绝字段', () => {
    const routeSrc = fs
      .readFileSync(path.resolve(__dirname, '../routes/deviceRoutes.js'), 'utf8')
      .replace(/\r\n/g, '\n');
    const serviceSrc = fs
      .readFileSync(path.resolve(__dirname, '../services/DeviceService.js'), 'utf8')
      .replace(/\r\n/g, '\n');

    /** 取 updateDeviceValidation 这一段里所有 body('X') 的字段名 */
    const updateValidationBlock = () => {
      const start = routeSrc.indexOf('const updateDeviceValidation');
      expect(start).toBeGreaterThan(-1);
      // 到下一个顶层 `const ` 声明为止
      const rest = routeSrc.slice(start);
      const endRel = rest.slice(1).search(/\n(?:const|module\.exports)\b/);
      const block = endRel === -1 ? rest : rest.slice(0, endRel + 1);
      return [...block.matchAll(/body\('([^']+)'\)/g)].map((m) => m[1]);
    };

    const whitelisted = () => {
      const m = serviceSrc.match(/const updatableFields = \[([\s\S]*?)\];/);
      expect(m).not.toBeNull();
      return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
    };

    /** 服务里"显式拒绝"的字段：形如 `updates.<field> !== undefined` */
    const explicitlyRejected = () =>
      [...serviceSrc.matchAll(/updates\.([A-Za-z0-9_.]+)\s*!==\s*undefined/g)].map(
        (m) => m[1].split('.')[0]
      );

    // 前端把 location 摊平成 building/floor/room/detail 提交，归一到 location
    const LOCATION_PARTS = new Set(['building', 'floor', 'room', 'detail', 'location']);
    const normalize = (field) => {
      const top = field.split('.')[0];
      return LOCATION_PARTS.has(top) ? 'location' : top;
    };

    test('前提自证：两侧解析都拿到东西（否则差集为空是解析失效的假绿）', () => {
      const routeFields = updateValidationBlock();
      expect(routeFields.length).toBeGreaterThanOrEqual(8);
      expect(routeFields).toContain('deviceType');
      expect(whitelisted().length).toBeGreaterThanOrEqual(9);
      expect(explicitlyRejected()).toContain('status');
    });

    test('路由校验过的每个字段，服务必须"可写"或"显式拒绝"，不得静默丢弃', () => {
      const writable = new Set(whitelisted());
      const rejected = new Set(explicitlyRejected());
      const silentlyDropped = [...new Set(updateValidationBlock().map(normalize))].filter(
        (f) => !writable.has(f) && !rejected.has(f)
      );
      expect(silentlyDropped).toEqual([]);
    });

    test('反向：服务白名单里的字段必须在更新路由上有校验（放行未校验字段＝注入面）', () => {
      const validated = new Set(updateValidationBlock().map(normalize));
      const unvalidated = whitelisted().filter((f) => !validated.has(f));
      expect(unvalidated).toEqual([]);
    });
  });
});
