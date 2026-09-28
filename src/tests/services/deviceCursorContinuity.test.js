/**
 * 设备列表的游标必须能被自己吃回去（F-169 的行为面）
 *
 * 缺陷本体：`DeviceService.getDevices` 用 `deviceCode` 作排序键（全仓唯一的
 * `valueType:'string'` 调用点），而 `cursorPagination` 对游标里的排序键值有一道长度上限
 * （L-14：封住"用超长 v 撑爆查询"）。上限曾取 32，而 deviceCode 的合法宽度是
 * 模型 `maxlength:50`（路由 `deviceRoutes.js` 的 `isLength({max:50})` 与它对齐）。
 * ⇒ 只要某页**最后一条**的编码长度落在 33–50，服务照样下发 nextCursor，
 * 客户端照原样回传却被 `decodeCursor` 拒成 400「分页游标无效，请从第一页重新查询」：
 * 翻页从这一页起死掉，服务端一条日志都没有，而用户看到的是"列表只有第一页"。
 *
 * 为什么单测常量不够：`cursorPagination.test.js` 里"超长字符串 → 400"那条把期望长度
 * **算自同一个常量**，上限从 32 改成任何值它都跟着变绿。所以本文件把期望取自**模型**，
 * 并且走真实服务调用（下发方与消费方是同一段生产代码）。
 */

const mongoose = require('mongoose');

const FireDevice = require('../../models/FireDevice');
const DeviceService = require('../../services/DeviceService');
const { encodeCursor, decodeCursor } = require('../../utils/cursorPagination');

const TAG = 'ZZCURSOR';

/** 排序键的合法最大宽度：事实来源是模型，不在测试里抄一个 50 */
const declared = FireDevice.schema.path('deviceCode').options.maxlength;
const WIDEST = Array.isArray(declared) ? declared[0] : declared;

// 升序排列下落在第一页末尾的那台：'ZZCURSOR' 之后一位是 Y，另一台是 Z ⇒ Y 在前
const LONG_CODE = `${TAG}${'Y'.repeat(WIDEST - TAG.length)}`;
const NEXT_CODE = `${TAG}Z1`;

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  await FireDevice.deleteMany({ deviceCode: new RegExp(`^${TAG}`) });
  for (const deviceCode of [LONG_CODE, NEXT_CODE]) {
    await FireDevice.create({
      deviceCode,
      deviceName: `${TAG} 探测器`,
      deviceType: 'extinguisher',
      installDate: new Date('2026-01-01'),
    });
  }
});

afterAll(async () => {
  await FireDevice.deleteMany({ deviceCode: new RegExp(`^${TAG}`) });
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});

/** 只取本文件那两台：search 与数据范围条件取交集，不受同库其它套件残留影响 */
const firstPage = () =>
  DeviceService.getDevices({ page: 1, limit: 1, search: TAG, dataScope: { type: 'all' } });

const mint = (v) => encodeCursor({ v, id: String(new mongoose.Types.ObjectId()) });

describe('设备列表游标的连续性', () => {
  test('前提自证：模型声明没变形，第一页末尾确实是那条"最宽合法"编码', async () => {
    expect(Number.isInteger(WIDEST)).toBe(true);
    const p1 = await firstPage();
    expect(p1.devices).toHaveLength(1);
    expect(p1.devices[0].deviceCode).toHaveLength(WIDEST);
    expect(p1.nextCursor).not.toBeNull();
    // 服务自己下发的游标，当场就要能过服务自己的解码器（修前在这一步抛 400）
    expect(decodeCursor(p1.nextCursor).v).toBe(LONG_CODE);
  });

  test('客户端照原样回传 nextCursor：必须拿到第二页，而不是 400', async () => {
    const p1 = await firstPage();
    const p2 = await DeviceService.getDevices({
      cursor: p1.nextCursor,
      limit: 1,
      search: TAG,
      dataScope: { type: 'all' },
    });
    expect(p2.devices.map((d) => d.deviceCode)).toEqual([NEXT_CODE]);
    // 第二页是末页：翻页链在这里正常收尾，而不是以"游标无效"收尾
    expect(p2.hasMore).toBe(false);
    expect(p2.nextCursor).toBeNull();
  });

  test('反向保护：上限是被抬高而不是被取消', async () => {
    // 200 特意选在"值超限但整条游标仍 < MAX_CURSOR_LENGTH(512)"的区间：
    // base64 后约 320 字符，所以这里的抛错只可能来自排序键值上限这一道闸。
    expect(() => decodeCursor(mint('Z'.repeat(200)))).toThrow();
    expect(() => decodeCursor(mint('Z'.repeat(4096)))).toThrow();
    // 而上限之下（含最宽合法编码）必须放行，否则就是本文件第一条用例的反面
    expect(decodeCursor(mint('Z'.repeat(WIDEST))).v).toHaveLength(WIDEST);
  });
});
