/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：DeviceService.updateDeviceStatus / scrapDevice 的"已报废"守卫
 * 守护的不变式：报废是终态——**任何**在报废之前加载的快照都不得再把它写回在用，
 *              原始 scrapDate / scrapReason 不得被第二次报废覆盖。
 * 可证伪性：除名为「负对照」的那一条（它**应当**恒绿，用来证明新增分支没把兜底 500
 *              吞成 400）外，本套件每一条在"守卫只读内存快照 + 无条件 save()"的实现下为红。
 *
 * 手法说明（为什么不靠真并发）：并发用例的时序不受测试控制，pre-fix 也可能碰巧全绿
 * ——那是假绿源。这里用**同一文档的两份独立 findById 快照**确定性地复现同一个交错：
 * 请求 A 加载 → 请求 B 报废并落库 → 请求 A 提交（它看到的仍是报废前的世界）。
 * 这与真实并发下的败者状态逐字节等价，且每次运行都成立。
 *
 * 判据边界：本套件钉的是**可观察不变式**，不证明实现细节必须是条件写；
 * "写前重读一次再判断"同样满足这些断言（虽然窗口更窄但仍非原子）。选条件写是因为
 * 它与本仓 InspectionService / AlarmService 的既有口径一致：守卫落在写条件里。
 * ──────────────────────────────────────────────────────────────────────────
 */

const mongoose = require('mongoose');

describe('设备报废终态：旧快照不得覆盖终态', () => {
  let FireDevice;
  let DeviceService;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../../models/FireDevice');
    DeviceService = require('../../services/DeviceService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 建一台"在用"设备（走完 installed → in_use，贴近真实数据形态） */
  const makeInUseDevice = async () => {
    const device = await FireDevice.create({
      deviceName: '测试灭火器',
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
    });
    await device.transitionTo('in_use');
    return device;
  };

  /** 另一次请求的独立快照（与传入 id 无共享内存） */
  const snapshot = (id) => FireDevice.findById(id);

  test('前提自证：两份 findById 确实是独立快照，改不到彼此', async () => {
    const device = await makeInUseDevice();
    const a = await snapshot(device._id);
    const b = await snapshot(device._id);
    expect(a).not.toBe(b);
    a.status = 'fault';
    expect(b.status).toBe('normal');
    // 前提的另一半：报废前 B 快照确实看不到报废（否则下面的用例全是恒绿）
    await DeviceService.scrapDevice(a, '前提校验');
    const afterScrap = await snapshot(device._id);
    expect(afterScrap.lifecycleStage).toBe('scrapped');
    expect(a.lifecycleStage).toBe('scrapped'); // 操作者自己的视图随写入更新
    expect(b.lifecycleStage).toBe('in_use'); // 另一路仍停在报废前的世界——缺陷的燃料
  });

  test('报废落库后，旧快照做标量状态写入必须被拒且库里仍是 scrapped', async () => {
    const device = await makeInUseDevice();
    const stale = await snapshot(device._id);
    const other = await snapshot(device._id);
    await DeviceService.scrapDevice(other, '到期报废');

    // 只断言"被拒"而不断言错误类型/状态码：守卫可以是版本冲突（本实现）也可以是
    // 条件写未命中，两者对调用方都必须是拒绝。对外状态码与"不回显内部错误"由本文件
    // 最后一条用例用**真实冲突产生的错误对象**过一遍 errorHandler 来钉。
    await expect(DeviceService.updateDeviceStatus(stale, 'fault')).rejects.toThrow();

    const fresh = await snapshot(device._id);
    expect(fresh.status).toBe('scrapped');
    expect(fresh.lifecycleStage).toBe('scrapped');
    // 危害本身也要钉住：status 被翻回非 scrapped 时，提醒/报表的排除集只看 status，
    // 这台已报废灭火器会重新出现在待更换/待维护五档里
    expect(fresh.scrapReason).toBe('到期报废');
  });

  test('报废落库后，旧快照走状态机迁移同样必须被拒（它会连 lifecycleStage 一起翻回）', async () => {
    const device = await makeInUseDevice();
    const stale = await snapshot(device._id);
    const other = await snapshot(device._id);
    await DeviceService.scrapDevice(other, '到期报废');

    await expect(DeviceService.updateDeviceStatus(stale, 'maintenance')).rejects.toThrow();

    const fresh = await snapshot(device._id);
    expect(fresh.lifecycleStage).toBe('scrapped');
    expect(fresh.status).toBe('scrapped');
  });

  test('并发重复报废不得覆盖原始 scrapDate 与 scrapReason（否则等于篡改报废时间）', async () => {
    const device = await makeInUseDevice();
    const first = await snapshot(device._id);
    const second = await snapshot(device._id);
    const originalDate = new Date('2020-01-02T03:04:05.000Z');

    await DeviceService.scrapDevice(first, '第一次报废', originalDate);
    await expect(DeviceService.scrapDevice(second, '第二次报废')).rejects.toThrow();

    const fresh = await snapshot(device._id);
    expect(fresh.scrapReason).toBe('第一次报废');
    expect(fresh.scrapDate.getTime()).toBe(originalDate.getTime());
  });

  test('正向对照：无人并报时状态变更照旧成功并返回落库后的新值', async () => {
    const device = await makeInUseDevice();
    const stale = await snapshot(device._id);
    const updated = await DeviceService.updateDeviceStatus(stale, 'maintenance');
    expect(updated.status).toBe('maintenance');
    expect(updated.lifecycleStage).toBe('maintenance');
    const fresh = await snapshot(device._id);
    expect(fresh.status).toBe('maintenance');
  });

  test('既有契约不破：非法生命周期迁移仍"仅告警不阻断"，status 照旧落库', async () => {
    const device = await FireDevice.create({
      deviceName: '测试灭火器',
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
    });
    expect(device.lifecycleStage).toBe('installed');
    await DeviceService.updateDeviceStatus(device, 'maintenance');
    const fresh = await snapshot(device._id);
    expect(fresh.status).toBe('maintenance');
    expect(fresh.lifecycleStage).toBe('installed');
  });

  test('既有契约不破：报废仍须经过 scrapDevice 接口且终态字段齐全', async () => {
    const device = await makeInUseDevice();
    const updated = await DeviceService.scrapDevice(device, '正常流程报废');
    expect(updated.status).toBe('scrapped');
    expect(updated.lifecycleStage).toBe('scrapped');
    expect(updated.scrapReason).toBe('正常流程报废');
    expect(updated.scrapDate).toBeInstanceOf(Date);
    const fresh = await snapshot(device._id);
    expect(fresh.status).toBe('scrapped');
  });

  test('既有契约不破：报废日期格式非法时零写入（校验前于任何落库动作）', async () => {
    const device = await makeInUseDevice();
    await expect(DeviceService.scrapDevice(device, '原因', 'not-a-date')).rejects.toMatchObject({
      statusCode: 400,
    });
    const fresh = await snapshot(device._id);
    expect(fresh.status).toBe('normal');
    expect(fresh.lifecycleStage).toBe('in_use');
    expect(fresh.scrapDate).toBeUndefined();
  });

  // ========== errorHandler 层：冲突对外是 400，且不回显内部错误文本 ==========
  // 上面三条用例只管"被拒"，不锁拒绝的形态；本组用例锁的正是**这一种**形态
  // （VersionError → 400）的对外契约，所以必须钉 err.name —— 换成条件写的实现会让
  // 前提红，那是诚实的信号（新实现也得给出自己的映射），不是假失败。
  // 用真实冲突产生的错误对象而不是手搓一个：VersionError 的 message 含文档 _id、
  // 加载时 __v 与 modifiedPaths，"不回显内部信息"只有拿它来喂才有内容可泄。

  /** 最小响应桩：errorHandler 只需要 headersSent / writableEnded / status / json */
  const makeRes = () => {
    const res = {
      headersSent: false,
      writableEnded: false,
      statusCode: undefined,
      body: undefined,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        return this;
      },
      end() {
        this.writableEnded = true;
      },
    };
    return res;
  };

  const makeReq = () => ({ method: 'PUT', originalUrl: '/api/devices/conflict', user: {} });

  /** 制造一次真实的乐观并发冲突并取出抛出的错误对象 */
  const triggerConflict = async () => {
    const device = await makeInUseDevice();
    const stale = await snapshot(device._id);
    const other = await snapshot(device._id);
    await DeviceService.scrapDevice(other, '到期报废');
    let captured;
    try {
      await DeviceService.updateDeviceStatus(stale, 'fault');
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(Error);
    return captured;
  };

  test('前提：冲突确实以 VersionError 的形式抛出（映射分支的入口条件）', async () => {
    const err = await triggerConflict();
    expect(err.name).toBe('VersionError');
    // 前提的另一半：message 里确有内部信息（_id / __v / modifiedPaths），
    // 否则下一条"不回显"的断言是恒绿的空话
    expect(err.message).toMatch(/version|No matching document/i);
  });

  test('VersionError 经 errorHandler 对外为 400，响应体不回显内部错误文本', async () => {
    const errorHandler = require('../../middleware/errorHandler');
    const err = await triggerConflict();

    const res = makeRes();
    errorHandler(err, makeReq(), res, () => {});

    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('刷新');
    // 不回显：内部原文（含 _id/__v/modifiedPaths）一个字都不该出现在响应里
    expect(JSON.stringify(res.body)).not.toContain(err.message);
  });

  test('负对照：普通错误仍落兜底 500（新增分支没有把兜底吞成 400）', async () => {
    const errorHandler = require('../../middleware/errorHandler');
    const res = makeRes();
    errorHandler(new Error('一条与并发无关的内部错误'), makeReq(), res, () => {});

    expect(res.statusCode).toBe(500);
    expect(res.body.errors.errorCode).toBe('INTERNAL_ERROR');
    expect(JSON.stringify(res.body)).not.toContain('一条与并发无关的内部错误');
  });

  // ========== Service 的 catch 收窄：只吞"迁移表不允许"，其余原样抛出 ==========
  // 真实冲突下这条不可观测（transitionTo 内部就是 save()，被吞后 Service 再 save()
  // 会撞上同一个版本守卫而再次抛错），所以这里在**被测单元自己**的边界上注入错误。
  // mock 的是 device.transitionTo —— 被 Service 调用的那一步，不是被证明的性质本身。

  /** 只可能来自版本守卫的错误形状（驱动原文含 _id / version / modifiedPaths） */
  const makeVersionError = () => {
    const err = new Error(
      'No matching document found for id "64b0f0" version 0 modifiedPaths "status"'
    );
    err.name = 'VersionError';
    return err;
  };

  test('transitionTo 抛出的版本冲突不得被降级成一条告警后继续写库', async () => {
    const device = await makeInUseDevice();
    const spy = jest.spyOn(device, 'transitionTo').mockRejectedValue(makeVersionError());
    try {
      await expect(DeviceService.updateDeviceStatus(device, 'maintenance')).rejects.toThrow(
        /No matching document/
      );
    } finally {
      spy.mockRestore();
    }
    // 关键的另一半：降级成告警时这里会把状态**真的写进去**（旧实现的缺陷形态）
    const fresh = await snapshot(device._id);
    expect(fresh.status).toBe('normal');
    expect(fresh.lifecycleStage).toBe('in_use');
  });

  test('scrapDevice 不得把版本冲突包成「报废失败：<内部原文>」（内部错误不回显）', async () => {
    const device = await makeInUseDevice();
    const internal = makeVersionError();
    const spy = jest.spyOn(device, 'transitionTo').mockRejectedValue(internal);
    let captured;
    try {
      await DeviceService.scrapDevice(device, '到期报废');
    } catch (err) {
      captured = err;
    } finally {
      spy.mockRestore();
    }
    expect(captured).toBe(internal); // 原样抛出，交给 errorHandler 统一映射
    expect(captured.message).not.toMatch(/报废失败/);
  });
});
