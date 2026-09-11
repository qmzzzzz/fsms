/**
 * 批次B 业务逻辑类修复回归（P2-16/17/19/20/21/23 + P3-10）
 *
 * 这些缺陷的共同形态是「校验写在了没人走的路径上」或「同一语义在多处各写一遍」：
 * - 报废守卫写在模型方法里，而 Service 直接 push 数组 → 守卫从未生效
 * - status 与 lifecycleStage 两套状态各自被直写 → 产生自相矛盾的设备
 * - 属主字段在列表/导出/统计各抄一份 → 可见清单与统计数字永久对不上
 * 因此本套件的断言重点不是"报错文案"，而是**不变量**：状态不分叉、
 * 越权面不扩大、缓冲不无界增长。
 */

const mongoose = require('mongoose');

describe('批次B 业务规则加固回归', () => {
  let FireDevice;
  let Inspection;
  let User;
  let DeviceService;
  let AlarmService;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireDevice = require('../../models/FireDevice');
    Inspection = require('../../models/Inspection');
    User = require('../../models/User');
    DeviceService = require('../../services/DeviceService');
    AlarmService = require('../../services/AlarmService');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const makeDevice = (over = {}) =>
    FireDevice.create({
      deviceName: '测试灭火器',
      deviceType: 'extinguisher',
      installDate: new Date('2025-01-01'),
      ...over,
    });

  // ================= P2-16 设备状态机双轨同步 =================
  describe('P2-16 设备状态机', () => {
    test('updateDevice 不接受 status（显式拒绝而非静默忽略）', async () => {
      const device = await makeDevice();
      await expect(DeviceService.updateDevice(device, { status: 'fault' })).rejects.toMatchObject({
        statusCode: 400,
      });
      // 传入与当前值相同的 status 视为无变更，不应报错
      const same = await DeviceService.updateDevice(device, {
        status: device.status,
        remark: 'ok',
      });
      expect(same.remark).toBe('ok');
    });

    test('updateDeviceStatus 拒绝 scrapped（报废必须走专用接口以留下原因与日期）', async () => {
      const device = await makeDevice();
      await expect(DeviceService.updateDeviceStatus(device, 'scrapped')).rejects.toMatchObject({
        statusCode: 400,
      });
    });

    test('status=maintenance 同步推进 lifecycleStage（两套状态不再分叉）', async () => {
      const device = await makeDevice();
      await device.transitionTo('in_use');
      await DeviceService.updateDeviceStatus(device, 'maintenance');
      const fresh = await FireDevice.findById(device._id);
      expect(fresh.status).toBe('maintenance');
      expect(fresh.lifecycleStage).toBe('maintenance');
    });

    test('生命周期迁移不合法时仅告警不阻断（status 仍然落库）', async () => {
      // installed 阶段不允许直接 → maintenance，业务上的"故障标记"不该被生命周期规则挡住
      const device = await makeDevice();
      expect(device.lifecycleStage).toBe('installed');
      await DeviceService.updateDeviceStatus(device, 'maintenance');
      const fresh = await FireDevice.findById(device._id);
      expect(fresh.status).toBe('maintenance');
      expect(fresh.lifecycleStage).toBe('installed');
    });

    test('已报废设备拒绝一切状态变更与维护记录', async () => {
      const device = await makeDevice();
      await DeviceService.scrapDevice(device, '到期报废');
      const scrapped = await FireDevice.findById(device._id);
      expect(scrapped.status).toBe('scrapped');
      expect(scrapped.lifecycleStage).toBe('scrapped');
      expect(scrapped.scrapDate).toBeInstanceOf(Date);

      await expect(DeviceService.updateDeviceStatus(scrapped, 'normal')).rejects.toMatchObject({
        statusCode: 400,
      });
      await expect(
        DeviceService.addMaintenanceRecord(scrapped, '偷偷维护', null)
      ).rejects.toMatchObject({ statusCode: 400 });
    });

    test('重复报废被拒（否则会覆盖原始报废日期，审计上等于篡改）', async () => {
      const device = await makeDevice();
      await DeviceService.scrapDevice(device, '第一次');
      const first = await FireDevice.findById(device._id);
      const firstDate = first.scrapDate.getTime();

      await expect(DeviceService.scrapDevice(first, '第二次')).rejects.toMatchObject({
        statusCode: 400,
      });
      const after = await FireDevice.findById(device._id);
      expect(after.scrapDate.getTime()).toBe(firstDate);
      expect(after.scrapReason).toBe('第一次');
    });

    test('报废日期补录必须是合法日期，且校验失败时设备不得已被报废（B-2）', async () => {
      const device = await makeDevice();
      await expect(DeviceService.scrapDevice(device, '原因', 'not-a-date')).rejects.toMatchObject({
        statusCode: 400,
      });
      // 回归点：原实现先报废落库再校验日期，400 返回时设备已是 scrapped；
      // 修复后校验前置，失败即零写入
      const fresh = await FireDevice.findById(device._id);
      expect(fresh.status).not.toBe('scrapped');
      expect(fresh.lifecycleStage).not.toBe('scrapped');
      expect(fresh.scrapDate).toBeFalsy();
    });

    test('补录报废日期与状态迁移在同一次原子写入完成（B-2）', async () => {
      const device = await makeDevice();
      const saveSpy = jest.spyOn(device, 'save');
      const backfilled = new Date('2020-01-02T00:00:00.000Z');
      await DeviceService.scrapDevice(device, '历史补录', backfilled.toISOString());
      // 单次 save：不再有「先迁移后补录」的第二次写入
      expect(saveSpy).toHaveBeenCalledTimes(1);

      const fresh = await FireDevice.findById(device._id);
      expect(fresh.status).toBe('scrapped');
      expect(fresh.lifecycleStage).toBe('scrapped');
      expect(fresh.scrapReason).toBe('历史补录');
      expect(fresh.scrapDate.getTime()).toBe(backfilled.getTime());
    });

    test('仅检查类维护记录顺延检查周期（维修不算完成一次检查）', async () => {
      const repaired = await makeDevice();
      await DeviceService.addMaintenanceRecord(repaired, '换配件', null, 'repair');
      const afterRepair = await FireDevice.findById(repaired._id);
      expect(afterRepair.lastCheckDate).toBeFalsy();

      const checked = await makeDevice();
      await DeviceService.addMaintenanceRecord(checked, '例行检查', null, 'routine');
      const afterCheck = await FireDevice.findById(checked._id);
      expect(afterCheck.lastCheckDate).toBeInstanceOf(Date);
      expect(afterCheck.nextCheckDate).toBeInstanceOf(Date);
    });
  });

  // ================= P2-17 handlerId 校验 =================
  describe('P2-17 dispatchAlarm 处理人校验', () => {
    let activeUser;
    let disabledUser;
    let otherDeptUser;

    beforeAll(async () => {
      activeUser = await User.create({
        username: 'dispatch_ok',
        email: 'dispatch_ok@example.com',
        password: 'Qz7#Lm42vTx9',
        department: 'A栋',
        status: 'active',
      });
      disabledUser = await User.create({
        username: 'dispatch_off',
        email: 'dispatch_off@example.com',
        password: 'Qz7#Lm42vTx9',
        department: 'A栋',
        status: 'inactive',
      });
      otherDeptUser = await User.create({
        username: 'dispatch_other',
        email: 'dispatch_other@example.com',
        password: 'Qz7#Lm42vTx9',
        department: 'B栋',
        status: 'active',
      });
    });

    const makeAlarm = () =>
      AlarmService.reportAlarm({
        alarmType: 'smoke',
        level: 'critical',
        location: { building: 'A栋' },
        description: '测试报警',
        reporterName: '张三',
        reporterPhone: '13800000000',
      });

    test('指派不存在的用户被拒（否则 handler 悬空、工单永久卡住）', async () => {
      const alarm = await makeAlarm();
      const ghost = new mongoose.Types.ObjectId();
      await expect(
        AlarmService.dispatchAlarm(alarm._id, ghost, activeUser._id)
      ).rejects.toMatchObject({ statusCode: 400 });
    });

    test('指派已停用账户被拒', async () => {
      const alarm = await makeAlarm();
      await expect(
        AlarmService.dispatchAlarm(alarm._id, disabledUser._id, activeUser._id)
      ).rejects.toMatchObject({ statusCode: 400 });
    });

    test('部门级操作者不得跨部门指派', async () => {
      const alarm = await makeAlarm();
      await expect(
        AlarmService.dispatchAlarm(alarm._id, otherDeptUser._id, activeUser._id, {
          dataScope: { type: 'department', department: 'A栋' },
        })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    test('部门为空的操作者不得指派（否则空部门等于放行全组织）', async () => {
      const alarm = await makeAlarm();
      await expect(
        AlarmService.dispatchAlarm(alarm._id, activeUser._id, activeUser._id, {
          dataScope: { type: 'department', department: '' },
        })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    test('同部门在职人员正常指派', async () => {
      const alarm = await makeAlarm();
      const updated = await AlarmService.dispatchAlarm(alarm._id, activeUser._id, activeUser._id, {
        dataScope: { type: 'department', department: 'A栋' },
      });
      expect(updated).toBeTruthy();
      expect(String(updated.handler)).toBe(String(activeUser._id));
      expect(updated.status).toBe('processing');
    });

    // P3-15：reportAlarm 曾是 create + save 两步写，中间崩溃留下无处理日志的报警
    test('reportAlarm 一次写入即带初始处理日志（P3-15 原子性）', async () => {
      const alarm = await makeAlarm();
      expect(alarm.processLog).toHaveLength(1);
      expect(alarm.processLog[0].action).toBe('alarm_received');
      expect(alarm.receivedAt).toBeInstanceOf(Date);
    });
  });

  // ================= P2-19 巡检时间窗与 overdue =================
  describe('P2-19 巡检逾期标记', () => {
    const { markOverdueInspections } = require('../../services/deviceReminder');

    const makeInspection = (over = {}) =>
      Inspection.create({
        inspectionType: 'daily',
        title: `逾期测试-${Math.random().toString(36).slice(2, 8)}`,
        planStartTime: new Date(Date.now() - 7200_000),
        planEndTime: new Date(Date.now() - 3600_000),
        ...over,
      });

    test('已过计划结束时间的 pending/in_progress 被置为 overdue', async () => {
      const pending = await makeInspection({ status: 'pending' });
      const running = await makeInspection({ status: 'in_progress' });
      await markOverdueInspections();
      expect((await Inspection.findById(pending._id)).status).toBe('overdue');
      expect((await Inspection.findById(running._id)).status).toBe('overdue');
    });

    test('终态与未到期任务不被改写', async () => {
      const completed = await makeInspection({ status: 'completed' });
      const cancelled = await makeInspection({ status: 'cancelled' });
      const future = await makeInspection({
        status: 'pending',
        planStartTime: new Date(Date.now() + 3600_000),
        planEndTime: new Date(Date.now() + 7200_000),
      });
      await markOverdueInspections();
      expect((await Inspection.findById(completed._id)).status).toBe('completed');
      expect((await Inspection.findById(cancelled._id)).status).toBe('cancelled');
      expect((await Inspection.findById(future._id)).status).toBe('pending');
    });

    test('标记失败不抛出（提醒扫描的附加职责不应中断主流程）', async () => {
      const spy = jest.spyOn(Inspection, 'updateMany').mockRejectedValueOnce(new Error('db down'));
      await expect(markOverdueInspections()).resolves.toBe(0);
      spy.mockRestore();
    });
  });

  // ================= P2-20 属主字段单一声明 + 数组语义 =================
  describe('P2-20 数据范围属主口径', () => {
    const { DATA_SCOPE_FIELDS } = require('../../constants/dataScopeFields');
    const { buildDataScopeFilter, isRecordInScope } = require('../../middleware/rbac');

    test('设备 self 范围用 $or 覆盖建档人与维护操作者', () => {
      const filter = buildDataScopeFilter(
        { type: 'self', userId: 'u1' },
        DATA_SCOPE_FIELDS.device.ownerField,
        DATA_SCOPE_FIELDS.device.departmentField
      );
      expect(filter).toEqual({
        $or: [{ createdBy: 'u1' }, { 'maintenanceRecord.operator': 'u1' }],
      });
    });

    test('数组属主任一命中即在范围内（建档人 / 维护人各自可见）', () => {
      const fields = { ...DATA_SCOPE_FIELDS.device, userId: 'u1' };
      const scope = { type: 'self', userId: 'u1' };
      expect(isRecordInScope(scope, { createdBy: 'u1' }, fields)).toBe(true);
      expect(isRecordInScope(scope, { maintenanceRecord: [{ operator: 'u1' }] }, fields)).toBe(
        true
      );
      expect(
        isRecordInScope(scope, { createdBy: 'u2', maintenanceRecord: [{ operator: 'u3' }] }, fields)
      ).toBe(false);
    });

    test('单字段属主保持原有等值语义（不被数组改造带偏）', () => {
      expect(
        buildDataScopeFilter(
          { type: 'self', userId: 'u1' },
          DATA_SCOPE_FIELDS.alarm.ownerField,
          DATA_SCOPE_FIELDS.alarm.departmentField
        )
      ).toEqual({ 'reporter.userId': 'u1' });
    });

    test('department 为空时数组属主同样兜底为空集（不得零过滤）', () => {
      const filter = buildDataScopeFilter(
        { type: 'department', department: '' },
        DATA_SCOPE_FIELDS.device.ownerField,
        DATA_SCOPE_FIELDS.device.departmentField
      );
      // 属主条件用 null 值 → 匹配不到任何文档，而非"无约束"
      expect(filter).toEqual({
        $or: [{ createdBy: null }, { 'maintenanceRecord.operator': null }],
      });
    });

    test('四类资源的字段声明都存在且非空（新增调用方不会拿到 undefined 字段名）', () => {
      for (const key of ['device', 'alarm', 'inspection', 'user']) {
        const f = DATA_SCOPE_FIELDS[key];
        expect(f).toBeDefined();
        expect(f.ownerField).toBeTruthy();
        expect(typeof f.departmentField).toBe('string');
      }
    });
  });

  // ================= P2-21 审计缓冲容量与重试保护 =================
  describe('P2-21 auditBuffer 容量保护', () => {
    const auditBuffer = require('../../services/auditBuffer');
    const AuditLog = require('../../models/AuditLog');

    // 缓冲满 100 条会触发异步 flush，若不等其结算，flushing 标志会串到下个用例，
    // 让后续的显式 flush() 直接早退（这类"测试间异步泄漏"比被测缺陷更难排查）
    const settle = () => new Promise((r) => setTimeout(r, 50));

    beforeEach(() => auditBuffer.__resetForTest());
    afterAll(() => auditBuffer.__resetForTest());

    test('缓冲不超过硬上限，超出部分计入 droppedCount', async () => {
      const spy = jest.spyOn(AuditLog, 'insertMany').mockResolvedValue([]);
      const { hardLimit } = auditBuffer.getStats();
      // 多推 300 条：首次达到 BUFFER_LIMIT=100 时会同步排空一批，
      // 余量必须仍能压到硬上限之上，才真正验证到裁剪逻辑
      for (let i = 0; i < hardLimit + 300; i += 1) {
        auditBuffer.push({ action: 'test', seq: i });
      }
      // 循环内无 await，此处读到的是纯同步裁剪后的状态
      const stats = auditBuffer.getStats();
      expect(stats.bufferLength).toBeLessThanOrEqual(hardLimit);
      expect(stats.droppedCount).toBeGreaterThan(0);

      await settle();
      spy.mockRestore();
      auditBuffer.__resetForTest();
    });

    test('droppedCount 可观测（静默丢弃审计数据在合规上等同篡改）', () => {
      const stats = auditBuffer.getStats();
      expect(stats).toHaveProperty('droppedCount');
      expect(stats).toHaveProperty('consecutiveFailures');
      expect(stats).toHaveProperty('hardLimit');
    });

    test('连续失败达阈值即丢弃毒文档批，不再无限滞留重试', async () => {
      await settle();
      const spy = jest.spyOn(AuditLog, 'insertMany').mockRejectedValue(new Error('poison doc'));
      auditBuffer.__resetForTest();
      auditBuffer.push({ action: 'poison' });

      // MAX_BATCH_RETRY = 5：前 4 次回退重试，第 5 次判定毒批并丢弃
      for (let i = 0; i < 5; i += 1) {
        await auditBuffer.flush();
      }
      const stats = auditBuffer.getStats();
      expect(stats.bufferLength).toBe(0);
      expect(stats.droppedCount).toBeGreaterThan(0);
      expect(stats.consecutiveFailures).toBe(0);
      spy.mockRestore();
    });

    test('失败后文档回到缓冲重试（at-least-once 未被容量保护破坏）', async () => {
      const spy = jest.spyOn(AuditLog, 'insertMany').mockRejectedValueOnce(new Error('transient'));
      auditBuffer.push({ action: 'retryable' });
      await auditBuffer.flush();
      expect(auditBuffer.getStats().bufferLength).toBe(1);
      spy.mockRestore();
      auditBuffer.__resetForTest();
    });
  });

  // ================= B-1 设备删除跨集合写（withTransaction 接入回归） =================
  describe('B-1 设备删除跨集合写', () => {
    test('deleteDevice 清理告警与巡检引用后删除设备（standalone 降级为顺序写）', async () => {
      const FireAlarm = require('../../models/FireAlarm');
      const stamp = `b1${Date.now()}`;
      const device = await makeDevice({ deviceCode: `${stamp}-DEV` });
      await FireAlarm.create({
        alarmCode: `${stamp}-ALM`,
        alarmType: 'smoke',
        description: 'B-1 引用清理验证',
        deviceId: device._id,
      });
      const inspection = await Inspection.create({
        inspectionType: 'daily',
        title: 'B-1 引用清理验证',
        devices: [device._id],
        findings: [{ deviceId: device._id }],
      });

      await DeviceService.deleteDevice(device);

      // 设备本体已删除
      expect(await FireDevice.findById(device._id)).toBeNull();
      // 告警 deviceId 被 $unset，无悬空引用
      const alarm = await FireAlarm.findOne({ alarmCode: `${stamp}-ALM` });
      expect(alarm).toBeTruthy();
      expect(alarm.deviceId).toBeUndefined();
      // 巡检 devices 被 $pull、findings[].deviceId 被按 arrayFilters $unset
      const insp = await Inspection.findById(inspection._id);
      expect(insp.devices.map(String)).not.toContain(String(device._id));
      expect(insp.findings[0].deviceId).toBeUndefined();

      await FireAlarm.deleteOne({ _id: alarm._id });
      await Inspection.deleteOne({ _id: inspection._id });
    });
  });
});
