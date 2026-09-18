/**
 * AuditLog 字段留存回归（P1-12）
 *
 * 缺陷：`AuditLog` schema 为 `strict: true`，而 `targetType` / `targetId` /
 * `dataType` / `description` 四个字段**未在 schema 中声明**——写入方
 * （`securityController.reportSuspiciousActivity` / `viewSensitiveData`）
 * 传入的这些键被 Mongoose **静默剔除**，落库后不存在。
 * 后果：
 *   - 举报记录（action=suspicious_report）无法定位被举报对象（targetType/targetId 丢失）；
 *   - 敏感数据查看记录（action=view_sensitive_data）无法回答"看了哪个字段"（dataType 丢失）。
 *
 * 修复方向：在 schema 中**显式声明**这 4 个字段（保持 strict: true，不放宽为 false），
 * 并保持写入方实际取值可落库。本测试即锁定「写入 → 读回 → 值正确」的完整链路。
 *
 * 类型与写入方依据（改动前请核对）：
 *   - targetType：securityRoutes.js 的 reportValidation 限定 isIn(['user','device','alarm','system'])
 *   - targetId：  请求体字符串（设备/报警 ID），无 ObjectId 约束
 *   - dataType：  securityRoutes.js 限定 isIn(['phone','email'])
 *   - description：securityRoutes.js 限 max 500 字符
 *   - reason：     securityRoutes.js 限 1..200 字符（既有字段，一并锁定）
 */

const mongoose = require('mongoose');

describe('AuditLog 字段留存（P1-12）', () => {
  let AuditLog;
  const stamp = `p1l12_${Date.now().toString(36)}`;

  beforeAll(async () => {
    AuditLog = require('../../models/AuditLog');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      // append-only 钩子会拒绝 deleteMany：测试清理走 bypassAppendOnly
      // （仅测试环境生效，见 models/auditLogHooks.js 的 P1-32 收紧）
      await AuditLog.deleteMany({ username: stamp }, { bypassAppendOnly: true }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('schema 显式声明 targetType/targetId/dataType/description（strict 仍为 true）', () => {
    expect(AuditLog.schema.options.strict).toBe(true);
    for (const field of ['targetType', 'targetId', 'dataType', 'description']) {
      expect(AuditLog.schema.path(field)).toBeTruthy();
      expect(AuditLog.schema.path(field).instance).toBe('String');
    }
  });

  test('举报记录落库后 targetType/targetId/description 可读回且值正确', async () => {
    const created = await AuditLog.create({
      action: 'suspicious_report',
      category: 'security',
      username: stamp,
      targetType: 'device',
      targetId: 'DEV-2026-0001',
      reason: '设备被反复触发误报',
      description: '连续三晚同一设备触发烟感报警，怀疑传感器故障或被蓄意触发',
      ip: '203.0.113.9',
      riskLevel: 'high',
    });

    // 直接经 DB 读回（绕过内存文档，验证的是"确实落库"而非"内存里有"）
    const readBack = await AuditLog.findById(created._id).lean();
    expect(readBack.targetType).toBe('device');
    expect(readBack.targetId).toBe('DEV-2026-0001');
    expect(readBack.description).toBe('连续三晚同一设备触发烟感报警，怀疑传感器故障或被蓄意触发');
    expect(readBack.reason).toBe('设备被反复触发误报');
  });

  test('敏感数据查看记录落库后 dataType 可读回（可回答"看了哪个字段"）', async () => {
    const targetId = new mongoose.Types.ObjectId();
    const created = await AuditLog.create({
      action: 'view_sensitive_data',
      category: 'auth',
      username: stamp,
      targetUserId: targetId,
      targetUsername: `${stamp}_target`,
      dataType: 'phone',
      ip: '203.0.113.9',
      success: true,
      riskLevel: 'medium',
    });

    const readBack = await AuditLog.findById(created._id).lean();
    expect(readBack.dataType).toBe('phone');
    // 既有字段未被本次改动破坏
    expect(String(readBack.targetUserId)).toBe(String(targetId));
    expect(readBack.targetUsername).toBe(`${stamp}_target`);
  });

  test('四个字段缺省时不报错（事件型审计不传这些字段是常态）', async () => {
    const created = await AuditLog.create({
      action: 'mfa_challenge',
      category: 'auth',
      username: stamp,
      success: true,
    });
    const readBack = await AuditLog.findById(created._id).lean();
    expect(readBack.targetType).toBeUndefined();
    expect(readBack.targetId).toBeUndefined();
    expect(readBack.dataType).toBeUndefined();
    expect(readBack.description).toBeUndefined();
  });
});
