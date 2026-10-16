/**
 * 导出侧真实姓名脱敏（A4，2026-10-16）
 *
 * 缺口形状：`reportExportService` 的行变换取 `item.handler.realName || item.handler.username`
 * ——**明文真实姓名进导出文件**。报表导出是典型的「数据离开受控边界」场景
 * （文件会被转发、落到个人电脑），而同一处的 `reporter.phone` 早已被投影收窄挡住。
 *
 * 本文件钉三层（缺一层就留假绿空间）：
 *   ① 判据层：掩码开关真的改变输出，且 realName 缺省时退回 username 的**原行为**不变；
 *   ② 接线层：开关必须从控制器一路流到行变换（`createSafeTransform` 的 options 透传、
 *      workbook service 的形参）——"语义对了但没接线"是这类修复最常见的落地失败形态；
 *   ③ 反向自证：不传开关时姓名必须仍是明文，否则 ① 的 `toBe('张*')` 可能只是因为
 *      默认就掩码（那会让所有既有导出件静默变样，是另一个方向的回归）。
 */

const fs = require('fs');
const path = require('path');

const {
  EXPORT_ROW_TRANSFORMS,
  createSafeTransform,
  PII_NAME_EXPORT_TYPES,
  auditUnmaskedPiiExport,
} = require('../../services/reportExportService');
const { DataMasking } = require('../../utils/encryption');

const HANDLER = { realName: '张伟明', username: 'zhangwm' };
const NO_NAME = { username: 'liulei' };

describe('导出侧真实姓名脱敏（A4）', () => {
  test('掩码开关真的改变输出：默认掩码，显式 false 时给全文', () => {
    const masked = EXPORT_ROW_TRANSFORMS.alarms({ handler: HANDLER }, { maskPii: true });
    const full = EXPORT_ROW_TRANSFORMS.alarms({ handler: HANDLER }, { maskPii: false });

    expect(masked.handler).toBe(DataMasking.maskName('张伟明')); // 张*明
    expect(masked.handler).toBe('张*明');
    expect(full.handler).toBe('张伟明');
  });

  test('反向自证：不传 options（旧调用方）时姓名保持明文——脱敏是**每请求**判据，不是新默认', () => {
    // 若这里变成掩码，说明开关被写成了模块级默认，所有既有导出件会静默变样
    expect(EXPORT_ROW_TRANSFORMS.alarms({ handler: HANDLER }).handler).toBe('张伟明');
    expect(createSafeTransform(EXPORT_ROW_TRANSFORMS.alarms)({ handler: HANDLER }).handler).toBe(
      '张伟明'
    );
  });

  test('realName 缺省时退回 username 且**不掩码**：username 是账号标识，掩掉会毁掉可追溯性', () => {
    expect(EXPORT_ROW_TRANSFORMS.alarms({ handler: NO_NAME }, { maskPii: true }).handler).toBe(
      'liulei'
    );
  });

  test('inspections 的执行人（多值）逐个掩码，空数组仍回占位符', () => {
    const row = EXPORT_ROW_TRANSFORMS.inspections(
      { assignedTo: [{ realName: '李四', username: 'lisi' }, NO_NAME] },
      { maskPii: true }
    );
    expect(row.assignedTo).toBe('李*, liulei');

    const empty = EXPORT_ROW_TRANSFORMS.inspections({ assignedTo: [] }, { maskPii: true });
    expect(empty.assignedTo).toBe('-');
  });

  test('options 穿过 createSafeTransform 的公式注入包装仍生效（接线层）', () => {
    const row = createSafeTransform(EXPORT_ROW_TRANSFORMS.alarms, { maskPii: true })({
      handler: HANDLER,
    });
    expect(row.handler).toBe('张*明');
  });

  test('掩码实现复用仓内既有 DataMasking.maskName，不另造一份', () => {
    // 反向：若有人把掩码写成 `name[0] + '***'`，这条会红
    const names = ['张伟明', '李四', '王'];
    for (const n of names) {
      const out = EXPORT_ROW_TRANSFORMS.alarms(
        { handler: { realName: n } },
        { maskPii: true }
      ).handler;
      expect(out).toBe(DataMasking.maskName(n));
    }
  });

  test('判据集合只有一处：携带姓名的报表类型 = alarms / inspections', () => {
    expect([...PII_NAME_EXPORT_TYPES].sort()).toEqual(['alarms', 'inspections']);
    // devices 无人员列、audit 只有 username ⇒ 不该被当成 PII 姓名报表
    expect(PII_NAME_EXPORT_TYPES).not.toContain('devices');
    expect(PII_NAME_EXPORT_TYPES).not.toContain('audit');
  });
});

describe('A4 接线闸（只登记不接线 = 缺陷）', () => {
  const squash = (p) =>
    fs
      .readFileSync(path.resolve(__dirname, p), 'utf8')
      .replace(/\/\/[^\n]*/g, '')
      .replace(/\s+/g, '');

  test('maskPii 从 workbook service 形参流到 createSafeTransform', () => {
    const wb = squash('../../services/reportWorkbookService.js');
    expect(wb).toContain('{type,query,total=null,collation=null,maskPii=false}');
    expect(wb).toContain('createSafeTransform(EXPORT_ROW_TRANSFORMS[type],{maskPii})');
  });

  test('控制器：脱敏档由 system:read 判定，且把 maskPii 交给 writeExportWorkbook', () => {
    const ctrl = squash('../../controllers/reportController.js');
    expect(ctrl).toContain("hasPermission(req.user.userId,'system:read')");
    expect(ctrl).toContain('constmaskPii=awaitresolveExportMasking(req,type)');
    expect(ctrl).toContain('...collationOptions,maskPii,}');
  });

  test('控制器：全文导出路径必须留痕（提权路径不能被静默放过）', () => {
    const ctrl = squash('../../controllers/reportController.js');
    expect(ctrl).toContain('auditFullPiiExportIfAny(req,type,exportTotal,maskPii)');
    expect(ctrl).toContain('clientIpForSecurityDecision(req)');
    // 反向：掩码档不得也写一条（否则真正的提权事件被淹没）
    expect(ctrl).toContain('if(maskPii||!PII_NAME_EXPORT_TYPES.includes(type))return');
  });

  test('留痕用的 action 是既有白名单动作，不新增枚举', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    expect(AUDIT_LOG_ACTIONS).toContain('view_sensitive_data');
    const svc = fs.readFileSync(
      path.resolve(__dirname, '../../services/reportExportService.js'),
      'utf8'
    );
    expect(svc).toContain("action: 'view_sensitive_data'");
  });

  test('审计落库失败不得冒泡（导出已完成，不能顶成 500）', async () => {
    // 直接驱动该函数：把 AuditLog.create 换成必然抛错的实现，函数必须正常 resolve
    const AuditLog = require('../../models/AuditLog');
    const original = AuditLog.create;
    AuditLog.create = jest.fn().mockRejectedValue(new Error('模拟落库失败'));
    try {
      await expect(
        auditUnmaskedPiiExport({ userId: 'u1', username: 'alice', type: 'alarms', total: 3 })
      ).resolves.toBeUndefined();
      expect(AuditLog.create).toHaveBeenCalled();
    } finally {
      AuditLog.create = original;
    }
  });
});
