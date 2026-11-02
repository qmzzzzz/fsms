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
    // lang 与 maskPii 一样是**每请求**判据，必须一并透传（否则英文界面导出的仍是中文标签）
    expect(wb).toContain(
      "{type,query,total=null,collation=null,maskPii=false,lang='zh',watermark=null}"
    );
    // A-8：水印四路同号之三/四（表尾可见行 + 响应头），且只在 watermark 非空时落
    // italic 是自研写入器挑水印样式的唯一依据（xlsxWriter 按 font.italic===true 施加
    // STYLE_WATERMARK）——所以它必须长在这次调用里，不能事后赋值（那会被静默丢掉样式）
    expect(wb).toContain('worksheet.addRow([watermark.text],{font:{italic:true}})');
    expect(wb).toContain('res.setHeader(TRACE_HEADER,watermark.traceId)');
    expect(wb).toContain('filename=watermark');
    expect(wb).toContain('createSafeTransform(EXPORT_ROW_TRANSFORMS[type],{maskPii,lang})');
  });

  test('控制器：脱敏档由 pii:export 判定，且把 maskPii 交给 writeExportWorkbook', () => {
    const ctrl = squash('../../controllers/reportController.js');
    // L-17：判据从 system:read 收窄为 pii:export（只读管理员不再顺带拿全文导出权）
    expect(ctrl).toContain("hasPermission(req.user.userId,'pii:export')");
    expect(ctrl).not.toContain("hasPermission(req.user.userId,'system:read')");
    expect(ctrl).toContain('if(req.forceMaskPii)returntrue');
    expect(ctrl).toContain('constmaskPii=awaitresolveExportMasking(req,type)');
    expect(ctrl).toContain('...collationOptions,maskPii,lang,watermark,}');
    // A-8：水印由同一处判据生成，并同时喂给「写出」与「留痕」两条腿
    expect(ctrl).toContain('constwatermark=piiExportWatermarkFor(req,{type,maskPii,lang})');
  });

  test('路由：GET 恒掩码，未脱敏只经 POST /export/pii 且叠加 pii:export + 二次验证', () => {
    const routes = squash('../../routes/reportRoutes.js');
    // GET 必须挂 forceMaskPii —— 否则持 pii:export 的会话可绕过步进验证直接 GET 全文
    expect(routes).toContain(
      "checkPermission('report:export'),strictLimiter,forceMaskPii,reportController.exportReport"
    );
    // POST 的权限与二次验证一个都不能少
    expect(routes).toContain("router.post('/export/pii',authenticate,requirePiiExportType,");
    expect(routes).toContain(
      "checkPermission('report:export'),checkPermission('pii:export'),requirePiiExportQuota,requireReAuthentication(),reportController.exportReport"
    );
    // A-8：配额闸也得在二次验证之前——注定被配额拒绝的请求不该先烧掉凭据尝试
    expect(routes.indexOf('requirePiiExportQuota')).toBeLessThan(
      routes.indexOf('requireReAuthentication()')
    );
    expect(routes.lastIndexOf("checkPermission('pii:export')")).toBeLessThan(
      routes.lastIndexOf('requirePiiExportQuota')
    );
    // 类型闸必须在二次验证之前：注定 400 的请求不得消耗凭据尝试
    expect(routes.indexOf('requirePiiExportType')).toBeLessThan(
      routes.indexOf('requireReAuthentication()')
    );
  });

  test('控制器：全文导出路径必须留痕（提权路径不能被静默放过）', () => {
    const ctrl = squash('../../controllers/reportController.js');
    expect(ctrl).toContain('auditFullPiiExportIfAny(req,type,exportTotal,watermark)');
    expect(ctrl).toContain('clientIpForSecurityDecision(req)');
    // A-8：追溯号与用途随留痕一并落库（审计里没有追溯号就答不上「哪一次导出」）
    expect(ctrl).toContain('traceId:watermark.traceId,purpose:watermark.purpose');
    // 反向：掩码档不得也写一条（否则真正的提权事件被淹没）；判据为 watermark 非空
    expect(ctrl).toContain('if(!watermark)return');
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

  test('审计落库失败必须计入 audit_write_failed 指标（不得静默）', async () => {
    // 缺口形状（第 16 轮审计 P1-1）：旧实现在 catch 里只写一行 logger.error。
    // 此刻明文姓名已经写进 xlsx 并发出，而这条 create 是本次外流在审计库里唯一的
    // 留痕（掩码档由全局中间件覆盖，未脱敏档刻意不写第二条）。审计库抖动时
    // "明文 PII 外流 + 零留痕"在监控面完全不可见——日志会淹没在噪声里。
    // 判据钉在指标上，而不是"有没有写日志"：日志无法被门禁观测，指标可以。
    const metrics = require('../../utils/metrics');
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
    const AuditLog = require('../../models/AuditLog');
    const original = AuditLog.create;
    AuditLog.create = jest.fn().mockRejectedValue(new Error('模拟落库失败'));
    try {
      await auditUnmaskedPiiExport({ userId: 'u1', username: 'alice', type: 'alarms', total: 3 });
      expect(alertSpy).toHaveBeenCalledWith('audit_write_failed', 'high');
    } finally {
      AuditLog.create = original;
      alertSpy.mockRestore();
    }
  });

  test('审计落库成功时不得计入 audit_write_failed（否则指标恒亮=假信号）', async () => {
    // 反向对照：本文件不连库，真实的 AuditLog.create 必然 reject，
    // 那样这条会因"确实失败了"而变红——红的理由不对。显式打桩成成功，
    // 钉的才是"成功路径不得计指标"这一条。
    const metrics = require('../../utils/metrics');
    const alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
    const AuditLog = require('../../models/AuditLog');
    const original = AuditLog.create;
    AuditLog.create = jest.fn().mockResolvedValue({ _id: 'audit-ok' });
    try {
      await auditUnmaskedPiiExport({ userId: 'u1', username: 'alice', type: 'alarms', total: 3 });
      expect(alertSpy).not.toHaveBeenCalledWith('audit_write_failed', 'high');
    } finally {
      AuditLog.create = original;
      alertSpy.mockRestore();
    }
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

/**
 * 静态闸：任何记「未脱敏 PII 外流」的审计写入点，失败时都必须有监控信号
 *
 * 为什么要单独一条静态判据：上面的行为用例只钉住了 reportExportService 这一个
 * 函数。而真正常见的落地失败形态是「新写一个 PII 外流留痕点，catch 里只 logger.error」
 * ——行为用例管不到还不存在的函数。这条扫的是**判据**（写入点写法），
 * 让同类新增点直接变红。
 *
 * 判据取 dataType: 'export_realname'：它是审计表里唯一表示"这份文件带明文姓名"
 * 的标记（AuditLog.dataType maxlength:20）。谁写它，谁就必须在失败时喊一声。
 */
describe('静态闸：未脱敏 PII 外流留痕点必须接失败信号', () => {
  const SRC = path.resolve(__dirname, '../..');
  const SKIP = new Set(['node_modules', 'tests']);

  const listFiles = (dir, out = []) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (SKIP.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) listFiles(full, out);
      else if (entry.name.endsWith('.js')) out.push(full);
    }
    return out;
  };

  const isPiiEgressAuditSite = (src) =>
    /AuditLog\.create\(/.test(src) && /dataType:\s*'export_realname'/.test(src);

  test('每个写入点所在的文件都必须引用 onAuditWriteFailure（否则失败只剩日志噪声）', () => {
    const sites = listFiles(SRC).filter((file) =>
      isPiiEgressAuditSite(fs.readFileSync(file, 'utf8'))
    );
    // 前提自证：今天恰好有一个这样的点。低于 1 说明判据本身失效（正则拼错/标记改名），
    // 那样这条会变成永远绿的空转——比不写更糟。
    expect(sites.length).toBeGreaterThanOrEqual(1);
    for (const file of sites) {
      const rel = path.relative(SRC, file).replace(/\\/g, '/');
      const src = fs.readFileSync(file, 'utf8');
      expect({ file: rel, guarded: /onAuditWriteFailure/.test(src) }).toEqual({
        file: rel,
        guarded: true,
      });
    }
  });

  test('反向对照：把守卫去掉的文件必须被同一条判据点名', () => {
    const target = listFiles(SRC).find((file) =>
      isPiiEgressAuditSite(fs.readFileSync(file, 'utf8'))
    );
    expect(target).toBeTruthy();
    const src = fs.readFileSync(target, 'utf8');
    const mutated = src.replace(/onAuditWriteFailure/g, 'logger.error');
    expect(/onAuditWriteFailure/.test(mutated)).toBe(false);
    // 判据在变异后必须变红，否则上面那条的绿没有意义
    expect(isPiiEgressAuditSite(mutated)).toBe(true);
    expect(/onAuditWriteFailure/.test(mutated)).toBe(false);
  });
});
