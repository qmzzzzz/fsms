/**
 * 合规门禁自检（L-25 同族：门禁自身不得误报）
 *
 * 背景：scripts/compliance-check.js 的「审计导出接口」检查曾长期误报
 * 「exportAuditLogs 未定义」——因为它查的是 securityController，
 * 而该函数实际位于 auditController.js（securityRoutes.js:248 引用）。
 *
 * 门禁指向错位置的红灯比没有门禁更危险：它会训练出「红灯可忽略」的习惯。
 * 本测试把「门禁必须能对真实代码判绿」固化为回归断言。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');

describe('合规门禁 · 审计导出接口检查（L-25 同族回归）', () => {
  it('auditController.exportAuditLogs 已定义', () => {
    const auditController = require(path.join(ROOT, 'src/controllers/auditController'));
    expect(typeof auditController.exportAuditLogs).toBe('function');
  });

  it('该函数确实挂在 GET /audit-logs/export 路由上', () => {
    const routesSrc = fs.readFileSync(path.join(ROOT, 'src/routes/securityRoutes.js'), 'utf8');
    expect(routesSrc).toMatch(/\/audit-logs\/export[\s\S]{0,200}?auditController\.exportAuditLogs/);
  });

  it('门禁脚本检查的是路由实际挂载的控制器，而非同名函数的旧位置', () => {
    const gateSrc = fs.readFileSync(path.join(ROOT, 'scripts/compliance-check.js'), 'utf8');
    // 必须引用 auditController（正确位置）
    expect(gateSrc).toMatch(/require\(['"][^'"]*controllers\/auditController['"]\)/);
    // 不得再回退到 securityController 查这个函数
    expect(gateSrc).not.toMatch(/securityController\.exportAuditLogs/);
  });

  it('门禁脚本可独立执行且退出码为 0（就绪）', () => {
    const { execFileSync } = require('child_process');
    const out = execFileSync(process.execPath, [path.join(ROOT, 'scripts/compliance-check.js')], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(out).toContain('总体: 就绪');
  });
});
