/**
 * pii 模块的高敏判定（2026-10-31 审计二-1）
 *
 * 缺陷形状：目录里登记着 `pii:*`（权限树与播种都要求每个 code 前缀有对应通配符），
 * 而临时授权的高敏判据只看**模块前缀**。`pii` 原先落在 KNOWN_MODULES 的低敏侧
 * ⇒ `pii:*` 单人签批即可授予 ⇒ 它覆盖 `pii:export`，等于让"未脱敏 PII 导出"
 * 这条本就单人可完成的路径再省掉一次复核，与 `system:read` 需双人的口径不自洽。
 *
 * 本套件盯三件事，缺一条结论就不成立：
 *   ① 判据结果：pii 前缀的通配码与具体码都必须进双人档（本文件是唯一断点）；
 *   ② 判据不是"巧合成立"：`pii` 必须**已登记**在 KNOWN_MODULES 里——
 *      否则它只是因为"未登记模块一律按高敏"这条 fail-closed 兜底而显得正确，
 *      哪天有人在 KNOWN_MODULES 里补登记 `pii`（本仓确有这条对账压力），
 *      同一条码就会静默降级回单人档；
 *   ③ 判据有对象：目录里确实存在 `pii:*` 与 `pii:export`——没有对象的防线是空防。
 */

const {
  HIGH_RISK_MODULES,
  KNOWN_MODULES,
  isHighRiskCode,
  approvalPolicyOf,
} = require('../../constants/privilegeGrant');
const { defaultPermissions } = require('../../services/initData/permissions');

const HIGH_RISK_SET = new Set(HIGH_RISK_MODULES);

describe('pii：高敏模块清单与判定', () => {
  test('pii 已登记在 KNOWN_MODULES 且同时在高敏侧（不是靠 fail-closed 兜底）', () => {
    expect(KNOWN_MODULES).toContain('pii');
    expect(HIGH_RISK_MODULES).toContain('pii');
    expect(HIGH_RISK_SET.has('pii')).toBe(true);
  });

  test.each(['pii:*', 'pii:export', 'pii:read'])('%s 按高敏处理（双人签批）', (code) => {
    expect(isHighRiskCode(code)).toBe(true);
    expect(approvalPolicyOf([code])).toEqual({ highRisk: true, requiredApprovals: 2 });
  });

  test('混入任一 pii 码即整体双人（只算命中数，不按条数摊薄）', () => {
    expect(approvalPolicyOf(['report:read', 'report:export', 'pii:*'])).toEqual({
      highRisk: true,
      requiredApprovals: 2,
    });
  });

  test('低敏业务模块不受影响：device / alarm / inspection / report 仍单人签批', () => {
    for (const code of ['device:read', 'alarm:read', 'inspection:read', 'report:export']) {
      expect(approvalPolicyOf([code])).toEqual({ highRisk: false, requiredApprovals: 1 });
    }
  });
});

describe('pii：判据的对象确实存在（否则是空防）', () => {
  test('目录里登记着 pii:* 通配码与 pii:export（本判据覆盖的正是这两条）', () => {
    const codes = defaultPermissions.map((item) => item.code);
    expect(codes).toContain('pii:*');
    expect(codes).toContain('pii:export');
  });

  test('通配码的前缀就是模块判据的输入（判据读 code 前缀，不读 Permission.module）', () => {
    const wildcard = defaultPermissions.find((item) => item.code === 'pii:*');
    expect(wildcard).toBeDefined();
    // 播种里 pii 码的 module 字段沿用 'report'（不新增界面模块），
    // 所以判据必须取 code 前缀 —— 若改读文档 module 字段，这条防线立刻失效
    expect(wildcard.module).not.toBe('pii');
    expect(approvalPolicyOf([wildcard.code]).requiredApprovals).toBe(2);
  });
});
