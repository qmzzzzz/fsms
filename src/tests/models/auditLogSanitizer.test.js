/**
 * 审计 body 脱敏名单统一（评价报告 #10）
 *
 * 此前 middleware/security.js 内联名单与 models/auditLogSanitizer.js 名单
 * 各自维护（前者缺 secret/apikey），同一审计体两条路径脱敏口径不一，
 * 可能明文入库。修复后 security.js 复用 auditLogSanitizer 导出的
 * SENSITIVE_KEYS 作为单一事实来源。
 */

const { sanitizeAuditBody, SENSITIVE_KEYS } = require('../../models/auditLogSanitizer');

describe('auditLogSanitizer — 脱敏名单单一事实来源（#10）', () => {
  test('名单包含完整敏感键集合（含 secret / apikey）', () => {
    const missing = ['password', 'token', 'refreshtoken', 'secret', 'apikey', 'mfacode'].filter(
      (k) => !SENSITIVE_KEYS.includes(k)
    );
    expect(missing).toEqual([]);
  });

  test('sanitizeAuditBody 递归脱敏 secret / apikey / 嵌套字段', () => {
    const cleaned = sanitizeAuditBody({
      password: 'plain',
      apiSecret: 'sk-123',
      apikey: 'key-456',
      nested: { currentPassword: 'x', inner: { token: 't' } },
      safe: 'keep-me',
    });
    expect(cleaned.password).toBe('***');
    expect(cleaned.apiSecret).toBe('***');
    expect(cleaned.apikey).toBe('***');
    expect(cleaned.nested.currentPassword).toBe('***');
    expect(cleaned.nested.inner.token).toBe('***');
    expect(cleaned.safe).toBe('keep-me');
  });

  test('middleware/security.js 与 auditLogSanitizer 复用同一名单', () => {
    // 经 require 链路验证：security.js 从 auditLogSanitizer 引入 SENSITIVE_KEYS，
    // 两处名单必须恒等（防再次漂移）
    require('../../middleware/security');
    // security.js 未直接导出名单；此处通过 source 断言其引用同一来源，
    // 防止重新硬编码一份独立数组
    const src = require('fs').readFileSync(require.resolve('../../middleware/security'), 'utf8');
    expect(src).toContain('AUDIT_SENSITIVE_KEYS');
    expect(src).toMatch(/SENSITIVE_KEYS\s*=\s*AUDIT_SENSITIVE_KEYS/);
    // 名单本身必须与审计模型侧一致（前面用例已断言名单含 secret/apikey）
  });
});
