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

  test('middleware/security.js 与 auditLogSanitizer 复用同一名单（真实中间件驱动）', async () => {
    // 【本轮改造：源码正则 → 行为断言】原用例断言 security.js 源码里出现
    // `SENSITIVE_KEYS = AUDIT_SENSITIVE_KEYS` 这行文本——把它改成一份独立的
    // 内联数组（漂移回原缺陷形态）而在注释里保留该字样，断言照样绿。
    // 现直接驱动 security.js 的 auditLog() 中间件：构造一个包含**全部**
    // SENSITIVE_KEYS（含时常被漏掉的 secret/apikey）的请求体，
    // 断言审计落库文档里这些键**全部**变成 '***'。
    // 若 security.js 重新硬编码一份缺少某键的名单，对应键会以明文出现 → 立即转红。
    const express = require('express');
    const request = require('supertest');
    const auditBuffer = require('../../services/auditBuffer');
    const { auditLog } = require('../../middleware/security');
    const spyPush = jest.spyOn(auditBuffer, 'push');

    const app = express();
    app.use(express.json());
    app.use('/api/', auditLog());
    app.post('/api/probe', (req, res) => res.json({ ok: true }));

    // 每个敏感键绑上可识别的明文值，方便失败时定位
    const body = {};
    SENSITIVE_KEYS.forEach((k, i) => {
      body[k] = `PLAINTEXT-${i}-${k}`;
    });
    body.safeField = 'keep-me';

    try {
      const res = await request(app).post('/api/probe').send(body);
      expect(res.status).toBe(200);
      await new Promise((r) => setImmediate(r));

      const pushed = spyPush.mock.calls
        .map(([doc]) => doc)
        .filter((d) => d && d.path === '/api/probe');
      expect(pushed).toHaveLength(1);
      const recorded = pushed[0].body;
      for (const k of SENSITIVE_KEYS) {
        expect(recorded[k]).toBe('***');
      }
      // 双重保障：整个序列化结果不得含任何明文标记
      const serialized = JSON.stringify(recorded);
      SENSITIVE_KEYS.forEach((k, i) => {
        expect(serialized).not.toContain(`PLAINTEXT-${i}-${k}`);
      });
      // 非敏感字段必须保留（防「全量抹掉」式假修复）
      expect(recorded.safeField).toBe('keep-me');
    } finally {
      spyPush.mockRestore();
    }
  });
});
