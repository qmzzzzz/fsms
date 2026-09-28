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
    // 【本次改动改造：源码正则 → 行为断言】原用例断言 security.js 源码里出现
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

/**
 * F-124：键名里的噪声不得让凭据漏网（名单一致 + 判定一致）
 *
 * 判据形状是"插在名单词中间"：`pass\u0000word`、`to\u0000ken`、`se\u0000cret`。
 * 落在首尾的噪声早已被 stripControlChars 的 trim 处理掉，插在中间则把子串切断，
 * 于是明文口令进 append-only、定期导出 CSV 的审计集合。
 * 两类形态都必须钉住，因为两条链路的清洗/脱敏先后不同：
 *   · 清洗之前 ⇒ 键里是原始控制字符（models 侧 sanitizeAuditBody）；
 *   · 清洗之后 ⇒ 控制字符变成空格（stripControlChars 是"换成空格"，`pass word`）。
 */
describe('auditLogSanitizer — 键名噪声不得绕过脱敏（F-124）', () => {
  const SECRET = 'PLAIN-LEAK-9E2C';
  // 必须走 JSON.parse：对象字面量里写 \u0000 与真实请求体的键名同源（express.json 也是 JSON.parse）
  const noisy = () =>
    JSON.parse(
      `{"pass\\u0000word":"${SECRET}","to\\u0000ken":"${SECRET}","se\\u0000cret":"${SECRET}","nested":{"mfa\\u0000code":"${SECRET}"},"arr":[{"api\\u0000key":"${SECRET}"}]}`
    );
  // 反例集合：删掉空白后仍不该命中名单的业务键（ postcode/zipcode 是既有判据，
  // `confirm password` 这类"空格在词外"的键今天已能命中，一并放进来看住不回退）
  const business = () =>
    JSON.parse(`{"zip code":"KEEP1","postcode":"KEEP2","user name":"KEEP3","theme":"KEEP4"}`);

  test('models 侧：控制字符切断名单词也必须打码（含嵌套与数组元素）', () => {
    const out = sanitizeAuditBody(noisy());
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out['pass\u0000word']).toBe('***');
    expect(out.nested['mfa\u0000code']).toBe('***');
    expect(out.arr[0]['api\u0000key']).toBe('***');
  });

  test('清洗之后的空格形态同样打码（strip∘sanitize 与 sanitize∘strip 口径一致）', () => {
    const { stripControlCharsDeep } = require('../../utils/helpers');
    for (const doc of [
      stripControlCharsDeep(sanitizeAuditBody(noisy())),
      sanitizeAuditBody(stripControlCharsDeep(noisy())),
    ]) {
      expect(JSON.stringify(doc)).not.toContain(SECRET);
    }
    // 空格形态的键名（清洗后）确实存在，否则本用例只是在测原始形态
    const stripped = stripControlCharsDeep(noisy());
    expect(stripped['pass word']).toBeDefined();
    expect(sanitizeAuditBody(stripped)['pass word']).toBe('***');
  });

  test('不误伤：删噪声后仍不含名单词的业务键保持可读', () => {
    const out = sanitizeAuditBody(business());
    expect(out).toEqual({
      'zip code': 'KEEP1',
      postcode: 'KEEP2',
      'user name': 'KEEP3',
      theme: 'KEEP4',
    });
  });

  test('middleware 侧真实驱动：内联副本不得再自成一套判定', async () => {
    const express = require('express');
    const request = require('supertest');
    const auditBuffer = require('../../services/auditBuffer');
    const { auditLog } = require('../../middleware/security');
    const spyPush = jest.spyOn(auditBuffer, 'push');

    const app = express();
    app.use(express.json());
    app.use('/api/', auditLog());
    app.post('/api/probe', (req, res) => res.json({ ok: true }));

    try {
      const res = await request(app)
        .post('/api/probe')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ ...noisy(), ...business() }));
      expect(res.status).toBe(200);
      await new Promise((r) => setImmediate(r));

      const pushed = spyPush.mock.calls
        .map(([doc]) => doc)
        .filter((d) => d && d.path === '/api/probe');
      expect(pushed).toHaveLength(1);
      const serialized = JSON.stringify(pushed[0].body);
      // 凭据不得以明文出现（中间件侧会把键名清洗成 `pass word`，值必须已是 ***）
      expect(serialized).not.toContain(SECRET);
      // 业务键必须活着：防"整片抹掉"式假修复
      for (const keep of ['KEEP1', 'KEEP2', 'KEEP3', 'KEEP4']) expect(serialized).toContain(keep);
    } finally {
      spyPush.mockRestore();
    }
  });
});
