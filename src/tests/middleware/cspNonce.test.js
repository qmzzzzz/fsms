/**
 * L-5：CSP style-src 去 unsafe-inline —— 行为级验证
 *
 * 覆盖：
 * - 普通路径：style-src 含每请求 'nonce-...'，且不含 'unsafe-inline'；
 * - 两次请求的 nonce 不同（每请求随机）；
 * - /api-docs（及子路径）：style-src 放行 'unsafe-inline'，不含 nonce；
 * - nonce 为合法 base64（16 字节熵）。
 */

const express = require('express');
const request = require('supertest');

const { attachCspNonce, securityHeaders } = require('../../middleware/security');

function buildApp() {
  const app = express();
  app.use(attachCspNonce);
  app.use(securityHeaders);
  app.use((req, res) => res.json({ ok: true }));
  return app;
}

const parseStyleSrc = (csp) => {
  const m = csp
    .split(';')
    .map((d) => d.trim())
    .find((d) => d.startsWith('style-src'));
  return m || '';
};

describe('CSP nonce（L-5）', () => {
  test('普通路径 style-src 含 nonce 且无 unsafe-inline', async () => {
    const res = await request(buildApp()).get('/api/anything').expect(200);
    const styleSrc = parseStyleSrc(res.headers['content-security-policy']);
    expect(styleSrc).toMatch(/'nonce-[A-Za-z0-9+/=]+'/);
    expect(styleSrc).not.toContain("'unsafe-inline'");
  });

  test('nonce 每请求随机且为 16 字节 base64', async () => {
    const app = buildApp();
    const r1 = await request(app).get('/a');
    const r2 = await request(app).get('/a');
    const nonceOf = (csp) => parseStyleSrc(csp).match(/'nonce-([A-Za-z0-9+/=]+)'/)[1];
    const n1 = nonceOf(r1.headers['content-security-policy']);
    const n2 = nonceOf(r2.headers['content-security-policy']);
    expect(n1).not.toBe(n2);
    expect(Buffer.from(n1, 'base64').length).toBe(16);
  });

  test('/api-docs 放行 unsafe-inline 且不下发 nonce', async () => {
    const res = await request(buildApp()).get('/api-docs').expect(200);
    const styleSrc = parseStyleSrc(res.headers['content-security-policy']);
    expect(styleSrc).toContain("'unsafe-inline'");
    expect(styleSrc).not.toContain("'nonce-");
  });

  test('/api-docs 子路径同样放行', async () => {
    const res = await request(buildApp()).get('/api-docs/swagger-ui.css').expect(200);
    const styleSrc = parseStyleSrc(res.headers['content-security-policy']);
    expect(styleSrc).toContain("'unsafe-inline'");
  });

  test('script-src 不受影响（仍仅 self）', async () => {
    const res = await request(buildApp()).get('/api/anything').expect(200);
    const csp = res.headers['content-security-policy'];
    expect(csp).toMatch(/script-src 'self'/);
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
  });

  /**
   * 文档路径判定必须与路由用同一把尺（大小写不敏感 + 段边界）。
   * 手写的 `=== '/api-docs' || startsWith('/api-docs/')` 会让 `/API-docs`
   * 命中 Swagger 路由（本仓 app.set('case sensitive routing') 为默认 false）
   * 却判为"非文档路径" ⇒ 给它下发 nonce，而 Swagger UI 自注入的内联 <style>
   * 带不上这个 nonce，页面直接白屏。方向是"变严"，所以不是漏洞，是功能断裂。
   */
  test('文档路径的大小写变体与相似前缀路径各按应有结论', async () => {
    const upper = await request(buildApp()).get('/API-docs').expect(200);
    expect(parseStyleSrc(upper.headers['content-security-policy'])).toContain("'unsafe-inline'");

    const mixed = await request(buildApp()).get('/API-Docs/swagger-ui.css').expect(200);
    expect(parseStyleSrc(mixed.headers['content-security-policy'])).toContain("'unsafe-inline'");

    // 反向对照：只是"前缀相似"而非段边界的路径不得被放宽（防按字面 startsWith 误放）
    const lookalike = await request(buildApp()).get('/api-docsX').expect(200);
    expect(parseStyleSrc(lookalike.headers['content-security-policy'])).toContain("'nonce-");
    expect(parseStyleSrc(lookalike.headers['content-security-policy'])).not.toContain(
      "'unsafe-inline'"
    );
  });
});
