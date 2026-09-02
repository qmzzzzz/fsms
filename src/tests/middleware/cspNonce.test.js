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
});
