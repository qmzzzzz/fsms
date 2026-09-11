const request = require('supertest');

describe('app.js startup behavior', () => {
  const saved = {};

  beforeAll(() => {
    ['NODE_ENV', 'TRUST_PROXY_HOPS', 'ENABLE_API_DOCS', 'DOCS_USERNAME', 'DOCS_PASSWORD'].forEach(
      (key) => {
        saved[key] = process.env[key];
      }
    );
    process.env.NODE_ENV = 'development';
    process.env.TRUST_PROXY_HOPS = 'not-a-number';
    process.env.ENABLE_API_DOCS = 'true';
    process.env.DOCS_USERNAME = 'docs';
    process.env.DOCS_PASSWORD = 'docs-secret';
  });

  afterAll(() => {
    Object.entries(saved).forEach(([key, value]) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    });
  });

  test('warns for invalid proxy hops and falls back to one development hop', () => {
    const { createApp } = require('../../app');
    const app = createApp();
    expect(app.get('trust proxy')).toBe(1);
  });

  test('serves the OpenAPI document behind configured Basic Auth', async () => {
    const { createApp } = require('../../app');
    const app = createApp();
    const res = await request(app)
      .get('/api-docs.json')
      .set('Authorization', `Basic ${Buffer.from('docs:docs-secret').toString('base64')}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ openapi: expect.any(String) });
  });
});
