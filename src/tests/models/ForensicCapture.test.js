/**
 * ForensicCapture 模型（P2）：字段冻结面、索引、业务保留期 TTL 计划
 *
 * 被测对象：models/ForensicCapture.js（schema 声明）+ constants/businessRetention.js 的
 * resolveTtlIndexPlan('ForensicCapture')。
 *
 * 这条用例守两类"改坏了也未必红"的事：
 *  ① 字段名是跨 lane 冻结契约（任务书 §2.3），改名会让 P2b 清单/前端检索静默错位；
 *  ② 保留期 90 天若既没建 TTL 也没登记，数据会**永久保留**——声明与数据面相反，
 *     且没有任何信号（本仓出过同类事故，见 constants/retention.js 文件头）。
 */

const mongoose = require('mongoose');

describe('ForensicCapture 模型与保留期', () => {
  let ForensicCapture;

  beforeAll(async () => {
    ForensicCapture = require('../../models/ForensicCapture');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('冻结字段全部在 schema 上（§2.3 逐字，改名即红）', () => {
    const paths = ForensicCapture.schema.paths;
    const required = [
      'createdAt',
      'ip',
      'ipSegment',
      'method',
      'path',
      'action',
      'category',
      'userId',
      'username',
      'sessionId',
      'fingerprint',
      'trigger.reason',
      'trigger.markedAt',
      'request.headers',
      'request.body',
      'request.query',
      'request.params',
      'request.bodyBytes',
      'request.bodyTruncated',
      'request.bodySha256',
      'response.status',
      'response.headers',
      'response.body',
      'response.contentType',
      'response.bodyBytes',
      'response.bodyTruncated',
      'response.bodySha256',
      'device.ua',
      'device.browser',
      'device.os',
      'device.deviceType',
      'device.secChUa',
      'device.acceptLanguage',
      'device.acceptEncoding',
      'device.httpVersion',
      'device.tlsProtocol',
      'device.tlsCipher',
      'location.country',
      'location.province',
      'location.city',
      'location.isp',
      'location.text',
      'net.reportedIp',
      'net.socketPeer',
      'recordHash',
      'seq',
    ];
    const missing = required.filter((p) => !paths[p]);
    expect(missing).toEqual([]);
  });

  test('索引齐备：集合按 ip/ipSegment/fingerprint/createdAt 做检索（§2.1 的取值路径）', () => {
    const names = ForensicCapture.schema.indexes().map(([fields]) => JSON.stringify(fields));
    expect(names).toContain(JSON.stringify({ createdAt: -1 }));
    expect(names).toContain(JSON.stringify({ ip: 1, createdAt: -1 }));
    expect(names).toContain(JSON.stringify({ ipSegment: 1, createdAt: -1 }));
    expect(names).toContain(JSON.stringify({ fingerprint: 1, createdAt: -1 }));
  });

  test('落库往返：Mixed 头袋/体与 Date、recordHash 原样保真', async () => {
    const doc = {
      createdAt: new Date('2026-10-31T00:00:00Z'),
      ip: '203.0.113.7',
      ipSegment: '203.0.113.0/24',
      method: 'POST',
      path: '/api/probe',
      action: 'login',
      category: 'auth',
      username: 'bob',
      fingerprint: 'fp-1',
      trigger: { reason: 'honeypot_login', markedAt: new Date('2026-10-31T00:00:00Z') },
      request: {
        headers: { 'content-type': 'application/json', authorization: '[REDACTED]' },
        body: { password: { len: 18, hmac: 'a'.repeat(64) } },
        query: {},
        params: {},
        bodyBytes: 42,
        bodyTruncated: false,
        bodySha256: 'b'.repeat(64),
      },
      response: { status: 200, headers: {}, body: '{"ok":true}', contentType: 'application/json' },
      device: { ua: 'curl/8', browser: 'curl', os: null, deviceType: null },
      location: { text: null },
      net: { reportedIp: null, socketPeer: '203.0.113.7' },
      recordHash: 'c'.repeat(64),
      seq: 'run-1',
    };
    await ForensicCapture.deleteMany({ ip: doc.ip });
    await ForensicCapture.create(doc);
    const back = await ForensicCapture.findOne({ ip: doc.ip }).lean();
    expect(back.createdAt.toISOString()).toBe('2026-10-31T00:00:00.000Z');
    expect(back.trigger.markedAt.toISOString()).toBe('2026-10-31T00:00:00.000Z');
    expect(back.request.body).toEqual({ password: { len: 18, hmac: 'a'.repeat(64) } });
    expect(back.request.headers.authorization).toBe('[REDACTED]');
    expect(back.recordHash).toBe('c'.repeat(64));
    expect(back.seq).toBe('run-1');
    await ForensicCapture.deleteMany({ ip: doc.ip });
  });

  test('保留期计划：未配置 ⇒ days=null（无 TTL，数据常留且有原因）；配置 30 ⇒ 建 ttl_createdAt', () => {
    jest.isolateModules(() => {
      const {
        resolveTtlIndexPlan,
        BUSINESS_RETENTION_POLICY,
      } = require('../../constants/businessRetention');
      const policy = BUSINESS_RETENTION_POLICY.find((p) => p.modelName === 'ForensicCapture');
      expect(policy).toBeDefined();
      expect(policy.ttlField).toBe('createdAt');
      expect(policy.disposition).toBe('ttl');
      expect(policy.declaredDays).toBe(30);
      expect(policy.envKey).toBe('BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE');

      const prev = process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE;
      delete process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE;
      const off = resolveTtlIndexPlan('ForensicCapture');
      expect(off.days).toBeNull();
      expect(off.reason).toContain('BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE');

      process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE = '30';
      expect(resolveTtlIndexPlan('ForensicCapture')).toEqual({ days: 30, reason: null });

      // 低于取证下限（30 天，用户 2026-10-31 书面确认）必须被拒绝，不能静默降级成更短保留
      process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE = '7';
      const tooShort = resolveTtlIndexPlan('ForensicCapture');
      expect(tooShort.days).toBeNull();
      expect(tooShort.reason).toContain('30');

      if (prev === undefined) delete process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE;
      else process.env.BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE = prev;
    });
  });
});
