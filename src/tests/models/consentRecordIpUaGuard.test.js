/**
 * P3：ConsentRecord.ip / userAgent 与 AuditLog/UserSession 同族口径——
 * 请求方可控文本，落库前上界截断 + 控制字符中和（stripControlChars）。
 * 三个判据：控制字符被中和、超长截断到上限、非字符串原样交给既有校验器。
 * 探针控制字符用 String.fromCharCode 构造（源码不出现原始控制字符/控制正则）。
 */
const mongoose = require('mongoose');

const CONTROL_PROBES = [
  String.fromCharCode(0), // NUL
  String.fromCharCode(27), // ESC
  String.fromCharCode(7), // BEL
  String.fromCharCode(9), // TAB
  String.fromCharCode(8232), // LINE SEPARATOR
];

describe('ConsentRecord ip/userAgent 落库闸（P3）', () => {
  let ConsentRecord;
  let User;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    ConsentRecord = require('../../models/ConsentRecord');
    User = require('../../models/User');
  });

  afterAll(async () => {
    await ConsentRecord.deleteMany({ username: /^p3consent_/ }).catch(() => {});
    await User.deleteMany({ username: /^p3consent_/ }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const mkRecord = (overrides = {}) =>
    ConsentRecord.create({
      userId: new mongoose.Types.ObjectId(),
      username: 'p3consent_user',
      policy: 'privacy',
      version: '2026-11-01',
      scopes: ['basic'],
      acceptedAt: new Date(),
      source: 'self-register',
      ...overrides,
    });

  test('ip 的控制字符被中和并截断到 64，userAgent 截断到 512', async () => {
    const dirtyIp =
      '203.0.113.7' +
      String.fromCharCode(0) +
      String.fromCharCode(27) +
      '[31m' +
      String.fromCharCode(9) +
      'x'.repeat(100);
    const dirtyUa =
      'Mozilla/5.0' + String.fromCharCode(8232) + 'evil' + String.fromCharCode(7) + 'a'.repeat(600);
    const rec = await mkRecord({ ip: dirtyIp, userAgent: dirtyUa });
    const cleanHead = '203.0.113.7' + '  [31m ';
    expect(rec.ip).toBe(cleanHead + 'x'.repeat(64 - cleanHead.length));
    expect(rec.ip.length).toBeLessThanOrEqual(64);
    expect(rec.userAgent.length).toBeLessThanOrEqual(512);
    for (const ch of CONTROL_PROBES) {
      expect(rec.userAgent.includes(ch)).toBe(false);
      expect(rec.ip.includes(ch)).toBe(false);
    }
    expect(rec.userAgent.startsWith('Mozilla/5.0 evil')).toBe(true);
  });

  test('缺省/空值仍为空串（default 语义不变），合法短值原样保留', async () => {
    const rec = await mkRecord({ ip: '198.51.100.9', userAgent: 'ua/1.0' });
    expect(rec.ip).toBe('198.51.100.9');
    expect(rec.userAgent).toBe('ua/1.0');
    const bare = await mkRecord();
    expect(bare.ip).toBe('');
    expect(bare.userAgent).toBe('');
  });
});
