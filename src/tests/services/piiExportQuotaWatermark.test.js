/**
 * 未脱敏 PII 导出的配额与水印（审计 A-8）
 *
 * 两条控制各有独立的失效形态，都要能被证伪：
 *   - 配额：过滤条件与留痕写入侧不同形 ⇒ 计数恒为 0（静默失效）；窗口算错 ⇒ 跨零点双倍配额。
 *   - 水印：判据写反（掩码档也打标）或追溯号进不了文件 ⇒ "外流件能反查导出人"就是空话。
 * 每个正向用例都配一条负前提，避免"判据其实恒真/恒假"也能绿。
 */

const mongoose = require('mongoose');
const AuditLog = require('../../models/AuditLog');
const { WINDOW_MS, DAILY_QUOTA, checkPiiExportQuota } = require('../../services/piiExportQuota');
const {
  PURPOSE_MAX,
  normalizePurpose,
  piiExportWatermarkFor,
} = require('../../services/piiExportWatermark');

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
});

afterAll(async () => {
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});

/** 每条用例独立的用户：本文件内的计数互不串味（也证明计数确实按 userId 分流） */
const freshUser = () => new mongoose.Types.ObjectId();

const exportRow = (userId, timestamp) => ({
  action: 'view_sensitive_data',
  category: 'report',
  userId,
  username: 'quota-user',
  dataType: 'export_realname',
  success: true,
  riskLevel: 'medium',
  timestamp,
});

describe('配额：滚动 24h 窗口与判据形状', () => {
  test('前提自证：限额是 1~100 的整数，窗口是 24 小时（基线被改小/改大都会先在这里红）', () => {
    expect(Number.isInteger(DAILY_QUOTA)).toBe(true);
    expect(DAILY_QUOTA).toBeGreaterThanOrEqual(1);
    expect(DAILY_QUOTA).toBeLessThanOrEqual(100);
    expect(WINDOW_MS).toBe(24 * 60 * 60 * 1000);
    expect(DAILY_QUOTA).toBe(5);
  });

  test('低水位放行且回显已用次数（计数不是恒 0 也不是恒满）', async () => {
    const userId = freshUser();
    const now = new Date();
    await AuditLog.create(exportRow(userId, new Date(now.getTime() - 60_000)));
    await AuditLog.create(exportRow(userId, new Date(now.getTime() - 120_000)));
    const verdict = await checkPiiExportQuota({ userId, now });
    expect(verdict).toMatchObject({ allowed: true, used: 2, limit: DAILY_QUOTA });
    expect(verdict.retryAfterSeconds).toBe(0);
  });

  test('到达上限即拒绝，Retry-After 指向"最早一次滑出窗口"还需多久', async () => {
    const userId = freshUser();
    const now = new Date();
    const oldest = new Date(now.getTime() - 60 * 60 * 1000);
    for (let i = 0; i < DAILY_QUOTA; i += 1) {
      await AuditLog.create(exportRow(userId, i === 0 ? oldest : now));
    }
    const verdict = await checkPiiExportQuota({ userId, now });
    expect(verdict.allowed).toBe(false);
    expect(verdict.used).toBe(DAILY_QUOTA);
    // 最早那条是 1 小时前 ⇒ 还需 23 小时；钳在窗口内且不为 0
    expect(verdict.retryAfterSeconds).toBeGreaterThan(22 * 3600);
    expect(verdict.retryAfterSeconds).toBeLessThanOrEqual(WINDOW_MS / 1000);
  });

  test('窗口外的行不算（否则配额一旦用满就永久不再释放）', async () => {
    const userId = freshUser();
    const now = new Date();
    const stale = new Date(now.getTime() - WINDOW_MS - 60_000);
    for (let i = 0; i < DAILY_QUOTA; i += 1) await AuditLog.create(exportRow(userId, stale));
    const verdict = await checkPiiExportQuota({ userId, now });
    expect(verdict).toMatchObject({ allowed: true, used: 0 });
  });

  test('负前提：同用户但别的 dataType/action 不计入（判据吃的是三元组，不只是 userId）', async () => {
    const userId = freshUser();
    const now = new Date();
    for (let i = 0; i < DAILY_QUOTA; i += 1) {
      await AuditLog.create({ ...exportRow(userId, now), dataType: 'view_field' });
      await AuditLog.create({ ...exportRow(userId, now), action: 'report_export' });
    }
    const verdict = await checkPiiExportQuota({ userId, now });
    expect(verdict).toMatchObject({ allowed: true, used: 0 });
  });

  test('另一用户的配额互不挤占（计数按 userId 分流）', async () => {
    const busy = freshUser();
    const idle = freshUser();
    const now = new Date();
    for (let i = 0; i < DAILY_QUOTA; i += 1) await AuditLog.create(exportRow(busy, now));
    expect((await checkPiiExportQuota({ userId: busy, now })).allowed).toBe(false);
    expect((await checkPiiExportQuota({ userId: idle, now })).allowed).toBe(true);
  });
});

describe('水印：判据与文案', () => {
  const req = (username, body) => ({
    user: { userId: 'u-1', username },
    body,
    headers: {},
    ip: '10.1.2.3',
  });

  test('负前提：掩码档与非姓名报表都不得打标（判据写反就是"每份导出都带追溯号"）', () => {
    expect(piiExportWatermarkFor(req('alice', {}), { type: 'alarms', maskPii: true })).toBeNull();
    expect(piiExportWatermarkFor(req('alice', {}), { type: 'devices', maskPii: false })).toBeNull();
    expect(piiExportWatermarkFor(req('alice', {}), { type: 'audit', maskPii: false })).toBeNull();
  });

  test('正向：未脱敏姓名报表必须有 16 位 hex 追溯号，且文案带导出人/追溯号/IP', () => {
    const wm = piiExportWatermarkFor(req('alice', { purpose: '  季度  报表  ' }), {
      type: 'alarms',
      maskPii: false,
      lang: 'zh',
    });
    expect(wm).toBeTruthy();
    expect(wm.traceId).toMatch(/^[0-9a-f]{16}$/);
    expect(wm.operator).toBe('alice');
    expect(wm.purpose).toBe('季度 报表');
    expect(wm.text).toContain('未脱敏导出');
    expect(wm.text).toContain('alice');
    expect(wm.text).toContain(wm.traceId);
  });

  test('英文界面用英文文案（与导出语言同一处判据）', () => {
    const wm = piiExportWatermarkFor(req('alice', {}), {
      type: 'alarms',
      maskPii: false,
      lang: 'en',
    });
    expect(wm.text).toContain('Unmasked export');
    expect(wm.text).not.toContain('未脱敏导出');
  });

  test('两次导出的追溯号不同（可预测的序号等于泄露"第几次导出"）', () => {
    const a = piiExportWatermarkFor(req('alice', {}), { type: 'alarms', maskPii: false });
    const b = piiExportWatermarkFor(req('alice', {}), { type: 'alarms', maskPii: false });
    expect(a.traceId).not.toBe(b.traceId);
  });

  test('用途字段：非字符串丢弃、空白折叠、超长截断（控制字符不得进单元格与文件属性）', () => {
    expect(normalizePurpose(undefined)).toBe('');
    expect(normalizePurpose(42)).toBe('');
    expect(normalizePurpose('  a\n\tb  ')).toBe('a b');
    expect(normalizePurpose('x'.repeat(PURPOSE_MAX + 50)).length).toBe(PURPOSE_MAX);
  });
});
