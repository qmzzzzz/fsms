/**
 * P3：配额日键改走业务时区（constants/timezone 单一口径），不再硬编码 UTC+8。
 *
 * 在独立测试文件里设置 TZ_BUSINESS 后重新加载被测模块（BUSINESS_TIMEZONE 在模块加载期定型）：
 * 洛杉矶时区下，UTC 2026-11-03T02:00Z 还是当地的 11-02 ⇒ 日键应为 20261102；
 * 若仍按 UTC+8 或 UTC 计算，会分别得到 20261103 / 20261103——两种错误写法都会在此变红。
 */
describe('piiExportQuota 配额日键按业务时区翻日（P3）', () => {
  const ORIGINAL_TZ = process.env.TZ_BUSINESS;

  afterAll(() => {
    if (ORIGINAL_TZ === undefined) delete process.env.TZ_BUSINESS;
    else process.env.TZ_BUSINESS = ORIGINAL_TZ;
  });

  test('TZ_BUSINESS=America/Los_Angeles：日键按当地自然日，跨当地午夜翻日', () => {
    process.env.TZ_BUSINESS = 'America/Los_Angeles';
    jest.resetModules();
    const svc = require('../../services/piiExportQuota');
    // UTC 02:00 = 洛杉矶前一天 18:00 ⇒ 归前一天
    expect(svc.quotaDayKey('u1', new Date('2026-11-03T02:00:00.000Z'))).toBe(
      'pii_export_quota:u1:20261102'
    );
    // UTC 08:00 = 洛杉矶当天 00:00 ⇒ 归当天
    expect(svc.quotaDayKey('u1', new Date('2026-11-03T08:00:00.000Z'))).toBe(
      'pii_export_quota:u1:20261103'
    );
  });

  test('缺省（Asia/Shanghai）口径与原 UTC+8 行为一致：UTC 16:00 翻日', () => {
    delete process.env.TZ_BUSINESS;
    jest.resetModules();
    const svc = require('../../services/piiExportQuota');
    expect(svc.quotaDayKey('u1', new Date('2026-11-03T15:59:59.000Z'))).toBe(
      'pii_export_quota:u1:20261103'
    );
    expect(svc.quotaDayKey('u1', new Date('2026-11-03T16:00:00.000Z'))).toBe(
      'pii_export_quota:u1:20261104'
    );
  });
});
