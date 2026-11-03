/**
 * PII 导出配额的 Redis 主源语义（E2）。
 *
 * 三档行为分界：Redis 未配置 ⇒ 服务返回 null，调用方退回审计计数路径（现状口径，
 * 滚动窗口语义由 piiExportQuotaWatermark.test.js 钉住）；Redis 配置但未就绪/命令失败
 * ⇒ fail-closed 上抛（PII_EXPORT_QUOTA_UNAVAILABLE，绝不折算成放行）；Redis 正常 ⇒
 * 自然日键 + INCR/GET。sharedCache 整体打桩，TTL 语义（首次置 24h、EXPIRE NX）由
 * sharedCache.incrWithTtl 的既有契约承载——这里钉的是"调用面把 WINDOW_MS 交给它"。
 */

jest.mock('../../services/sharedCache', () => ({
  isRedisConfigured: (...args) => mockShared.isRedisConfigured(...args),
  isRedisEnabled: (...args) => mockShared.isRedisEnabled(...args),
  getRedisClient: (...args) => mockShared.getRedisClient(...args),
  incrWithTtl: (...args) => mockShared.incrWithTtl(...args),
}));

const mockShared = {
  isRedisConfigured: jest.fn(),
  isRedisEnabled: jest.fn(),
  getRedisClient: jest.fn(),
  incrWithTtl: jest.fn(),
};

const {
  WINDOW_MS,
  DAILY_QUOTA,
  quotaDayKey,
  consumePiiExportQuota,
  readPiiExportQuotaCount,
  checkPiiExportQuota,
} = require('../../services/piiExportQuota');

beforeEach(() => {
  jest.clearAllMocks();
});

describe('piiExportQuota — Redis 主源（E2）', () => {
  test('自然日键：UTC+8 挂钟，跨 16:00Z 翻日', () => {
    expect(quotaDayKey('u1', new Date('2026-11-03T10:00:00.000Z'))).toBe(
      'pii_export_quota:u1:20261103'
    );
    expect(quotaDayKey('u1', new Date('2026-11-03T15:59:59.000Z'))).toBe(
      'pii_export_quota:u1:20261103'
    );
    expect(quotaDayKey('u1', new Date('2026-11-03T16:00:00.000Z'))).toBe(
      'pii_export_quota:u1:20261104'
    );
  });

  test('Redis 模式检查：GET 计数判断 allowed，超限时 Retry-After 指向次日零点', async () => {
    mockShared.isRedisConfigured.mockReturnValue(true);
    mockShared.isRedisEnabled.mockReturnValue(true);
    mockShared.getRedisClient.mockReturnValue({ get: jest.fn().mockResolvedValue('3') });
    const AuditLog = require('../../models/AuditLog');
    const countSpy = jest.spyOn(AuditLog, 'countDocuments');
    const ok = await checkPiiExportQuota({ userId: 'u1' });
    expect(ok).toMatchObject({ allowed: true, used: 3, limit: DAILY_QUOTA });
    expect(ok.retryAfterSeconds).toBe(0);

    mockShared.getRedisClient.mockReturnValue({ get: jest.fn().mockResolvedValue('5') });
    const full = await checkPiiExportQuota({ userId: 'u1' });
    expect(full.allowed).toBe(false);
    expect(full.retryAfterSeconds).toBeGreaterThan(0);
    expect(full.retryAfterSeconds).toBeLessThanOrEqual(WINDOW_MS / 1000);
    // AuditLog 一行都没查（Redis 主源不数留痕）
    expect(countSpy).not.toHaveBeenCalled();
    countSpy.mockRestore();
  });

  test('consume：incrWithTtl 收到自然日键与 24h TTL；越限返回 allowed=false', async () => {
    mockShared.isRedisConfigured.mockReturnValue(true);
    mockShared.isRedisEnabled.mockReturnValue(true);
    mockShared.incrWithTtl.mockResolvedValue(1);
    const first = await consumePiiExportQuota({ userId: 'u1' });
    expect(mockShared.incrWithTtl).toHaveBeenCalledTimes(1);
    const [key, ttl] = mockShared.incrWithTtl.mock.calls[0];
    expect(ttl).toBe(WINDOW_MS);
    expect(key).toBe(quotaDayKey('u1', new Date()));
    expect(first).toMatchObject({ used: 1, allowed: true });

    mockShared.incrWithTtl.mockResolvedValue(DAILY_QUOTA + 1);
    const over = await consumePiiExportQuota({ userId: 'u1' });
    expect(over.allowed).toBe(false);
    expect(over.used).toBe(DAILY_QUOTA + 1);
    expect(over.retryAfterSeconds).toBeGreaterThan(0);
  });

  test('fail-closed：已配置未就绪 / INCR 返回 null / GET 抛错 ⇒ 上抛 PII_EXPORT_QUOTA_UNAVAILABLE', async () => {
    mockShared.isRedisConfigured.mockReturnValue(true);
    mockShared.isRedisEnabled.mockReturnValue(false);
    await expect(checkPiiExportQuota({ userId: 'u1' })).rejects.toMatchObject({
      code: 'PII_EXPORT_QUOTA_UNAVAILABLE',
    });
    await expect(consumePiiExportQuota({ userId: 'u1' })).rejects.toMatchObject({
      code: 'PII_EXPORT_QUOTA_UNAVAILABLE',
    });

    mockShared.isRedisEnabled.mockReturnValue(true);
    mockShared.incrWithTtl.mockResolvedValue(null); // sharedCache 契约：命令失败返回 null
    await expect(consumePiiExportQuota({ userId: 'u1' })).rejects.toMatchObject({
      code: 'PII_EXPORT_QUOTA_UNAVAILABLE',
    });

    mockShared.getRedisClient.mockReturnValue({
      get: jest.fn().mockRejectedValue(new Error('connection dropped')),
    });
    await expect(checkPiiExportQuota({ userId: 'u1' })).rejects.toMatchObject({
      code: 'PII_EXPORT_QUOTA_UNAVAILABLE',
    });
  });

  test('未配置 Redis ⇒ 读与消费都返回 null（调用方退回审计计数路径）', async () => {
    mockShared.isRedisConfigured.mockReturnValue(false);
    expect(await readPiiExportQuotaCount({ userId: 'u1' })).toBeNull();
    expect(await consumePiiExportQuota({ userId: 'u1' })).toBeNull();
    expect(mockShared.incrWithTtl).not.toHaveBeenCalled();
    expect(mockShared.getRedisClient).not.toHaveBeenCalled();
  });
});
