/**
 * 审计导出 manifest 的 HMAC 签名（#17）：
 *   · 签名覆盖 generatedAt、csvSha256、链摘要与全部声明字段；
 *   · 任一字段被改，重算的 HMAC 必须与清单里的签名不一致；
 *   · 未配置密钥时不产生签名（未签名状态必须是可见的，而不是伪造一个假签名）。
 */

const crypto = require('crypto');

jest.mock('../../utils/auditChain', () => ({ getHmacSecret: jest.fn() }));

const { getHmacSecret } = require('../../utils/auditChain');
const {
  buildAuditExportManifest,
  manifestSigningPayload,
  signAuditExportManifest,
  MANIFEST_SIGNATURE_VERSION,
} = require('../../services/auditExportService');

const SECRET = 'test-export-manifest-secret';
const counters = () => ({
  recordCount: 3,
  chainRecords: 3,
  startTime: new Date('2026-09-08T00:00:00.000Z'),
  endTime: new Date('2026-09-08T00:00:02.000Z'),
  sha256: 'a'.repeat(64),
  csvSha256: 'b'.repeat(64),
  csvBytes: 1234,
  truncated: false,
});

const hmacOf = (manifest) =>
  crypto
    .createHmac('sha256', SECRET)
    .update(manifestSigningPayload(manifest), 'utf8')
    .digest('hex');

describe('buildAuditExportManifest 的 HMAC 签名', () => {
  beforeEach(() => {
    getHmacSecret.mockReturnValue(SECRET);
  });

  test('签名覆盖清单本体（去掉 signature 后逐字复算一致）', () => {
    const manifest = buildAuditExportManifest(counters());
    const { signature, ...signed } = manifest;

    expect(signature.version).toBe(MANIFEST_SIGNATURE_VERSION);
    expect(signature.algorithm).toBe('hmac-sha256');
    expect(signature.value).toBe(hmacOf(signed));
    expect(signature.keyId).toMatch(/^[0-9a-f]{16}$/);
    // 时间戳参与签名：改 1 毫秒即失配
    expect(
      hmacOf({ ...signed, generatedAt: new Date(Date.parse(signed.generatedAt) + 1).toISOString() })
    ).not.toBe(signature.value);
  });

  test('csvSha256 / 链摘要 / 记录数 任一被改，签名都不再成立', () => {
    const { signature, ...signed } = buildAuditExportManifest(counters());
    for (const patch of [
      { csvSha256: 'c'.repeat(64) },
      { sha256: 'd'.repeat(64) },
      { recordCount: 4 },
      { generatedAt: new Date(Date.now() - 60000).toISOString() },
      { truncated: true, notice: '人为添加的截断说明' },
    ]) {
      expect(hmacOf({ ...signed, ...patch })).not.toBe(signature.value);
    }
  });

  test('条件字段（截断/覆盖率缺口）在签名之后追加，且同样被覆盖', () => {
    const manifest = buildAuditExportManifest({
      ...counters(),
      recordCount: 5,
      chainRecords: 3,
      truncated: true,
    });
    const { signature, ...signed } = manifest;
    expect(signed.notice).toContain('50000');
    expect(signed.notice).toContain('3/5');
    expect(signature.value).toBe(hmacOf(signed));

    // 抹掉 notice 也是篡改
    const { notice, ...withoutNotice } = signed;
    expect(notice).toBeTruthy();
    expect(hmacOf(withoutNotice)).not.toBe(signature.value);
  });

  test('未配置 HMAC_SECRET：不产生签名（不伪造摘要冒充签名）', () => {
    getHmacSecret.mockReturnValue('');
    const manifest = buildAuditExportManifest(counters());
    expect(manifest.signature).toBeUndefined();
    expect(signAuditExportManifest(manifest)).toBeNull();
  });
});
