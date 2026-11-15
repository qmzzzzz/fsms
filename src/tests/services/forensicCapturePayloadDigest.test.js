/**
 * P2-05：取证口令摘要的 pepper 纪律。
 *
 * 守的是什么：口令类字段落取证副本时只许存 { len, hmac }，且 hmac 必须带 pepper
 * （HMAC-SHA256）。原实现经 passwordHistory.digestOf 在 pepper 缺失时**静默**退化为
 * 无盐 sha256——那是可离线爆破的口令等价物，落进长期留存的取证副本等于变相明文。
 * 修复后：pepper 缺失 ⇒ { len, hmac: null }（宁缺毋假）+ error 日志 + 安全告警计数。
 *
 * 环境说明：jest setup 预置了 HMAC_SECRET（config.hmacSecret 非空），所以
 * 「pepper 在场」分支直接用真实 env 验；「pepper 缺失」分支用 doMock 把
 * config.hmacSecret 置空并删掉 env 兜底。
 */
const PREV_HMAC_SECRET = process.env.HMAC_SECRET;

const withFreshModule = (hmacSecret) => {
  jest.resetModules();
  const realConfig = jest.requireActual('../../config');
  jest.doMock('../../config', () => ({ ...realConfig, hmacSecret }));
  if (hmacSecret) process.env.HMAC_SECRET = hmacSecret;
  else delete process.env.HMAC_SECRET;
  const logger = require('../../utils/logger');
  const metrics = require('../../utils/metrics');
  const errors = [];
  const alerts = [];
  jest.spyOn(logger, 'error').mockImplementation((...a) => errors.push(a.join(' ')));
  jest.spyOn(metrics, 'incSecurityAlert').mockImplementation((...a) => alerts.push(a));
  const payload = require('../../services/forensicCapturePayload');
  return { payload, errors, alerts };
};

afterAll(() => {
  if (PREV_HMAC_SECRET === undefined) delete process.env.HMAC_SECRET;
  else process.env.HMAC_SECRET = PREV_HMAC_SECRET;
});

describe('P2-05 取证口令摘要：pepper 在场/缺失两态', () => {
  afterEach(() => jest.restoreAllMocks());

  test('pepper 在场：口令键仍落 { len, hmac }，hmac 与单源 digestOf 逐字一致（不许过度降级）', () => {
    const { payload } = withFreshModule(PREV_HMAC_SECRET || 'test-hmac-secret-1234');
    const { digestOf } = require('../../utils/passwordHistory');
    const out = payload.sanitizeBodyForForensic({
      password: 'Secret123!',
      recoveryCodes: ['1111-2222', '3333-4444'],
    });
    expect(out.password).toEqual({ len: 10, hmac: digestOf('Secret123!') });
    expect(out.recoveryCodes).toEqual([
      { len: 9, hmac: digestOf('1111-2222') },
      { len: 9, hmac: digestOf('3333-4444') },
    ]);
    expect(out.password.hmac).toHaveLength(64);
  });

  test('pepper 缺失：hmac 记 null（不落无盐 sha256）+ error 日志 + 安全告警计数', () => {
    const { payload, errors, alerts } = withFreshModule('');
    const out = payload.sanitizeBodyForForensic({ password: 'Secret123!' });
    expect(out.password).toEqual({ len: 10, hmac: null });
    expect(errors.join('\n')).toContain('HMAC_SECRET');
    expect(alerts).toContainEqual(['forensic_digest_no_pepper', 'medium']);
  });

  test('pepper 缺失：error 日志只喊一次（不刷屏），告警计数逐次累加', () => {
    const { payload, errors, alerts } = withFreshModule('');
    payload.sanitizeBodyForForensic({ password: 'a' });
    payload.sanitizeBodyForForensic({ password: 'b' });
    expect(errors.filter((e) => e.includes('HMAC_SECRET'))).toHaveLength(1);
    expect(alerts.filter((a) => a[0] === 'forensic_digest_no_pepper')).toHaveLength(2);
  });

  test('非口令键不受降级影响：普通字段原样通过（PII 文本掩码由 captureRequestBody 的 maskPiiDeep 负责）', () => {
    const { payload } = withFreshModule('');
    const out = payload.sanitizeBodyForForensic({ note: 'plain note', password: 'p' });
    expect(out.note).toBe('plain note');
    expect(out.password).toEqual({ len: 1, hmac: null });
  });
});
