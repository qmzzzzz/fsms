/**
 * 凭据键判定只剩一处声明：访问日志 URL 打码 与 审计 query 脱敏 必须同结论
 *
 * 缺陷形态：判定规则有两条互补的名单（整键/下划线边界 与 子串），
 * 审计侧取了两条的并集，访问日志侧却只取了边界那半条——于是
 *   GET /api/x?accessToken=<口令>
 * 在 combined 日志里是明文，在同一条请求的审计副本里是 ***。
 * 两条链路互为"我已经处理过了"的证据，缺口因此长期不可见。
 *
 * 现在两侧共用同一个并集函数，本用例钉住三件事：
 *  1) 对同一批键，URL 是否打码 ⇔ 审计是否脱敏（逐键等价，口径漂移即刻转红）；
 *  2) 并集确实比任何一半都宽：accessToken 只有子串那半抓得住，
 *     otp / authorization / code 只有边界那半抓得住；
 *  3) 不误伤：postcode / zipCode / errorCode / design 仍是明文（原豁免保持），
 *     避免"为了绿而一律打码"的假修复。
 */

const {
  redactUrlQuery,
  isCredentialQueryKey,
  matchesSensitiveQueryKey,
  matchesSensitiveBodyKey,
  SENSITIVE_KEY_SUBSTRINGS,
  SENSITIVE_QUERY_KEYS,
} = require('../utils/helpers');

const {
  isQuerySensitiveKey,
  isBodySensitiveKey,
  SENSITIVE_KEYS,
} = require('../models/auditLogSanitizer');

const SECRET = 'Sup3rS3cretShouldNotAppear';

/** 被探值是否在该键的 URL 位置被打码 */
const urlMasked = (key) => redactUrlQuery(`/api/x?${key}=${SECRET}`).includes(`${key}=***`);

// 应被判为凭据的两类键：各覆盖一条名单的独有能力
const CREDENTIAL_KEYS = [
  // 边界那半条名单的独有能力（裸键）
  'code',
  'otp',
  'authorization',
  'session',
  'captcha',
  'signature',
  'sign',
  'mfa',
  // 子串那半条名单的独有能力（camelCase / 拼接键）
  'accessToken',
  'access_token',
  'refreshToken',
  'refreshtoken',
  'csrfToken',
  'idToken',
  'apiSecret',
  'newPassword',
  'currentPassword',
  'mfaCode',
  'apiKey',
  // 两条名单都能抓到
  'password',
  'token',
  'Password',
  'user_password',
];

// 合法业务参数：一律不得被打码（短键子串误伤正是原豁免要防的）
const BUSINESS_KEYS = [
  'postcode',
  'zipcode',
  'zipCode',
  'postCode',
  'errorCode',
  'design',
  'qrcode',
  'page',
  'limit',
  'sort',
  'keyword',
  'search',
  'department',
  'username',
  'filename',
  'id',
  'type',
  'region',
];

describe('URL 打码与审计脱敏同结论（防口径漂移）', () => {
  test('前提：两条名单各自的独有能力都存在（否则下面的等价断言无意义）', () => {
    // accessToken 只被子串那半条抓到
    expect(matchesSensitiveQueryKey('accesstoken')).toBe(false);
    expect(matchesSensitiveBodyKey('accesstoken')).toBe(true);
    // 裸键 otp 只被边界那半条抓到
    expect(matchesSensitiveBodyKey('otp')).toBe(false);
    expect(matchesSensitiveQueryKey('otp')).toBe(true);
    // 并集两侧都覆盖
    expect(isCredentialQueryKey('accessToken')).toBe(true);
    expect(isCredentialQueryKey('otp')).toBe(true);
  });

  test('逐键等价：URL 打码 ⇔ 审计 query 脱敏（凭据键与业务键全量）', () => {
    const drifted = [...CREDENTIAL_KEYS, ...BUSINESS_KEYS]
      .map((key) => ({ key, url: urlMasked(key), audit: isQuerySensitiveKey(key) }))
      .filter((x) => x.url !== x.audit);
    expect(drifted).toEqual([]);
  });

  test('凭据键在 URL 里被打码，且明文不再出现', () => {
    const leaks = CREDENTIAL_KEYS.filter((key) => !urlMasked(key));
    expect(leaks).toEqual([]);
    const line = redactUrlQuery('/api/export?accessToken=abc&refreshToken=def');
    expect(line).toBe('/api/export?accessToken=***&refreshToken=***');
  });

  test('反向保护：业务键保持明文（不得退化成一律打码）', () => {
    const falsePositives = BUSINESS_KEYS.filter((key) => urlMasked(key));
    expect(falsePositives).toEqual([]);
    const line = redactUrlQuery('/api/list?page=2&zipcode=310000&errorCode=E1');
    expect(line).toBe('/api/list?page=2&zipcode=310000&errorCode=E1');
  });

  test('结构保真：键名、顺序、无值键与非 query URL 原样返回', () => {
    expect(redactUrlQuery('/a?x=1&token=t&y=2')).toBe('/a?x=1&token=***&y=2');
    expect(redactUrlQuery('/a?token&page=2')).toBe('/a?token&page=2');
    expect(redactUrlQuery('/a?token=t&token=u')).toBe('/a?token=***&token=***');
    expect(redactUrlQuery('/a/b/c')).toBe('/a/b/c');
    expect(redactUrlQuery('')).toBe('');
    expect(redactUrlQuery('/a?t=?&token=?')).toBe('/a?t=?&token=***');
  });
});

describe('名单与判定函数的单一事实来源', () => {
  test('审计侧的子串名单就是 helpers 里那一份（同一引用，不是复制）', () => {
    expect(Object.is(SENSITIVE_KEYS, SENSITIVE_KEY_SUBSTRINGS)).toBe(true);
    expect(Object.is(isQuerySensitiveKey, isCredentialQueryKey)).toBe(true);
  });

  test('两份名单都被冻结，无法在使用点被就地增删', () => {
    expect(Object.isFrozen(SENSITIVE_KEY_SUBSTRINGS)).toBe(true);
    expect(Object.isFrozen(SENSITIVE_QUERY_KEYS)).toBe(true);
  });

  test('body 侧仍只用子串名单：裸键 code 不得被 body 脱敏误伤', () => {
    expect(isBodySensitiveKey('code')).toBe(false);
    expect(isBodySensitiveKey('password')).toBe(true);
    expect(isCredentialQueryKey('code')).toBe(true);
  });
});
