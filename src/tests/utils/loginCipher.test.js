/**
 * 登录口令传输加密单元测试（utils/loginCipher.js）
 *
 * 覆盖：加解密往返（P-256/P-384）、公钥下发、信封格式校验、
 * 防重放（ts 窗口 / nonce 一次性 / 篡改 GCM 拒绝）、密钥注入校验。
 * 密文构造器见 tests/helpers/buildLoginEnvelope.js（镜像前端 WebCrypto 流程）。
 *
 * decryptLoginCredential 为异步（nonce 一次性消费经 sharedCache 原子占位，
 * 配置 REDIS_URL 时跨实例共享；测试环境走内存回退）。
 */

const crypto = require('crypto');
const {
  CredentialError,
  getPublicKeyInfo,
  decryptLoginCredential,
  _resetForTests,
} = require('../../utils/loginCipher');
const sharedCache = require('../../services/sharedCache');
const {
  buildLoginEnvelope,
  randomPassword,
  generateEcKeyPem,
} = require('../helpers/buildLoginEnvelope');

const injectKey = (pem) => {
  process.env.LOGIN_ECDH_PRIVATE_KEY = pem;
  _resetForTests();
};

describe('loginCipher 登录口令传输加密', () => {
  let p256Key;

  beforeAll(() => {
    p256Key = generateEcKeyPem().privateKey;
  });

  beforeEach(() => {
    injectKey(p256Key);
  });

  afterEach(() => {
    sharedCache._resetForTests();
    // 清理本文件注入的 ECDH 密钥，避免同 worker 后续文件读到残留值
    delete process.env.LOGIN_ECDH_PRIVATE_KEY;
  });

  test('公钥信息：返回 PEM / keyId / curve / 算法标识', () => {
    const info = getPublicKeyInfo();
    expect(info.publicKey).toMatch(/BEGIN PUBLIC KEY/);
    expect(info.curve).toBe('P-256');
    expect(info.keyId).toMatch(/^[0-9a-f]{8}$/);
    expect(info.algorithm).toContain('ECDH');
  });

  test('加解密往返：明文口令逐字节一致', async () => {
    const pwd = randomPassword();
    const envelope = await buildLoginEnvelope(pwd);
    expect(await decryptLoginCredential(envelope)).toBe(pwd);
  });

  test('重放防护：同一信封二次提交被拒（NONCE_REPLAY）', async () => {
    const envelope = await buildLoginEnvelope(randomPassword());
    expect(typeof (await decryptLoginCredential(envelope))).toBe('string');
    await expect(decryptLoginCredential(envelope)).rejects.toThrow(CredentialError);
    await expect(decryptLoginCredential(envelope)).rejects.toMatchObject({ code: 'NONCE_REPLAY' });
  });

  test('时间窗：过期 ts 被拒（TS_WINDOW）', async () => {
    const envelope = await buildLoginEnvelope(randomPassword(), { ts: Date.now() - 6 * 60 * 1000 });
    await expect(decryptLoginCredential(envelope)).rejects.toThrow(/TS_WINDOW/);
  });

  test('时间窗：超前 ts 被拒（TS_WINDOW）', async () => {
    const envelope = await buildLoginEnvelope(randomPassword(), { ts: Date.now() + 6 * 60 * 1000 });
    await expect(decryptLoginCredential(envelope)).rejects.toThrow(/TS_WINDOW/);
  });

  test('nonce 格式非法被拒（NONCE_FORMAT）', async () => {
    const envelope = await buildLoginEnvelope(randomPassword(), { nonce: 'not-hex-xyz!' });
    await expect(decryptLoginCredential(envelope)).rejects.toThrow(/NONCE_FORMAT/);
  });

  test('信封版本号错误被拒（ENVELOPE_VERSION）', async () => {
    const envelope = await buildLoginEnvelope(null, {
      raw: { v: 99, x: 'a', y: 'b', salt: 'c', iv: 'd', c: 'e' },
    });
    await expect(decryptLoginCredential(envelope)).rejects.toThrow(/ENVELOPE_VERSION/);
  });

  test('非 base64 / 非 JSON 信封被拒（ENVELOPE_FORMAT）', async () => {
    await expect(decryptLoginCredential('!!!not-base64-json!!!')).rejects.toThrow(
      /ENVELOPE_FORMAT/
    );
    await expect(decryptLoginCredential('')).rejects.toThrow(/ENVELOPE_FORMAT/);
    await expect(decryptLoginCredential(null)).rejects.toThrow(/ENVELOPE_FORMAT/);
  });

  test('超长信封被拒（ENVELOPE_FORMAT）', async () => {
    await expect(decryptLoginCredential('A'.repeat(1100))).rejects.toThrow(/ENVELOPE_FORMAT/);
  });

  test('篡改密文被 GCM 认证拒绝（DECRYPT）', async () => {
    const envelope = await buildLoginEnvelope(randomPassword());
    const inner = JSON.parse(Buffer.from(envelope, 'base64').toString('utf8'));
    // 篡改密文段末 4 字符（nonce 随 payload 加密，篡改会破坏认证标签）
    inner.c = inner.c.slice(0, -4) + 'AAAA';
    const tampered = Buffer.from(JSON.stringify(inner), 'utf8').toString('base64');
    await expect(decryptLoginCredential(tampered)).rejects.toThrow(/DECRYPT/);
  });

  test('错配公钥（重启换钥后前端缓存未刷新）被拒（DECRYPT）', async () => {
    const otherKey = generateEcKeyPem();
    const envelope = await buildLoginEnvelope(randomPassword(), {
      serverPublicPem: otherKey.publicKey,
    });
    await expect(decryptLoginCredential(envelope)).rejects.toThrow(/DECRYPT/);
  });

  test('口令超长（>128 字符）被拒（PAYLOAD_FORMAT）', async () => {
    const envelope = await buildLoginEnvelope('a'.repeat(129));
    await expect(decryptLoginCredential(envelope)).rejects.toThrow(/PAYLOAD_FORMAT/);
  });

  test('P-384 密钥注入与往返', async () => {
    const { privateKey } = generateEcKeyPem('secp384r1');
    injectKey(privateKey);
    expect(getPublicKeyInfo().curve).toBe('P-384');
    const pwd = randomPassword();
    const envelope = await buildLoginEnvelope(pwd, { curve: 'P-384' });
    expect(await decryptLoginCredential(envelope)).toBe(pwd);
  });

  test('注入非 EC 密钥（Ed25519）：首次使用即拒绝', () => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    injectKey(privateKey);
    expect(() => getPublicKeyInfo()).toThrow(/P-256\/P-384 EC/);
  });

  test('注入非法 PEM：首次使用即拒绝', () => {
    injectKey('not-a-valid-pem-key');
    expect(() => getPublicKeyInfo()).toThrow();
  });
});
