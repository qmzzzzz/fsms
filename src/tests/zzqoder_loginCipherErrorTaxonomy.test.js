/**
 * 口令密文解段的错误分类法：每种畸形输入必须落到它**自己的**那个错误码
 *
 * 为什么要单独钉这一层：`decryptLoginCredential` 对外只有一句"失败一律抛
 * CredentialError"，而 code 是运维与告警区分「客户端加密用错了」与
 * 「有人在探测/重放」的唯一依据。既有 loginCipher.test.js 用
 * `rejects.toThrow(/CODE/)` 覆盖了主干，但实测有四道闸门删掉后**套件全绿**
 * （密文最短长度、临时公钥坐标长度、ts 必须是整数、nonce 形态）——
 * 因为它们与"下一步会撞出的另一个 code"行为近似，只有直接断言 code 才分得开。
 *
 * 本文件的可证伪性由末条反向用例提供：一个用真实 WebCrypto 流程构造的信封
 * 必须能解出明文。若哪天夹具坏了（所有输入都"恰好抛错"），那条会先红。
 */

const crypto = require('crypto');
const { decryptLoginCredential, CredentialError } = require('../utils/loginCipher');
const { buildLoginEnvelope, randomPassword } = require('./helpers/buildLoginEnvelope');

const b64 = (n) => Buffer.from(crypto.randomBytes(n)).toString('base64');
const NONCE_OK = crypto.randomBytes(16).toString('hex');

/** 结构合法、仅指定字段畸形的信封 */
const envelopeWith = (over = {}) => ({
  v: 1,
  x: b64(32).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  y: b64(32).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  salt: b64(16),
  iv: b64(12),
  c: b64(40),
  ...over,
});

const codeOf = async (raw) => {
  const env = await buildLoginEnvelope(null, { raw });
  try {
    await decryptLoginCredential(env);
    return 'NO_THROW';
  } catch (err) {
    if (!(err instanceof CredentialError)) throw new Error(`非 CredentialError：${err.message}`);
    return err.code;
  }
};

/** ts / nonce 在密文**载荷里**，只能走真实加密路径注入畸形值 */
const codeOfReal = async (over = {}) => {
  const env = await buildLoginEnvelope(randomPassword(), over);
  try {
    await decryptLoginCredential(env);
    return 'NO_THROW';
  } catch (err) {
    if (!(err instanceof CredentialError)) throw new Error(`非 CredentialError：${err.message}`);
    return err.code;
  }
};

describe('口令密文的错误分类法', () => {
  test('反向前提：真实前端流程构造的信封能解出明文（夹具没坏）', async () => {
    const pwd = randomPassword();
    const env = await buildLoginEnvelope(pwd);
    await expect(decryptLoginCredential(env)).resolves.toBe(pwd);
  });

  test('密文短于 GCM 标签（≤16 字节）→ ENVELOPE_FORMAT，而不是含糊的 DECRYPT', async () => {
    expect(await codeOf(envelopeWith({ c: b64(5) }))).toBe('ENVELOPE_FORMAT');
    // 边界本身也要钉住：恰好等于标签长度仍是畸形（没有明文体），多一字节才谈得上解密
    expect(await codeOf(envelopeWith({ c: b64(16) }))).toBe('ENVELOPE_FORMAT');
    expect(await codeOf(envelopeWith({ c: b64(17) }))).toBe('DECRYPT');
  });

  test('临时公钥坐标长度与曲线不符 → ENVELOPE_FORMAT（在 ECDH 之前挡下）', async () => {
    expect(await codeOf(envelopeWith({ x: b64(31) }))).toBe('ENVELOPE_FORMAT');
    expect(await codeOf(envelopeWith({ y: b64(48) }))).toBe('ENVELOPE_FORMAT');
    expect(await codeOf(envelopeWith({ x: 123 }))).toBe('ENVELOPE_FORMAT');
    expect(await codeOf(envelopeWith({ x: '' }))).toBe('ENVELOPE_FORMAT');
  });

  test('salt / iv 长度不符 → ENVELOPE_FORMAT', async () => {
    expect(await codeOf(envelopeWith({ salt: b64(15) }))).toBe('ENVELOPE_FORMAT');
    expect(await codeOf(envelopeWith({ iv: b64(13) }))).toBe('ENVELOPE_FORMAT');
  });

  test('ts 必须是整数且在窗口内：字符串/浮点/缺省/超窗都归 TS_WINDOW', async () => {
    expect(await codeOfReal({ ts: String(Date.now()) })).toBe('TS_WINDOW');
    expect(await codeOfReal({ ts: Date.now() + 0.5 })).toBe('TS_WINDOW');
    // null 才测得到"缺字段"：undefined 会触发构造器的默认值（那等于测了合法路径）
    expect(await codeOfReal({ ts: null })).toBe('TS_WINDOW');
    expect(await codeOfReal({ ts: Date.now() - 6 * 60 * 1000 })).toBe('TS_WINDOW');
  });

  test('nonce 形态：长度与字符集都算 NONCE_FORMAT，重放才算 NONCE_REPLAY', async () => {
    expect(await codeOfReal({ nonce: 'a'.repeat(15) })).toBe('NONCE_FORMAT');
    expect(await codeOfReal({ nonce: 'g'.repeat(32) })).toBe('NONCE_FORMAT');
    expect(await codeOfReal({ nonce: 12345 })).toBe('NONCE_FORMAT');
  });

  test('版本号必须严格等于数字 1（"1" 也拒），归 ENVELOPE_VERSION', async () => {
    expect(await codeOf(envelopeWith({ v: 2 }))).toBe('ENVELOPE_VERSION');
    expect(await codeOf(envelopeWith({ v: '1' }))).toBe('ENVELOPE_VERSION');
    // 缺字段（键整个不存在）与 v:"1" 同属版本不符；undefined 会被 JSON.stringify 省掉键
    expect(await codeOf(envelopeWith({ v: undefined }))).toBe('ENVELOPE_VERSION');
  });

  test('口令超长 → PAYLOAD_FORMAT（与明文轨上限一致）', async () => {
    const long = 'x'.repeat(129);
    const env = await buildLoginEnvelope(long);
    await expect(decryptLoginCredential(env)).rejects.toMatchObject({
      code: 'PAYLOAD_FORMAT',
    });
  });

  test('同一 nonce 二次提交 → NONCE_REPLAY（一次性消费确实是那道闸）', async () => {
    const nonce = NONCE_OK;
    const pwd = randomPassword();
    const first = await buildLoginEnvelope(pwd, { nonce });
    await expect(decryptLoginCredential(first)).resolves.toBe(pwd);
    const second = await buildLoginEnvelope(pwd, { nonce });
    await expect(decryptLoginCredential(second)).rejects.toMatchObject({
      code: 'NONCE_REPLAY',
    });
  });
});
