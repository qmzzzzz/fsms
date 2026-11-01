/**
 * 离线包签名（scripts/offlineBundleSignature.js）
 *
 * 守的失效形态（全是「包被整体重写却宣称同一版」的变体）：
 *   · 签验回环必须通——构建机签、目标机验按 manifest **原始字节**，任何转码/规范化都会
 *     让「构建机能验、目标机验不过」或反之；
 *   · manifest 被改一个字节 ⇒ 验签必红（这是签名存在的唯一理由，红不得）；
 *   · sig 缺失/为空/超长 ⇒ 红，且原因可读，而不是被当成「未签名」放过；
 *   · 公钥与签名私钥不是同一对 ⇒ 红；
 *   · 非 Ed25519 密钥塞进来 ⇒ 显式报错，不按通用 verify 悄悄工作。
 *
 * 密钥全部现场生成（crypto.generateKeyPairSync）：测试文件里没有任何凭据字面量，
 * 生成出的密钥也不落仓库目录（keyobject 只在内存里 export 成 PEM 字符串）。
 */
'use strict';

const crypto = require('crypto');

const {
  SIG_FILE,
  MAX_SIG_BYTES,
  parsePublicKey,
  signManifestBytes,
  verifyManifestBytes,
} = require('../../../scripts/offlineBundleSignature');

const ed25519PrivatePem = () =>
  crypto
    .generateKeyPairSync('ed25519')
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
    .toString();
const ed25519PublicPem = (privatePem) =>
  crypto.createPublicKey(privatePem).export({ type: 'spki', format: 'pem' }).toString();

const MANIFEST_BYTES = Buffer.from(
  JSON.stringify(
    {
      format: 1,
      version: '1.2.3',
      buildId: 'ci-42',
      createdAt: '2026-11-01T00:00:00Z',
      images: [
        {
          role: 'app',
          ref: `ghcr.io/acme/fsms@sha256:${'b'.repeat(64)}`,
          file: 'payload/fsms-app.tar',
          bytes: 1024,
          sha256: 'a'.repeat(64),
        },
      ],
    },
    null,
    2
  ),
  'utf8'
);

describe('常量', () => {
  test('签名文件名固定为 manifest.sig，与打包脚本/导入器同一口径', () => {
    expect(SIG_FILE).toBe('manifest.sig');
    expect(MAX_SIG_BYTES).toBeGreaterThanOrEqual(64); // Ed25519 签名恒 64 字节
  });
});

describe('签验回环', () => {
  test('构建机私钥签 → 目标机公钥验：同一字节必绿', () => {
    const priv = ed25519PrivatePem();
    const pub = ed25519PublicPem(priv);
    const sig = signManifestBytes(MANIFEST_BYTES, priv);
    expect(sig).toHaveLength(64); // Ed25519 签名恒 64 字节
    expect(verifyManifestBytes(MANIFEST_BYTES, sig, pub)).toEqual({ ok: true });
  });

  test('manifest 被改一个字节 ⇒ 验签必红（包被篡改或公钥配错，两种都该拦下）', () => {
    const priv = ed25519PrivatePem();
    const pub = ed25519PublicPem(priv);
    const sig = signManifestBytes(MANIFEST_BYTES, priv);
    const tampered = Buffer.from(MANIFEST_BYTES);
    tampered[tampered.indexOf(Buffer.from('1.2.3')[0])] = 0x39; // '1' → '9'：只动一个字节
    expect(tampered.equals(MANIFEST_BYTES)).toBe(false);
    const result = verifyManifestBytes(tampered, sig, pub);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/字节不符|篡改/);
  });

  test('换行/空白差异也算字节不符（canonical 化会把「被改过」洗白，必须按原始字节）', () => {
    const priv = ed25519PrivatePem();
    const pub = ed25519PublicPem(priv);
    const sig = signManifestBytes(MANIFEST_BYTES, priv);
    // 语义相同的 JSON（键序一致，仅行尾 \n → \r\n）必须验签失败：
    // 否则一个「重排字节但宣称同版」的包就能通过验签。
    const crlf = Buffer.from(MANIFEST_BYTES.toString('utf8').replace(/\n/g, '\r\n'), 'utf8');
    expect(verifyManifestBytes(crlf, sig, pub).ok).toBe(false);
  });
});

describe('失败形态', () => {
  test('sig 为空/缺失 ⇒ 红，原因指向 manifest.sig', () => {
    const priv = ed25519PrivatePem();
    const pub = ed25519PublicPem(priv);
    const empty = verifyManifestBytes(MANIFEST_BYTES, Buffer.alloc(0), pub);
    expect(empty.ok).toBe(false);
    expect(empty.reason).toMatch(/manifest\.sig/);
  });

  test('sig 超过形状上限 ⇒ 红（sig 路径被指到别的文件时不再读完整文件）', () => {
    const priv = ed25519PrivatePem();
    const pub = ed25519PublicPem(priv);
    const big = Buffer.alloc(MAX_SIG_BYTES + 1, 0x41);
    const result = verifyManifestBytes(MANIFEST_BYTES, big, pub);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/形状上限|超过/);
  });

  test('公钥与签名私钥不是同一对 ⇒ 红，原因可读', () => {
    const sig = signManifestBytes(MANIFEST_BYTES, ed25519PrivatePem());
    const otherPub = ed25519PublicPem(ed25519PrivatePem());
    const result = verifyManifestBytes(MANIFEST_BYTES, sig, otherPub);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/不符|篡改|同一对/);
  });

  test('公钥 PEM 非法 ⇒ 红（不是 throw：调用方要把原因写进留痕）', () => {
    const result = verifyManifestBytes(MANIFEST_BYTES, Buffer.alloc(64, 1), 'not-a-pem');
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/公钥/);
  });

  test('manifest 字节为空 ⇒ 红，不进入任何计算', () => {
    const priv = ed25519PrivatePem();
    const pub = ed25519PublicPem(priv);
    const sig = signManifestBytes(MANIFEST_BYTES, priv);
    expect(verifyManifestBytes(Buffer.alloc(0), sig, pub).ok).toBe(false);
  });
});

describe('密钥类型收紧', () => {
  test('非 Ed25519 公钥 ⇒ parsePublicKey 抛可读错误（不许按通用 verify 悄悄工作）', () => {
    const rsaPem = crypto
      .generateKeyPairSync('rsa', { modulusLength: 2048 })
      .publicKey.export({ type: 'spki', format: 'pem' })
      .toString();
    expect(() => parsePublicKey(rsaPem)).toThrow(/Ed25519/);
  });

  test('非 Ed25519 私钥 ⇒ signManifestBytes 抛可读错误', () => {
    const rsaPem = crypto
      .generateKeyPairSync('rsa', { modulusLength: 2048 })
      .privateKey.export({ type: 'pkcs1', format: 'pem' })
      .toString();
    expect(() => signManifestBytes(MANIFEST_BYTES, rsaPem)).toThrow(/Ed25519/);
  });

  test('PEM 解析失败给出原因而不是裸错误', () => {
    expect(() => parsePublicKey('not-a-pem')).toThrow(/公钥无法解析/);
    expect(() => signManifestBytes(MANIFEST_BYTES, 'not-a-pem')).toThrow(/私钥无法解析/);
  });
});
