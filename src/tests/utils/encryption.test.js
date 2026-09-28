/**
 * 加密工具函数测试 — 补齐 GCM 完整性校验、CBC 兼容路径、HMAC 时序安全
 */

describe('Encryption Utils', () => {
  let aesCipher, hmacSigner;

  beforeAll(() => {
    process.env.AES_SECRET_KEY = 'test-aes-key-32-chars-minimum!!';
    process.env.HMAC_SECRET = 'test-hmac-secret';

    const encryption = require('../../utils/encryption');
    aesCipher = new encryption.AESCipher();
    hmacSigner = new encryption.HMACSigner();
  });

  describe('AES-GCM encrypt/decrypt', () => {
    test('should encrypt and decrypt text correctly', () => {
      const text = 'Hello World';
      const encrypted = aesCipher.encrypt(text);
      const decrypted = aesCipher.decrypt(encrypted);
      expect(decrypted).toBe(text);
    });

    test('should produce different ciphertext for same plaintext (random IV)', () => {
      const text = 'Hello World';
      const encrypted1 = aesCipher.encrypt(text);
      const encrypted2 = aesCipher.encrypt(text);
      expect(encrypted1).not.toBe(encrypted2);
    });

    test('should handle empty string', () => {
      const encrypted = aesCipher.encrypt('');
      const decrypted = aesCipher.decrypt(encrypted);
      expect(decrypted).toBe('');
    });

    test('should handle Chinese characters', () => {
      const text = '你好世界';
      const encrypted = aesCipher.encrypt(text);
      const decrypted = aesCipher.decrypt(encrypted);
      expect(decrypted).toBe(text);
    });

    // 密文格式是 `gcm:<ivHex>:<tagHex>:<cipherB64>`，decrypt 先切掉 'gcm:' 前缀，
    // 再按 3 段解析。原两条"篡改"用例把 payload 当成了 `iv:tag:cipher`（实际它
    // 只是 ivHex 一段），造出来的串分别是 2 段和"tag 段为空"，于是抛的是
    // 「无效的 GCM 密文格式」/ ERR_CRYPTO_INVALID_AUTH_TAG —— 两条都在**抵达
    // 认证判定之前**就抛了。实测：删掉 `decipher.setAuthTag(authTag)` 整行，
    // 旧用例仍全绿，即"GCM 完整性校验"当时零防护。
    const splitGcm = (encrypted) => {
      const [prefix, ivHex, tagHex, cipherB64] = encrypted.split(':');
      expect(prefix).toBe('gcm');
      expect(ivHex).toMatch(/^[0-9a-f]{24}$/);
      expect(tagHex).toMatch(/^[0-9a-f]{32}$/);
      expect(cipherB64).toBeTruthy();
      return { ivHex, tagHex, cipherB64 };
    };
    // GCM 认证失败的报错文案（Node/OpenSSL）；据此区分"认证没通过"与"输入不合格式"
    const AUTH_FAILURE = /Unsupported state|unable to authenticate|bad decrypt|auth tag/i;

    test('GCM: 同格式同长度的 authTag 被改 → 必须是认证失败而非格式错误', () => {
      const { ivHex, tagHex, cipherB64 } = splitGcm(aesCipher.encrypt('sensitive data'));
      // 逐字保持合法：仍是 16 字节十六进制，只翻转第一个字节
      const flipped = (tagHex[0] === '0' ? '1' : '0') + tagHex.slice(1);
      expect(flipped).toHaveLength(tagHex.length);
      expect(() => aesCipher.decrypt(`gcm:${ivHex}:${flipped}:${cipherB64}`)).toThrow(AUTH_FAILURE);
    });

    test('GCM: 密文被改（tag 保持原值）→ 必须是认证失败', () => {
      const text = 'sensitive data for gcm';
      const { ivHex, tagHex, cipherB64 } = splitGcm(aesCipher.encrypt(text));
      const buf = Buffer.from(cipherB64, 'base64');
      buf[0] ^= 0x01;
      const tampered = buf.toString('base64');
      expect(tampered).not.toBe(cipherB64);
      expect(Buffer.from(tampered, 'base64')).toHaveLength(buf.length);
      expect(() => aesCipher.decrypt(`gcm:${ivHex}:${tagHex}:${tampered}`)).toThrow(AUTH_FAILURE);
    });

    test('GCM: 未被篡改的原样密文仍可解密（上面三条的前置对照）', () => {
      const encrypted = aesCipher.encrypt('sensitive data');
      expect(aesCipher.decrypt(encrypted)).toBe('sensitive data');
    });

    // ===== F-181：接受集必须等于产出集 =====
    // 解密侧原先不校验三段形状，直接把密文交给 Buffer 的 hex/base64 解码与 OpenSSL。
    // 实测对照（before = git HEAD 版本、after = 加校验后，同一批 23 条输入跑两遍，
    // 脚本 D:/tmp/f181_matrix.js）：19 条行为发生变化——
    //   · 10 条**改前照常解出明文**：`Buffer.from(x,'hex')` 截断到第一个坏字符、
    //     base64 解码跳过坏字符与空白、填充可有可无、十六进制大小写不敏感。
    //     也就是同一个密钥有多种互不相同的字符串写法都能解密，而 encrypt() 永远
    //     产不出那些写法：按密文字符串做的比对（改动检测/去重/取证）会全部漏掉。
    //   · 9 条改前由 OpenSSL 报错（iv 长度 8/16 字节、tag 截到 4/12 字节、tag 空/超长…）
    //     ——改前也失败关闭，但那是运行时容错兜住的（截断的 tag 被 setAuthTag 接受，
    //     Node 为此打 DEP0182 弃用告警）。「认证强度由标签长度决定」不该寄望于运行时。
    // 表里放"如何把规范串改坏"的函数而不是成品串：test.each 在 describe 阶段求值，
    // 那时 beforeAll 还没造出 aesCipher（实测直接 TypeError，整文件 0 条用例）。
    // 每条变异都必须"与规范串必然不同"：早先一条 `b64.replace(/\+/g,'-')` 的写法在
    // 随机密文不含 + 也不含 / 时是空操作，等于拿合法密文去断言"必须被拒"——实测 12
    // 次跑红 8 次。数据相关的空操作变异比普通断言更隐蔽，所以每条都自校一次。
    const NON_CANONICAL = [
      [
        'iv 段写成大写十六进制（同字节）',
        (p) => `gcm:${p.ivHex.toUpperCase()}:${p.tagHex}:${p.cipherB64}`,
      ],
      [
        'tag 段写成大写十六进制（同字节）',
        (p) => `gcm:${p.ivHex}:${p.tagHex.toUpperCase()}:${p.cipherB64}`,
      ],
      [
        'iv 段尾随非法字符（Buffer 截断到坏字符前）',
        (p) => `gcm:${p.ivHex}zz:${p.tagHex}:${p.cipherB64}`,
      ],
      ['tag 段尾随非法字符', (p) => `gcm:${p.ivHex}:${p.tagHex}zz:${p.cipherB64}`],
      [
        '密文段尾随非法字符（base64 解码跳过）',
        (p) => `gcm:${p.ivHex}:${p.tagHex}:${p.cipherB64}@`,
      ],
      ['密文段多余填充', (p) => `gcm:${p.ivHex}:${p.tagHex}:${p.cipherB64}====`],
      [
        '密文段去掉 base64 填充',
        (p) => `gcm:${p.ivHex}:${p.tagHex}:${p.cipherB64.replace(/=/g, '')}`,
      ],
      [
        '密文段中间插非法字符',
        (p) => `gcm:${p.ivHex}:${p.tagHex}:${p.cipherB64.slice(0, 4)}#${p.cipherB64.slice(4)}`,
      ],
      [
        '密文段首字符换成 base64url 的 _',
        (p) => `gcm:${p.ivHex}:${p.tagHex}:${p.cipherB64.replace(/^./, '_')}`,
      ],
      ['密文段尾随空格（解码同样跳过）', (p) => `gcm:${p.ivHex}:${p.tagHex}:${p.cipherB64} `],
      [
        '密文段中间插换行（MIME 折行写法）',
        (p) => `gcm:${p.ivHex}:${p.tagHex}:${p.cipherB64.slice(0, 8)}\n${p.cipherB64.slice(8)}`,
      ],
    ];

    test.each(NON_CANONICAL)(
      'GCM: 非规范写法一律拒绝（本模块的格式错误，不是 OpenSSL 的认证错误）：%s',
      (_label, mutate) => {
        const parts = splitGcm(aesCipher.encrypt('f181-baseline'));
        const canonical = `gcm:${parts.ivHex}:${parts.tagHex}:${parts.cipherB64}`;
        const payload = mutate(parts);
        // 变异自校：改坏后的串必须真的与规范串不同，否则这条用例是在拿合法密文
        // 断言"必须被拒"，红绿取决于随机字节
        expect(payload).not.toBe(canonical);
        expect(aesCipher.decrypt(canonical)).toBe('f181-baseline');
        let err = null;
        try {
          aesCipher.decrypt(payload);
        } catch (e) {
          err = e;
        }
        expect(err).not.toBeNull();
        expect(err.message).toMatch(/无效的 GCM 密文格式/);
        // 没有 code ＝ 不是 Node/OpenSSL 抛的（ERR_CRYPTO_* 都带 code）
        expect(err.code).toBeUndefined();
      }
    );

    test('GCM: iv/tag 的长度与字符集任一变体都在抵达密码学调用前被拒', () => {
      const { ivHex, tagHex, cipherB64 } = splitGcm(aesCipher.encrypt('shape'));
      const crypto = require('crypto');
      const real = crypto.createDecipheriv;
      const reached = [];
      crypto.createDecipheriv = (...args) => {
        reached.push(args);
        return real(...args);
      };
      try {
        const bad = [
          // iv：短/长/奇数长度/非十六进制
          `gcm:${'00'.repeat(8)}:${tagHex}:${cipherB64}`,
          `gcm:${'00'.repeat(16)}:${tagHex}:${cipherB64}`,
          `gcm:${ivHex.slice(0, 23)}:${tagHex}:${cipherB64}`,
          `gcm:${ivHex.slice(0, 4)}-${ivHex.slice(5)}:${tagHex}:${cipherB64}`,
          // tag：截断到 4/8/12 字节（Node 曾接受，DEP0182）、超长、空
          `gcm:${ivHex}:${'ab'.repeat(4)}:${cipherB64}`,
          `gcm:${ivHex}:${'ab'.repeat(8)}:${cipherB64}`,
          `gcm:${ivHex}:${'ab'.repeat(12)}:${cipherB64}`,
          `gcm:${ivHex}:${'ab'.repeat(17)}:${cipherB64}`,
          `gcm:${ivHex}::${cipherB64}`,
        ];
        for (const payload of bad) {
          expect(() => aesCipher.decrypt(payload)).toThrow(/无效的 GCM 密文格式/);
        }
        // 变异对照：把三段校验整体挪到 createDecipheriv 之后，上面仍全绿（报的却是
        // OpenSSL 的错），只有这一行会红——所以它才是"之前"的证据
        expect(reached).toHaveLength(0);

        const good = `gcm:${ivHex}:${tagHex}:${cipherB64}`;
        expect(aesCipher.decrypt(good)).toBe('shape');
        expect(reached).toHaveLength(1);
        // authTagLength 显式传入且等于标签长度：不依赖 SDK 默认值
        expect(reached[0][3]).toEqual({ authTagLength: 16 });
      } finally {
        crypto.createDecipheriv = real;
      }
    });

    test('GCM: 写入侧产出始终落在读取侧接受集内（校验过严会锁死存量数据）', () => {
      // 接受集⊇产出集是"严格化不伤存量"的唯一证据。口径用生产模块自己导出的
      // GCM_FIELD_SHAPES，而不是在测试里再抄一遍正则——抄一份的话生产侧放宽、
      // 测试侧不会跟着红。
      const { GCM_FIELD_SHAPES: shapes } = require('../../utils/encryption');
      expect(shapes).toBeDefined();
      const texts = [
        '',
        'x',
        '你好世界',
        'a'.repeat(4096),
        JSON.stringify({ k: [1, 2, 3] }),
        Buffer.alloc(31, 7).toString('base64'),
      ];
      for (let i = 0; i < 40; i += 1) {
        const text = texts[i % texts.length] + i;
        const encrypted = aesCipher.encrypt(text);
        const { ivHex, tagHex, cipherB64 } = splitGcm(encrypted);
        expect(shapes.iv.test(ivHex)).toBe(true);
        expect(shapes.tag.test(tagHex)).toBe(true);
        expect(shapes.cipher.test(cipherB64)).toBe(true);
        expect(aesCipher.decrypt(encrypted)).toBe(text);
      }
      // 空明文＝空密文段，这条形状必须被接受（否则 MFA 空种子之类的历史数据会解不开）
      expect(shapes.cipher.test('')).toBe(true);
      expect(aesCipher.decrypt(aesCipher.encrypt(''))).toBe('');
    });

    // P3-27 把 CBC 解密改成"默认拒绝"（无认证 → 填充预言机面）。这条安全控制
    // 此前完全没有用例：把 decrypt 的 `ALLOW_LEGACY_CBC_DECRYPT !== 'true'` 判断
    // 删掉，让所有历史格式默认可解，全仓无人变红。
    test('CBC 遗留格式默认拒绝解密，仅显式开关可放行（P3-27）', () => {
      expect(() => aesCipher.decrypt('aabbccddeeff00112233445566778899:Zm9vYmFy')).toThrow(
        /拒绝解密无认证的 CBC 遗留密文/
      );

      const previous = process.env.ALLOW_LEGACY_CBC_DECRYPT;
      process.env.ALLOW_LEGACY_CBC_DECRYPT = 'true';
      try {
        // 开关打开后进入 CBC 分支：密钥/IV 不匹配会抛密码学错误，
        // 但不得再抛"拒绝解密"——那才是本条要钉的行为差异
        expect(() => aesCipher.decrypt('aabbccddeeff00112233445566778899:Zm9vYmFy')).not.toThrow(
          /拒绝解密无认证的 CBC 遗留密文/
        );
      } finally {
        if (previous === undefined) delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
        else process.env.ALLOW_LEGACY_CBC_DECRYPT = previous;
      }
    });
  });

  describe('HMAC sign/verify', () => {
    test('should sign and verify correctly', () => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      expect(hmacSigner.verify(data, signature)).toBe(true);
    });

    test('should reject wrong signature', () => {
      const data = 'important data';
      expect(hmacSigner.verify(data, 'wrongsignature')).toBe(false);
    });

    test('should reject signature with different length', () => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      // 截断签名
      expect(hmacSigner.verify(data, signature.slice(0, 10))).toBe(false);
    });

    // 上面两条都在 verify 的**形状早退分支**结束（F-182 之前是长度早退分支：实测
    // 'wrongsignature' 的 hex 解码长度为 0、截断 10 字符解码长度为 5，而真签名是 32 字节），
    // 于是"等长但内容不同"这条唯一真正走 timingSafeEqual 的输入从未被覆盖：
    // 把 verify 最后那条 timingSafeEqual 的返回改成 `return true`（当时写作
    // `return crypto.timingSafeEqual(sigBuffer, expectedBuffer)`），本文件当时 10 个用例全绿。
    test('HMAC: 等长但内容不同的签名必须为 false（唯一抵达 timingSafeEqual 的输入）', () => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      expect(signature).toMatch(/^[0-9a-f]{64}$/);

      const flipped = (signature[0] === '0' ? '1' : '0') + signature.slice(1);
      expect(flipped).toHaveLength(signature.length);
      expect(Buffer.from(flipped, 'hex')).toHaveLength(Buffer.from(signature, 'hex').length);
      expect(hmacSigner.verify(data, flipped)).toBe(false);

      // 数据侧同长度改动同样必须为 false（签名与数据必须绑定）
      expect(hmacSigner.verify(`${data} `, signature)).toBe(false);
    });

    // ===== F-182：接受集必须等于产出集（与 F-181 同一类，见其注释） =====
    // 改前 verify 直接把签名串交给 Buffer.from(x,'hex')：大小写不敏感、且截断到第一个
    // 坏字符，于是同一份数据有多个"合法签名"写法（sig 与 sig.toUpperCase() 与 sig+'zz'）。
    // 实测（before = git HEAD、after = 现在，脚本 D:/tmp/f182_probe.js）：
    //   · 由 true 变 false 的 2 条 —— 大写等价、尾随 zz（这两条改前是真的判等成立）；
    //   · 由抛 ERR_INVALID_ARG_TYPE 变 false 的 3 条 —— data 为 123 / null / {}；
    //   · 其余负例改前改后都是 false（形状收紧没有扩大拒绝集，只是把"宽"的那部分削掉）；
    //   · data 为 Buffer 的 2 条改前改后都是 true —— 严格化只砍非规范写法，
    //     不砍 update() 合法接受的输入类型，这条本身是一条反向门禁。
    // 本行标题的前提在 F-182 里被**反转**了：原先断言"大写十六进制仍判等"（当时的顾虑是
    // 长度比较因大小写误判），现在断言它必须被拒——写法等价但形状不同，正是取证/去重比对
    // 会漏的那一类，所以旧前提不再成立。
    const NON_CANONICAL_SIG = [
      ['大写十六进制等价（同字节，改前判等成立）', (s) => s.toUpperCase()],
      ['尾随非法字符（hex 截断到坏字符前，改前判等成立）', (s) => `${s}zz`],
      ['尾随合法 hex（长度不等，改前也拒）', (s) => `${s}00`],
      ['前缀非法字符', (s) => `zz${s}`],
      ['中间插非法字符', (s) => `${s.slice(0, 8)}#${s.slice(8)}`],
      ['尾随空格', (s) => `${s} `],
    ];

    test.each(NON_CANONICAL_SIG)('HMAC: 非规范签名写法一律 false：%s', (_label, mutate) => {
      const data = 'important data';
      const signature = hmacSigner.sign(data);
      const mutated = mutate(signature);
      expect(mutated).not.toBe(signature); // 变异自校：空操作会让这条变成"合法签名必须被拒"
      expect(hmacSigner.verify(data, signature)).toBe(true); // 同行对照：规范串必须仍通过
      expect(hmacSigner.verify(data, mutated)).toBe(false);
    });

    test('HMAC: data 非字符串时判定 false，不把异常抛给调用方（Buffer 仍是合法输入）', () => {
      const signature = hmacSigner.sign('important data');
      for (const bad of [123, null, undefined, {}, [], Symbol('x')]) {
        expect(() => hmacSigner.verify(bad, signature)).not.toThrow();
        expect(hmacSigner.verify(bad, signature)).toBe(false);
      }
      // Buffer 是 update() 文档接受的类型：改前就返回 true，收紧后不得变 false
      expect(hmacSigner.verify(Buffer.from('important data'), signature)).toBe(true);
    });

    test('HMAC: 写入侧产出始终落在读取侧接受集内（形状由算法推导，不得反过来锁死产出）', () => {
      const shape = hmacSigner.signatureShape;
      for (let i = 0; i < 20; i += 1) {
        const data = `payload-${i}-${'x'.repeat(i)}`;
        const signature = hmacSigner.sign(data);
        expect(shape.test(signature)).toBe(true);
        expect(hmacSigner.verify(data, signature)).toBe(true);
      }
      // 空数据同样成对：sign('') 的产出必须仍在接受集内
      expect(shape.test(hmacSigner.sign(''))).toBe(true);
      expect(hmacSigner.verify('', hmacSigner.sign(''))).toBe(true);
    });

    test('should reject null/undefined signature', () => {
      const data = 'important data';
      expect(hmacSigner.verify(data, null)).toBe(false);
      expect(hmacSigner.verify(data, undefined)).toBe(false);
    });
  });
});
