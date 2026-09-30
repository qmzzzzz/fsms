/**
 * PII at-rest 加密（P1-②）的行为门禁
 *
 * 两个层次：
 *  A. utils/piiCrypto 纯判据真值表：随机 IV 密文不可链接、解密往返、
 *     存量明文透传（迁移前旧数据照常可读）、密文形态非法即抛（GCM 认证失败
 *     是"数据被改"的信号，吞掉它等于把篡改静默降级成乱码）、
 *     检索键归一化与空值语义；
 *  B. User schema 接线（真实 Mongo）：写侧钩子真的加密 + 检索键真的同步 +
 *     读侧 getter 真的解密——**语义测对了而没接线**是这类修复最常见的落地
 *     失败形态（passwordHistory.test.js 头注释的同一条经验），故 B 层不可省。
 *     手机号校验在钩子内、加密之前：非法手机号的错误文案必须与
 *     明文时代逐字一致（userController 的错误映射契约）。
 */

const mongoose = require('mongoose');
const { encryptPii, decryptPii, piiSearchKey, VERSION_PREFIX } = require('../../utils/piiCrypto');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const User = require('../../models/User');

const PLAIN_NAME = '张三 Zhang-San';
const PLAIN_PHONE = '13812345678';

describe('piiCrypto 纯判据', () => {
  test('加密往返：密文带版本前缀、非确定性（随机 IV）、可解回明文', () => {
    const a = encryptPii(PLAIN_NAME);
    const b = encryptPii(PLAIN_NAME);
    expect(a).toMatch(/^enc\.v1\./);
    expect(a).not.toBe(b); // 随机 IV ⇒ 同明文两次加密密文不同（不可链接）
    expect(decryptPii(a)).toBe(PLAIN_NAME);
    expect(decryptPii(b)).toBe(PLAIN_NAME);
  });

  test('存量明文透传：不带版本前缀的值原样返回（迁移前的旧行照常可读）', () => {
    expect(decryptPii('张三')).toBe('张三');
    expect(decryptPii('13812345678')).toBe('13812345678');
    expect(decryptPii('')).toBe('');
    expect(decryptPii(null)).toBeNull();
    expect(decryptPii(undefined)).toBeUndefined();
  });

  test('空值不产生密文也不产生检索键（清空手机号是合法操作）', () => {
    expect(encryptPii('')).toBe('');
    expect(piiSearchKey('')).toBe('');
    expect(piiSearchKey(null)).toBe('');
  });

  test('篡改密文 ⇒ 解密抛错而不是返回乱码（GCM 认证标签的用途所在）', () => {
    const enc = encryptPii(PLAIN_PHONE);
    const parts = enc.slice(VERSION_PREFIX.length).split('.');
    const data = Buffer.from(parts[1], 'base64');
    data[data.length - 1] ^= 0x01; // 翻转认证标签最后一个位
    const tampered = `${VERSION_PREFIX}${parts[0]}.${data.toString('base64')}`;
    expect(() => decryptPii(tampered)).toThrow();
  });

  test('检索键：归一化（trim+lower）后 HMAC，同一明文稳定、异文明文不同', () => {
    expect(piiSearchKey(`  ${PLAIN_NAME} `)).toBe(piiSearchKey(PLAIN_NAME.toLowerCase().trim()));
    expect(piiSearchKey(PLAIN_NAME)).toHaveLength(64);
    expect(piiSearchKey('李四')).not.toBe(piiSearchKey(PLAIN_NAME));
  });

  /**
   * 主密钥退化取值必须**响**，不许静默降级（2026-09-30 审计线，lane-pii P1）。
   *
   * 原缺陷形态：`currentAesKey()` 用 `if (!process.env.AES_SECRET_KEY)` 判缺失，
   * 而 `process.env.X = undefined` 被 Node 强转成字符串 "undefined"（实测 v24.15.0），
   * dotenv 里写 `AES_SECRET_KEY=undefined` 给出的也是这四个字符 ⇒ 判据恒真通过，
   * 于是加密侧与 **检索键侧（原先连这道判据都没有）** 一起落到
   * `sha256("undefined:pii:aes:v1")` 这把任何读得到源码的人都能算出的密钥上。
   * 轮换脚本更狠：它照样打印「✅ 轮换完成」，事后无人察觉。
   */
  describe('主密钥取值退化：三处消费点一律抛错，不给可推导常量密钥留活路', () => {
    const runWithKey = (value, fn) => {
      const saved = process.env.AES_SECRET_KEY;
      if (value === undefined) delete process.env.AES_SECRET_KEY;
      else process.env.AES_SECRET_KEY = value;
      try {
        return fn();
      } finally {
        if (saved === undefined) delete process.env.AES_SECRET_KEY;
        else process.env.AES_SECRET_KEY = saved;
      }
    };

    test.each([
      ['未设置', undefined],
      ['空串', ''],
      ['纯空白', '   '],
      ['字面量 undefined', 'undefined'],
      ['字面量 null', 'null'],
      ['字面量 NaN', 'NaN'],
    ])('%s ⇒ 加密/检索键/解密文三处都抛（fail-closed）', (_label, value) => {
      runWithKey(value, () => {
        expect(() => encryptPii(PLAIN_PHONE)).toThrow(/AES_SECRET_KEY/);
        expect(() => piiSearchKey(PLAIN_PHONE)).toThrow(/AES_SECRET_KEY/);
        expect(() => decryptPii('enc.v1.eA==.eA==')).toThrow(/AES_SECRET_KEY/);
      });
    });

    test('反向自证：正常密钥下三处都不抛——上一条不是一句"永远抛"的恒真判据', () => {
      expect(() => encryptPii(PLAIN_PHONE)).not.toThrow();
      expect(() => piiSearchKey(PLAIN_PHONE)).not.toThrow();
      expect(() => decryptPii(encryptPii(PLAIN_PHONE))).not.toThrow();
    });

    test('空值语义不被这道闸影响：空手机号仍返回空串而不是抛错（清空字段是合法操作）', () => {
      runWithKey(undefined, () => {
        expect(piiSearchKey('')).toBe('');
        expect(piiSearchKey('  ')).toBe('');
        expect(encryptPii('')).toBe('');
        expect(decryptPii('存量明文')).toBe('存量明文');
      });
    });

    test('字面量 undefined 那一档命中的是主密钥守卫本身（不是"恰好抛了个别的错"）', () => {
      const underRealKey = piiSearchKey(PLAIN_PHONE);
      const outcome = runWithKey('undefined', () => {
        try {
          return { threw: false, digest: piiSearchKey(PLAIN_PHONE) };
        } catch (e) {
          return { threw: true, message: e.message };
        }
      });
      // 只认这道守卫自己的文案前缀：把字面量清单删掉（回到"非空即通过"）后，
      // 这里会拿到一把 64 位摘要 ⇒ 两条断言同时变红，而不是继续绿着替降级背书。
      expect(outcome.threw).toBe(true);
      expect(outcome.digest).toBeUndefined();
      expect(outcome.message.startsWith('PII 加密不可用')).toBe(true);
      expect(underRealKey).toHaveLength(64);
    });
  });
});

describe('User schema 接线（真实 Mongo：phone 写侧加密、读侧解密、检索键同步）', () => {
  let userId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });
  afterAll(async () => {
    if (userId) await User.deleteOne({ _id: userId }, { bypassAppendOnly: true });
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  });

  test('创建：phone 库内是密文 + 检索键同步；realName 按决策保持明文', async () => {
    const u = await User.create({
      username: `pii_${Date.now().toString(36)}`,
      email: `pii_${Date.now().toString(36)}@example.invalid`,
      password: randomPassword(),
      realName: PLAIN_NAME,
      phone: PLAIN_PHONE,
      roles: [],
    });
    userId = u._id;

    // 绕过 getter 看库内原始形态
    const raw = await User.collection.findOne({ _id: u._id });
    expect(raw.phone).toMatch(/^enc\.v1\./);
    expect(raw.phone).not.toContain(PLAIN_PHONE);
    // realName 决策：暂不加密（姓名模糊检索依赖），库内保持明文
    expect(raw.realName).toBe(PLAIN_NAME);
    // 检索键同步且 select:false（realName 无检索键：无消费者，不造死数据）
    expect(raw.phoneKey).toBe(piiSearchKey(PLAIN_PHONE));
    expect(raw.realNameKey).toBeUndefined();

    // 模型读回（默认投影不含检索键；明文经 getter 还原）
    const read = await User.findById(u._id);
    expect(read.realName).toBe(PLAIN_NAME);
    expect(read.phone).toBe(PLAIN_PHONE);
    const withKey = await User.findById(u._id).select('+phoneKey');
    expect(withKey.phoneKey).toBe(piiSearchKey(PLAIN_PHONE));
  });

  test('按检索键精确查找（列表搜索的接入方式）', async () => {
    const found = await User.findOne({ phoneKey: piiSearchKey(PLAIN_PHONE) }).select('+phoneKey');
    expect(found).toBeTruthy();
    expect(found._id.toString()).toBe(String(userId));
    // 不存在的手机号查不到
    expect(await User.findOne({ phoneKey: piiSearchKey('13900000000') })).toBeNull();
  });

  test('更新：只改 phone 时 phone 重加密、realName 明文原样', async () => {
    const before = await User.collection.findOne({ _id: userId });
    const u = await User.findById(userId);
    u.phone = '13987654321';
    await u.save();
    const after = await User.collection.findOne({ _id: userId });
    expect(after.realName).toBe(before.realName); // 未修改字段原样（随机 IV 下重加密=假变更）
    expect(after.phone).not.toBe(before.phone);
    expect(after.phoneKey).toBe(piiSearchKey('13987654321'));
    expect((await User.findById(userId)).phone).toBe('13987654321');
  });

  test('非法手机号：文案与明文时代逐字一致，且不落任何写入', async () => {
    const u = await User.findById(userId);
    const beforeRaw = await User.collection.findOne({ _id: userId });
    u.phone = '12345';
    await u.save().catch(() => {});
    // 校验失败 ⇒ save 被拒 ⇒ 库内不变
    const afterRaw = await User.collection.findOne({ _id: userId });
    expect(afterRaw.phone).toBe(beforeRaw.phone);
    const again = await User.findById(userId);
    again.phone = '12345';
    const err = await again.save().then(
      () => null,
      (e) => e
    );
    expect(err).toBeTruthy();
    expect(err.errors.phone.message).toBe('请输入有效的手机号');
  });
});
