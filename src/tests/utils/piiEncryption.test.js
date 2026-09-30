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
});

describe('User schema 接线（真实 Mongo：写侧加密、读侧解密、检索键同步）', () => {
  let userId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });
  afterAll(async () => {
    if (userId) await User.deleteOne({ _id: userId }, { bypassAppendOnly: true });
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  });

  test('创建：库内是密文 + 检索键同步，模型读回是明文', async () => {
    const u = await User.create({
      username: `pii_${Date.now().toString(36)}`,
      email: `pii_${Date.now().toString(36)}@example.invalid`,
      password: randomPassword(),
      realName: PLAIN_NAME,
      phone: PLAIN_PHONE,
      roles: [],
    });
    userId = u._id;

    // 绕过 getter 看库内原始形态：必须是密文且不含明文
    const raw = await User.collection.findOne({ _id: u._id });
    expect(raw.realName).toMatch(/^enc\.v1\./);
    expect(raw.phone).toMatch(/^enc\.v1\./);
    expect(raw.realName).not.toContain(PLAIN_NAME);
    expect(raw.phone).not.toContain(PLAIN_PHONE);
    // 检索键同步且 select:false
    expect(raw.phoneKey).toBe(piiSearchKey(PLAIN_PHONE));
    expect(raw.realNameKey).toBe(piiSearchKey(PLAIN_NAME));

    // 模型读回（默认投影不含检索键；明文经 getter 还原）
    const read = await User.findById(u._id);
    expect(read.realName).toBe(PLAIN_NAME);
    expect(read.phone).toBe(PLAIN_PHONE);
    const withKey = await User.findById(u._id).select('+phoneKey +realNameKey');
    expect(withKey.phoneKey).toBe(piiSearchKey(PLAIN_PHONE));
  });

  test('按检索键精确查找（列表搜索的接入方式）', async () => {
    const found = await User.findOne({ phoneKey: piiSearchKey(PLAIN_PHONE) }).select('+phoneKey');
    expect(found).toBeTruthy();
    expect(found._id.toString()).toBe(String(userId));
    // 不存在的手机号查不到
    expect(await User.findOne({ phoneKey: piiSearchKey('13900000000') })).toBeNull();
  });

  test('更新：改动一个字段只重加密该字段，另一个字段密文不动', async () => {
    const before = await User.collection.findOne({ _id: userId });
    const u = await User.findById(userId);
    u.phone = '13987654321';
    await u.save();
    const after = await User.collection.findOne({ _id: userId });
    expect(after.realName).toBe(before.realName); // 未修改字段密文原样（随机 IV 下重加密=假变更）
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
