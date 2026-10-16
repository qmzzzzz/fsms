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
const {
  encryptPii,
  decryptPii,
  piiSearchKey,
  piiSubstringKeys,
  SUBSTRING_GRAM_SIZE,
  VERSION_PREFIX,
} = require('../../utils/piiCrypto');
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

  /**
   * v2 AAD 行绑定（2026-10-01 审计 finding：v1 密文可跨行搬运）。
   * 同一把派生钥下，把受害者的 enc.v1 串复制到自己那行，getter 就会解出受害者的
   * 明文——一次 DB 写权限兑换任意用户 PII。v2 把 pii:v2:<subjectId>:<field> 灌进
   * GCM 认证标签：换行、换字段、缺上下文一律认证失败。
   */
  describe('v2 AAD 行绑定', () => {
    const ctxA = { subjectId: 'a'.repeat(24), field: 'phone' };
    const ctxB = { subjectId: 'b'.repeat(24), field: 'phone' };

    test('往返：密文带 enc.v2. 前缀、随机 IV 不可链接、正确上下文可解', () => {
      const a = encryptPii(PLAIN_PHONE, ctxA);
      const b = encryptPii(PLAIN_PHONE, ctxA);
      expect(a).toMatch(/^enc\.v2\./);
      expect(a).not.toBe(b); // 随机 IV ⇒ 不可链接
      expect(decryptPii(a, ctxA)).toBe(PLAIN_PHONE);
      expect(decryptPii(b, ctxA)).toBe(PLAIN_PHONE);
    });

    test('跨行搬运被拦：换 subjectId / 换字段 / 缺上下文 ⇒ 解密失败，正确上下文仍可解', () => {
      const enc = encryptPii(PLAIN_PHONE, ctxA);
      expect(() => decryptPii(enc, ctxB)).toThrow(); // 复制到别人行 ⇒ GCM 认证失败
      expect(() => decryptPii(enc, { subjectId: ctxA.subjectId, field: 'realName' })).toThrow();
      expect(() => decryptPii(enc)).toThrow(/AAD 绑定上下文/); // 形态层就说清楚缺了什么
      // 正向对照：密文本身没坏，只是绑定不符
      expect(decryptPii(enc, ctxA)).toBe(PLAIN_PHONE);
    });

    test('AAD 上下文非法即抛：subjectId/field 任一为空都不允许造出弱绑定密文', () => {
      expect(() => encryptPii(PLAIN_PHONE, { subjectId: '', field: 'phone' })).toThrow(/AAD/);
      expect(() => encryptPii(PLAIN_PHONE, { subjectId: 'a'.repeat(24), field: '' })).toThrow(
        /AAD/
      );
      expect(() => encryptPii(PLAIN_PHONE, {})).toThrow(/AAD/);
      expect(() => encryptPii(PLAIN_PHONE, null)).not.toThrow(); // 无上下文 = v1 旧格式，见下条
    });

    test('v1 兼容：无上下文加密仍是 v1、解密不需要上下文（存量行迁移前照常可读）', () => {
      const enc = encryptPii(PLAIN_PHONE);
      expect(enc).toMatch(/^enc\.v1\./);
      expect(decryptPii(enc)).toBe(PLAIN_PHONE);
      // getter 统一传上下文读 v1 也不受影响（v1 路径忽略上下文）
      expect(decryptPii(enc, ctxA)).toBe(PLAIN_PHONE);
    });

    test('形态前置校验：IV 非 12 字节 / 数据段不足以容纳 tag ⇒ "形态非法"而非 GCM 原生报错', () => {
      // 原先 data < 16 字节时 subarray 负索引静默变形（整段当 tag、空 ct），
      // 要到 setAuthTag/final 才以 GCM 原生报错浮现
      expect(() => decryptPii('enc.v1.eA==.eA==')).toThrow(/形态非法/);
      const longIv = Buffer.alloc(16).toString('base64');
      expect(() => decryptPii(`enc.v1.${longIv}.${Buffer.alloc(20).toString('base64')}`)).toThrow(
        /形态非法/
      );
    });
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
   * 子串盲索引（A3 / D1-c）：email 加密后「按邮箱片段搜索」不能静默消失。
   *
   * 真值表钉的是三件容易写错的事：
   *  ① 位置无关 —— 片段键只对**内容**做 HMAC，不含位置，否则查询侧无法构造；
   *  ② 归一化一致 —— 与 piiSearchKey 同一口径（trim + lowercase）；
   *  ③ **短串返回空数组**（不是空串键）—— 查询侧要用 `{ $all: [...] }`，
   *     而 `$all: []` 在 MongoDB 里匹配**全部文档**，返回空串键会让"搜 2 个字符"
   *     退化成"返回所有用户"。这条边界是整套设计里最危险的一格。
   */
  describe('子串盲索引（n-gram）', () => {
    test('长度不足 n 返回空数组（不是空串键）：$all:[] 会匹配全部文档，调用方必须跳过该分支', () => {
      expect(piiSubstringKeys('a')).toEqual([]);
      expect(piiSubstringKeys('ab')).toEqual([]);
      expect(piiSubstringKeys('')).toEqual([]);
      expect(piiSubstringKeys('   ')).toEqual([]);
      expect(piiSubstringKeys(null)).toEqual([]);
      expect(piiSubstringKeys(undefined)).toEqual([]);
      expect(piiSubstringKeys(12345)).toEqual([]);
      // 与 piiSearchKey 的差异点：后者对空值返回空串（那是一个"查得到的键"）
      expect(piiSearchKey('')).toBe('');
      expect(piiSubstringKeys('')).not.toBe('');
    });

    test('长度恰为 n 时只有一个 gram；n+1 时有两个（重叠切分）', () => {
      expect(piiSubstringKeys('abc')).toHaveLength(1);
      expect(piiSubstringKeys('abcd')).toHaveLength(2);
      expect(piiSubstringKeys('abcde')).toHaveLength(3);
      expect(SUBSTRING_GRAM_SIZE).toBe(3);
    });

    test('位置无关：同一片段出现在不同位置 ⇒ 同一个键（否则查询侧构造不出来）', () => {
      const head = piiSubstringKeys('abcX');
      const tail = piiSubstringKeys('Xabc');
      // 两者都含 'abc' 这个 gram ⇒ 交集非空
      expect(head.filter((k) => tail.includes(k))).toHaveLength(1);
    });

    test('归一化：大小写与首尾空白不影响键（与检索键同口径）', () => {
      expect(piiSubstringKeys('  A@B.C  ')).toEqual(piiSubstringKeys('a@b.c'));
    });

    test('去重：重复片段只留一个键（aaa 不产生三个相同键）', () => {
      expect(piiSubstringKeys('aaaa')).toHaveLength(1);
      expect(new Set(piiSubstringKeys('aaaa')).size).toBe(1);
    });

    test('域分离：子串键与整串检索键不共用派生标签（同明文两者不相等）', () => {
      expect(piiSubstringKeys('abc')).not.toContain(piiSearchKey('abc'));
    });

    test('候选超集（已知边界）：abc 与 bcd 同时命中不蕴含存在连续的 abcd', () => {
      const probe = piiSubstringKeys('abcXbcd');
      const search = piiSubstringKeys('abcd');
      // 搜索串的每个 gram 都在候选行里 ⇒ $all 会命中，但该行并不含 'abcd'
      expect(search.every((k) => probe.includes(k))).toBe(true);
      expect('abcXbcd'.includes('abcd')).toBe(false);
    });
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
  let seq = 0;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });
  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  });

  /**
   * 每条用例独占自己的用户切片：userId 只在单条用例内有效，不跨用例传递。
   *
   * 原实现把 `userId = u._id` 写在「创建」用例内部，于是整个 describe 块依赖
   * **声明顺序**——「创建」没排第一时，后三条用例拿到 userId=undefined ⇒
   * `User.findById(undefined)` 得 null ⇒
   *   · 按检索键精确查找：expect(found).toBeTruthy() 收到 null
   *   · 更新 / 非法手机号：TypeError: Cannot set properties of null (setting 'phone')
   * CI 的顺序无关门禁（--randomize，seed 20260917/31337/777001）实测三种子全红，
   * 且失败条数随「创建」落在第 2/3/4 位变化（1/2/3 条），正是顺序耦合的指纹。
   *
   * 只把创建挪进 beforeAll 并不够：「更新」会把 phone 改成 13987654321，与
   * 「按检索键精确查找」按 piiSearchKey(PLAIN_PHONE) 查找互相冲突——两条用例
   * 要的是**各自**的切片，而不是一个共享可变对象。
   */
  beforeEach(async () => {
    seq += 1;
    const u = await User.create({
      username: `pii_${Date.now().toString(36)}_${seq}`,
      email: `pii_${Date.now().toString(36)}_${seq}@example.invalid`,
      password: randomPassword(),
      realName: PLAIN_NAME,
      phone: PLAIN_PHONE,
      roles: [],
    });
    userId = u._id;
  });
  afterEach(async () => {
    if (userId) await User.deleteOne({ _id: userId }, { bypassAppendOnly: true });
    userId = undefined;
  });

  test('创建：phone 库内是 v2 密文（AAD 行绑定）+ 检索键同步；realName 按决策保持明文', async () => {
    // 写侧钩子在 beforeEach 的 User.create 上已经跑过，这里断言其落库形态。
    // 绕过 getter 看库内原始形态
    const raw = await User.collection.findOne({ _id: userId });
    expect(raw.phone).toMatch(/^enc\.v2\./);
    expect(raw.phone).not.toContain(PLAIN_PHONE);
    // realName 决策：暂不加密（姓名模糊检索依赖），库内保持明文
    expect(raw.realName).toBe(PLAIN_NAME);
    // 检索键同步且 select:false（realName 无检索键：无消费者，不造死数据）
    expect(raw.phoneKey).toBe(piiSearchKey(PLAIN_PHONE));
    expect(raw.realNameKey).toBeUndefined();

    // 模型读回（默认投影不含检索键；明文经 getter 还原）
    const read = await User.findById(userId);
    expect(read.realName).toBe(PLAIN_NAME);
    expect(read.phone).toBe(PLAIN_PHONE);
    const withKey = await User.findById(userId).select('+phoneKey');
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

  test('跨行搬运（库级端到端）：把 A 行密文整体写进 B 行，B 的读取以认证失败暴露', async () => {
    // 攻击位面：持 DB 写权限者把受害者 A 行的 enc.v2 串复制到自己 B 行。
    // AAD 绑定的是「写密文那一行的 _id」，B 行的 _id 与之不符 ⇒ getter 解密认证失败。
    const rawA = await User.collection.findOne({ _id: userId });
    expect(rawA.phone).toMatch(/^enc\.v2\./);
    const seqB = seq + 1000;
    const inserted = await User.collection.insertOne({
      username: `pii_xplant_${Date.now().toString(36)}_${seqB}`,
      email: `pii_xplant_${Date.now().toString(36)}_${seqB}@example.invalid`,
      // 原生 collection 插入不过模型校验，口令值无语义；用生成器避免硬编码字面量
      password: randomPassword(),
      phone: rawA.phone, // 受害者的密文原样复制
      phoneKey: '',
      roles: [],
    });
    try {
      const read = await User.findById(inserted.insertedId);
      expect(read).toBeTruthy();
      // getter 在属性访问时解密：A 行密文 × B 行 _id ⇒ AAD 不匹配 ⇒ 抛错
      expect(() => read.phone).toThrow();
    } finally {
      await User.collection.deleteOne({ _id: inserted.insertedId });
    }
  });

  test('存量 v1 行（迁移前写入）读侧照常可读：透传口径不因 v2 引入而断裂', async () => {
    const legacy = encryptPii(PLAIN_PHONE); // 无上下文 = v1 形态（旧行的真实库内形态）
    expect(legacy).toMatch(/^enc\.v1\./);
    const seqC = seq + 2000;
    const inserted = await User.collection.insertOne({
      username: `pii_legacy_${Date.now().toString(36)}_${seqC}`,
      email: `pii_legacy_${Date.now().toString(36)}_${seqC}@example.invalid`,
      password: randomPassword(),
      phone: legacy,
      phoneKey: piiSearchKey(PLAIN_PHONE),
      roles: [],
    });
    try {
      const read = await User.findById(inserted.insertedId);
      // getter 统一传上下文，v1 路径忽略之——迁移脚本跑完之前旧数据照常可读
      expect(read.phone).toBe(PLAIN_PHONE);
    } finally {
      await User.collection.deleteOne({ _id: inserted.insertedId });
    }
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

/**
 * A3（2026-10-16）：email 与 phone 走同一套接线，但 schema 上有三处**不同**，
 * 所以不能只靠"phone 那组绿了"来推定 email 也对（方案 §2 的三个地雷）：
 *   ① phone 没有 `lowercase` —— 而 `lowercase` 是每次赋值都生效的 setter，
 *      会吃掉 pre('validate') 钩子刚写进去的 base64 密文；
 *   ② phone 没有 schema 级 `match`/`maxlength` —— 那两个 validator 在钩子**之后**跑，
 *      看到的已是密文，会把每一行都判非法；
 *   ③ phoneKey 非唯一 —— emailKey 是唯一索引，而唯一索引把「缺失」视作 null。
 * 本组逐条把这三件事钉成断言（③ 的索引存在性在下面，① ② 由行为断言覆盖）。
 */
describe('User schema 接线（A3：email 写侧加密 / 读侧解密 / 检索键 / 子串盲索引）', () => {
  const PLAIN_EMAIL = 'A3.Probe@Example.COM';
  const NORMALIZED = 'a3.probe@example.com';
  let id;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
  });
  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
  });
  beforeEach(async () => {
    const u = await User.create({
      username: `pii_email_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6)}`,
      email: PLAIN_EMAIL,
      password: randomPassword(),
      realName: PLAIN_NAME,
      roles: [],
    });
    id = u._id;
  });
  afterEach(async () => {
    if (id) await User.deleteOne({ _id: id }, { bypassAppendOnly: true });
    id = undefined;
  });

  test('地雷 ①：lowercase 不再作用于落库密文（base64 的 A-Z 必须原样保留）', async () => {
    const raw = await User.collection.findOne({ _id: id });
    expect(raw.email).toMatch(/^enc\.v2\./);
    expect(raw.email).not.toContain(NORMALIZED);
    // 密文主体里必须还能看到大写字母——若 lowercase 仍在，base64 会被整体压成小写，
    // 解密时 GCM 认证必然失败（这正是地雷 ① 的指纹）。用多行样本降低"恰好全小写"的偶然性。
    const samples = [];
    for (let i = 0; i < 5; i += 1) {
      const extra = await User.create({
        username: `pii_case_${Date.now().toString(36)}_${i}_${Math.floor(Math.random() * 1e6)}`,
        email: `case.probe.${i}@example.com`,
        password: randomPassword(),
        roles: [],
      });
      samples.push((await User.collection.findOne({ _id: extra._id })).email);
      await User.deleteOne({ _id: extra._id }, { bypassAppendOnly: true });
    }
    expect(samples.some((c) => /[A-Z]/.test(c.slice(7)))).toBe(true);
  });

  test('地雷 ②：schema 级 match/maxlength 已摘掉，钩子写入的密文不会被判非法', async () => {
    // 若 match 还在，User.create 会抛 ValidationError（密文过不了邮箱正则）
    const u = await User.findById(id);
    expect(u.email).toBe(NORMALIZED);
    // 明文期校验仍在：非法邮箱文案与被摘掉的 schema match 逐字一致
    const bad = await User.create({
      username: `pii_bad_${Date.now().toString(36)}`,
      email: 'not-an-email',
      password: randomPassword(),
      roles: [],
    }).then(
      () => null,
      (e) => e
    );
    expect(bad).toBeTruthy();
    expect(bad.errors.email.message).toBe('请输入有效的邮箱地址');
  });

  test('归一化：大写/空白提交 ⇒ 落库密文解回**小写**，且与已有行同 emailKey', async () => {
    const raw = await User.collection.findOne({ _id: id });
    expect(raw.emailKey).toBe(piiSearchKey(NORMALIZED));
    expect(raw.emailKey).toHaveLength(64);
    // 用同一邮箱的不同形态再建一个用户：emailKey 必然相同（唯一索引会拦下，这里只验键）
    const u = new User({
      username: 'probe2',
      email: `  ${PLAIN_EMAIL}  `,
      password: randomPassword(),
    });
    await u.validate();
    expect(u.emailKey).toBe(raw.emailKey);
  });

  test('emailGrams 同步且为子串检索的真候选集（含该行的片段）', async () => {
    const raw = await User.collection.findOne({ _id: id });
    expect(Array.isArray(raw.emailGrams)).toBe(true);
    expect(raw.emailGrams.length).toBeGreaterThan(0);
    // 搜索串 'probe' 的全部 gram 都应出现在该行里 ⇒ $all 能命中
    const search = piiSubstringKeys('probe');
    expect(search.every((k) => raw.emailGrams.includes(k))).toBe(true);
    // 不存在的片段不应命中
    const miss = piiSubstringKeys('zzz');
    expect(miss.some((k) => raw.emailGrams.includes(k))).toBe(false);
  });

  test('跨行搬运 email 密文：AAD 行绑定使 B 行读取以认证失败暴露', async () => {
    const rawA = await User.collection.findOne({ _id: id });
    const other = await User.create({
      username: `pii_email_other_${Date.now().toString(36)}`,
      email: `other.probe.${Date.now().toString(36)}@example.com`,
      password: randomPassword(),
      roles: [],
    });
    try {
      await User.collection.updateOne({ _id: other._id }, { $set: { email: rawA.email } });
      const hijacked = await User.findById(other._id);
      let outcome = null;
      try {
        outcome = hijacked.email;
      } catch (e) {
        outcome = 'AUTH-FAIL';
      }
      expect(outcome).toBe('AUTH-FAIL');
    } finally {
      await User.deleteOne({ _id: other._id }, { bypassAppendOnly: true });
    }
  });

  test('emailKey / emailGrams 默认不出现在读回文档（select:false），显式 select 才拿得到', async () => {
    const plain = await User.findById(id);
    expect(plain.emailKey).toBeUndefined();
    expect(plain.emailGrams).toBeUndefined();
    const withKeys = await User.findById(id).select('+emailKey +emailGrams');
    expect(withKeys.emailKey).toBe(piiSearchKey(NORMALIZED));
    expect(withKeys.emailGrams.length).toBeGreaterThan(0);
    // 但 email 本身必须照常可读（A3 刻意不加 -email）
    expect(plain.email).toBe(NORMALIZED);
  });

  test('地雷 ③ 的前置：schema 声明了 emailKey_1 唯一索引与 emailGrams_1 多键索引', () => {
    const byName = Object.fromEntries(
      User.schema
        .indexes()
        .map(([keys, opts]) => [opts.name || JSON.stringify(keys), { keys, opts }])
    );
    expect(byName.emailKey_1).toBeTruthy();
    expect(byName.emailKey_1.opts.unique).toBe(true);
    expect(byName.emailGrams_1).toBeTruthy();
    expect(byName.emailGrams_1.opts.unique).toBeUndefined();
  });

  test('清空 email 不产生可检索键（空串键会被唯一索引视作同一个键，多行即冲突）', async () => {
    const u = await User.findById(id);
    // email 是 required：清空必须被拦下，而不是落到 emailKey:'' 上
    u.email = '';
    const err = await u.save().then(
      () => null,
      (e) => e
    );
    expect(err).toBeTruthy();
    expect(err.errors.email.message).toBe('邮箱不能为空');
  });
});
