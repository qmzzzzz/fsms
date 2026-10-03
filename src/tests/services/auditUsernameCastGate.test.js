/**
 * 审计 username 维的落库闸（本会话独立实测，非采信任何报告）
 *
 * 【缺陷本体】`username` 是全仓唯一由**未认证请求方直接决定**的被哈希字段：
 * `authController.js:170` 把 `req.body.username` 原样交给登录失败审计，路由侧只做了
 * `.trim()` / `notEmpty` / `isLength({max:128})`，既不碰控制字符也不碰代理项。
 * 实测（本文件第一条用例，闸之前跑出的真实数字）：请求体 `{"username":"a\ud800b"}` 里
 * `JSON.parse` 自己就产出孤立代理项 ⇒ 铸造后内存形态 `61 d800 62`，BSON 落盘形态
 * `61 fffd 62`，而哈希是在序列化**之前**用内存文档算的（auditLogHooks pre('save')）、
 * 校验器却拿读回来的文档重算 ⇒ 这条没人碰过的记录**永久 hash_mismatch**，与真实篡改同形，
 * 而 `scripts/verify-audit-chain.js` 的退出码是部署门禁。
 *
 * 【为什么不能只靠"上游别传脏东西"】写入点 30+ 个，`req.user.username` 与
 * `req.body.username` 在同一行代码里长得一模一样；闸补在 schema 单点上，
 * 才不要求每个新写入点都记得清洗（同族先例：ip / userAgent 的闸，判据见 constants/audit.js）。
 *
 * 【实测过的负结果，一并钉住免得重复量】
 *  - 控制字符（NUL / CR / U+202E Bidi）**逐字符原样往返**，不产生哈希伪影——它的危害面是
 *    审计列表与导出的终端渲染，不是链；
 *  - 2000 字符的 username 能正常入库，collated 索引 `{username:1, timestamp:-1}`
 *    不因超键长拒写 ⇒ 这一维没有"静默丢行"风险，上界的价值是单点防御与渲染口径。
 *
 * 【闸的两处偏离本族工厂的理由】见 constants/audit.js 的 `cleanAuditUsername` 注释；
 * 本文件把它们各自钉成一条可响的用例（丢行方向与不变形方向各一侧，缺一条就是假绿）。
 */

const mongoose = require('mongoose');

const { stripControlChars } = require('../../utils/helpers');
const {
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  computeHash,
  chainBatch,
} = require('../../utils/auditChain');
const { AUDIT_USERNAME_MAX_LENGTH, cleanAuditUsername } = require('../../constants/audit');

const AuditLog = require('../../models/AuditLog');

/** 逐码元打印十六进制：`a\ud800b` 与 `a\ufffdb` 在人眼里都是"a?b"，只有码元分得开 */
const cps = (s) =>
  Array.from(String(s))
    .map((c) => c.charCodeAt(0).toString(16))
    .join(' ');

const base = (overrides) => ({
  action: 'zz_username_gate',
  category: 'auth',
  ip: '203.0.113.99',
  ...overrides,
});

/** 铸造 = insertMany 收到的那一步：同一条 schema、同一组 setter，只是不经 DB */
const castToStoredShape = (raw) => new AuditLog(raw).toObject({ getters: false, virtuals: false });

const hasLoneSurrogate = (s) => {
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
};

const HOSTILE_SURROGATE = JSON.parse('{"u":"a\\ud800b"}').u;
const HOSTILE_CONTROL = JSON.parse('{"u":"a\\u0000b\\u202ec\\r"}').u;

describe('审计 username 维：被哈希的形态必须等于落盘的形态', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    // 本套件写的是共享内存库：留下的记录会进别的套件的链核验窗口（--randomize 下顺序不定）。
    // bypassAppendOnly 只在 NODE_ENV=test 生效（auditLogHooks.js 的守卫）。
    await AuditLog.deleteMany({ action: 'zz_username_gate' }, { bypassAppendOnly: true });
  });

  it('孤立代理项用户名：入库后读回来的形态必须仍能算回同一条哈希', async () => {
    const doc = await AuditLog.create(base({ username: HOSTILE_SURROGATE }));
    const stored = await AuditLog.findById(doc._id).lean();

    // 前提自证 + **这条自证的边界在哪**（2026-10-01 复核后重写，原注释是假的）：
    // 实测 bson 自己在序列化时就把孤立代理项改写成 U+FFFD（`serialize({u:'a\ud800b'})`
    // 尾部字节 `61 ef bf bd 62`），所以下面这两条钉的是**驱动形态**，删掉 schema 的
    // `set` 它们照样绿。本用例真正有牙的是后面两条：`stored.username === doc.username`
    // （内存形态必须已经是落盘形态）与哈希复算相等。判据见本文件变异台账 M1/M9。
    expect(cps(stored.username)).toBe('61 fffd 62');
    expect(hasLoneSurrogate(stored.username)).toBe(false);
    // 正向对照：合法 ASCII 用户名不得被改写（否则就是改了哈希口径）
    expect(cps(cleanAuditUsername('kq7t_admin'))).toBe('6b 71 37 74 5f 61 64 6d 69 6e');

    expect(stored.username).toBe(doc.username);
    expect(
      computeHash(
        doc.prevHash,
        canonicalPayload(stored, doc.hashVersion || CURRENT_PAYLOAD_VERSION)
      )
    ).toBe(doc.hash);
  });

  it('反向对照：同一条载荷里换回未清洗的代理项，哈希必须不同（判据有牙）', async () => {
    const doc = await AuditLog.create(base({ username: HOSTILE_SURROGATE }));
    const stored = await AuditLog.findById(doc._id).lean();
    const poisoned = computeHash(
      doc.prevHash,
      canonicalPayload({ ...stored, username: HOSTILE_SURROGATE }, doc.hashVersion)
    );
    expect(poisoned).not.toBe(doc.hash);
  });

  it('控制字符不入库（它原样往返，危害面是审计列表与导出的渲染）', async () => {
    const doc = await AuditLog.create(base({ username: HOSTILE_CONTROL }));
    const stored = await AuditLog.findById(doc._id).lean();
    expect(stored.username).toBe('a b c');
    // 闸自身不得留下孤立代理项（上面 HOSTILE_CONTROL 不含代理项，这里补一个含的）
    expect(hasLoneSurrogate(cleanAuditUsername(JSON.parse('"\\ud800"')))).toBe(false);
    expect(doc.hash).toBe(computeHash(doc.prevHash, canonicalPayload(stored, doc.hashVersion)));
  });

  it('批量路径（chainBatch → insertMany 铸造）同样同源：少了镜像行本条就红', () => {
    const docs = [
      base({ username: HOSTILE_SURROGATE }),
      base({ username: HOSTILE_CONTROL }),
      base({ username: 'x'.repeat(AUDIT_USERNAME_MAX_LENGTH + 71) }),
      base({ username: 'A' + '\u{1F600}'.repeat(100) }), // 截断点落在代理对中间
      base({ username: 'a'.repeat(AUDIT_USERNAME_MAX_LENGTH - 1) + ' c' }), // 截断点落在空格上
    ];
    chainBatch(docs, null);
    for (const raw of docs) {
      const stored = castToStoredShape(raw);
      expect(hasLoneSurrogate(stored.username)).toBe(false);
      expect(computeHash(stored.prevHash, canonicalPayload(stored, CURRENT_PAYLOAD_VERSION))).toBe(
        stored.hash
      );
      // 二次铸造（schema 的 set 在 insertMany 时还会再跑一次）不得再改变形态
      expect(cps(castToStoredShape(stored).username)).toBe(cps(stored.username));
    }
  });

  it('上界封顶且幂等：算哈希前一次、铸造时一次，两侧必须同形', () => {
    const samples = [
      'admin',
      '张三',
      'kq7t_admin',
      'a'.repeat(AUDIT_USERNAME_MAX_LENGTH - 1) + ' c', // 截断点正落在替换出来的空格上
      '\u0000'.repeat(AUDIT_USERNAME_MAX_LENGTH + 72), // 清洗后为空 ⇒ 走回退分支，仍须封顶
      JSON.parse('"a\\ud800b"'),
      JSON.parse('"\\u0000abc\\u202e"'),
      'x'.repeat(AUDIT_USERNAME_MAX_LENGTH + 1),
      'A' + '\u{1F600}'.repeat(100),
      '   ',
      '',
    ];
    for (const s of samples) {
      const once = cleanAuditUsername(s);
      expect(cps(cleanAuditUsername(once))).toBe(cps(once));
      if (typeof once === 'string') {
        expect(once.length).toBeLessThanOrEqual(AUDIT_USERNAME_MAX_LENGTH);
        expect(hasLoneSurrogate(once)).toBe(false);
      }
    }
    // 合法值逐字符不变
    expect(cleanAuditUsername('kq7t_admin')).toBe('kq7t_admin');
    expect(cleanAuditUsername('张三')).toBe('张三');
  });

  it('行为保全：闸不得把「今天存得下的」变成「丢一行」', () => {
    // 实测 Mongoose 8：数字/布尔照旧转文本，对象/数组照旧在校验期报铸造失败
    expect(new AuditLog(base({ username: 12345 })).username).toBe('12345');
    expect(new AuditLog(base({ username: true })).username).toBe('true');
    expect(new AuditLog(base({ username: {} })).validateSync()?.errors?.username?.message).toMatch(
      /Cast to string failed/
    );
    // 纯空白今天入库成功（required 只拒空串）——降级成 undefined 就是新增一种丢行
    const blank = new AuditLog(base({ username: '   ' }));
    expect(blank.validateSync()?.errors?.username).toBeUndefined();
    // 空串仍是 required 失败，与今日同形（闸没有把它变成能存）
    expect(new AuditLog(base({ username: '' })).validateSync()?.errors?.username).toBeDefined();
  });

  it('闸与工厂的偏离：number/boolean 收成文本，null/undefined/object 不降级 undefined', () => {
    // makeAuditTextFieldGate 对非字符串一律 undefined——这里必须不同，否则 username 丢整行。
    // 而 number/boolean 必须**收成文本**：Mongoose 的 String 铸造会把它们变成
    // '12345'/'true'（实测 `cast(12345)==='12345'`），批量路径是"先算哈希后铸造"，
    // 透传数字就是被哈希的形态（12345）≠ 落库的形态（'12345'）⇒ 又是一条永久 hash_mismatch。
    expect(cleanAuditUsername(12345)).toBe('12345');
    expect(cleanAuditUsername(true)).toBe('true');
    expect(cleanAuditUsername(null)).toBeNull();
    expect(cleanAuditUsername(undefined)).toBeUndefined();
    // object 仍原样：交给铸造抛 Cast to string failed（收成 '[object Object]' 是把丢行换成垃圾 who）
    expect(cleanAuditUsername({})).toEqual({});
    expect(stripControlChars('a\u0000b', 128)).toBe('a b');
  });

  it('批量路径的非字符串 username：算哈希之前就必须已经是铸造后的形态', () => {
    const docs = [base({ username: 12345 }), base({ username: true })];
    chainBatch(docs, null);
    for (const raw of docs) {
      expect(typeof raw.username).toBe('string');
      const stored = castToStoredShape(raw);
      expect(computeHash(stored.prevHash, canonicalPayload(stored, CURRENT_PAYLOAD_VERSION))).toBe(
        stored.hash
      );
    }
  });

  it('超长原始行仍能读回：本闸不是修一个正在发生的丢数据故障（散文改成断言）', async () => {
    const long = 'z'.repeat(2000);
    const inserted = await AuditLog.collection.insertOne({
      _id: new mongoose.Types.ObjectId(),
      action: 'zz_username_gate',
      category: 'auth',
      username: long,
      ip: '203.0.113.96',
      timestamp: new Date(),
      riskLevel: 'low',
      success: true,
      hashVersion: CURRENT_PAYLOAD_VERSION,
    });
    const back = await AuditLog.collection.findOne({ _id: inserted.insertedId });
    expect(back.username).toHaveLength(2000); // collated 索引不因超键长拒写
    expect(cleanAuditUsername(long)).toHaveLength(AUDIT_USERNAME_MAX_LENGTH); // 经闸的写入封顶
  });

  it('查询侧也过闸（实测形状）：等值被改写、区间两端各自改写后可塌成空区间', async () => {
    const raw = 'a' + String.fromCharCode(0) + 'b';
    const mk = (ip, username) => ({
      _id: new mongoose.Types.ObjectId(),
      action: 'zz_username_gate',
      category: 'auth',
      username,
      ip,
      timestamp: new Date(),
      riskLevel: 'low',
      success: true,
      hashVersion: CURRENT_PAYLOAD_VERSION,
    });
    // R1 模拟本闸之前写入的存量脏行（username 里真带 NUL）；R2 是闸后形态
    const dirty = mk('203.0.113.94', raw);
    const clean = mk('203.0.113.95', 'a b');
    await AuditLog.collection.insertMany([dirty, clean]);

    // 判别"查询侧过闸"还是"读取侧过闸"：按 ip 读回 R1，形态不变 ⇒ 铸造/set 不参与 hydrate
    // （resign 脚本与链核验按库中原形态算哈希这一点也因此成立）
    expect((await AuditLog.findOne({ ip: '203.0.113.94' }).lean()).username).toBe(raw);
    // 原文等值查 R1 打不中（0），却打得中 R2（1）⇒ 是**下发条件被 set 改写了**，不是读侧
    expect(await AuditLog.countDocuments({ ip: '203.0.113.94', username: raw })).toBe(0);
    expect(await AuditLog.countDocuments({ ip: '203.0.113.95', username: raw })).toBe(1);
    // 区间两侧**同样**过闸（本机实测，见下几行）：原文范围经原生 driver 能捞出 R1，
    const range = { $gte: raw.slice(0, 2), $lt: 'a' + String.fromCharCode(1) };
    // 经 Mongoose 则把 `$gte:'a\0'` 与 `$lt:'a\u0001'` 分别洗成 'a' 与 'a' ⇒ 塌成空区间，0 命中。
    // ⇒ 存量脏行在 model 层**两条路都查不到**（等值被改写、区间被改写后塌空），
    //   只有原生 driver 的原文查询看得见它。
    expect(
      (
        await AuditLog.collection.find({ action: 'zz_username_gate', username: range }).toArray()
      ).map((d) => cps(d.username))
    ).toEqual([cps(raw)]);
    const ranged = await AuditLog.find({ action: 'zz_username_gate', username: range })
      .select('username')
      .lean();
    expect(ranged).toEqual([]);
    expect([cleanAuditUsername(range.$gte), cleanAuditUsername(range.$lt)]).toEqual(['a', 'a']);
    // 反向对照：合法前缀的两个边界都不含空白/控制字符 ⇒ 过闸后逐字符不变，区间不塌
    expect([cleanAuditUsername('admin'), cleanAuditUsername('admio')]).toEqual(['admin', 'admio']);
    // ↑ 若给前缀项补上别的清洗口径，本组断言会响——它钉的是"边界独立改写"这个事实。
  });
});
