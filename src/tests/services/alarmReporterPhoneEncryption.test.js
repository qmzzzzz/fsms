/**
 * FireAlarm.reporter.phone at-rest 加密（P1，2026-10-16）
 *
 * 缺口形状：`reporter.phone` 原先明文落库（`{ type: String, maxlength: 20 }`，
 * 无 getter / 无加密钩子），而读侧虽已由 `ALARM_READ_SELECT` 收窄、消费方为零，
 * 「at-rest 明文」这一半从未关闭——拿到备份转储 / DB 文件的人可直读第三方上报人
 * 手机号（个保法第 51 条的加密/去标识化要求，与 User.phone 同一威胁位面）。
 *
 * 本文件与 utils/piiEncryption.test.js 的 B 层同构，但**不是**重复：
 * 后者钉的是 User schema 的接线，这里是 FireAlarm 的**嵌套路径**接线——
 * 最容易落地失败的一点是 AAD 主体取错：reporter 是嵌套 Document，`this._id`
 * 为 undefined，只有经 `$parent()` 上溯到报警文档才拿得到正确的绑定主体。
 * 取错主体 ⇒ 密文退化成无绑定（跨行可搬运），而"加密了"这件事照样成立、
 * 表面用例照样全绿。故这里必须有「跨行搬运被拦」这条可证伪用例。
 *
 * 可证伪对：每条断言都配一条反向证据（夹具自证密文真的落库、getter 真能解回明文、
 * 正确上下文仍可解），避免"其实没加密"或"其实解不开"被读成通过。
 */

const mongoose = require('mongoose');

const PLAIN_PHONE = '13700137000';

describe('FireAlarm.reporter.phone at-rest 加密', () => {
  let FireAlarm;
  const stamp = `arpe${String(Date.now()).slice(-8)}`;
  const rawPhone = async (id) =>
    (await mongoose.connection.collection('firealarms').findOne({ _id: id }))?.reporter?.phone;

  const mk = (phone, suffix = '') =>
    FireAlarm.create({
      alarmType: 'smoke',
      description: `${stamp}${suffix} 加密用例`,
      reporter: { name: '上报人丙', phone },
    });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../../models/FireAlarm');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await FireAlarm.deleteMany({ description: new RegExp(stamp) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('写侧加密 / 读侧解密：库里是 enc.v2. 密文，getter 解回明文', async () => {
    const alarm = await mk(PLAIN_PHONE);
    const stored = await rawPhone(alarm._id);

    // 落库形态：v2（AAD 行绑定），且**不含明文**
    expect(stored).toMatch(/^enc\.v2\./);
    expect(stored).not.toContain(PLAIN_PHONE);
    // 读侧 getter 解回明文（证明密文没坏，只是 at-rest 被保护）
    expect(alarm.reporter.phone).toBe(PLAIN_PHONE);
  });

  test('AAD 行绑定：把一条的密文搬到另一条上，读侧必须认证失败（绑定主体取的是父文档 _id）', async () => {
    const victim = await mk(PLAIN_PHONE, '-victim');
    const other = await mk('13600136000', '-other');
    const victimCipher = await rawPhone(victim._id);

    // 模拟"持 DB 写权限者把受害者密文复制到自己那行"
    await mongoose.connection
      .collection('firealarms')
      .updateOne({ _id: other._id }, { $set: { 'reporter.phone': victimCipher } });

    const reloaded = await FireAlarm.findById(other._id);
    expect(() => reloaded.reporter.phone).toThrow(); // GCM 认证失败
    // 反向对照：受害者自己那行照常可解
    const victimReloaded = await FireAlarm.findById(victim._id);
    expect(victimReloaded.reporter.phone).toBe(PLAIN_PHONE);
  });

  test('长度校验在明文阶段：超过 20 字符被拦，文案与路由同口径', async () => {
    await expect(mk('1'.repeat(21), '-long')).rejects.toThrow(/上报人电话最多 20 个字符/);
  });

  test('幂等：未修改的行重复 save 不重加密（随机 IV 下密文应保持逐字节不变）', async () => {
    const alarm = await mk(PLAIN_PHONE, '-idem');
    const before = await rawPhone(alarm._id);

    const reloaded = await FireAlarm.findById(alarm._id);
    await reloaded.save();
    const after = await rawPhone(reloaded._id);

    expect(after).toBe(before);
  });

  test('存量明文透传：迁移脚本跑之前的旧行照常可读', async () => {
    // 绕过文档中间件直接写明文，模拟加密上线前的存量行
    const id = new mongoose.Types.ObjectId();
    await mongoose.connection.collection('firealarms').insertOne({
      _id: id,
      alarmCode: `${stamp}-legacy`,
      alarmType: 'smoke',
      description: `${stamp}-legacy 存量行`,
      reporter: { name: '存量上报人', phone: PLAIN_PHONE },
      occurredAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const doc = await FireAlarm.findById(id);
    expect(doc.reporter.phone).toBe(PLAIN_PHONE); // 无版本前缀 ⇒ 原样返回
    expect(await rawPhone(id)).toBe(PLAIN_PHONE); // 且库里确实还是明文（未被读操作改写）
  });
});
