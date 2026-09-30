'use strict';

/**
 * `PUT /api/auth/profile` 的"清空"语义：按字段分档，不是一刀切
 *
 * 三个可选文本字段在 `User` 模型里的形态约束并不相同，所以"提交空值"的含义也不同：
 *   · phone —— schema 校验器显式允许 `''`（"允许留空（清空手机号是合法操作）"），
 *     于是空串是一条**合法指令**：必须 200 并把库里的号码清掉；
 *   · email —— `required + unique`，库里永远不可能有 `''`，两条唯一索引会互相打架。
 *     于是空串只能是**非法输入**：必须 400（fail-closed），不得冒到 DB 层变 500；
 *   · 空白串（phone `'   '`）—— 既不是合法号码也不是"清空"，同样只能 400。
 *
 * 修复前 `body('phone')` 用的是默认 `.optional()`，只放过 `undefined` ⇒ 空串走到
 * `matches(/^1[3-9]\d{9}$/)` 被 400 拦下。前端为了不被拦，只能把空值改发 `undefined`
 * （语义 = 不改），于是"清掉手机号"这条用户可见的操作在整条链上表达不出来。
 * 改成 `.optional({ values: 'falsy' })` 后，空串跳过形状校验、由服务层写入 `''`。
 *
 * 反向对照（钉"没被顺手放宽"）：合法号码照旧改得动，非法号码照旧 400。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');
const { decryptPii } = require('../../utils/piiCrypto');

const stamp = `pfc${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();

describe('资料接口的空值分档：手机号可清空、邮箱不可清空', () => {
  let app;
  let User;
  const tokens = new Map();

  const sign = (u) =>
    jwt.sign(
      { userId: String(u._id), username: u.username, tokenVersion: u.tokenVersion ?? 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

  /** 每个用例一个专属账号：清空类用例会改写库，账号复用会构成跨用例的顺序前提 */
  const makeUser = async (slug, extra) => {
    const u = await User.create({
      username: `${stamp}_${slug}`,
      email: `${slug}${stamp}@example.com`,
      password: PASSWORD,
      ...extra,
    });
    tokens.set(String(u._id), sign(u));
    return u;
  };

  const putProfile = (id, body) =>
    request(app)
      .put('/api/auth/profile')
      .set('Authorization', `Bearer ${tokens.get(id)}`)
      .send(body);

  // P1-②：realName/phone 在库里是密文（getter 只在 mongoose 文档上生效，lean 拿到
  // 原始形态）——本用例断言的是"业务意义上的字段值"，故对密文先解密再比对；
  // 明文存量行透传，两种形态都归一到明文口径。
  const fieldOf = async (id, field) => decryptPii((await User.findById(id).lean())[field]);

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    require('../../models/TokenBlacklist');
    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}_`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('手机号提交空串 ⇒ 200 且库里的号码真的被清掉（清空是合法操作）', async () => {
    const u = await makeUser('clear', { phone: '13800001111' });
    expect(await fieldOf(String(u._id), 'phone')).toBe('13800001111'); // 起点自证

    const res = await putProfile(String(u._id), { phone: '' });
    expect(res.status).toBe(200);
    expect(await fieldOf(String(u._id), 'phone')).toBe('');
    // 回包必须与库一致：前端把回包当作本地态的唯一来源，回 `undefined` 会让下次
    // 打开资料页又显示成旧号码（"清空成功了但看起来没生效"）。
    expect(res.body.data.phone).toBe('');
  });

  test('反向对照：合法号码照旧改得动，非法号码照旧 400 且原值不动', async () => {
    const u = await makeUser('keep', { phone: '13800002222' });

    const ok = await putProfile(String(u._id), { phone: '13900003333' });
    expect(ok.status).toBe(200);
    expect(await fieldOf(String(u._id), 'phone')).toBe('13900003333');

    const bad = await putProfile(String(u._id), { phone: '12345' });
    expect(bad.status).toBe(400);
    expect(await fieldOf(String(u._id), 'phone')).toBe('13900003333');
  });

  test('空白串不算清空：手机号提交三个空格 ⇒ 400，不得把空格落库', async () => {
    const u = await makeUser('blank', { phone: '13800004444' });
    const res = await putProfile(String(u._id), { phone: '   ' });
    expect(res.status).toBe(400);
    expect(await fieldOf(String(u._id), 'phone')).toBe('13800004444');
  });

  test('邮箱提交空串 ⇒ 400（required + unique 的字段没有"清空"这条出路）且原值不动', async () => {
    const u = await makeUser('mail');
    const res = await putProfile(String(u._id), { email: '' });
    expect(res.status).toBe(400);
    // 必须是校验器那句错，而不是唯一索引撞车冒出来的通用 400/500
    const errs = (res.body?.errors?.fieldErrors || []).map((e) => `${e.path}=${e.msg}`);
    expect(errs).toContain('email=请输入有效的邮箱地址');
    expect(await fieldOf(String(u._id), 'email')).toBe(u.email);
  });

  test('未提交字段保持原值：只改邮箱不得顺手清掉手机号', async () => {
    const u = await makeUser('partial', { phone: '13800005555' });
    const res = await putProfile(String(u._id), { email: `new${stamp}@example.com` });
    expect(res.status).toBe(200);
    expect(await fieldOf(String(u._id), 'email')).toBe(`new${stamp}@example.com`);
    expect(await fieldOf(String(u._id), 'phone')).toBe('13800005555');
  });
});
