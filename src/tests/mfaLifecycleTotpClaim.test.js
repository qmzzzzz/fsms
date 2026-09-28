'use strict';

/**
 * MFA 生命周期端点必须**消费**口令窗口，而不只是"单调推进"它
 *
 * 现状（落地前的行为，逐行读 `src/controllers/mfaController.js` 三处消费点 + 对照
 * `src/services/authService.js:534` 与 `middleware/security` 的步进实现）：
 *
 *   登录 / 步进二次验证：条件更新 `mfaLastCounter < counter` 做**原子认领**
 * ⇒ 同一时间窗的码只能用一次（P2-12 / 已修）。
 *   mfaDisable / regenerateRecoveryCodes / mfaEnable：只做
 *     `$max: { mfaLastCounter: counter }` ⇒ **只保证不把水位拉回，不拒绝已消费的窗口**。
 *
 * `$max` 修的是"把守卫拉回"这一半；另一半分文未提：
 * **等于水位的窗口（也就是登录刚刚用掉的那个码）在这两个端点上依然有效。**
 * verifyTotp 的 ±1 窗口 ≈ 90 秒，所以：
 *   AiTM 钓鱼代理把受害者实时口令转发到真实登录（水位推进到 W，代理方拿到会话），
 *   ≤90s 内**同一个码**还能在代理方会话上通过"关闭两步验证"与"重新生成恢复码"。
 * mfaDisable 自己的注释写着该端点的第二因子是为了
 * "关闭属敏感操作……**防会话劫持后被冒关**"——被登录消费过的码仍可冒关，
 * 这条不变量在实现上只剩"知道当前码"这一项，而它已被证明是一次性的。
 * 拿到 10 张新恢复码 + 关掉 MFA = 换密码也带不走的持久访问。
 *
 * 不在本判据范围内的：`mfaEnable`。它在校验口令**之前**就用
 * `if (user.mfaEnabled) return MFA_ALREADY_ENABLED` 挡下（第 178 行早于 186 行），
 * 而"已消费的登录码"前提是 MFA 已启用 ⇒ 无可双花的状态。
 * 因此本判据只钉 disable / regenerate 两处，不夸大成"三处都有洞"。
 *
 * 本文件同时给出"夹具本身有效"的对照断言（新鲜窗口必须成功）：
 * 记账期它们若一起红，说明是"环境搭错了"而不是"缺陷已记账"；
 * 现在它们同样是门禁——认领逻辑写宽了会先把正当用户挡在门外，这里立刻可见。
 */

const mongoose = require('mongoose');

const CURRENT_WINDOW = () => Math.floor(Date.now() / 1000 / 30);

const makeRes = () => {
  const res = { statusCode: 200, body: null, locals: {} };
  res.status = (c) => {
    res.statusCode = c;
    return res;
  };
  res.json = (b) => {
    res.body = b;
    return res;
  };
  return res;
};

describe('MFA 生命周期端点的口令认领语义', () => {
  let User;
  let controller;
  let generateSecret;
  let hotp;
  let base32Decode;
  let encryptMfaSecret;
  let secret;
  let uid;
  const username = 'f85';

  const codeFor = (offset = 0) => hotp(base32Decode(secret), CURRENT_WINDOW() + offset);

  /** 模拟"登录侧刚刚消费掉窗口 W"：原子认领的产物就是水位被推进到 W */
  const markWindowConsumed = async (offset) => {
    await User.findByIdAndUpdate(uid, { mfaLastCounter: CURRENT_WINDOW() + offset });
  };

  const call = async (fn, body) => {
    const res = makeRes();
    const req = {
      user: { userId: uid, username },
      body,
      ip: '127.0.0.1',
      method: 'POST',
      originalUrl: '/api/auth/mfa/x',
      get: () => 'jest',
    };
    await controller[fn](req, res, (err) => {
      throw err;
    });
    return res;
  };

  const errorCode = (res) => res.body?.errors?.errorCode;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    controller = require('../controllers/mfaController');
    const totp = require('../utils/totp');
    generateSecret = totp.generateSecret;
    hotp = totp.hotp;
    base32Decode = totp.base32Decode;
    encryptMfaSecret = require('../utils/mfaSecret').encryptMfaSecret;
  });

  beforeEach(async () => {
    await User.deleteMany({ username });
    secret = generateSecret();
    const created = await User.create({
      username,
      email: `${username}@example.com`,
      password: 'Aa1!aaaaaaaaaaaaaaaa',
      status: 'active',
      roles: [],
      mfaEnabled: true,
      mfaSecret: encryptMfaSecret(secret),
      mfaFailCount: 0,
      mfaLockUntil: null,
      mfaLastCounter: 0,
    });
    uid = created._id;
  });

  afterAll(async () => {
    await User.deleteMany({ username });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  describe('夹具有效性（这些必须是普通断言，不能挂 .failing）', () => {
    test('新鲜窗口的码可以重新生成恢复码（否则下面的"重放被拒"会因环境而红）', async () => {
      const res = await call('regenerateRecoveryCodes', { mfaCode: codeFor() });
      expect(errorCode(res)).toBeUndefined();
      expect(res.statusCode).toBe(200);
      expect(Array.isArray(res.body.data.recoveryCodes)).toBe(true);
      expect(res.body.data.recoveryCodes).toHaveLength(10);
      // 顺带钉住：成功后水位被推进到该窗口
      const after = await User.findById(uid).select('mfaLastCounter');
      expect(after.mfaLastCounter).toBe(CURRENT_WINDOW());
      // 这条投影在下面的重放用例里也会用一次：若选择器取不到值，那三条
      // 会以"没有变化"的形式假绿，所以先在响亮的路径上证明这个投影取得到值。
      const full = await User.findById(uid).select('+mfaRecoveryCodes mfaFailCount');
      expect(full.mfaRecoveryCodes).toHaveLength(10);
      expect(full.mfaFailCount).toBe(0);
    });

    test('新鲜窗口的码可以关闭 MFA', async () => {
      const res = await call('mfaDisable', { mfaCode: codeFor() });
      expect(errorCode(res)).toBeUndefined();
      const after = await User.findById(uid).select('mfaEnabled');
      expect(after.mfaEnabled).toBe(false);
    });

    test('口令错误的码仍然被拒（严格化不许把坏码放进来）', async () => {
      const res = await call('regenerateRecoveryCodes', { mfaCode: '000000' });
      expect(res.statusCode).toBe(400);
    });
  });

  /**
   * 以下三条是**本文件的存在理由**：已被登录消费的窗口不得再次生效。
   * 2026-09-19 首次实测为红灯（未加 .failing 跑：`Expected: 400 / Received: 200` × 3），
   * 当时因 `mfaController.js` 是并行会话的在途（M 态）文件而以 `test.failing` 记账；
   * 落地（两处改成原子认领 `claimTotpWindow`）后 `.failing` 已摘除，
   * 现在它们是常规回归门禁。
   * 夹具坏掉不会伪装成"缺陷已修"：上面那三条非 failing 的断言会先红。
   *
   * 断言写成"不变量"而不是具体状态码：`MFA_VERIFY_FAILED` 注册的是 **403**
   * （`utils/errorCodes.js:72`），`MFA_REGEN_CODE_INVALID` 才是 400；
   * 钉死 400 会让一条正确的修复在这三条上"仍然失败"，
   * 那样门禁就变成了挡路的假红而不是提示音。
   */
  describe('期望语义：已被登录消费的窗口不得再次生效（认领语义）', () => {
    test('regenerateRecoveryCodes 必须拒绝"水位所在窗口"的码', async () => {
      await markWindowConsumed(0);
      const res = await call('regenerateRecoveryCodes', { mfaCode: codeFor() });
      expect(res.statusCode).not.toBe(200);
      expect(errorCode(res)).toBeDefined();
      // 且旧恢复码不许被换掉（"拒绝"必须是零副作用，不是先改再报）
      const after = await User.findById(uid).select('+mfaRecoveryCodes mfaFailCount');
      expect(after.mfaRecoveryCodes).toHaveLength(0);
      // 重放要计入失败计数：不记就是给攻击者留一条免费的窗口探测通道
      expect(after.mfaFailCount).toBeGreaterThanOrEqual(1);
    });

    test('mfaDisable 必须拒绝"水位所在窗口"的码', async () => {
      await markWindowConsumed(0);
      const res = await call('mfaDisable', { mfaCode: codeFor() });
      expect(res.statusCode).not.toBe(200);
      const after = await User.findById(uid).select('mfaEnabled');
      expect(after.mfaEnabled).toBe(true); // 冒关未遂：MFA 必须还在
    });

    test('低于水位的窗口（旧码）同样不得生效', async () => {
      await markWindowConsumed(1);
      const res = await call('regenerateRecoveryCodes', { mfaCode: codeFor(-1) });
      expect(res.statusCode).not.toBe(200);
    });

    test('反向保护：拒绝重放不许把下一个新窗口一起废掉', async () => {
      await markWindowConsumed(0);
      await call('regenerateRecoveryCodes', { mfaCode: codeFor() }); // 重放：应被拒
      const fresh = await call('regenerateRecoveryCodes', { mfaCode: codeFor(1) });
      expect(fresh.statusCode).toBe(200);
    });
  });
});
