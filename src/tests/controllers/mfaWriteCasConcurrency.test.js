'use strict';

/**
 * MFA 状态变更的写必须**条件化**（CAS），不能是 last-write-wins
 *
 * 背景（逐行读 `src/controllers/mfaController.js` 的四个写点）：
 *   mfaEnroll      → `findOneAndUpdate(pendingFilter)` 条件写（已修，:174）
 *   mfaEnable      → `findOneAndUpdate({mfaEnabled:false, mfaSecret})`（已修，:273）
 *   regenerateRecoveryCodes → `findByIdAndUpdate(_id)` **无条件**（原状，:104）
 *   mfaDisable              → `findByIdAndUpdate(_id)` **无条件**（原状，:368）
 *
 * 同一份文件里前两处写着「下发即生效，不得被并发请求静默回收」的注释，后两处
 * 却是无条件覆盖 —— 这正是「已修的同类漏了一处」：`mfaEnable` 的注释解释了
 * 「后到者会把先到者刚下发的 10 张恢复码整组顶掉」，而 `regenerateRecoveryCodes`
 * 下发的**就是同样那 10 张**，且它的并发窗口更宽（相邻时间窗的两个码都能通过
 * `claimTotpWindow`，因为窗口不同不算重放）。
 *
 * 两处失败模式：
 *   ① 重生成：A 返回 10 张码（用户抄走并保存），B 后写把它们全部作废。
 *      用户手里的恢复码一张都不成立，而两个响应都说"已生成"。
 *   ② 关闭：验证是对 `user.mfaSecret` 解密后做的。该字段被并发 enroll/enable
 *      换掉后，无条件写仍会执行 `mfaEnabled:false, mfaSecret:''` —— 把一个本次
 *      从未证明过控制权的**新登记**一起清掉，审计还记成"用户关闭 MFA"。
 *
 * 本文件用真实 Mongo（mongodb-memory-server）跑，不用 mock 顶替被测逻辑：
 * CAS 的判据在 DB 的匹配语义里，mock 掉 model 等于把被测对象本身 mock 掉。
 * 并发用「闸门」制造：把先到者的写停在执行前，让后到者先落库，再放行先到者 ——
 * 这样"陈旧快照的写"是确定的，不靠 sleep 赌时序。
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

describe('MFA 写点的并发条件化（CAS）', () => {
  let User;
  let controller;
  let totp;
  let mfaService;
  let mfaSecretUtil;
  let sessionService;
  let secret;
  let uid;
  const username = 'mfa_cas_probe';

  const codeFor = (offset = 0) => totp.hotp(totp.base32Decode(secret), CURRENT_WINDOW() + offset);

  const call = async (fn, body, userExtra = {}) => {
    const res = makeRes();
    const req = {
      user: { userId: uid, username, ...userExtra },
      body,
      ip: '127.0.0.1',
      method: 'POST',
      originalUrl: '/api/auth/mfa/x',
      get: () => 'jest',
    };
    await controller[fn](req, res, (err) => {
      if (err) throw err;
    });
    return res;
  };

  const errorCode = (res) => res.body?.errors?.errorCode;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    controller = require('../../controllers/mfaController');
    totp = require('../../utils/totp');
    mfaService = require('../../services/mfaService');
    mfaSecretUtil = require('../../utils/mfaSecret');
    sessionService = require('../../services/sessionService');
  });

  beforeEach(async () => {
    await User.deleteMany({ username });
    secret = totp.generateSecret();
    const created = await User.create({
      username,
      email: `${username}@example.com`,
      password: 'Aa1!aaaaaaaaaaaaaaaa',
      status: 'active',
      roles: [],
      mfaEnabled: true,
      mfaSecret: mfaSecretUtil.encryptMfaSecret(secret),
      mfaFailCount: 0,
      mfaLockUntil: null,
      mfaLastCounter: 0,
    });
    uid = created._id;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(async () => {
    await User.deleteMany({ username });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('并发重生成：陈旧写必须被拒，成功响应下发的 10 张码必须全部真的能用', async () => {
    const orig = User.findOneAndUpdate.bind(User);
    let releaseFirst;
    const gate = new Promise((resolve) => {
      releaseFirst = resolve;
    });
    let markBlocked;
    const firstBlocked = new Promise((resolve) => {
      markBlocked = resolve;
    });
    let held = false;

    jest.spyOn(User, 'findOneAndUpdate').mockImplementation(async (filter, update, opts) => {
      // 只卡"换恢复码组"这一笔写；claimTotpWindow 的 $set.mfaLastCounter 照常走
      if (!held && update?.$set?.mfaRecoveryCodes) {
        held = true;
        markBlocked();
        await gate;
      }
      return orig(filter, update, opts);
    });

    // A：窗口 W，读到"还没有恢复码"的快照，认领 W，然后停在写之前
    const pendingA = call('regenerateRecoveryCodes', { mfaCode: codeFor(0) });
    await firstBlocked;
    // B：窗口 W+1（W+1 > W，claim 照样成功），读到同一份陈旧快照后先落库
    const resB = await call('regenerateRecoveryCodes', { mfaCode: codeFor(1) });
    releaseFirst();
    const resA = await pendingA;

    const winners = [resA, resB].filter((r) => r.statusCode === 200);
    const losers = [resA, resB].filter((r) => r.statusCode !== 200);

    // ① 只能有一个 200：无条件覆盖时两个都是 200，而先返回的那组码已经作废
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    expect(errorCode(losers[0])).toBe('USER_STATE_CONFLICT');

    // ② 真正的不变量：**凡是宣称成功的那一组，必须逐张能对上库里的摘要**
    const issued = winners[0].body.data.recoveryCodes;
    expect(issued).toHaveLength(10);
    const stored = await User.findById(uid).select('+mfaRecoveryCodes');
    expect(stored.mfaRecoveryCodes).toHaveLength(10);
    const storedSet = new Set(stored.mfaRecoveryCodes);
    for (const code of issued) {
      expect(storedSet.has(mfaService.hashRecoveryCode(code))).toBe(true);
    }
  });

  test('关闭 MFA 与重新登记并发：旧密钥的验证不得清掉新登记', async () => {
    const newSecret = totp.generateSecret();
    const newCodeHash = mfaService.hashRecoveryCode(mfaService.generateRecoveryCodes(1)[0]);
    const orig = User.findOneAndUpdate.bind(User);
    let swapped = false;

    jest.spyOn(User, 'findOneAndUpdate').mockImplementation(async (filter, update, opts) => {
      // 在关闭的写落库之前，插入"用户刚重新登记并启用了新认证器"这一事实
      if (!swapped && update?.$set?.mfaEnabled === false) {
        swapped = true;
        await User.updateOne(
          { _id: uid },
          {
            $set: {
              mfaSecret: mfaSecretUtil.encryptMfaSecret(newSecret),
              mfaEnabled: true,
              mfaRecoveryCodes: [newCodeHash],
            },
          }
        );
      }
      return orig(filter, update, opts);
    });

    const res = await call('mfaDisable', { mfaCode: codeFor(0) });

    expect(swapped).toBe(true); // 夹具确实执行了（否则下面的断言会因为"没发生"而假绿）
    expect(errorCode(res)).toBe('USER_STATE_CONFLICT');

    const after = await User.findById(uid).select('mfaEnabled +mfaSecret +mfaRecoveryCodes');
    expect(after.mfaEnabled).toBe(true);
    expect(mfaSecretUtil.decryptMfaSecret(after.mfaSecret)).toBe(newSecret);
    expect(after.mfaRecoveryCodes).toEqual([newCodeHash]);
  });

  test('历史文档缺 mfaRecoveryCodes 字段时仍可重生成（空数组分支必须含"字段缺失"）', async () => {
    // Mongoose 读时给缺失路径补 default:[]，库里却没有这个字段。
    // 若 CAS 过滤条件只写 `mfaRecoveryCodes: []`，这类文档永不命中 ⇒ 永久 409。
    await User.collection.updateOne({ _id: uid }, { $unset: { mfaRecoveryCodes: '' } });

    const res = await call('regenerateRecoveryCodes', { mfaCode: codeFor(0) });

    expect(res.statusCode).toBe(200);
    expect(res.body.data.recoveryCodes).toHaveLength(10);
  });

  test('控制：无并发时两个端点照常成功（CAS 不得把正当用户挡在门外）', async () => {
    const regen = await call('regenerateRecoveryCodes', { mfaCode: codeFor(0) });
    expect(regen.statusCode).toBe(200);

    const disable = await call('mfaDisable', { mfaCode: codeFor(1) });
    expect(disable.statusCode).toBe(200);

    const after = await User.findById(uid).select('mfaEnabled +mfaRecoveryCodes');
    expect(after.mfaEnabled).toBe(false);
    expect(after.mfaRecoveryCodes).toHaveLength(0);
  });

  test('MFA 开关变更后吊销其他设备会话，保留当前 sid', async () => {
    const revoke = jest.spyOn(sessionService, 'revokeOtherSessions').mockResolvedValue(1);
    const currentSid = 'sid-current-device';

    const disabled = await call('mfaDisable', { mfaCode: codeFor(0) }, { sid: currentSid });
    expect(disabled.statusCode).toBe(200);
    expect(revoke).toHaveBeenCalledWith({
      userId: uid,
      exceptSid: currentSid,
      reason: 'mfa_disabled',
    });

    // 复位为「密钥已登记、尚未开启」，再走一次开启路径
    await User.updateOne(
      { _id: uid },
      {
        $set: {
          mfaEnabled: false,
          mfaSecret: mfaSecretUtil.encryptMfaSecret(secret),
          mfaRecoveryCodes: [],
          mfaLastCounter: 0,
        },
      }
    );
    revoke.mockClear();

    const enabled = await call('mfaEnable', { mfaCode: codeFor(1) }, { sid: currentSid });
    expect(enabled.statusCode).toBe(200);
    expect(revoke).toHaveBeenCalledWith({
      userId: uid,
      exceptSid: currentSid,
      reason: 'mfa_enabled',
    });
  });
});
