'use strict';

/**
 * 落地侧的第二批判据（与 `zzqoder_mfaLifecycleTotpClaim.test.js` 互补，不重复它）
 *
 * 技术文档里那三条钉的是"重放必须被拒"（行为存在性）。本文件钉的是**实现选择**带来的
 * 三个可回归维度——它们都是这次补丁新引入的、既有测试面没有覆盖的：
 *
 * 1. **失败计数不翻倍**。原补丁草稿在"口令正确但窗口已被消费"路径上先
 *    `recordMfaFailure` 一次，又因 `verified=false` 落到末尾的同一句 ⇒ 计两次。
 *    MFA_MAX_FAILS 阈值固定，翻倍等于把正当用户的锁定提前一半，
 *    而这条危害只有在"重放"这一格才出现 ⇒ 必须精确断言 `=== 1`，`>= 1` 挡不住。
 * 2. **重放与"输错一位数字"在审计上可区分**（riskFactors 单列 mfa_code_replayed，
 *    riskLevel 升 high）。混为一谈等于把最强的会话劫持信号降级成噪声。
 * 3. **认领写库失败时必须拒绝**（fail-closed）。`.catch(() => null)` 与登录侧同形；
 *    若有人改成"写不进去就当认领成功"，重放守卫在 DB 故障期整体失效且不留痕迹。
 *
 * 另加一条反向保护：口令轨（currentPassword）不得被认领逻辑波及——
 * 它本来就不消费任何 TOTP 窗口，改动若把水位一起写了，属于越界。
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

describe('zzqA 认领实现的选择性判据', () => {
  let User;
  let AuditLog;
  let controller;
  let generateSecret;
  let hotp;
  let base32Decode;
  let encryptMfaSecret;
  let secret;
  let uid;
  const username = 'zzqa_f85impl';

  const codeFor = (offset = 0) => hotp(base32Decode(secret), CURRENT_WINDOW() + offset);

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

  const readState = () =>
    User.findById(uid).select('+mfaRecoveryCodes mfaFailCount mfaLastCounter mfaEnabled');

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    controller = require('../../controllers/mfaController');
    const totp = require('../../utils/totp');
    generateSecret = totp.generateSecret;
    hotp = totp.hotp;
    base32Decode = totp.base32Decode;
    encryptMfaSecret = require('../../utils/mfaSecret').encryptMfaSecret;
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

  describe('1. 失败计数恰好一次', () => {
    test('regenerateRecoveryCodes 重放：mfaFailCount 必须为 1（不是 2）', async () => {
      await User.findByIdAndUpdate(uid, { mfaLastCounter: CURRENT_WINDOW() });
      const res = await call('regenerateRecoveryCodes', { mfaCode: codeFor() });
      expect(res.statusCode).not.toBe(200);
      const after = await readState();
      expect(after.mfaFailCount).toBe(1);
    });

    test('mfaDisable 重放：mfaFailCount 必须为 1，且水位与 mfaEnabled 分毫未动', async () => {
      const watermark = CURRENT_WINDOW();
      await User.findByIdAndUpdate(uid, { mfaLastCounter: watermark });
      const res = await call('mfaDisable', { mfaCode: codeFor() });
      expect(res.statusCode).not.toBe(200);
      const after = await readState();
      expect(after.mfaFailCount).toBe(1);
      expect(after.mfaEnabled).toBe(true);
      // 拒绝必须是零副作用：水位若被"顺手又写一次"，语义就退回 $max 了
      expect(after.mfaLastCounter).toBe(watermark);
    });

    test('对照：口令确实输错时也只记一次（防止把上面的修复改成"重放不计数"）', async () => {
      const res = await call('regenerateRecoveryCodes', { mfaCode: '000000' });
      expect(res.statusCode).toBe(400);
      const after = await readState();
      expect(after.mfaFailCount).toBe(1);
    });
  });

  describe('2. 重放在审计上与口令错误可区分', () => {
    let recordSpy;
    let sent;

    beforeEach(() => {
      sent = [];
      recordSpy = jest.spyOn(AuditLog, 'record').mockImplementation((payload) => {
        sent.push(payload);
        return Promise.resolve(null);
      });
    });

    afterEach(() => {
      recordSpy.mockRestore();
    });

    test('重放：riskFactors 含 mfa_code_replayed 且 riskLevel=high', async () => {
      await User.findByIdAndUpdate(uid, { mfaLastCounter: CURRENT_WINDOW() });
      await call('mfaDisable', { mfaCode: codeFor() });
      const failure = sent.find((p) => p.success === false);
      expect(failure).toBeDefined();
      expect(failure.riskFactors).toEqual(['mfa_code_replayed']);
      expect(failure.riskLevel).toBe('high');
    });

    test('对照：普通输错码仍是 mfa_code_invalid / medium（不得一起被升级）', async () => {
      await call('mfaDisable', { mfaCode: '000000' });
      const failure = sent.find((p) => p.success === false);
      expect(failure).toBeDefined();
      expect(failure.riskFactors).toEqual(['mfa_code_invalid']);
      expect(failure.riskLevel).toBe('medium');
    });
  });

  describe('3. 认领写库失败 ⇒ fail-closed 拒绝', () => {
    test('水位更新抛错时两个端点都必须拒绝，而不是"当作认领成功"', async () => {
      const real = User.findOneAndUpdate;
      const spy = jest
        .spyOn(User, 'findOneAndUpdate')
        .mockImplementation(function (filter, update, options) {
          if (update && update.$set && update.$set.mfaLastCounter !== undefined) {
            return Promise.reject(new Error('模拟：水位写入失败'));
          }
          return real.call(this, filter, update, options);
        });
      try {
        const r1 = await call('regenerateRecoveryCodes', { mfaCode: codeFor() });
        expect(r1.statusCode).not.toBe(200);
        const r2 = await call('mfaDisable', { mfaCode: codeFor() });
        expect(r2.statusCode).not.toBe(200);

        const after = await readState();
        expect(after.mfaEnabled).toBe(true);
        expect(after.mfaRecoveryCodes).toHaveLength(0);
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('4. 反向保护：口令轨不被认领逻辑波及', () => {
    test('用 currentPassword 关闭 MFA 成功，且不消费任何 TOTP 窗口', async () => {
      const watermark = CURRENT_WINDOW() - 5;
      await User.findByIdAndUpdate(uid, { mfaLastCounter: watermark });
      const res = await call('mfaDisable', {
        currentPassword: 'Aa1!aaaaaaaaaaaaaaaa',
      });
      expect(res.statusCode).toBe(200);
      const after = await readState();
      expect(after.mfaEnabled).toBe(false);
      // 密码路径与水位无关：不得被"顺手 $max/认领"改写
      expect(after.mfaLastCounter).toBe(watermark);
    });
  });
});
