/**
 * 恢复码关闭 MFA：消费码与清状态必须是同一条文档写
 *
 * 拆成「先 $pull 码、再清 MFA」时，第二步失败会留下"码已消费、MFA 仍开启"的
 * 死局：用户手里少一张码，却什么都没关掉；只剩最后一张码时直接锁死在登录
 * 第二步。这里让原子写失败一次，断言恢复码仍在、MFA 仍开启、判定为失败；
 * 恢复写能力后重试同一张码必须成功——证明没有中间态。
 */

const mongoose = require('mongoose');

describe('恢复码关闭 MFA 的原子写', () => {
  let User;
  let mfaService;
  let mfaDisable;
  let mfaSecretUtil;
  const stamp = `ra${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]).slice(0, 10);
  const code = 'ABCD-EFGH';
  let user;

  const reload = () => User.findById(user._id).select('+mfaSecret +mfaRecoveryCodes +mfaFailCount');

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    mfaService = require('../../services/mfaService');
    mfaDisable = require('../../services/mfaDisable');
    mfaSecretUtil = require('../../utils/mfaSecret');
    const { generateSecret } = require('../../utils/totp');
    require('../../models/AuditLog');
    user = await User.create({
      username: `${stamp}u`,
      email: `${stamp}u@example.com`,
      password: 'Test@1234567',
      status: 'active',
      mfaEnabled: true,
      mfaSecret: mfaSecretUtil.encryptMfaSecret(generateSecret()),
      mfaRecoveryCodes: [mfaService.hashRecoveryCode(code)],
      mfaFailCount: 0,
      mfaLockUntil: null,
    });
  });

  afterEach(() => jest.restoreAllMocks());

  afterAll(async () => {
    await User.deleteMany({ _id: user._id }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('原子写失败 ⇒ 码不清、MFA 不关、判定失败；写能力恢复后同一张码仍可用', async () => {
    const snapshot = await reload();
    const orig = User.findOneAndUpdate;
    let failedOnce = false;
    jest
      .spyOn(User, 'findOneAndUpdate')
      .mockImplementation(function failFirst(filter, update, opts) {
        if (!failedOnce && update?.$set?.mfaEnabled === false) {
          failedOnce = true;
          return Promise.reject(new Error('db down (故障注入：关闭 MFA)'));
        }
        return orig.call(User, filter, update, opts);
      });

    const first = await mfaDisable.disableWithRecoveryCode(snapshot, code);
    expect(first.outcome).toBe('VERIFY_FAILED');
    jest.restoreAllMocks();

    const afterFailure = await reload();
    expect(afterFailure.mfaEnabled).toBe(true);
    expect(afterFailure.mfaRecoveryCodes).toHaveLength(1);
    expect(afterFailure.mfaFailCount).toBe(1);

    const second = await mfaDisable.disableWithRecoveryCode(afterFailure, code);
    expect(second.outcome).toBe('OK');

    const afterSuccess = await reload();
    expect(afterSuccess.mfaEnabled).toBe(false);
    expect(afterSuccess.mfaRecoveryCodes).toHaveLength(0);
    expect(afterSuccess.mfaSecret).toBe('');
  });
});
