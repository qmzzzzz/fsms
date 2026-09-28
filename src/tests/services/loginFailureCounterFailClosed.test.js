/**
 * 登录失败计数的 fail-closed 契约
 *
 * 被测对象：authService 的失败计数解析（resolveFailedLoginCount，口令错误主路径与
 * MFA/恢复码累计路径共用）
 * 守护的不变式：计数写不进库时按"已达阈值"处理，锁定必须真的发生。
 *
 * 为什么这是漏洞而不是保守策略：旧实现读不到计数就当"第一次失败"（`?? 1`），
 * 另一处则回退到请求早先读到的陈旧快照 +1（写路径持续失败时该快照永不变，等效卡在 1）。
 * Mongo 可读不可写的窗口里，攻击者对已知用户名连续试错，failedLoginCount 落不了库
 * ⇒ 阈值永远到不了 ⇒ 账户临时锁定与自动封禁同时静默消失，只剩 IP 限流；
 * 而日志与响应一切正常（INVALID_CREDENTIALS），没有任何信号说明防线已经不工作。
 *
 * 可证伪性：把 resolveFailedLoginCount 改回 `updated?.failedLoginCount ?? 1`
 * ⇒ "注入写故障仍必须锁定"那条用例变红；改成无条件锁定
 * ⇒ "计数正常时一次失败不得锁定"那条对照用例变红。
 */

const mongoose = require('mongoose');
const authService = require('../../services/authService');
const User = require('../../models/User');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const PASSWORD = randomPassword();
const TAG = `lf${Date.now().toString(36)}`;

const ctx = {
  ip: '127.0.0.1',
  userAgent: 'test-agent',
  fingerprint: 'fp-test',
  method: 'POST',
  path: '/api/auth/login',
  req: { headers: { 'user-agent': 'test-agent' }, ip: '127.0.0.1', connection: {} },
};

describe('登录失败计数写故障时的锁定行为', () => {
  const ids = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (ids.length) await User.deleteMany({ _id: { $in: ids } });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  const makeUser = async (suffix) => {
    const user = await User.create({
      username: `${TAG}${suffix}`,
      email: `${TAG}${suffix}@example.com`,
      password: PASSWORD,
    });
    ids.push(user._id);
    return user;
  };

  /**
   * 只在"计数写入"上注入故障（$inc:failedLoginCount 或 $set:failedLoginCount），
   * 锁定那条（只带 lockUntil）放行——否则测的是"整库不可写"，
   * 那个场景里锁定本身就写不进，无法证明"防线收紧了"。
   */
  const injectCounterFailure = () => {
    const original = User.findByIdAndUpdate;
    return jest.spyOn(User, 'findByIdAndUpdate').mockImplementation((...args) => {
      const [, payload] = args;
      const touchesCounter =
        payload &&
        (payload.$inc?.failedLoginCount !== undefined ||
          payload.$set?.failedLoginCount !== undefined);
      if (touchesCounter) return Promise.reject(new Error('db down (计数写入故障)'));
      return original.apply(User, args);
    });
  };

  const readBack = (id) => User.findById(id).select('+failedLoginCount +lockUntil');

  test('对照：计数写入正常时，一次密码错误不得锁定（否则"总是锁定"也能骗绿）', async () => {
    const user = await makeUser('healthy');
    const result = await authService.loginUser(
      { username: user.username, password: `${PASSWORD}wrong` },
      ctx
    );
    expect(result.outcome).toBe('INVALID_CREDENTIALS');
    const after = await readBack(user._id);
    expect(after.failedLoginCount).toBe(1);
    expect(after.lockUntil).toBeFalsy();
  });

  test('计数写入故障时：不抛错、仍返回凭据无效，且锁定必须真的落库', async () => {
    const user = await makeUser('counterdown');
    const spy = injectCounterFailure();
    let result;
    try {
      result = await authService.loginUser(
        { username: user.username, password: `${PASSWORD}wrong` },
        ctx
      );
    } finally {
      spy.mockRestore();
    }
    expect(result.outcome).toBe('INVALID_CREDENTIALS');

    const after = await readBack(user._id);
    expect(after.lockUntil).toBeInstanceOf(Date);
    expect(after.lockUntil.getTime()).toBeGreaterThan(Date.now());
  });

  test('故障期间的锁定对后续尝试持续生效（下一次登录在计数写入前就被拒）', async () => {
    const user = await makeUser('stilllocked');
    const spy = injectCounterFailure();
    try {
      const first = await authService.loginUser(
        { username: user.username, password: `${PASSWORD}wrong` },
        ctx
      );
      const second = await authService.loginUser(
        { username: user.username, password: `${PASSWORD}wrong` },
        ctx
      );
      expect(first.outcome).toBe('INVALID_CREDENTIALS');
      // 第二次进入时账户已处于锁定窗口：走的是"锁定中提前返回"这条臂，
      // 不再依赖那个写不进去的计数——这正是收紧后的效果
      expect(second.outcome).toBe('INVALID_CREDENTIALS');
    } finally {
      spy.mockRestore();
    }
    const after = await readBack(user._id);
    expect(after.lockUntil).toBeInstanceOf(Date);
  });

  test('整库不可写时不得抛错给调用方（降级为"本次未能收紧"，不是 500）', async () => {
    const user = await makeUser('alldown');
    const spy = jest
      .spyOn(User, 'findByIdAndUpdate')
      .mockRejectedValue(new Error('db down (全库写故障)'));
    try {
      await expect(
        authService.loginUser({ username: user.username, password: `${PASSWORD}wrong` }, ctx)
      ).resolves.toEqual({ outcome: 'INVALID_CREDENTIALS' });
    } finally {
      spy.mockRestore();
    }
    const after = await readBack(user._id);
    expect(after.lockUntil).toBeFalsy(); // 锁定那条同样写不进：不会误锁正当用户
  });
});
