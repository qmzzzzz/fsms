/**
 * 过期锁定的清零必须是条件写，不能用陈旧快照直接 `$set`
 *
 * 三条路径同形：登录口令失败、MFA 失败累计、MFA 惰性解锁。旧实现读到
 * `lockUntil <= now` 后无条件 `$set count:1 / 0`，并发请求各自基于同一份
 * 过期快照写"1" ⇒ 刚刚记下的失败被覆盖，阈值永远到不了（或解锁后第一次
 * 手滑把别人的失败一起清掉）。条件写只让第一个请求重置，其余 miss 后累加。
 */

const mongoose = require('mongoose');

describe('过期锁定的清零是条件写', () => {
  let User;
  let authService;
  let failureAndMfa;
  let mfaService;
  const stamp = `lk${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]).slice(0, 10);
  const PASSWORD = 'Test@1234567';
  const created = [];

  const mkUser = async (tag, extra = {}) => {
    const user = await User.create({
      username: `${stamp}${tag}`,
      email: `${stamp}${tag}@example.com`,
      password: PASSWORD,
      ...extra,
    });
    created.push(user._id);
    return user;
  };

  const ctx = () => ({
    ip: '127.0.0.1',
    userAgent: 'jest',
    fingerprint: 'fp-test',
    method: 'POST',
    path: '/api/auth/login',
    req: { headers: { 'user-agent': 'jest' }, ip: '127.0.0.1', connection: {} },
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    authService = require('../../services/authService');
    failureAndMfa = require('../../services/authService/failureAndMfa');
    mfaService = require('../../services/mfaService');
    require('../../models/AuditLog');
  });

  afterEach(() => jest.restoreAllMocks());

  afterAll(async () => {
    await User.deleteMany({ _id: { $in: created } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('同一份"锁定已过期"快照的两个并发失败必须累加为 2，而不是各自重置为 1', async () => {
    const user = await mkUser('mfa', {
      failedLoginCount: 9,
      lockUntil: new Date(Date.now() - 60 * 1000),
    });
    // 两份独立读取的陈旧快照 = 两个并发请求各自载入的文档
    const [snapA, snapB] = await Promise.all([User.findById(user._id), User.findById(user._id)]);

    await Promise.all([
      failureAndMfa.incrementFailedLoginCount(snapA, { username: user.username, lockReason: 't' }),
      failureAndMfa.incrementFailedLoginCount(snapB, { username: user.username, lockReason: 't' }),
    ]);

    const after = await User.findById(user._id).select('failedLoginCount');
    expect(after.failedLoginCount).toBe(2);
  });

  test('口令路径：清零 CAS 未命中（并发请求先重置）时必须改走 $inc，不得覆盖为 1', async () => {
    const user = await mkUser('pwd', {
      failedLoginCount: 9,
      lockUntil: new Date(Date.now() - 60 * 1000),
    });
    const orig = User.findOneAndUpdate;
    jest.spyOn(User, 'findOneAndUpdate').mockImplementation(function casMiss(filter, update, opts) {
      if (filter && filter.lockUntil) return Promise.resolve(null);
      return orig.call(User, filter, update, opts);
    });

    const result = await authService.loginUser(
      { username: user.username, password: 'WrongPass!99zz' },
      ctx()
    );
    expect(result.outcome).toBe('INVALID_CREDENTIALS');

    const after = await User.findById(user._id).select('failedLoginCount lockUntil');
    expect(after.failedLoginCount).toBe(10);
    expect(after.lockUntil.getTime()).toBeGreaterThan(Date.now());
  });

  test('口令路径触发锁定时必须失效认证缓存（否则旧 access token 在 TTL 内仍可用）', async () => {
    const user = await mkUser('pwdlockcache', { failedLoginCount: 9 });
    const authMiddleware = require('../../middleware/auth');
    const spy = jest.spyOn(authMiddleware, 'invalidateUserCache').mockImplementation(() => {});

    const result = await authService.loginUser(
      { username: user.username, password: 'WrongPass!99zz' },
      ctx()
    );
    expect(result.outcome).toBe('INVALID_CREDENTIALS');
    expect(spy.mock.calls.some(([id]) => String(id) === String(user._id))).toBe(true);
  });

  test('MFA 失败路径触发锁定时同样必须失效认证缓存', async () => {
    const user = await mkUser('mfalockcache', { failedLoginCount: 9 });
    const authMiddleware = require('../../middleware/auth');
    const spy = jest.spyOn(authMiddleware, 'invalidateUserCache').mockImplementation(() => {});

    const snapshot = await User.findById(user._id);
    await failureAndMfa.incrementFailedLoginCount(snapshot, {
      username: user.username,
      lockReason: 'test',
    });
    expect(spy.mock.calls.some(([id]) => String(id) === String(user._id))).toBe(true);
  });

  test('过期锁定 CAS 写入失败时退回 $inc（catch → null），不得把计数重置为 1', async () => {
    // 条件写本身失败（写关注失败/主从切换）时 catch 落到 null，
    // 后续必须走 $inc 继续累加；若把 catch 改成吞掉并返回旧快照，
    // 阈值就永远到不了——与 fail-closed 口径相反。
    const user = await mkUser('casreject', {
      failedLoginCount: 9,
      lockUntil: new Date(Date.now() - 60 * 1000),
    });
    const snapshot = await User.findById(user._id);
    const spy = jest
      .spyOn(User, 'findOneAndUpdate')
      .mockRejectedValue(new Error('write concern failed'));

    try {
      const count = await failureAndMfa.incrementFailedLoginCount(snapshot, {
        username: user.username,
        lockReason: 'test',
      });
      expect(count).toBe(10);
    } finally {
      spy.mockRestore();
    }
  });

  test('锁定写入失败时不得失效缓存，也不得把 lockUntil 当成已落库', async () => {
    // 第 1 次 findByIdAndUpdate 是 $inc，第 2 次是写 lockUntil。
    // 第 2 次失败时 lockApplied=false：缓存不能失效（没有要失效的锁定），
    // 库里也必须是"未锁定"的真实状态，审计里的 lockApplied 才是可核对的。
    const user = await mkUser('lockwritefail', { failedLoginCount: 9 });
    const snapshot = await User.findById(user._id);
    const original = User.findByIdAndUpdate.bind(User);
    let calls = 0;
    const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation((...args) => {
      calls += 1;
      if (calls === 2) return Promise.reject(new Error('write failed'));
      return original(...args);
    });
    const invalidate = jest
      .spyOn(require('../../middleware/auth'), 'invalidateUserCache')
      .mockImplementation(() => {});

    try {
      const count = await failureAndMfa.incrementFailedLoginCount(snapshot, {
        username: user.username,
        lockReason: 'test',
      });
      expect(count).toBe(10);
      expect(invalidate).not.toHaveBeenCalled();
      const after = await User.findById(user._id).select('lockUntil');
      expect(after.lockUntil).toBeNull();
    } finally {
      spy.mockRestore();
      invalidate.mockRestore();
    }
  });

  test('isMfaLocked：读到的计数快照在清零前已变（并发又失败一次）时不得把新失败抹掉', async () => {
    const expiredAt = new Date(Date.now() - 60 * 1000);
    const user = await mkUser('mfalock', { mfaFailCount: 5, mfaLockUntil: expiredAt });
    // 模拟"读到 5 之后，并发路径已经把它加到 6"
    await User.updateOne({ _id: user._id }, { $set: { mfaFailCount: 6 } });
    const stale = { _id: user._id, mfaFailCount: 5, mfaLockUntil: expiredAt };
    const spy = jest
      .spyOn(User, 'findById')
      .mockReturnValue({ select: () => Promise.resolve(stale) });

    try {
      await expect(mfaService.isMfaLocked(user._id)).resolves.toBe(false);
    } finally {
      spy.mockRestore();
    }

    const after = await User.findById(user._id).select('mfaFailCount mfaLockUntil');
    expect(after.mfaFailCount).toBe(6);
    expect(after.mfaLockUntil).not.toBeNull();
  });
});
