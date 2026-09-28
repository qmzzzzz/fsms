'use strict';

/**
 * MFA 防爆破计数「写不进去」时必须收紧，不能当没记过
 *
 * 修复前 `recordMfaFailure` 的这句：
 *   const count = updated?.mfaFailCount ?? 1;
 * 把「findByIdAndUpdate 抛错」与「文档不存在」都折算成 count=1 ⇒ 永不触发锁定。
 * 而 `isMfaLocked` 读的正是同一个库，所以 DB 故障持续 = 锁定能力持续消失，
 * 6 位动态口令（10^6 空间）退化成可无限在线尝试的口令。
 * 判据不是新增的：同仓 `middleware/tokenBlacklist.blacklistToken` 的 P2-26
 * 已经裁定过"吊销写不进必须上抛"——访问控制类防线观测不到时要收紧。
 *
 * 断言全部落在**数据库回读**上（锁定字段真的写了值），
 * 注入故障只打在 `$inc` 那一条更新上、锁定更新走真实路径，
 * 这样"尝试写锁定"与"真的写成了"是两件事，测试断言后者。
 */

const mongoose = require('mongoose');

describe('MFA 失败计数的 fail-closed 语义', () => {
  let User;
  let AuditLog;
  let mfaService;
  let uid;
  const username = 'f86';

  const readBack = async () => {
    // 走 collection 层，绕开 select:false 投影，读到的是落库真值
    const doc = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(uid) });
    return { failCount: doc?.mfaFailCount ?? null, lockUntil: doc?.mfaLockUntil ?? null };
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    AuditLog = require('../models/AuditLog');
    mfaService = require('../services/mfaService');
  });

  beforeEach(async () => {
    await User.deleteMany({ username });
    const created = await User.create({
      username,
      email: `${username}@example.com`,
      password: 'Aa1!aaaaaaaaaaaaaaaa',
      status: 'active',
      roles: [],
      mfaFailCount: 0,
      mfaLockUntil: null,
    });
    uid = created._id;
  });

  afterAll(async () => {
    await User.deleteMany({ username });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  /** 只让带 $inc 的那条更新失败，其余写操作照常落库 */
  const injectCounterFailure = () => {
    const real = User.findByIdAndUpdate.bind(User);
    const spy = jest.spyOn(User, 'findByIdAndUpdate').mockImplementation((id, update, opts) => {
      if (update && update.$inc) {
        const rejected = Promise.reject(new Error('injected: counter write failed'));
        // 生产代码会在返回值上链式 .select()，桩必须保持同一形状
        return { select: () => rejected };
      }
      return real(id, update, opts);
    });
    return () => spy.mockRestore();
  };

  test('正向：连续失败达阈值 → 锁定真实落库（原语义不许被我改坏）', async () => {
    for (let i = 0; i < mfaService.MFA_MAX_FAILS; i++) {
      await mfaService.recordMfaFailure({ _id: uid, username });
    }
    const { failCount, lockUntil } = await readBack();
    expect(failCount).toBe(mfaService.MFA_MAX_FAILS);
    expect(lockUntil).toBeInstanceOf(Date);
    expect(lockUntil.getTime()).toBeGreaterThan(Date.now());
  });

  test('未达阈值不得锁定（fail-closed 不许变成"永远锁"）', async () => {
    await mfaService.recordMfaFailure({ _id: uid, username });
    const { failCount, lockUntil } = await readBack();
    expect(failCount).toBe(1);
    expect(lockUntil).toBeNull();
  });

  test('核心：计数写不进 → 仍必须落下锁定，且告警真的可观测', async () => {
    // 取证走真实 sink（process.stdout.write），不是 jest.spyOn(logger,'error')：
    // 后者在本仓 jest 沙箱里收到 0 次调用，而那条代码路径确实执行了
    // （锁定就是它写的）——即"spy 装上但听不到"，用它断言会得到一个假红/假绿随机的用例。
    const chunks = [];
    const outSpy = jest.spyOn(process.stdout, 'write').mockImplementation((c) => {
      chunks.push(String(c));
      return true;
    });
    const restore = injectCounterFailure();
    try {
      await mfaService.recordMfaFailure({ _id: uid, username });
    } finally {
      restore();
      outSpy.mockRestore();
    }
    const { failCount, lockUntil } = await readBack();
    // 计数确实没写进去（前提自证：注入真的生效了，否则下面断言可能假绿）
    expect(failCount).toBe(0);
    expect(lockUntil).toBeInstanceOf(Date);
    expect(lockUntil.getTime()).toBeGreaterThan(Date.now());
    // "不再静默"是本修复的另一半：防线观测不到时必须告警，否则故障可以永久隐身
    expect(chunks.join('')).toContain('计数写入失败');
  });

  test('计数写不进时审计不得谎报次数（宁可缺字段也不写一个没发生过的数字）', async () => {
    const calls = [];
    // record 在生产里返回 promise（调用方链式 .catch），桩必须保持同一形状
    const spy = jest.spyOn(AuditLog, 'record').mockImplementation((doc) => {
      calls.push(doc);
      return Promise.resolve();
    });
    const restoreInject = injectCounterFailure();
    try {
      await mfaService.recordMfaFailure({ _id: uid, username });
      restoreInject();
      // 阈值路径（无故障）：仍走 mfa_bruteforce + 真实次数
      for (let i = 0; i < mfaService.MFA_MAX_FAILS; i++) {
        await mfaService.recordMfaFailure({ _id: uid, username });
      }
    } finally {
      restoreInject();
      spy.mockRestore();
    }

    const counterGated = calls.find((c) => c.riskFactors?.includes('mfa_counter_unavailable'));
    expect(counterGated).toBeDefined();
    expect(counterGated.reason).not.toMatch(/\d+ 次/);

    const brute = calls.filter((c) => c.riskFactors?.includes('mfa_bruteforce'));
    expect(brute.length).toBeGreaterThan(0);
    // 既有套件（mfaTokenPrimitiveGuards）钉着这条文案里的次数，改坏会双红
    expect(brute[brute.length - 1].reason).toMatch(/\d+ 次/);
  });

  test('用户文档已消失且无故障 ⇒ 静默返回、不抛错、不写锁定', async () => {
    await User.deleteOne({ _id: uid });
    await expect(mfaService.recordMfaFailure({ _id: uid, username })).resolves.toBeUndefined();
    expect(await User.collection.findOne({ _id: new mongoose.Types.ObjectId(uid) })).toBeNull();
  });
});
