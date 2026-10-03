/**
 * 会话缓存命中时仍必须重算"是否已过期"（F-101）
 *
 * `validateSession` 的直查路径用 `doc.isUsable()`——它同时判 status 与 expiresAt。
 * 而缓存命中路径原先直接返回缓存里的 `usable` 结论（TTL 15 秒），
 * 于是"会话到点"这件事被静默推迟最长 15 秒。
 *
 * 为什么这是缺陷而不是"缓存固有的 15 秒延迟"：
 * 吊销的延迟是有意的、且有主动 invalidate + 跨实例广播兜底；
 * **过期不是一个会被通知的事件**——没有任何路径会去清这条缓存，
 * 所以只有读取侧重新比对时刻，规则才仍然成立。
 * 同一份"结论被缓存复用时不再复核不变量"的错法，权限缓存早已修过一次。
 *
 * 判据的关键是"必须证明第二次读走的是缓存"——否则用例只是在测直查路径，
 * 修没修都绿。这里用 findOne 的调用次数把它钉死。
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

const UserSession = require('../models/UserSession');
const sessionService = require('../services/sessionService');

const mkSid = () => `zz-sess-${crypto.randomBytes(6).toString('hex')}`;

async function seedSession({ expiresAt, status = 'active' }) {
  const sid = mkSid();
  await UserSession.create({
    sid,
    userId: new mongoose.Types.ObjectId(),
    status,
    expiresAt,
    lastSeenAt: new Date(),
  });
  return sid;
}

describe('会话缓存命中仍须复核过期时刻', () => {
  const created = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    for (const sid of created) {
      await UserSession.collection.deleteMany({ sid });
    }
    sessionService.clearSessionCache();
  });

  test('缓存里的"可用"结论不得让已过期会话继续通过认证', async () => {
    // 真实缺陷形态：会话在缓存 TTL（15 秒）**之内**自然到点。
    // 缓存里存的是首次读取时的文档副本，其 expiresAt 就是那一刻的未来时刻；
    // 修前缓存命中直接返回 usable:true ⇒ 到点后还会被放行最长 15 秒。
    const sid = await seedSession({ expiresAt: new Date(Date.now() + 1500) });
    created.push(sid);

    const first = await sessionService.validateSession(sid);
    expect(first.usable).toBe(true); // 直查：此刻确实未过期

    await new Promise((r) => setTimeout(r, 2200)); // 越过 expiresAt，但仍在 15 秒缓存窗口内

    // 必须证明第二次读走的是缓存（否则只是在测直查路径，修没修都绿）
    const findSpy = jest.spyOn(UserSession, 'findOne');
    const again = await sessionService.validateSession(sid);
    expect(findSpy).not.toHaveBeenCalled();
    findSpy.mockRestore();

    expect(again.usable).toBe(false);
  });

  test('反向控制：缓存里的"可用"在未过期时不得被误判成不可用', async () => {
    const sid = await seedSession({ expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
    created.push(sid);

    expect((await sessionService.validateSession(sid)).usable).toBe(true);
    const findSpy = jest.spyOn(UserSession, 'findOne');
    const cached = await sessionService.validateSession(sid);
    expect(findSpy).not.toHaveBeenCalled();
    findSpy.mockRestore();
    expect(cached.usable).toBe(true);
    expect(cached.session.sid).toBe(sid);
  });

  test('取数有效：本用例跑在缓存路径上，而不是"每次都直查"的假绿', async () => {
    const sid = await seedSession({ expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
    created.push(sid);
    await sessionService.validateSession(sid);

    let hits = 0;
    const original = UserSession.findOne.bind(UserSession);
    UserSession.findOne = (...args) => {
      hits += 1;
      return original(...args);
    };
    try {
      await sessionService.validateSession(sid);
      await sessionService.validateSession(sid);
    } finally {
      UserSession.findOne = original;
    }
    expect(hits).toBe(0);
  });

  test('与直查路径同口径：缺失 expiresAt 的会话在两条路径上都是不可用', async () => {
    // 直查路径的 `isUsable()`：status!=='active' 或 !expiresAt ⇒ false。
    // 缓存复核用的是同一个判据（`instanceof Date && > now`），
    // 所以这里钉的是"两侧一致"，而不是缓存层单独的宽松策略。
    const sid = await seedSession({ expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
    created.push(sid);
    await UserSession.collection.updateOne({ sid }, { $unset: { expiresAt: 1 } });
    sessionService.clearSessionCache();
    const r = await sessionService.validateSession(sid);
    expect(r.usable).toBe(false);
  });

  test('吊销路径不受影响：revoke 之后校验必须为 false（本改动不得让缓存变黏）', async () => {
    const sid = await seedSession({ expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
    const userId = (await UserSession.findOne({ sid })).userId;
    created.push(sid);

    expect((await sessionService.validateSession(sid)).usable).toBe(true);
    expect(await sessionService.revokeSession({ sid, userId, reason: 'zz_test' })).toBe(true);
    expect((await sessionService.validateSession(sid)).usable).toBe(false);
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
