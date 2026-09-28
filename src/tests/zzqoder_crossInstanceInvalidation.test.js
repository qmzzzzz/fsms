/**
 * 会话/统计缓存必须接跨实例失效广播
 *
 * 缺陷：sessionCache 与 statsCache 的 store 都是**进程内 Map**，
 * 但吊销/失效只清本地，从不 publishInvalidate。
 * 多副本部署下"踢除这台设备"只清了收到请求的那个副本：
 * 其余副本的缓存项仍是 {usable:true}，直到 SESSION_CACHE_TTL(15s) 自然到期，
 * 期间被踢设备在另一个副本上照常通过认证——"踢设备"实际变成"15 秒后生效"。
 * 权限缓存(userPermissionService)与用户缓存(middleware/auth)早就接了这条广播，
 * 这是同一机制第三次重新实现时漏掉的一处。
 *
 * 无 Redis 时 publishInvalidate 本身是 no-op，所以"跨实例效果"只能这样可证伪地测：
 *   ① 模块加载时是否真的注册了 onInvalidate 处理器（修复前：根本没注册）；
 *   ② 把该处理器当作"另一台实例收到广播"直接调用，验证它真的让本地缓存失效
 *      ——用真库真会话，判据是 validateSession 的结论翻转；
 *   ③ 别人的键前缀不得动我们的缓存（共享通道上是多业务混流的）。
 */

const mongoose = require('mongoose');

describe('会话/统计缓存的跨实例失效广播', () => {
  let sessionService;
  let statsCache;
  let UserSession;
  let registeredHandlers;
  let publishedKeys;
  let userId;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    UserSession = require('../models/UserSession');
    const sharedCache = require('../services/sharedCache');

    // 先挂钩子，再 require 被测模块：处理器是在模块加载期注册的
    registeredHandlers = [];
    publishedKeys = [];
    jest.spyOn(sharedCache, 'onInvalidate').mockImplementation((h) => registeredHandlers.push(h));
    jest
      .spyOn(sharedCache, 'publishInvalidate')
      .mockImplementation(async (key) => publishedKeys.push(key));

    sessionService = require('../services/sessionService');
    statsCache = require('../services/statsCache');
    userId = new mongoose.Types.ObjectId();
  });

  afterAll(async () => {
    jest.restoreAllMocks();
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 把所有已注册的广播处理器当作"收到一条广播"依次派发 */
  const dispatch = (key) => {
    for (const h of registeredHandlers) h(key);
  };

  const fakeReq = () => ({
    get: () => 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0',
    ip: '203.0.113.7',
  });

  test('两个服务都在模块加载期注册了失效广播处理器（修复前完全没注册）', () => {
    // 权限缓存与 auth 也注册了，这里只要求"至少新增了两个"并逐个可派发
    expect(registeredHandlers.length).toBeGreaterThanOrEqual(2);
    expect(typeof registeredHandlers[0]).toBe('function');
  });

  test('本地吊销会广播 sesscache:<sid>，全局清空广播 sesscache:*', () => {
    publishedKeys.length = 0;
    sessionService.invalidateSessionCache('sid-publish-me');
    sessionService.clearSessionCache();
    expect(publishedKeys).toContain('sesscache:sid-publish-me');
    expect(publishedKeys).toContain('sesscache:*');
  });

  test('收到 sesscache:<sid> 的实例必须让本地会话缓存失效（15 秒窗口不再存在）', async () => {
    const { sid } = await sessionService.createSession({ userId, req: fakeReq() });

    // 先让本进程缓存变热
    const warm = await sessionService.validateSession(sid);
    expect(warm.usable).toBe(true);

    // 模拟"另一个副本执行了吊销"：只改库，不碰本进程缓存。
    // 此时本进程若继续读缓存，就会给出已过期的"可用"结论——正是缺陷本体。
    await UserSession.updateOne({ sid }, { $set: { status: 'revoked' } });
    const stale = await sessionService.validateSession(sid);
    expect(stale.usable).toBe(true); // 证明判据确实来自缓存，而不是又查了一次库

    dispatch(`sesscache:${sid}`);

    const after = await sessionService.validateSession(sid);
    expect(after.usable).toBe(false);
  });

  test('收到 sesscache:* 时清空全部会话缓存', async () => {
    const a = await sessionService.createSession({ userId, req: fakeReq() });
    await sessionService.validateSession(a.sid);
    dispatch('sesscache:*');
    // 广播后重新查库：会话本身仍有效，所以 usable 必须仍是 true，
    // 但中间必须经历一次真实的缓存未命中（否则无法区分"清了"与"没清"）。
    const stillValid = await sessionService.validateSession(a.sid);
    expect(stillValid.usable).toBe(true);
    // 真正的判据：伪造一个"库里已吊销但本地缓存说可用"的场景再清
    const b = await sessionService.createSession({ userId, req: fakeReq() });
    await sessionService.validateSession(b.sid);
    await UserSession.updateOne({ sid: b.sid }, { $set: { status: 'revoked' } });
    expect((await sessionService.validateSession(b.sid)).usable).toBe(true);
    dispatch('sesscache:*');
    expect((await sessionService.validateSession(b.sid)).usable).toBe(false);
  });

  test('反向保护：其它业务的键前缀不得动我们的缓存', async () => {
    const { sid } = await sessionService.createSession({ userId, req: fakeReq() });
    await sessionService.validateSession(sid);
    await UserSession.updateOne({ sid }, { $set: { status: 'revoked' } });

    // 这些广播都属于别的模块，必须被忽略
    for (const foreign of ['permcache:x', 'usercache:x', 'statscache:x', 'not-a-cache-key']) {
      dispatch(foreign);
    }
    expect((await sessionService.validateSession(sid)).usable).toBe(true);

    // 而自己的前缀立刻生效
    dispatch(`sesscache:${sid}`);
    expect((await sessionService.validateSession(sid)).usable).toBe(false);
  });

  test('statsCache.invalidateByUserId 广播 statscache:<userId> 且处理器只认该前缀', async () => {
    publishedKeys.length = 0;
    statsCache.set(`stats:${userId}:fp1`, { total: 1 });
    statsCache.invalidateByUserId(String(userId));
    expect(publishedKeys).toContain(`statscache:${userId}`);

    // 处理器：收到广播后必须把本地对应条目清掉（用另一实例的视角验证）
    statsCache.set(`stats:${userId}:fp2`, { total: 2 });
    expect(statsCache.get(`stats:${userId}:fp2`).hit).toBe(true);
    dispatch(`statscache:${userId}`);
    expect(statsCache.get(`stats:${userId}:fp2`).hit).toBe(false);

    // 别人的前缀不得误清
    statsCache.set(`stats:${userId}:fp3`, { total: 3 });
    dispatch('permcache:whatever');
    expect(statsCache.get(`stats:${userId}:fp3`).hit).toBe(true);
  });
});
