/**
 * 会话缓存的跨实例失效广播—— 行为级测试
 *
 * 为什么必须有：`sessionCache` 是**进程内** Map，而 `validateSession` 读的就是它。
 * 多副本部署下「踢除设备」的请求只落在一个副本：它清了本地缓存并写库，
 * 其余副本的缓存项仍标着 usable:true，直到 15 秒 TTL 自然到期——
 * 期间被踢设备打到别的副本就照常通过认证。用户与合规的预期都是「立即生效」。
 *
 * 这份测试此前不存在：`handleRemoteSessionInvalidation` 在覆盖率报告里是
 * **从未被调用过的函数**（functions 95.45% = 21/22），也就是说这条广播
 * 接上了没有、处理器认不认自己的前缀，全仓没有任何一处证明过。
 * 下面用「DB 被查询的次数」作为缓存是否真被清掉的观测口，逐分支验证：
 *   ① 别的业务的键（permcache:）必须被忽略——否则权限缓存的一条广播
 *      会把全站会话缓存清空（可用性问题）甚至掩盖成"会话已失效"；
 *   ② sesscache:<sid> 只清那一条；
 *   ③ sesscache:* 清全部。
 */

const captured = { handler: null };

jest.mock('../../services/sharedCache', () => ({
  onInvalidate: jest.fn((cb) => {
    captured.handler = cb;
  }),
  publishInvalidate: jest.fn(() => Promise.resolve()),
}));

jest.mock('../../models/UserSession', () => ({
  findOne: jest.fn(),
}));

jest.mock('../../utils/logger', () => ({
  warn: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const UserSession = require('../../models/UserSession');
const sharedCache = require('../../services/sharedCache');
const {
  validateSession,
  invalidateSessionCache,
  clearSessionCache,
} = require('../../services/sessionService');

const SID = 'sid-cross-instance-1';

/** 让 DB 返回一条可用会话，并返回"至今被查了几次"的读数器 */
const primeDb = () => {
  UserSession.findOne.mockResolvedValue({ isUsable: () => true, sid: SID });
  return () => UserSession.findOne.mock.calls.length;
};

beforeEach(() => {
  jest.clearAllMocks();
  // 处理器在模块加载期注册一次；clearAllMocks 不清实现，注册关系仍然有效
  clearSessionCache();
  captured.handler('sesscache:*');
  jest.clearAllMocks();
});

describe('跨实例会话失效广播', () => {
  test('服务在加载时就把处理器注册到了共享失效通道上', () => {
    expect(typeof captured.handler).toBe('function');
  });

  test('缓存命中时不再打库（否则后面的"广播后必须打库"就没有判据）', async () => {
    const dbHits = primeDb();
    await validateSession(SID);
    await validateSession(SID);
    expect(dbHits()).toBe(1);
  });

  test('其它业务前缀的广播不得清掉会话缓存', async () => {
    const dbHits = primeDb();
    await validateSession(SID);
    captured.handler('permcache:some-user');
    await validateSession(SID);
    expect(dbHits()).toBe(1);
    captured.handler(null);
    await validateSession(SID);
    expect(dbHits()).toBe(1);
  });

  test('收到本前缀的 sid 广播后，该会话必须立刻回源查库', async () => {
    const dbHits = primeDb();
    await validateSession(SID);
    captured.handler(`sesscache:${SID}`);
    await validateSession(SID);
    expect(dbHits()).toBe(2);
  });

  test('收到通配广播后全部会话缓存作废', async () => {
    const dbHits = primeDb();
    await validateSession(SID);
    await validateSession('sid-another-one');
    expect(dbHits()).toBe(2);
    captured.handler('sesscache:*');
    await validateSession(SID);
    expect(dbHits()).toBe(3);
  });

  test('本地吊销路径既清本地也广播出去', async () => {
    await invalidateSessionCache(SID);
    expect(sharedCache.publishInvalidate).toHaveBeenCalledWith(`sesscache:${SID}`);
  });

  test('空 sid 不得广播（否则其他实例会收到 sesscache:undefined 这类垃圾键）', async () => {
    await invalidateSessionCache(null);
    expect(sharedCache.publishInvalidate).not.toHaveBeenCalled();
  });

  /**
   * 缓存容量保护（sessionService:161-165）：超限整体清空。
   * 这条不变量此前没有任何测试：会话表按「每个登录设备一条缓存」增长，
   * 没有上限就是无界内存增长（多副本长时间运行后 OOM），
   * 而上限设错/清空条件写反，又会让缓存形同虚设（每次认证都打库）。
   * 断言用「清空后必须回源查库」这个可观测后果，而不是去读内部 Map 尺寸。
   */
  test('缓存超过上限时整体清空，之后必须回源查库', async () => {
    UserSession.findOne.mockResolvedValue({ isUsable: () => true, sid: 'x' });
    const MAX = 5000; // 与 SESSION_CACHE_MAX 一致；改这个数值要同步这里（本用例即为该耦合而存在）
    for (let i = 0; i < MAX; i += 1) await validateSession(`sid-fill-${i}`);
    expect(UserSession.findOne).toHaveBeenCalledTimes(MAX);

    // 上限内：重复访问命中缓存，不打库
    await validateSession('sid-fill-0');
    expect(UserSession.findOne).toHaveBeenCalledTimes(MAX);

    // 判据是 `size > MAX` 而非 `>=`，所以清空发生在越过上限后的那一次调用里：
    // 第 MAX+1 条写入时 size 恰为 MAX（不清空），第 MAX+2 条写入时 size 为 MAX+1 → 整体清空。
    await validateSession(`sid-fill-${MAX}`);
    await validateSession(`sid-fill-${MAX + 1}`);
    expect(UserSession.findOne).toHaveBeenCalledTimes(MAX + 2);

    // 清空后，最早那条必须回源（若清空条件写反，这里仍然是缓存命中 → 断言会红）
    await validateSession('sid-fill-0');
    expect(UserSession.findOne).toHaveBeenCalledTimes(MAX + 3);

    // 清空后重复访问新条目又应当命中缓存（不得退化成"每次都打库"）
    await validateSession('sid-fill-0');
    expect(UserSession.findOne).toHaveBeenCalledTimes(MAX + 3);
  });

  /**
   * 广播失败不得冒泡给调用方（sessionService:199-202 的 .catch）。
   *
   * `publishSessionInvalidation` 是 fire-and-forget：调用它是本地吊销已经做完之后。
   * 这个 catch 此前**从未被执行过**（覆盖率里它是本文件唯一一个"函数级 0 命中"），
   * 也就是说"Redis 抖动时登出/踢设备会不会跟着 500"这件事没有任何证明。
   * 若有人把这里改成 await、或删掉 catch，一次 Redis 故障就会让
   * 已经安全的登出路径报错（本地已清缓存已写库，只是没通知别的实例而已）。
   */
  test('失效广播失败时，本地吊销路径不得抛错', async () => {
    sharedCache.publishInvalidate.mockReturnValueOnce(Promise.reject(new Error('redis down')));
    expect(() => invalidateSessionCache('sid-publish-fails')).not.toThrow();
    expect(() => clearSessionCache()).not.toThrow();
    // 让被吞掉的 rejection 有机会变成 unhandledRejection（若有泄漏，jest 会在此处报错）
    await new Promise((resolve) => setImmediate(resolve));
    expect(sharedCache.publishInvalidate).toHaveBeenCalledTimes(2);
  });
});
