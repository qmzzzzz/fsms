'use strict';

/**
 * （2026-09-19）：登录防重放占位在 Redis 故障期不得退回进程内内存
 *
 * `setIfAbsent` 的注释一直声明"Redis 已配置但失败 ⇒ 按重复处理（拒绝）"，
 * 既有测试也只钉住了**命令抛错**那一格。真正更常见的故障形态是连接整体不可用
 * （未就绪 / 断线 / init 失败）：此时 isRedisEnabled()=false，原实现直接落内存分支，
 * 而"内存里从没见过这个 nonce"不等于"全局第一次见"。
 * 多实例部署下（配 REDIS_URL 的唯一理由），被别的实例消费过的 nonce 会被判为首次
 * ⇒ 登录防重放在 Redis 故障期间整体失效。
 *
 * 现口径：配了 REDIS_URL 就绝不退到内存占位；未配 REDIS_URL 的单实例语义一字不改。
 * 边界同样钉住：普通 set/get/del/incr 的回退不受影响（它们的"内存里没有"
 * 不构成任何"全局第一次"的论证）。
 */

const cache = require('../../src/services/sharedCache');

describe('占位类判据不回退内存', () => {
  const savedRedisUrl = process.env.REDIS_URL;
  const savedCacheMax = process.env.SHARED_CACHE_MEM_MAX;

  afterEach(() => {
    cache._resetForTests();
    if (savedRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = savedRedisUrl;
    if (savedCacheMax === undefined) delete process.env.SHARED_CACHE_MEM_MAX;
    else process.env.SHARED_CACHE_MEM_MAX = savedCacheMax;
  });

  beforeEach(() => {
    cache._resetForTests();
  });

  test('配了 REDIS_URL 但连接不可用 ⇒ setIfAbsent 一律 false（不接受"内存里没见过"当首次）', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:1'; // 必然连不上，且不去 init
    expect(cache.isRedisEnabled()).toBe(false);
    expect(cache.isRedisConfigured()).toBe(true);

    // 同一个 nonce 连打三次：旧实现第一次会返回 true（=放行一条重放）
    await expect(cache.setIfAbsent('xf:nonce:A', 1, 60000)).resolves.toBe(false);
    await expect(cache.setIfAbsent('xf:nonce:A', 1, 60000)).resolves.toBe(false);
    await expect(cache.setIfAbsent('xf:nonce:A', 1, 60000)).resolves.toBe(false);

    // 且没有任何内存占位被写进去（否则第二次就会因"自己见过"而 false，掩盖机制）
    await expect(cache.get('xf:nonce:A')).resolves.toBeNull();
  });

  test('未配 REDIS_URL（单实例部署）语义不变：首次 true、窗口内重复 false、过期后可再占', async () => {
    delete process.env.REDIS_URL;
    expect(cache.isRedisConfigured()).toBe(false);

    await expect(cache.setIfAbsent('nonce-single', 'v1', 60000)).resolves.toBe(true);
    await expect(cache.setIfAbsent('nonce-single', 'v2', 60000)).resolves.toBe(false);
    await expect(cache.get('nonce-single')).resolves.toBe('v1');

    await cache.setIfAbsent('nonce-exp', 'v', 4);
    await new Promise((r) => setTimeout(r, 12));
    await expect(cache.setIfAbsent('nonce-exp', 'v2', 4)).resolves.toBe(true);
  });

  test('边界：真正的缓存读写在同样状态下仍回退内存；计数类判据收紧（F-211）', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:1';
    await cache.set('stats:x', { n: 1 }, 60000);
    await expect(cache.get('stats:x')).resolves.toEqual({ n: 1 });
    await expect(cache.del('stats:x')).resolves.toBe(true);
    await expect(cache.get('stats:x')).resolves.toBeNull();
    // 而 getDel（消费类）在内存里没有时返回 null = 校验失败，方向本来就是拒绝
    await expect(cache.getDel('captcha:missing')).resolves.toBeNull();
    // F-211：incr **不属于**"普通读写"。它的返回值唯一的生产用途是
    // captchaService 拿去和 MAX_ACTIVE_ENTRIES（一个集群量）比，
    // 本进程的数字两个方向都是假的（偏小＝洪水期护栏被骗过、偏大＝恢复后仍被降级史拒）。
    // 同方向更早的表态见 sharedCacheBackends.test.js 里 F-205 那条
    // （"incr 与 set/get/del 不同向——它不回退内存，而是如实返回 null"）：
    // 那条只堵了「命令抛错」入口，这一条补的是「未就绪」入口。
    await expect(cache.incrWithTtl('rate:x', 60000)).resolves.toBeNull();
    await expect(cache.incrWithTtl('rate:x', 60000)).resolves.toBeNull();
    // 反向对照（防"一律 null"的实现也绿）：没配 REDIS_URL 时同一个键照常本地累加
    delete process.env.REDIS_URL;
    expect(await cache.incrWithTtl('rate:x', 60000)).toBe(1);
    expect(await cache.incrWithTtl('rate:x', 60000)).toBe(2);
  });

  test('负向自证：三态可区分——未配置/已配置可用/已配置不可用（防空集恒绿）', async () => {
    delete process.env.REDIS_URL;
    const noRedis = await cache.setIfAbsent('tri', 1, 60000);
    cache._resetForTests();
    process.env.REDIS_URL = 'redis://127.0.0.1:1';
    const configuredDown = await cache.setIfAbsent('tri', 1, 60000);
    expect(noRedis).toBe(true);
    expect(configuredDown).toBe(false);
    expect(noRedis).not.toBe(configuredDown);
  });
});
