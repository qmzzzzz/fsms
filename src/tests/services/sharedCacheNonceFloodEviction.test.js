/**
 * 共享缓存内存回退表的容量收口：防重放键（登录 nonce）不参与淘汰
 *
 * 缺陷原貌（探针实测复现）：`enforceMemCap` 原先按 Map 插入序淘汰最旧，
 * 而防重放表里"最旧"恰恰是**仍需保护**的那一批。登录信封用服务端**公钥**即可构造
 * （ECDH + HKDF + AES-GCM，不需要任何秘密），所以攻击者能自由灌满内存表，
 * 把受害者刚消费过的 nonce 挤出去，随后重放 10 分钟前抓到的那条信封——
 * `decryptLoginCredential` 会照样吐出口令明文。配置 REDIS_URL 时 nonce 在 Redis 里，
 * 本缺陷只在"未配 Redis 的单实例部署"（内存表是唯一真相）下成立。
 *
 * 收口后的两条承诺，各自都有对应用例：
 *   ① 关键键挤不动（洪水洗不掉防重放表）；
 *   ② 挤无可挤时**拒绝新写入**（fail-closed，与 Redis 抖动期 setIfAbsent 同口径），
 *      而不是回头去挤关键键。
 */

const crypto = require('crypto');

const cache = require('../../services/sharedCache');
const loginCipher = require('../../utils/loginCipher');
const logger = require('../../utils/logger');
const { buildLoginEnvelope } = require('../helpers/buildLoginEnvelope');

const CAP = 1000; // getMemStoreMax() 的下限钳位就是 1000，测试只能打到这个量级

let warnSpy;

beforeEach(() => {
  process.env.SHARED_CACHE_MEM_MAX = String(CAP);
  delete process.env.REDIS_URL;
  cache._resetForTests(); // 同时清 memCapRejects / lastMemCapWarnAt
  warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
});

afterAll(() => {
  delete process.env.SHARED_CACHE_MEM_MAX;
});

/** 洪水：n 个互不相同的 nonce 占位（攻击者只需要服务端公钥就能造出来） */
const floodNonces = async (n, prefix = 'login-nonce:flood') => {
  const results = [];
  for (let i = 0; i < n; i += 1) {
    results.push(await cache.setIfAbsent(`${prefix}${i}`, 1, 60000));
  }
  return results;
};

describe('① 关键键不参与淘汰', () => {
  test('nonce 洪水洗不掉已消费的 nonce（修复前：洪水后重放被判为首次）', async () => {
    expect(await cache.setIfAbsent('login-nonce:victim', 1, 600000)).toBe(true);
    expect(await cache.setIfAbsent('login-nonce:victim', 1, 600000)).toBe(false);

    await floodNonces(CAP + 2);

    expect(await cache.setIfAbsent('login-nonce:victim', 1, 600000)).toBe(false);
  });

  test('普通缓存洪水也洗不掉 nonce（淘汰只牺牲普通键）', async () => {
    const nonces = ['a', 'b', 'c'].map((n) => `login-nonce:${n}`);
    for (const key of nonces) {
      expect(await cache.setIfAbsent(key, 1, 600000)).toBe(true);
    }
    for (let i = 0; i < CAP + 200; i += 1) {
      await cache.set(`cache:${i}`, { i }, 600000);
    }
    // 普通键之间照常互相淘汰（否则这条收口就变成"饱和后什么都不写"）：
    // 最旧的已被挤掉、最新的仍在
    expect(await cache.get('cache:0')).toBeNull();
    expect(await cache.get(`cache:${CAP + 199}`)).toEqual({ i: CAP + 199 });
    // 淘汰只挤到上限、不清表：1200 次写入最多挤掉 ~200 条，中段必须还活着。
    // 少了这条断言，"每次把整表普通键全删光"的实现也是绿的（该实现会把缓存打成永久未命中）
    expect(await cache.get('cache:300')).toEqual({ i: 300 });
    for (const key of nonces) {
      expect(await cache.setIfAbsent(key, 1, 600000)).toBe(false);
    }
  });

  test('限流计数（incrWithTtl）也不能以 nonce 为代价腾空间', async () => {
    expect(await cache.setIfAbsent('login-nonce:victim', 1, 600000)).toBe(true);
    await floodNonces(CAP + 1);

    // 表里只剩关键键：本次计数不落库，返回 1（与原"淘汰命中计数器仅重置窗口"同口径）
    expect(await cache.incrWithTtl('rate:counter', 60000)).toBe(1);
    expect(await cache.incrWithTtl('rate:counter', 60000)).toBe(1);
    expect(await cache.setIfAbsent('login-nonce:victim', 1, 600000)).toBe(false);
  });
});

describe('② 饱和时拒绝新写入而不是挤掉关键键', () => {
  test('洪水期间新 nonce 被拒收（返回 false = 按重放处理，拒绝该请求）', async () => {
    const admitted = await floodNonces(CAP + 2);
    // 上限判定发生在"写入之前"，所以表会在 max+1 处抖动（与修复前的 set 路径同形）：
    // 前 CAP+1 条占位成功，之后一律拒收
    expect(admitted.filter(Boolean)).toHaveLength(CAP + 1);
    expect(admitted[admitted.length - 1]).toBe(false);
    expect(await cache.setIfAbsent('login-nonce:latecomer', 1, 600000)).toBe(false);
  });

  test('拒收留痕：上千次拒绝只打一条 warn，且文案给出可调上限的出口', async () => {
    await floodNonces(CAP + 300);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    const message = warnSpy.mock.calls[0][0];
    expect(message).toContain('共享缓存内存表饱和');
    expect(message).toContain('SHARED_CACHE_MEM_MAX');
  });

  test('未饱和时语义不变（对照组：正常占位/判重/计数累加/缓存命中）', async () => {
    expect(await cache.setIfAbsent('login-nonce:x', 1, 600000)).toBe(true);
    expect(await cache.setIfAbsent('login-nonce:x', 1, 600000)).toBe(false);
    expect(await cache.incrWithTtl('rate:a', 60000)).toBe(1);
    expect(await cache.incrWithTtl('rate:a', 60000)).toBe(2);
    await cache.set('cache:keep', { ok: true }, 600000);
    expect(await cache.get('cache:keep')).toEqual({ ok: true });
    expect(warnSpy).not.toHaveBeenCalled();
  });

  test('重放尝试本身不消耗淘汰额度（"先判重、后挤空间"的次序被钉住）', async () => {
    // 半表关键键 + 半表普通键：表已越过上限，普通键里最旧的一批在灌入阶段就被挤掉了
    for (let i = 0; i < 400; i += 1) {
      expect(await cache.setIfAbsent(`login-nonce:k${i}`, 1, 600000)).toBe(true);
    }
    for (let i = 0; i < 700; i += 1) {
      await cache.set(`cache:${i}`, { i }, 600000);
    }
    // 判据是"整段候选键的存活集合有没有变化"，不是"某一个键还在不在"：
    // 修复前的次序在饱和期每次判重都白挤一条普通缓存，而实测**只有第一条**——
    // 挤掉一条后 size 落回上限，后续 enforceMemCap 直接短路。
    // 拿单个键（最初写的探针用 cache:250）做断言会正好漏掉这一条，变异自检里 M4 全绿。
    const candidates = Array.from({ length: 700 }, (_, i) => `cache:${i}`);
    const survivors = async () => {
      const values = await Promise.all(candidates.map((k) => cache.get(k)));
      return values.filter(Boolean).map((v) => v.i);
    };
    const before = await survivors();
    // 自证前提：候选区间里既有幸存者也有被淘汰者（否则快照相等是空集恒绿）
    expect(before.length).toBeGreaterThan(0);
    expect(before.length).toBeLessThan(candidates.length);

    // 300 次全是判重命中：一次淘汰都不该发生
    for (let r = 0; r < 300; r += 1) {
      expect(await cache.setIfAbsent('login-nonce:k0', 1, 600000)).toBe(false);
    }
    expect(await survivors()).toEqual(before);
  });

  test('饱和期普通缓存写入被放弃（可重算，但不拿防重放换空间）', async () => {
    await floodNonces(CAP + 1);
    await cache.set('cache:after', { v: 1 }, 600000);
    expect(await cache.get('cache:after')).toBeNull();
    // 关键键一个没少
    expect(await cache.setIfAbsent('login-nonce:flood0', 1, 600000)).toBe(false);
  });
});

describe('端到端：登录信封重放', () => {
  test('灌满内存表后，抓到的登录信封仍然只能成功一次', async () => {
    // 信封用测试共用构造器（镜像前端 WebCrypto 流程）：攻击者只需要服务端公钥，
    // 不需要任何秘密，所以"灌表"这一步本身就是零成本的
    const envelope = await buildLoginEnvelope('S3cr3t!Passw0rd', {
      nonce: crypto.randomBytes(16).toString('hex'),
    });

    await expect(loginCipher.decryptLoginCredential(envelope)).resolves.toBe('S3cr3t!Passw0rd');
    await expect(loginCipher.decryptLoginCredential(envelope)).rejects.toMatchObject({
      code: 'NONCE_REPLAY',
    });

    // 攻击者的洪水：灌满整张表（等价于 1002 个合法但无主的信封）
    await floodNonces(CAP + 2, 'login-nonce:');

    // 修复前：受害者的 nonce 已被挤掉，这一行会再次拿到明文口令
    await expect(loginCipher.decryptLoginCredential(envelope)).rejects.toMatchObject({
      code: 'NONCE_REPLAY',
    });
  });
});
