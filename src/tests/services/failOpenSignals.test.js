/**
 * fail-open 降级点的**可观测信号**测试（2026-10-09）
 *
 * ## 这份文件守的是什么
 * 本仓有一条成文纪律，在三个地方被重复声明：
 *   · `middleware/security.js:668-672`：「fail-open 放行（缓存未命中）**必须有显式可观测信号**——
 *     否则『DB 挂了 + 全站裸奔』只有一条 error 日志可循」
 *   · `middleware/rateLimitStore.js:53-56`：「降级态只写日志等于没有可告警信号——
 *     `grep 日志` 不是运维动作」
 *   · `services/websocketService.js:723-725`：「fail-open 必须留 `ip_blacklist_failopen` 计数」
 *
 * 但实测有两处降级**完全没有信号**，且都属于「已修的同类漏了一处」：
 *   1. `services/captchaService.js`：Redis 就绪但计数命令报错时，上限判定被跳过。
 *      唯一痕迹是 `sharedCache.js:432` 的 `logger.debug`，而生产默认 `LOG_LEVEL=info`
 *      （`utils/logger.js:85`）⇒ **debug 不落盘**。即：没有日志、没有指标、没有告警。
 *   2. `models/SystemConfig.js` 的验证码开关：DB 故障 → 静态默认（fail-open），
 *      同一个 try/catch 在 **3 个调用点**各复刻一份，全都没有信号。
 *
 * ## 为什么必须同时钉「有信号」和「fail-open 行为不变」
 * 本批**只补信号，不改降级方向**——`captchaService.js:137` 的
 * 「刻意不 fail-closed：验证码是登录前置，Redis 抖动不该把合法用户挡在门外」
 * 是成文决策。所以每条用例都成对断言：**信号发了** 且 **请求照常放行**。
 * 只断信号会让「顺手改成 fail-closed」也算通过；只断放行会让「信号被删」也算通过。
 */

const sharedCache = require('../../services/sharedCache');
const metrics = require('../../utils/metrics');
const logger = require('../../utils/logger');

const ALERT_CALLS = (spy, type) =>
  spy.mock.calls.filter((c) => c[0] === type).map((c) => ({ type: c[0], level: c[1] }));

describe('captchaService：活跃数上限判定被跳过时必须留信号', () => {
  let captcha;
  let alertSpy;

  beforeAll(() => {
    captcha = require('../../services/captchaService');
  });

  beforeEach(() => {
    alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
    jest.spyOn(logger, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('Redis 已启用 + 计数返回 null（命令报错）→ 发 captcha_active_bound_lost/high，且**仍生成**（fail-open 不变）', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValue(null);
    jest.spyOn(sharedCache, 'set').mockResolvedValue(undefined);
    jest.spyOn(sharedCache, 'jitterTtl').mockImplementation((t) => t);

    const result = await captcha.generate();

    // ① 信号必须发（本批的目的）
    expect(ALERT_CALLS(alertSpy, 'captcha_active_bound_lost')).toEqual([
      { type: 'captcha_active_bound_lost', level: 'high' },
    ]);
    // ② fail-open 方向必须保持：不因拿不到计数就拒绝合法用户
    expect(result).toHaveProperty('captchaId');
    expect(result.svg).toContain('<svg');
  });

  test('内存模式（未启用 Redis）→ **不得**发上限丢失信号（上限本来就是 localStore.size，没丢）', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(false);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValue(null);

    const result = await captcha.generate();

    expect(ALERT_CALLS(alertSpy, 'captcha_active_bound_lost')).toEqual([]);
    expect(result).toHaveProperty('captchaId');
  });

  test('Redis 正常且未超限 → 不发信号（防"恒发"把告警训练成噪声）', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValue(1);
    jest.spyOn(sharedCache, 'set').mockResolvedValue(undefined);
    jest.spyOn(sharedCache, 'jitterTtl').mockImplementation((t) => t);

    const result = await captcha.generate();

    expect(ALERT_CALLS(alertSpy, 'captcha_active_bound_lost')).toEqual([]);
    expect(result).toHaveProperty('captchaId');
  });

  test('Redis 正常且已超限 → 拒绝生成（返回 null），但**不得**误报为"上限丢失"', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValue(10001); // MAX_ACTIVE_ENTRIES = 10000

    const result = await captcha.generate();

    expect(result).toBeNull();
    // 「被上限拦住」与「上限失效」是两个相反的事件，不能混用同一个告警类型
    expect(ALERT_CALLS(alertSpy, 'captcha_active_bound_lost')).toEqual([]);
  });
});

describe('SystemConfig.captchaSwitch：DB 故障降级为静态默认时必须留信号', () => {
  let SystemConfig;
  let config;
  let alertSpy;

  beforeAll(() => {
    SystemConfig = require('../../models/SystemConfig');
    config = require('../../config');
  });

  beforeEach(() => {
    alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
    jest.spyOn(logger, 'warn').mockImplementation(() => {});
    // 两个开关各自有 30 秒模块级缓存，不清会让用例互相串（第二个用例拿到第一个的值）
    SystemConfig.invalidateLoginCaptchaCache();
    SystemConfig.invalidateRegisterCaptchaCache();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    SystemConfig.invalidateLoginCaptchaCache();
    SystemConfig.invalidateRegisterCaptchaCache();
  });

  /** 让 findOne 在 `.lean()` 处 reject，模拟 DB 不可用 */
  const failDb = () =>
    jest.spyOn(SystemConfig, 'findOne').mockReturnValue({
      lean: () => Promise.reject(new Error('db down')),
    });

  test('login：DB 故障 → 返回静态默认 config.loginCaptchaEnabled + 发 captcha_switch_db_fallback/medium', async () => {
    failDb();
    const value = await SystemConfig.captchaSwitch('login');
    expect(value).toBe(config.loginCaptchaEnabled);
    expect(ALERT_CALLS(alertSpy, 'captcha_switch_db_fallback')).toEqual([
      { type: 'captcha_switch_db_fallback', level: 'medium' },
    ]);
  });

  test('register：DB 故障 → 返回静态默认 config.registerCaptchaEnabled + 发信号', async () => {
    failDb();
    const value = await SystemConfig.captchaSwitch('register');
    expect(value).toBe(config.registerCaptchaEnabled);
    expect(ALERT_CALLS(alertSpy, 'captcha_switch_db_fallback')).toHaveLength(1);
  });

  test('DB 正常 → 以库中值为准且**不发**信号（防"只要读了就告警"）', async () => {
    jest.spyOn(SystemConfig, 'findOne').mockReturnValue({
      lean: () => Promise.resolve({ key: 'loginCaptchaEnabled', value: true }),
    });
    const value = await SystemConfig.captchaSwitch('login');
    expect(value).toBe(true);
    expect(ALERT_CALLS(alertSpy, 'captcha_switch_db_fallback')).toEqual([]);
  });

  test('配置未落库（doc 为 null，非 DB 故障）→ 用静态默认但**不发**降级信号', async () => {
    // 这是「全新部署」的正常路径（config/index.js:73 注释自陈"全新部署必然走这条 fallback"），
    // 与 DB 故障是两件事。把它也算成降级会让告警在每次全新部署时响。
    jest.spyOn(SystemConfig, 'findOne').mockReturnValue({ lean: () => Promise.resolve(null) });
    const value = await SystemConfig.captchaSwitch('register');
    expect(value).toBe(config.registerCaptchaEnabled);
    expect(ALERT_CALLS(alertSpy, 'captcha_switch_db_fallback')).toEqual([]);
  });

  test('captchaSwitch 自身**从不抛错**（调用方原先靠空 catch 保证这一点，收口后不能丢）', async () => {
    failDb();
    await expect(SystemConfig.captchaSwitch('login')).resolves.toEqual(expect.any(Boolean));
    await expect(SystemConfig.captchaSwitch('register')).resolves.toEqual(expect.any(Boolean));
  });

  test('指标端不可用时仍返回静态默认（信号失败不得影响开关读取）', async () => {
    alertSpy.mockImplementation(() => {
      throw new Error('metrics down');
    });
    failDb();
    await expect(SystemConfig.captchaSwitch('login')).resolves.toBe(config.loginCaptchaEnabled);
  });
});

describe('反向对照：这两个告警类型必须真的进得了 security_alerts_total', () => {
  test('incSecurityAlert 未被 mock 时，两个类型都能被计数（证明上面用的 spy 口径不是空转）', () => {
    // 用真实实现跑一遍：若 incSecurityAlert 对未知 type 静默丢弃，上面的用例
    // 仍然全绿（因为 spy 拦在更外层），那本文件就只是"测试了 mock"。
    const real = jest.requireActual('../../utils/metrics');
    expect(() => real.incSecurityAlert('captcha_active_bound_lost', 'high')).not.toThrow();
    expect(() => real.incSecurityAlert('captcha_switch_db_fallback', 'medium')).not.toThrow();
    const snap = real.formatPrometheus();
    expect(snap).toContain('captcha_active_bound_lost');
    expect(snap).toContain('captcha_switch_db_fallback');
    expect(snap).toContain('security_alerts_total');
  });
});
