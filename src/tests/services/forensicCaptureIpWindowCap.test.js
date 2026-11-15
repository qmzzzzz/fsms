/**
 * P2-02：取证单 IP 配额窗口表（state.ipWindows）的容量闸。
 *
 * 守的是什么：窗口表的 key 是攻击者可控 IP，且条目在 60s 生命期后**无人删除**
 * （原实现只写不删，按去重 IP 无界增长——长跑进程的内存泄漏面，扫描器用
 * 伪造来源 IP 轮换即可驱动增长）。
 *
 * 修复语义（对齐 alertDispatch/captchaService 的有界做法）：
 *   ① 上限 env 可配（FORENSIC_IP_WINDOW_MAX），非法值回落默认并 error 告警；
 *   ② 插入新窗口前先惰性清掉过期窗口（60s 生命期）；
 *   ③ 仍超限按**插入序**淘汰最旧，并限频 warn（不静默）。
 *
 * 判定面：容量内行为不变（捕获照常）；淘汰只动窗口表、不动捕获结果——
 * 被淘汰 IP 的下一条记录会开新窗口重新计数，这正是"尽力而为的配额"该有的降级。
 */

const PREV_ENV = {
  FORENSIC_IP_WINDOW_MAX: process.env.FORENSIC_IP_WINDOW_MAX,
  FORENSIC_CAPTURE_ENABLED: process.env.FORENSIC_CAPTURE_ENABLED,
};

/** 在指定 env 下重载模块（模块在加载期读容量常量），返回模块与本次加载的 logger spy */
const reloadWithEnv = (envName, value) => {
  jest.resetModules();
  if (value === undefined) delete process.env[envName];
  else process.env[envName] = value;
  // 顺序纪律（同 f74NegativeEnvFallback）：先拿到本代 logger 装 spy，再 require 被测模块，
  // 否则加载期告警永远听不到
  const logger = require('../../utils/logger');
  const errors = [];
  const warns = [];
  jest.spyOn(logger, 'error').mockImplementation((...a) => errors.push(a.join(' ')));
  jest.spyOn(logger, 'warn').mockImplementation((...a) => warns.push(a.join(' ')));
  const mod = require('../../services/forensicCapture');
  return { mod, logger, errors, warns };
};

const makeReq = () => ({
  method: 'GET',
  originalUrl: '/api/probe?x=1',
  path: '/api/probe',
  query: { x: '1' },
  params: {},
  headers: {},
  httpVersion: '1.1',
  get: () => undefined,
});

const capture = (mod, ip) =>
  mod.record({
    req: makeReq(),
    ip,
    trigger: null,
    response: { status: 200, headers: {}, contentType: 'text/plain', body: 'probe' },
  });

afterAll(() => {
  for (const [key, prev] of Object.entries(PREV_ENV)) {
    if (prev === undefined) delete process.env[key];
    else process.env[key] = prev;
  }
});

describe('P2-02 ipWindows 容量闸', () => {
  afterEach(() => jest.restoreAllMocks());

  test('非法上限值回落默认并 error 告警（负值不得让窗口表变成"每次都清空"）', () => {
    const { mod, errors } = reloadWithEnv('FORENSIC_IP_WINDOW_MAX', '-1');
    expect(errors.join('\n')).toContain('FORENSIC_IP_WINDOW_MAX');
    expect(errors.join('\n')).toContain('非法');
    // 回落默认 10000：正常量级的去重 IP 不会触发任何淘汰告警
    mod.resetForTests();
    for (let i = 0; i < 5; i += 1) expect(capture(mod, `10.1.1.${i}`)).toBe(true);
    expect(mod.getForensicCaptureStats().captured).toBe(5);
  });

  test('未配置上限 ⇒ 静默用默认值，不制造噪音告警', () => {
    const { mod, errors } = reloadWithEnv('FORENSIC_IP_WINDOW_MAX', undefined);
    expect(errors).toHaveLength(0);
    mod.resetForTests();
    for (let i = 0; i < 5; i += 1) expect(capture(mod, `10.2.1.${i}`)).toBe(true);
    expect(mod.getForensicCaptureStats().captured).toBe(5);
  });

  test('超上限：按插入序淘汰最旧窗口并限频 warn；捕获本身不受影响', () => {
    const { mod, logger } = reloadWithEnv('FORENSIC_IP_WINDOW_MAX', '2');
    mod.resetForTests();
    expect(capture(mod, '10.3.0.1')).toBe(true);
    expect(capture(mod, '10.3.0.2')).toBe(true);
    logger.warn.mockClear();
    // 第 3 个去重 IP ⇒ 新窗口需要空位：先清过期（无）→ 淘汰最旧（10.3.0.1）
    expect(capture(mod, '10.3.0.3')).toBe(true);
    expect(logger.warn.mock.calls.map((a) => a.join(' ')).join('\n')).toContain('插入序淘汰');
    // 淘汰只动配额窗口表，不动捕获结果：三条都真捕获了
    expect(mod.getForensicCaptureStats().captured).toBe(3);
  });

  test('先惰性清过期：过期窗口让位时不淘汰、不告警（60s 生命期内自然回收）', () => {
    const { mod, logger } = reloadWithEnv('FORENSIC_IP_WINDOW_MAX', '1');
    mod.resetForTests();
    const t0 = Date.now();
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(t0);
    try {
      expect(capture(mod, '10.4.0.1')).toBe(true);
      // 61s 后：旧窗口已过生命期。插入新窗口前应**先清过期**（无淘汰、无告警）
      nowSpy.mockReturnValue(t0 + 61000);
      logger.warn.mockClear();
      expect(capture(mod, '10.4.0.2')).toBe(true);
      const warnText = logger.warn.mock.calls.map((a) => a.join(' ')).join('\n');
      expect(warnText).not.toContain('插入序淘汰');
      expect(mod.getForensicCaptureStats().captured).toBe(2);
    } finally {
      nowSpy.mockRestore();
    }
  });
});
