/**
 * 验证码服务分支——行为化测试
 *
 * 覆盖 captchaService.js 的两类此前未触达行为（2026-09-05 覆盖率复核）：
 *   1. 计数器故障降级：sharedCache.incrWithTtl 异常 → 告警 + 退化为
 *      内存上限判断，生成不受影响；
 *   2. 清理定时器防重入：startCaptchaCleanup 二次调用直接返回（幂等）。
 *
 * sharedCache 以 spyOn 注入故障；定时器用后即停，不向 worker 泄漏句柄。
 */
const sharedCache = require('../../services/sharedCache');
const logger = require('../../utils/logger');

describe('验证码服务分支（captchaService.js）', () => {
  let captcha;

  beforeAll(() => {
    captcha = require('../../services/captchaService');
  });

  test('incrWithTtl 异常 → 降级为内存上限判断，验证码仍正常生成', async () => {
    const errSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const incrSpy = jest
      .spyOn(sharedCache, 'incrWithTtl')
      .mockRejectedValueOnce(new Error('counter backend down'));
    const redisSpy = jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(false);

    const result = await captcha.generate();

    expect(result).toHaveProperty('captchaId');
    expect(result.svg).toContain('<svg');
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('验证码计数器异常'));

    incrSpy.mockRestore();
    redisSpy.mockRestore();
    errSpy.mockRestore();
  });

  test('startCaptchaCleanup 幂等：二次调用不重复注册，stop 后可重新注册', () => {
    // P1-29 修复（本轮复审）：原用例只有连续 start/stop 调用，零断言——
    // 测试名承诺的「二次调用直接返回」从未被验证（把 :56 的 if (cleanupTimer) return
    // 整行删掉，用例照样绿）。现用 setInterval spy 观察真实注册次数。
    const siSpy = jest.spyOn(global, 'setInterval');
    const ciSpy = jest.spyOn(global, 'clearInterval');
    try {
      captcha.stopCaptchaCleanup(); // 归零，避免受同文件其他用例影响
      siSpy.mockClear();
      ciSpy.mockClear();

      captcha.startCaptchaCleanup();
      captcha.startCaptchaCleanup(); // 第二次命中 if (cleanupTimer) return
      expect(siSpy).toHaveBeenCalledTimes(1); // 幂等：只注册一个定时器

      captcha.stopCaptchaCleanup();
      expect(ciSpy).toHaveBeenCalledTimes(1);

      // 再次 start 必须能注册（stop 已把句柄清空，未被永久锁死）
      captcha.startCaptchaCleanup();
      expect(siSpy).toHaveBeenCalledTimes(2);
      captcha.stopCaptchaCleanup();

      // 未启动状态下 stop 不应再调 clearInterval
      const before = ciSpy.mock.calls.length;
      captcha.stopCaptchaCleanup();
      expect(ciSpy.mock.calls.length).toBe(before);
    } finally {
      captcha.stopCaptchaCleanup();
      siSpy.mockRestore();
      ciSpy.mockRestore();
    }
  });
});
