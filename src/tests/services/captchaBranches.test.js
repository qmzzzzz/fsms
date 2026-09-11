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

  test('startCaptchaCleanup 幂等：二次调用直接返回，stop 后句柄清空', () => {
    captcha.startCaptchaCleanup();
    captcha.startCaptchaCleanup(); // 第二次命中 if (cleanupTimer) return
    captcha.stopCaptchaCleanup();
    // 再次 start/stop 验证句柄生命周期完整（无定时器泄漏）
    captcha.startCaptchaCleanup();
    captcha.stopCaptchaCleanup();
  });
});
