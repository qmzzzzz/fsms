/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：captchaService：计数器故障降级、清理定时器幂等
 * 守护的不变式：计数器异常时必须告警，且**生成不受影响**；`startCaptchaCleanup` 二次调用必须直接返回
 * 可证伪性：本轮未做变异实测
 *
 * 【2026-10-09 更正不变式表述】原写作「计数器异常必须告警并**退化为内存上限判断**」——
 * 后半句**只在内存模式下成立**，而本文件的第一条用例把 `isRedisEnabled` mock 成 false，
 * 所以它测的正是内存模式，Redis 模式下的真实行为**从未被本文件触达**：
 *   · 内存模式：上限判据本来就是 `localStore.size`，与计数器无关 ⇒ 等价于"照常按内存判"；
 *   · Redis 模式（就绪但命令报错）：`active === null` ⇒ **上限判定整个被跳过**，
 *     没有"退化为内存判断"这回事。
 * 这条名实不符让「Redis 模式上限消失」既没被断言、也没被观测到（信号缺口见下）。
 * Redis 模式的行为与新增信号由 `failOpenSignals.test.js` 覆盖，两文件互补、不重叠。
 *
 * 命名沿革：2026-09-20 由 `captchaBranches.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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
    // P1-29 修复（本次改动复审）：原用例只有连续 start/stop 调用，零断言——
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
