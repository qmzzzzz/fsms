/**
 * captchaService 分支补齐（覆盖率棘轮）
 *
 * 缺口：计数器异常降级（96-97）、Redis 模式上限拒绝（101-103）、
 * Redis 模式存储（121）与一次性校验（139-147）、_resetForTests（161）。
 * 测试环境无 Redis：Redis 分支通过 spyOn(sharedCache) 的查询门面驱动。
 */

const sharedCache = require('../../services/sharedCache');
const captchaService = require('../../services/captchaService');

describe('captchaService 分支补齐', () => {
  afterEach(() => {
    captchaService._resetForTests();
    jest.restoreAllMocks();
  });

  test('_resetForTests 清空本地回退存储后旧验证码不可再校验', async () => {
    const { captchaId } = await captchaService.generate();
    captchaService._resetForTests();
    await expect(captchaService.verify(captchaId, 'AAAA')).resolves.toBe(false);
  });

  test('计数器异常时降级为内存上限判断，仍可正常生成', async () => {
    jest.spyOn(sharedCache, 'incrWithTtl').mockRejectedValue(new Error('cache down (故障注入)'));
    const result = await captchaService.generate();
    expect(result).toBeTruthy();
    expect(result.captchaId).toBeTruthy();
    expect(result.svg).toContain('<svg');
  });

  test('Redis 模式下活跃数超限 → 拒绝生成（防刷取）', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValue(10001);
    await expect(captchaService.generate()).resolves.toBeNull();
  });

  test('Redis 模式正常生成：走共享存储（带抖动 TTL）', async () => {
    const setSpy = jest.spyOn(sharedCache, 'set').mockResolvedValue(true);
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValue(1);
    const result = await captchaService.generate();
    expect(result).toBeTruthy();
    expect(setSpy).toHaveBeenCalledTimes(1);
    const [key] = setSpy.mock.calls[0];
    expect(key).toMatch(/^captcha:/);
  });

  describe('Redis 模式校验（一次性消费语义）', () => {
    // 评价报告低危项：verify 已改用原子取删 getDel（GETDEL），不再 get→del 两步
    const setupRedisMode = () => {
      jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
      return {
        getDelSpy: jest.spyOn(sharedCache, 'getDel'),
      };
    };

    test('命中且文本匹配（大小写不敏感 + 去空白）→ true，且取删即消费', async () => {
      const { getDelSpy } = setupRedisMode();
      getDelSpy.mockResolvedValue({ text: 'AbCd' });
      await expect(captchaService.verify('cid-1', '  aBcD ')).resolves.toBe(true);
      expect(getDelSpy).toHaveBeenCalledWith('captcha:cid-1');
    });

    test('条目不存在 → false', async () => {
      const { getDelSpy } = setupRedisMode();
      getDelSpy.mockResolvedValue(null);
      await expect(captchaService.verify('cid-2', 'AAAA')).resolves.toBe(false);
    });

    test('条目 text 非字符串（脏数据）→ false', async () => {
      const { getDelSpy } = setupRedisMode();
      getDelSpy.mockResolvedValue({ text: 1234 });
      await expect(captchaService.verify('cid-3', '1234')).resolves.toBe(false);
    });

    test('取删抛错 → 按未通过处理（fail-closed，不悬挂验证码）', async () => {
      const { getDelSpy } = setupRedisMode();
      getDelSpy.mockRejectedValue(new Error('cache down (故障注入)'));
      await expect(captchaService.verify('cid-4', 'AAAA')).resolves.toBe(false);
      expect(getDelSpy).toHaveBeenCalledWith('captcha:cid-4');
    });
  });
});
