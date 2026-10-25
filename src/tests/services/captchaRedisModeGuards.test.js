/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：captchaService 的 Redis 模式分支
 * 守护的不变式：Redis 模式上限必须拒绝；一次性校验必须真的只放行一次
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `captchaGap.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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

  test('Redis 模式全局活跃数超限 → 拒绝生成，并归还本次预占的双配额', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValueOnce(1).mockResolvedValueOnce(10001);
    const decrSpy = jest.spyOn(sharedCache, 'decrWithFloorZero').mockResolvedValue(0);
    await expect(captchaService.generate({ ip: '203.0.113.7' })).resolves.toBeNull();
    // 先加后减：被拒绝的请求不得把全局计数继续推高（#8）
    expect(decrSpy).toHaveBeenCalledTimes(2);
  });

  test('Redis 模式单 IP 超限 → 不触全局键即拒绝（少数 IP 不能打满全局）', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    const incrSpy = jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValueOnce(21);
    jest.spyOn(sharedCache, 'decrWithFloorZero').mockResolvedValue(0);
    await expect(captchaService.generate({ ip: '203.0.113.8' })).resolves.toBeNull();
    expect(incrSpy).toHaveBeenCalledTimes(1);
    expect(incrSpy.mock.calls[0][0]).toMatch(/^captcha:active-count:ip:/);
  });

  test('Redis 模式正常生成：走共享存储（带抖动 TTL）并记录所属 IP 桶', async () => {
    const setSpy = jest.spyOn(sharedCache, 'set').mockResolvedValue(true);
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
    jest.spyOn(sharedCache, 'incrWithTtl').mockResolvedValue(1);
    const result = await captchaService.generate({ ip: '203.0.113.9' });
    expect(result).toBeTruthy();
    expect(setSpy).toHaveBeenCalledTimes(1);
    const [key, entry] = setSpy.mock.calls[0];
    expect(key).toMatch(/^captcha:/);
    expect(entry.ipKey).toMatch(/^captcha:active-count:ip:[0-9a-f]{16}$/);
  });

  test('内存模式：同一 IP 活跃数达到配额后拒绝，其他 IP 不受影响', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(false);
    for (let i = 0; i < 20; i += 1) {
      await expect(captchaService.generate({ ip: '203.0.113.10' })).resolves.toBeTruthy();
    }
    await expect(captchaService.generate({ ip: '203.0.113.10' })).resolves.toBeNull();
    await expect(captchaService.generate({ ip: '203.0.113.11' })).resolves.toBeTruthy();
  });

  test('内存模式：消费（即使校验失败）后归还配额，可再次生成', async () => {
    jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(false);
    const ip = '203.0.113.12';
    const issued = [];
    for (let i = 0; i < 20; i += 1) issued.push(await captchaService.generate({ ip }));
    await expect(captchaService.generate({ ip })).resolves.toBeNull();
    // 校验失败同样删除条目（一次性语义），配额必须随之归还
    await expect(captchaService.verify(issued[0].captchaId, 'WRONG')).resolves.toBe(false);
    await expect(captchaService.generate({ ip })).resolves.toBeTruthy();
  });

  describe('Redis 模式校验（一次性消费语义）', () => {
    // 评价报告低危项：verify 已改用原子取删 getDel（GETDEL），不再 get→del 两步
    const setupRedisMode = () => {
      jest.spyOn(sharedCache, 'isRedisEnabled').mockReturnValue(true);
      return {
        getDelSpy: jest.spyOn(sharedCache, 'getDel'),
        decrSpy: jest.spyOn(sharedCache, 'decrWithFloorZero').mockResolvedValue(0),
      };
    };

    test('命中且文本匹配（大小写不敏感 + 去空白）→ true，且取删即消费、双配额归还', async () => {
      const { getDelSpy, decrSpy } = setupRedisMode();
      getDelSpy.mockResolvedValue({ text: 'AbCd', ipKey: 'captcha:active-count:ip:abc' });
      await expect(captchaService.verify('cid-1', '  aBcD ')).resolves.toBe(true);
      expect(getDelSpy).toHaveBeenCalledWith('captcha:cid-1');
      expect(decrSpy.mock.calls).toEqual([
        ['captcha:active-count'],
        ['captcha:active-count:ip:abc'],
      ]);
    });

    test('条目不存在 → false，且不得凭空递减计数器', async () => {
      const { getDelSpy, decrSpy } = setupRedisMode();
      getDelSpy.mockResolvedValue(null);
      await expect(captchaService.verify('cid-2', 'AAAA')).resolves.toBe(false);
      expect(decrSpy).not.toHaveBeenCalled();
    });

    test('条目 text 非字符串（脏数据）→ false，但条目已消费，配额仍要归还', async () => {
      const { getDelSpy, decrSpy } = setupRedisMode();
      getDelSpy.mockResolvedValue({ text: 1234, ipKey: null });
      await expect(captchaService.verify('cid-3', '1234')).resolves.toBe(false);
      expect(decrSpy.mock.calls).toEqual([['captcha:active-count']]);
    });

    test('取删抛错 → 按未通过处理（fail-closed，不悬挂验证码）', async () => {
      const { getDelSpy } = setupRedisMode();
      getDelSpy.mockRejectedValue(new Error('cache down (故障注入)'));
      await expect(captchaService.verify('cid-4', 'AAAA')).resolves.toBe(false);
      expect(getDelSpy).toHaveBeenCalledWith('captcha:cid-4');
    });

    test('captchaId 撞活跃计数保留键（全局或按 IP）→ false，且绝不触达 getDel', async () => {
      // 越界值会让 entryKey(captchaId) 撞上计数器键，getDel 一旦执行就把
      // 活跃计数删掉、重置 generate 的洪水面护栏。闸门须在触存储前拦下。
      const { getDelSpy } = setupRedisMode();
      getDelSpy.mockResolvedValue({ text: 'AbCd' }); // 即便存储里有值也不该被读到
      await expect(captchaService.verify('active-count', 'AbCd')).resolves.toBe(false);
      await expect(captchaService.verify('active-count:ip:deadbeefdeadbeef', 'AbCd')).resolves.toBe(
        false
      );
      expect(getDelSpy).not.toHaveBeenCalled();
    });
  });
});
