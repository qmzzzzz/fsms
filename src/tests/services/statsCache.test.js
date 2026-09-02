/**
 * 统计缓存模块单元测试
 * 覆盖写入命中、TTL 过期、单条删除、按用户前缀失效、异常降级路径
 */

const statsCache = require('../../services/statsCache');

describe('statsCache', () => {
  afterEach(() => {
    statsCache._store.clear();
  });

  afterAll(() => {
    statsCache.stopCleanup();
  });

  describe('get / set', () => {
    test('写入后命中返回缓存数据', () => {
      const data = { total: 10, active: 5 };
      statsCache.set('stats:u1:h1', data, 60);
      const result = statsCache.get('stats:u1:h1');
      expect(result.hit).toBe(true);
      expect(result.data).toEqual(data);
    });

    test('TTL 过期后未命中', () => {
      jest.useFakeTimers();
      try {
        statsCache.set('stats:u1:h2', { total: 1 }, 1);
        expect(statsCache.get('stats:u1:h2').hit).toBe(true);
        jest.advanceTimersByTime(1001);
        const result = statsCache.get('stats:u1:h2');
        expect(result.hit).toBe(false);
      } finally {
        jest.useRealTimers();
      }
    });

    test('未写入的键未命中', () => {
      expect(statsCache.get('stats:none:missing').hit).toBe(false);
    });

    test('set 缺省 ttl 时使用配置默认值', () => {
      statsCache.set('stats:u1:h3', { total: 2 });
      expect(statsCache.get('stats:u1:h3').hit).toBe(true);
    });
  });

  describe('del', () => {
    test('删除指定缓存键', () => {
      statsCache.set('stats:u1:h4', { total: 1 }, 60);
      statsCache.del('stats:u1:h4');
      expect(statsCache.get('stats:u1:h4').hit).toBe(false);
    });

    test('删除不影响其他键', () => {
      statsCache.set('stats:u1:h5', { total: 1 }, 60);
      statsCache.set('stats:u2:h5', { total: 2 }, 60);
      statsCache.del('stats:u1:h5');
      expect(statsCache.get('stats:u1:h5').hit).toBe(false);
      expect(statsCache.get('stats:u2:h5').hit).toBe(true);
    });
  });

  describe('invalidateByUserId', () => {
    test('删除该用户全部缓存条目', () => {
      statsCache.set('stats:u1:a', { total: 1 }, 60);
      statsCache.set('stats:u1:b', { total: 2 }, 60);
      statsCache.set('stats:u2:a', { total: 3 }, 60);
      statsCache.invalidateByUserId('u1');
      expect(statsCache.get('stats:u1:a').hit).toBe(false);
      expect(statsCache.get('stats:u1:b').hit).toBe(false);
      expect(statsCache.get('stats:u2:a').hit).toBe(true);
    });

    test('不误删前缀相似的其他用户缓存', () => {
      statsCache.set('stats:user1:a', { total: 1 }, 60);
      statsCache.set('stats:user10:a', { total: 2 }, 60);
      statsCache.invalidateByUserId('user1');
      expect(statsCache.get('stats:user1:a').hit).toBe(false);
      // "stats:user1:" 前缀不会命中 "stats:user10:a"（前缀是 stats:user10:）
      expect(statsCache.get('stats:user10:a').hit).toBe(true);
    });
  });

  describe('异常降级', () => {
    test('store 抛异常时 get 返回 { hit: false }', () => {
      const originalGet = statsCache._store.get;
      statsCache._store.get = () => {
        throw new Error('mock get error');
      };
      try {
        statsCache.set('stats:u1:err', { total: 1 }, 60);
        const result = statsCache.get('stats:u1:err');
        expect(result.hit).toBe(false);
      } finally {
        statsCache._store.get = originalGet;
      }
    });

    test('store 抛异常时 set 不向上抛错', () => {
      const originalSet = statsCache._store.set;
      statsCache._store.set = () => {
        throw new Error('mock set error');
      };
      try {
        expect(() => statsCache.set('stats:u1:err', { total: 1 }, 60)).not.toThrow();
      } finally {
        statsCache._store.set = originalSet;
      }
    });
  });

  describe('sweepExpired 清理机制', () => {
    test('清除过期条目并保留未过期条目', () => {
      jest.useFakeTimers();
      try {
        statsCache.set('stats:u1:old', { total: 1 }, 1);
        statsCache.set('stats:u1:new', { total: 2 }, 60);
        const now = Date.now();
        statsCache._store.get('stats:u1:old').expireAt = now - 1;
        statsCache.sweepExpired();
        expect(statsCache.get('stats:u1:old').hit).toBe(false);
        expect(statsCache.get('stats:u1:new').hit).toBe(true);
      } finally {
        jest.useRealTimers();
      }
    });
  });
});
