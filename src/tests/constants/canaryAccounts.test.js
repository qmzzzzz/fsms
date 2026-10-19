/**
 * 哨兵用户名名单（constants/canaryAccounts）：默认值、env 解析与匹配。
 *
 * 纯函数测试，无 DB。判据聚焦三件事：
 *  1) 默认名单是**幽灵语义的构造性前提**——全小写 ASCII、不含 admin（默认超管
 *     真实存在，放进默认名单等于默认一个固定失效项）；
 *  2) CANARY_USERNAMES 的覆盖语义与 fail-loud 行为（空条目记 errors、
 *     全部无效回退默认而不是静默关停哨兵）；
 *  3) 匹配的大小写/空白归一化与默认名单的不可变性（返回副本）。
 */
const {
  DEFAULT_CANARY_USERNAMES,
  normalizeCanaryUsername,
  parseCanaryUsernames,
  findCanaryMatch,
} = require('../../constants/canaryAccounts');

describe('canaryAccounts 哨兵用户名名单', () => {
  describe('默认名单', () => {
    test('10 个幽灵名，全小写 ASCII（与 username_ci 大小写不敏感索引同口径）', () => {
      expect(DEFAULT_CANARY_USERNAMES).toHaveLength(10);
      for (const name of DEFAULT_CANARY_USERNAMES) {
        expect(name).toBe(name.trim().toLowerCase());
        expect(name).toMatch(/^[a-z]+$/);
      }
    });

    test('不含 admin：默认超管真实存在，放进去等于默认一个固定失效项', () => {
      expect(DEFAULT_CANARY_USERNAMES).not.toContain('admin');
    });

    test('默认名单被冻结（不可被调用方改写）', () => {
      expect(Object.isFrozen(DEFAULT_CANARY_USERNAMES)).toBe(true);
    });
  });

  describe('parseCanaryUsernames', () => {
    test('未配置（undefined/空串/纯空白）→ 默认名单，fromEnv=false，无 errors', () => {
      for (const raw of [undefined, null, '', '   ']) {
        const r = parseCanaryUsernames(raw);
        expect(r.names).toEqual([...DEFAULT_CANARY_USERNAMES]);
        expect(r.fromEnv).toBe(false);
        expect(r.errors).toEqual([]);
      }
    });

    test('配置非空 → 整体覆盖（默认名不在结果里，不合并）', () => {
      const r = parseCanaryUsernames('myghost,otherghost');
      expect(r.names).toEqual(['myghost', 'otherghost']);
      expect(r.fromEnv).toBe(true);
      expect(r.errors).toEqual([]);
    });

    test('归一化 + 去重：大小写/空白等价，重复项静默去重（不记错误）', () => {
      const r = parseCanaryUsernames('  Root , ROOT ,test ');
      expect(r.names).toEqual(['root', 'test']);
      expect(r.errors).toEqual([]);
    });

    test('空条目记 errors（不静默吞掉配置手误）', () => {
      const r = parseCanaryUsernames('root,,  ,demo');
      expect(r.names).toEqual(['root', 'demo']);
      expect(r.errors).toHaveLength(2);
      expect(r.errors.every((m) => m.includes('空条目'))).toBe(true);
    });

    test('全部无效 → 回退默认名单 + 记 errors（fail-loud，不静默停用哨兵）', () => {
      const r = parseCanaryUsernames(' , ,');
      expect(r.names).toEqual([...DEFAULT_CANARY_USERNAMES]);
      expect(r.fromEnv).toBe(false);
      expect(r.errors.some((m) => m.includes('回退默认名单'))).toBe(true);
    });

    test('非字符串 raw 按未配置处理（防御性，不抛错）', () => {
      for (const raw of [42, {}, ['root']]) {
        const r = parseCanaryUsernames(raw);
        expect(r.names).toEqual([...DEFAULT_CANARY_USERNAMES]);
        expect(r.fromEnv).toBe(false);
      }
    });

    test('每次返回新副本：改结果不影响冻结默认名单', () => {
      const r = parseCanaryUsernames(undefined);
      r.names.push('mutated');
      expect(DEFAULT_CANARY_USERNAMES).not.toContain('mutated');
    });
  });

  describe('normalizeCanaryUsername', () => {
    test('非字符串 → null（不抛错）', () => {
      for (const v of [undefined, null, 7, {}, []]) expect(normalizeCanaryUsername(v)).toBeNull();
    });

    test('trim + lower；空白串 → null', () => {
      expect(normalizeCanaryUsername('  ROOT ')).toBe('root');
      expect(normalizeCanaryUsername('')).toBeNull();
      expect(normalizeCanaryUsername('   ')).toBeNull();
    });
  });

  describe('findCanaryMatch', () => {
    test('大小写/空白不敏感命中，返回归一化名（稳定键）', () => {
      expect(findCanaryMatch(' ROOT ', ['root'])).toBe('root');
      expect(findCanaryMatch('x', ['root'])).toBeNull();
    });

    test('非字符串与非法名单 → null', () => {
      expect(findCanaryMatch(undefined, ['root'])).toBeNull();
      expect(findCanaryMatch('root', 'not-an-array')).toBeNull();
    });

    test('缺省名单 = 默认名单', () => {
      expect(findCanaryMatch('POSTGRES')).toBe('postgres');
      expect(findCanaryMatch('admin')).toBeNull();
    });
  });
});
