/**
 * 蜜罐账户名单与判据的单元闸（不连库）
 *
 * 与 tests/constants/canaryAccounts.test.js 同构：这里测「名单是什么、怎么解析、怎么归一化、
 * 什么口令算诱饵」；检测、物化与接线在 tests/services/honeypotWatch.test.js，
 * 枚举面排除的静态台账在 tests/ci/honeypotExclusionLedger.test.js。
 *
 * 钉住的边界（都是「看起来对、实际会把蜜罐变成可见账户」的形态）：
 *  1. 默认名单**整体接管**默认哨兵名（幽灵账号升级为可登录蜜罐）：交集必须恰好等于默认
 *     哨兵名单，且逐条登记在 tests/ci/honeypotNameOverlapLedger——交集"少一个"（漏接管）
 *     与"多一个"（接管了没登记的名字）都视为漂移；
 *  2. 生效名单必须**恒不含当前超管名**（getSuperAdminUsername，默认 admin）：占用超管名
 *     等于把最高权限账户变成陷阱。admin 写在默认名单里是有意的未来意图，由解析层剔除；
 *  3. env 整份覆盖（不并集）、条目 trim+小写、重复项去重、空条目记 errors、全无效回退默认；
 *  4. 排除判据单一声明且**不可被调用方覆盖**（withHoneypotExcluded 的展开顺序）；
 *  5. 总开关只认真值词表（'TRUE' / ' on ' 算开，'false' / '0' / 未设置算关）。
 */

'use strict';

const {
  DEFAULT_HONEYPOT_USERNAMES,
  HONEYPOT_ENABLED_ENV,
  HONEYPOT_EXCLUDED_FILTER,
  HONEYPOT_USERNAMES_ENV,
  findNameOverlap,
  isHoneypotEnabled,
  isLurePassword,
  matchHoneypotName,
  normalizeHoneypotUsername,
  parseHoneypotUsernames,
  withHoneypotExcluded,
} = require('../../constants/honeypotAccounts');
const { DEFAULT_CANARY_USERNAMES } = require('../../constants/canaryAccounts');

describe('蜜罐账户名单（constants/honeypotAccounts）', () => {
  test('默认名单：整体接管默认哨兵名（逐条登记），且生效名单恒不含超管名', () => {
    expect(DEFAULT_HONEYPOT_USERNAMES.length).toBeGreaterThanOrEqual(1);
    expect(findNameOverlap(DEFAULT_HONEYPOT_USERNAMES, DEFAULT_CANARY_USERNAMES)).toEqual([
      ...DEFAULT_CANARY_USERNAMES,
    ]);
    expect(DEFAULT_HONEYPOT_USERNAMES).toContain('admin');
    const parsed = parseHoneypotUsernames();
    expect(parsed.names).not.toContain('admin');
    expect(parsed.dropped).toEqual(['admin']);
    expect(parsed.names).toEqual(DEFAULT_HONEYPOT_USERNAMES.filter((name) => name !== 'admin'));
    expect(Object.isFrozen(DEFAULT_HONEYPOT_USERNAMES)).toBe(true);
  });

  test('超管名判据：生效名单永不含**当前**超管名，env 显式写入也剔除', () => {
    const saved = process.env.SUPER_ADMIN_USERNAME;
    try {
      process.env.SUPER_ADMIN_USERNAME = 'chief';
      const byDefault = parseHoneypotUsernames();
      expect(byDefault.names).toContain('admin');
      expect(byDefault.names).not.toContain('chief');
      expect(byDefault.dropped).toEqual([]);
      const viaEnv = parseHoneypotUsernames(' SYSADMIN , chief ');
      expect(viaEnv.names).toEqual(['sysadmin']);
      expect(viaEnv.dropped).toEqual(['chief']);
    } finally {
      if (saved === undefined) delete process.env.SUPER_ADMIN_USERNAME;
      else process.env.SUPER_ADMIN_USERNAME = saved;
    }
  });

  test('未配置 env：用默认名单（剔除超管名），fromEnv=false，无 errors', () => {
    const expected = DEFAULT_HONEYPOT_USERNAMES.filter((name) => name !== 'admin');
    for (const raw of [undefined, null, '', '   ']) {
      const parsed = parseHoneypotUsernames(raw);
      expect(parsed.names).toEqual(expected);
      expect(parsed.dropped).toEqual(['admin']);
      expect(parsed.fromEnv).toBe(false);
      expect(parsed.errors).toEqual([]);
    }
  });

  test('配了 env：整份覆盖默认名单（不并集），trim + 小写 + 去重', () => {
    const parsed = parseHoneypotUsernames(' Sec_Ops , OPS ,sec_ops');
    expect(parsed.names).toEqual(['sec_ops', 'ops']);
    expect(parsed.fromEnv).toBe(true);
    expect(parsed.errors).toEqual([]);
    expect(parsed.names).not.toContain(DEFAULT_HONEYPOT_USERNAMES[0]);
  });

  test('空条目记 errors 但仍保留有效条目；全无效则回退默认名单并记 errors', () => {
    const partial = parseHoneypotUsernames('ops,, ,backup2');
    expect(partial.names).toEqual(['ops', 'backup2']);
    expect(partial.errors.length).toBe(2);
    const allInvalid = parseHoneypotUsernames(',,  ,');
    expect(allInvalid.names).toEqual(DEFAULT_HONEYPOT_USERNAMES.filter((name) => name !== 'admin'));
    expect(allInvalid.errors.length).toBeGreaterThanOrEqual(1);
    expect(allInvalid.fromEnv).toBe(false);
  });

  test('matchHoneypotName：大小写不敏感、非字符串/空白一律不命中', () => {
    expect(matchHoneypotName('SYSADMIN')).toBe('sysadmin');
    expect(matchHoneypotName(' sysadmin ')).toBe('sysadmin');
    for (const value of ['admin', '', '   ', undefined, null, 42, {}, [], 'sysadmin2']) {
      expect(matchHoneypotName(value)).toBe(null);
    }
    expect(normalizeHoneypotUsername(123)).toBe(null);
  });

  test('排除判据单一声明、形状固定、且调用方覆盖不掉', () => {
    expect(HONEYPOT_EXCLUDED_FILTER).toEqual({ isHoneypot: { $ne: true } });
    expect(Object.isFrozen(HONEYPOT_EXCLUDED_FILTER)).toBe(true);
    expect(withHoneypotExcluded({ department: 'A' })).toEqual({
      department: 'A',
      isHoneypot: { $ne: true },
    });
    expect(withHoneypotExcluded({ isHoneypot: true })).toEqual({ isHoneypot: { $ne: true } });
    expect(withHoneypotExcluded()).toEqual({ isHoneypot: { $ne: true } });
  });

  test('总开关只认真值词表，未设置即关闭', () => {
    for (const raw of ['true', 'TRUE', ' True ', '1', 'yes', 'on']) {
      expect(isHoneypotEnabled(raw)).toBe(true);
    }
    for (const raw of [undefined, null, '', '   ', 'false', '0', 'no', 'off', 'enabled']) {
      expect(isHoneypotEnabled(raw)).toBe(false);
    }
    expect(HONEYPOT_ENABLED_ENV).toBe('HONEYPOT_ENABLED');
    expect(HONEYPOT_USERNAMES_ENV).toBe('HONEYPOT_USERNAMES');
  });

  test('诱饵口令判据：命中弱口令词干表即算，强口令与非字符串不算', () => {
    expect(isLurePassword('admin@123456')).toBe(true);
    expect(isLurePassword('Admin@123456')).toBe(true);
    expect(isLurePassword('P@ssw0rd')).toBe(true);
    for (const value of ['Zz9!kLm3#Tuv7', '', undefined, null, 42, {}]) {
      expect(isLurePassword(value)).toBe(false);
    }
  });

  test('名单交集是纯函数（启动期据此提示「哨兵改由蜜罐接管」）', () => {
    expect(findNameOverlap(['a', 'b'], ['b', 'c'])).toEqual(['b']);
    expect(findNameOverlap(['a'], [])).toEqual([]);
  });
});
