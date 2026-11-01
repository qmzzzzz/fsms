/**
 * 诱饵画像派生闸（P1e，不连库）
 *
 * 背景：蜜罐账户原先共用 realName '运维管理员' + 同一邮箱域名 + 同一创建批次，
 * 11 条记录构成一个「一眼可辨的簇」——持库读权限者（或任何一个越权读到 users 集合的人）
 * 看到 11 行同名同域账户，蜜罐当场失效。本闸钉住画像派生本身的不变量。
 *
 * 钉四件事（每条都配反向自证，避免「判据没牙」）：
 *  1. 确定性：同一名字恒派同一画像（重跑 init 幂等，不会每次刷新改名换岗）；
 *  2. 互不相同：默认名单逐条派生时 realName 两两不同——「统一 realName」正是本批要消灭的形态；
 *  3. 去重有牙：把已派出的 realName 喂回 taken，必须换一批（而不是原地返回同一个）；
 *  4. 取值合法：只在池内取值、realName 不含 ASCII、长度在 schema 上限内、非字符串输入不抛。
 *
 * 与相邻闸的分工：名单/判据在 tests/constants/honeypotAccounts.test.js；
 * 「物化时真的写进 realName/department」在 tests/services/honeypotWatch.test.js 与
 * tests/ci/honeypotPersonaDifferentiation.test.js（静态接线）。
 */

'use strict';

const {
  PERSONA_DEPARTMENTS,
  PERSONA_GIVEN_NAMES,
  PERSONA_SURNAMES,
  deriveHoneypotPersona,
} = require('../../constants/honeypotPersonas');
const {
  DEFAULT_HONEYPOT_USERNAMES,
  parseHoneypotUsernames,
} = require('../../constants/honeypotAccounts');

describe('诱饵画像派生（constants/honeypotPersonas）', () => {
  test('前提自证：池非空且够大，否则「两两不同」是空话', () => {
    expect(PERSONA_SURNAMES.length).toBeGreaterThanOrEqual(10);
    expect(PERSONA_GIVEN_NAMES.length).toBeGreaterThanOrEqual(10);
    expect(PERSONA_DEPARTMENTS.length).toBeGreaterThanOrEqual(4);
    // 姓氏×名字 = 候选空间；远大于生效名单条数才谈得上「不撞名」
    expect(PERSONA_SURNAMES.length * PERSONA_GIVEN_NAMES.length).toBeGreaterThanOrEqual(200);
    expect(Object.isFrozen(PERSONA_SURNAMES)).toBe(true);
    expect(Object.isFrozen(PERSONA_GIVEN_NAMES)).toBe(true);
    expect(Object.isFrozen(PERSONA_DEPARTMENTS)).toBe(true);
  });

  test('确定性 + 归一化：同名（含大小写/空格差异）恒派同一画像', () => {
    const once = deriveHoneypotPersona('sysadmin');
    expect(deriveHoneypotPersona('sysadmin')).toEqual(once);
    expect(deriveHoneypotPersona('  SYSADMIN  ')).toEqual(once);
    expect(deriveHoneypotPersona('root')).toEqual(deriveHoneypotPersona('ROOT'));
  });

  test('默认名单逐条派生：realName 两两不同，且都不等于用户名', () => {
    const taken = [];
    const seen = new Set();
    for (const name of DEFAULT_HONEYPOT_USERNAMES) {
      const persona = deriveHoneypotPersona(name, taken);
      taken.push(persona.realName);
      seen.add(persona.realName);
      expect(persona.realName).not.toBe(name);
    }
    expect(seen.size).toBe(DEFAULT_HONEYPOT_USERNAMES.length);
  });

  test('生效名单（超管名已剔除）逐条派生：画像仍两两不同', () => {
    const names = parseHoneypotUsernames().names;
    expect(names.length).toBeGreaterThanOrEqual(1);
    const taken = [];
    for (const name of names) taken.push(deriveHoneypotPersona(name, taken).realName);
    expect(new Set(taken).size).toBe(names.length);
  });

  test('去重有牙（反向自证）：taken 命中首候选 ⇒ 必须换一批', () => {
    const first = deriveHoneypotPersona('oracle');
    const next = deriveHoneypotPersona('oracle', [first.realName]);
    expect(next.realName).not.toBe(first.realName);
    // 合仓后仍然只出现一次：换出来的画像不会被 taken 里的旧值污染
    expect([first.realName, next.realName].filter((v) => v === first.realName)).toHaveLength(1);
  });

  test('取值合法：池内取值、纯中文姓名、长度在 schema 上限内、部门非空', () => {
    for (const name of [...DEFAULT_HONEYPOT_USERNAMES, 'toolong'.repeat(6)]) {
      const { realName, department } = deriveHoneypotPersona(name);
      const surname = [...PERSONA_SURNAMES].find((s) => realName.startsWith(s));
      expect(surname).toBeTruthy();
      expect(PERSONA_GIVEN_NAMES).toContain(realName.slice(surname.length));
      expect(PERSONA_DEPARTMENTS).toContain(department);
      expect(/[A-Za-z0-9]/.test(realName)).toBe(false);
      expect(realName.length).toBeLessThanOrEqual(50);
      expect(department.length).toBeLessThanOrEqual(100);
      expect(realName.trim()).toBe(realName);
    }
  });

  test('边界：非字符串/空串输入不抛异常，仍返回一份合法画像', () => {
    for (const value of [undefined, null, '', '   ', 42, {}, []]) {
      const persona = deriveHoneypotPersona(value);
      expect(typeof persona.realName).toBe('string');
      expect(persona.realName.length).toBeGreaterThan(0);
      expect(PERSONA_DEPARTMENTS).toContain(persona.department);
    }
  });

  test('taken 为 undefined 时等价于空集（调用方不必先建数组）', () => {
    expect(deriveHoneypotPersona('backup', undefined)).toEqual(deriveHoneypotPersona('backup', []));
  });
});
