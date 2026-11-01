/**
 * 蜜罐「接管哨兵名」台账闸（幽灵账号 → 蜜罐账户的升级是逐条决策，不是默认漂移）
 *
 * 为什么需要：默认诱饵名单 = sysadmin + 全部默认哨兵名 + admin。这不是配置巧合，
 * 而是把「猜名字」的幽灵哨兵升级成「猜对口令就进得来」的蜜罐：每接管一个哨兵名，
 * 该名字的 canary 分支就永久走不到（库里已存在），检测责任转由蜜罐登录信号承担。
 * 台账把这条决定变成机器判据：接管集合必须**逐条**登记，多一个少一个都红。
 *
 * 钉四件事：① 接管集合与台账双向一致且等于全部默认哨兵名；② 台账条目必须是真哨兵名
 * （防幽灵条目）；③ 生效名单非空、不含当前超管名、且口径可预测；④ 判据有牙——未登记项
 * 与残留条目都必须能被抓出。
 */

'use strict';

const {
  DEFAULT_HONEYPOT_USERNAMES,
  findNameOverlap,
  parseHoneypotUsernames,
} = require('../../constants/honeypotAccounts');
const { DEFAULT_CANARY_USERNAMES } = require('../../constants/canaryAccounts');
const { getSuperAdminUsername } = require('../../utils/superAdmin');

/** 接管台账：哨兵名 → 升级为蜜罐的理由。新增接管必须在此登记，否则本闸红 */
const TAKEOVER_LEDGER = Object.freeze({
  administrator: '超管别名，爆破字典首位；本仓真超管是 admin，此名不可能是真人',
  root: 'Unix 根账户名，凭据填充字典常客；口令本身也在弱口令词干表内',
  user: '泛用占位名，字典高频；口令 user 同样在词干表内',
  test: '测试遗留名，字典高频；口令 test 同样在词干表内',
  guest: '来宾账户默认名；口令 guest 同样在词干表内',
  system: '系统服务默认名，运维误配残留',
  oracle: '数据库默认账户残留，字典高频',
  postgres: '数据库默认账户残留，字典高频',
  backup: '备份账户默认名，运维误配残留',
  demo: '演示账户默认名，字典高频',
});

const registeredTakeovers = (ledger = TAKEOVER_LEDGER) => Object.keys(ledger).sort();
const unregisteredTakeovers = (overlap, ledger = TAKEOVER_LEDGER) =>
  overlap.filter((name) => ledger[name] === undefined);
const staleLedgerEntries = (overlap, ledger = TAKEOVER_LEDGER) =>
  registeredTakeovers(ledger).filter((name) => !overlap.includes(name));

describe('蜜罐接管哨兵名台账', () => {
  const overlap = findNameOverlap(DEFAULT_HONEYPOT_USERNAMES, DEFAULT_CANARY_USERNAMES);

  test('接管集合 = 全部默认哨兵名，且与台账双向一致', () => {
    expect(overlap).toHaveLength(DEFAULT_CANARY_USERNAMES.length);
    expect(unregisteredTakeovers(overlap)).toEqual([]);
    expect(staleLedgerEntries(overlap)).toEqual([]);
    expect([...overlap].sort()).toEqual(registeredTakeovers());
  });

  test('台账每条都必须是默认哨兵名且写了理由（防幽灵条目）', () => {
    for (const name of registeredTakeovers()) {
      expect(DEFAULT_CANARY_USERNAMES).toContain(name);
      expect(String(TAKEOVER_LEDGER[name]).length).toBeGreaterThan(0);
    }
  });

  test('生效名单：非空、不含当前超管名、等于默认名单减去被剔除项', () => {
    const parsed = parseHoneypotUsernames();
    expect(parsed.names.length).toBeGreaterThan(0);
    expect(parsed.names).not.toContain(getSuperAdminUsername());
    expect(parsed.names).toEqual(
      DEFAULT_HONEYPOT_USERNAMES.filter((n) => !parsed.dropped.includes(n))
    );
  });

  test('反向对照：未登记接管与残留台账都必须报红（判据有牙）', () => {
    expect(unregisteredTakeovers(['root', 'nobody_registered'])).toEqual(['nobody_registered']);
    expect(staleLedgerEntries(['root'], { root: 'x' })).toEqual([]);
    expect(staleLedgerEntries(['root'], { root: 'x', gone: 'y' })).toEqual(['gone']);
  });
});
