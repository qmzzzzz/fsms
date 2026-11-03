'use strict';

/**
 * 撞库画像（P2 情报）的判据面：ADR-013「P2 情报：撞库画像」五条判据的可执行版。
 *
 * 为什么单开一个闸：画像是个聚合面——一次读取横向看到许多来源，而审计行是逐条的。
 * 所以这里要钉的不只是「字段算得对」，还有三条结构面：键集合与 ADR 字段表双向一致、
 * 输出不得回显口令与陷阱判据（阶段名/哨兵名/诱饵名）、出口必须自述窗口端点且实现里
 * 不得有承载样本的模块级容器。一半用例是反证：正例只证明「算得出」，反例才证明「算错会红」。
 */
const fs = require('fs');
const path = require('path');
const {
  MIN_SAMPLES,
  PROFILE_FIELDS,
  SAMPLED_ACTIONS,
  SUCCESS_ACTION,
  byStrength,
  isBlacklistCandidate,
} = require('../../constants/stuffingProfile');
const { credentialShapeOf } = require('../../constants/credentialShape');
const { aggregateRows, resolveWindow } = require('../../services/stuffingProfile');
const { businessDayBounds } = require('../../constants/timezone');

const DAY = '2026-03-05';
const WINDOW = resolveWindow({ businessDay: DAY, now: Date.parse(DAY + 'T23:59:00+08:00') });

const row = (over = {}) => ({
  action: 'canary_username_attempt',
  username: 'ghost-a',
  ip: '203.0.113.9',
  body: {},
  ...over,
});

const shaped = (password, over = {}) =>
  row({
    body: { canary: 'ghost-a', credentialShape: credentialShapeOf(password) },
    ...over,
  });

describe('撞库画像：五条判据（ADR-013 P2）', () => {
  test('#3 键集合：出口键 === ADR 字段表（双向），且表本身是冻结的十元组', () => {
    const adr = fs.readFileSync(
      path.resolve(__dirname, '../../../docs/adr/ADR-013-蜜罐账户与诱饵登录.md'),
      'utf8'
    );
    const section = adr.slice(adr.indexOf('## P2 情报'), adr.indexOf('## 后续演进'));
    const declared = [];
    for (const line of section.split(/\r?\n/)) {
      if (!line.startsWith('| `')) continue;
      for (const cell of line.split('|')[1].split('/')) {
        declared.push(cell.trim().replace(/`/g, '').split(' ')[0]);
      }
    }
    expect(declared.length).toBeGreaterThanOrEqual(10);
    expect([...PROFILE_FIELDS].sort()).toEqual([...declared].sort());
    expect(Object.isFrozen(PROFILE_FIELDS)).toBe(true);
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) rows.push(shaped('Password123'));
    const out = aggregateRows(rows, WINDOW);
    expect(out.entries).toHaveLength(1);
    expect(Object.keys(out.entries[0]).sort()).toEqual([...PROFILE_FIELDS].sort());
  });

  test('#1 正向现算：每个字段当场算出来对拍，不抄期望值', () => {
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) {
      rows.push(shaped('Password123', { username: 'acct' + (i % 4) }));
    }
    rows.push(row({ action: SUCCESS_ACTION, username: 'acct0' }));
    const out = aggregateRows(rows, WINDOW);
    expect(out.entries).toHaveLength(1);
    const entry = out.entries[0];
    expect(entry.sourceKey).toBe('203.0.113');
    expect(entry.attempts).toBe(MIN_SAMPLES);
    expect(entry.successes).toBe(1);
    expect(entry.credentialStemHits).toBe(MIN_SAMPLES);
    expect(entry.accountCardinality).toBe(4);
    expect(entry.lengthBucket).toBe('8-11');
    expect(entry.businessDay).toBe(WINDOW.businessDay);
    expect(entry.windowStart).toBe(WINDOW.windowStart);
    expect(entry.windowEnd).toBe(WINDOW.windowEnd);
  });

  test('#2 反证：拿掉词干命中标记 ⇒ credentialStemHits 归零', () => {
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) rows.push(row({ username: 'acct' + i }));
    const out = aggregateRows(rows, WINDOW);
    expect(out.entries[0].credentialStemHits).toBe(0);
    expect(out.entries[0].lengthBucket).toBeNull();
  });

  test('#2 反证：sourceKey 不回落裸文本——不可解析的 IP 被丢弃且丢弃量可见', () => {
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) rows.push(shaped('Password123'));
    rows.push(row({ ip: 'not-an-ip' }));
    rows.push(row({ ip: undefined }));
    const out = aggregateRows(rows, WINDOW);
    expect(out.droppedUnparsable).toBe(2);
    expect(out.entries.map((e) => e.sourceKey)).toEqual(['203.0.113']);
  });

  test('#2 反证：上游顺手带进来的口令明文不得出现在画像任何字段', () => {
    const secret = 'Sup3rSecret!x9';
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) {
      rows.push(
        row({
          username: 'acct' + i,
          body: { canary: 'ghost-a', credentialShape: credentialShapeOf(secret), leaked: secret },
        })
      );
    }
    const serialized = JSON.stringify(aggregateRows(rows, WINDOW));
    expect(serialized).not.toContain(secret);
    for (const piece of [secret.slice(0, 6), secret.slice(4, 10)]) {
      expect(serialized).not.toContain(piece);
    }
  });

  test('#2 反证：输出不回显阶段名/哨兵名/诱饵名', () => {
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) rows.push(shaped('Password123'));
    rows.push(
      row({
        ip: '198.51.100.7',
        action: 'honeypot_login',
        body: { honeypot: 'sysadmin', credentialShape: credentialShapeOf('Password123') },
      })
    );
    const out = aggregateRows(rows, WINDOW);
    expect(out.entries.length).toBe(1);
    const serialized = JSON.stringify(out);
    for (const name of ['sysadmin', 'ghost-a', 'canary', 'honeypot', ...SAMPLED_ACTIONS]) {
      expect([name, serialized.includes(name)]).toEqual([name, false]);
    }
  });

  test('#4 跨实例面：出口自述窗口端点；服务里无承载样本的模块级容器', () => {
    const out = aggregateRows([], WINDOW);
    expect(typeof out.windowStart).toBe('string');
    expect(typeof out.windowEnd).toBe('string');
    expect(new Date(out.windowStart).getTime()).toBeLessThanOrEqual(
      new Date(out.windowEnd).getTime()
    );
    expect(out.entries).toEqual([]);
    const src = fs.readFileSync(
      path.resolve(__dirname, '../../services/stuffingProfile.js'),
      'utf8'
    );
    const containers = src
      .split(/\r?\n/)
      .filter((line) => /^(?:const|let|var)\s+\w+\s*=\s*new\s+(?:Map|Set)\b/.test(line)); // 只看列 0：函数内的局部聚合是本函数要的形状
    expect(containers).toEqual([]);
    expect(src).not.toMatch(/\bsetInterval\b|\bsetTimeout\b/);
  });

  test('#1 确定性：同一份行集的任意顺序得到逐字相同的画像与排名', () => {
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) {
      rows.push(shaped('Password123', { username: 'a' + i, ip: '203.0.113.9' }));
      rows.push(shaped('Passw0rd!', { username: 'b' + i, ip: '198.51.100.4' }));
    }
    const forward = JSON.stringify(aggregateRows(rows, WINDOW));
    const backward = JSON.stringify(aggregateRows([...rows].reverse(), WINDOW));
    expect(backward).toBe(forward);
    expect(byStrength.toString()).toContain('localeCompare');
  });

  test('样本不足不出口：低于 MIN_SAMPLES 的来源不出现，丢弃量可见', () => {
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES - 1; i += 1) rows.push(shaped('Password123'));
    const out = aggregateRows(rows, WINDOW);
    expect(out.entries).toEqual([]);
    expect(out.droppedBelowMin).toBe(1);
  });

  test('successes 只拉真实登录成功：诱饵放行落的那条 login_success 不算', () => {
    const rows = [];
    for (let i = 0; i < MIN_SAMPLES; i += 1) rows.push(shaped('Password123'));
    rows.push(
      row({
        action: 'honeypot_login',
        body: { honeypot: 'sysadmin', credentialShape: credentialShapeOf('Password123') },
      })
    );
    rows.push(row({ action: SUCCESS_ACTION, username: 'sysadmin' }));
    const out = aggregateRows(rows, WINDOW);
    expect(out.entries[0].successes).toBe(0);
    expect(out.entries[0].attempts).toBe(MIN_SAMPLES + 1);
  });

  test('共享出口判据：一个账号反复试（词干零命中）不进候选，多账号试才进', () => {
    const shared = {
      sourceKey: '203.0.113',
      attempts: 40,
      accountCardinality: 1,
      credentialStemHits: 0,
      successes: 0,
    };
    const stuffer = { ...shared, accountCardinality: 12, credentialStemHits: 33 };
    expect([isBlacklistCandidate(shared), isBlacklistCandidate(stuffer)]).toEqual([false, true]);
    expect(isBlacklistCandidate({ ...shared, attempts: MIN_SAMPLES - 1 })).toBe(false);
  });

  test('窗口 = 业务日 ∩ 保留期：下界被夹住时窗口跟着缩，两界都自述', () => {
    const bounds = businessDayBounds(DAY);
    const fresh = resolveWindow({
      businessDay: DAY,
      now: bounds.start.getTime() + 3600 * 1000,
    });
    expect(fresh.windowStart).toBe(bounds.start.toISOString());
    expect(fresh.windowEnd).toBe(bounds.end.toISOString());
    const stale = resolveWindow({
      businessDay: DAY,
      now: bounds.start.getTime() + 200 * 86400 * 1000, // 200 天 > 保留期 180 天：整轮落到保留期下界之外
    });
    expect(stale.expired).toBe(true);
    expect(new Date(stale.windowStart).getTime()).toBeGreaterThan(bounds.start.getTime());
  });
});

describe('E4：读侧行数上限（撞顶自述 truncated/sampledRows/total）', () => {
  const AuditLog = require('../../models/AuditLog');
  const { buildProfile, MAX_STUFFING_ROWS } = require('../../services/stuffingProfile');

  /** 链式记录器：sort/limit 的实参要在断言里核对（不定 sort 的 limit 是"不确定样本"） */
  const stubFind = (rows) => {
    const steps = [];
    const chain = {
      __steps: steps,
      select(a) {
        steps.push(['select', a]);
        return chain;
      },
      sort(a) {
        steps.push(['sort', a]);
        return chain;
      },
      limit(n) {
        steps.push(['limit', n]);
        return chain;
      },
      lean: async () => rows,
    };
    return chain;
  };

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('撞顶 ⇒ 截到 MAX_STUFFING_ROWS、countDocuments 补 total、truncated=true，且查询带 sort', async () => {
    const rows = Array.from({ length: MAX_STUFFING_ROWS }, () => row());
    const chain = stubFind(rows);
    const findSpy = jest.spyOn(AuditLog, 'find').mockReturnValue(chain);
    const countSpy = jest
      .spyOn(AuditLog, 'countDocuments')
      .mockResolvedValue(MAX_STUFFING_ROWS + 37);
    const profile = await buildProfile({
      businessDay: DAY,
      now: Date.parse(DAY + 'T23:59:00+08:00'),
    });
    expect(profile.sampledRows).toBe(MAX_STUFFING_ROWS);
    expect(profile.total).toBe(MAX_STUFFING_ROWS + 37);
    expect(profile.truncated).toBe(true);
    expect(countSpy).toHaveBeenCalledTimes(1);
    expect(findSpy).toHaveBeenCalledTimes(1);
    const steps = Object.fromEntries(chain.__steps);
    expect(steps.sort).toEqual({ timestamp: -1, _id: -1 }); // 必须带 sort（与审计列表同向）
    expect(steps.limit).toBe(MAX_STUFFING_ROWS);
  });

  test('未撞顶 ⇒ 不发 count 查询（取回数即命中总数），truncated=false', async () => {
    const chain = stubFind([row(), row(), row()]);
    jest.spyOn(AuditLog, 'find').mockReturnValue(chain);
    const countSpy = jest.spyOn(AuditLog, 'countDocuments');
    const profile = await buildProfile({
      businessDay: DAY,
      now: Date.parse(DAY + 'T23:59:00+08:00'),
    });
    expect(profile.sampledRows).toBe(3);
    expect(profile.total).toBe(3);
    expect(profile.truncated).toBe(false);
    expect(countSpy).not.toHaveBeenCalled();
  });
});
