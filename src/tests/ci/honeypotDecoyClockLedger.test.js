/**
 * 诱饵时间列与聚合取值的双向判据（批次 E-2）
 *
 * 四条已实测的边界缺陷，各对应一条「只降不升」的判据：
 *
 * E5 取值域：`xOffsetMin: null` 会被 `Number(null)===0` 静默折成「此刻」，`undefined`/`NaN` 会让
 *    `toISOString()` 抛 RangeError ⇒ 500。合成表现在全是有限数字，所以这是**潜伏**缺陷；本闸把
 *    「有值」的定义钉成「有限数字」，并现算 `materializeRow` 对四种非数值都必须回 `null`、且不抛。
 * E3 行时间平移：行时间由「此刻 − 偏移」现算，两次抓取相隔 1.2s 就是 1201ms 的整体平移；真实库里
 *    时间是存量、不可变，一次 diff 即可自动化识别。本闸现算「同一小时内两次解析逐字相同」，
 *    聚合面则只允许在 `asOf`/`scannedAt` 这类**真·请求时刻**字段上不同。
 * E8 字段名漂移：`tally`/`windowRowsOf` 按字段名取值，改名漏改一处不会报错，只会静默产出丢 `_id`
 *    的桶或整段落空。本闸从**聚合模块源码**扫出被引用的字段名，再回到合成表逐行核对（双向：引用的
 *    字段必须在表里存在；表里有的字段必须每行都有）。「扫到几条」与「源码里有几次调用」也必须相等，
 *    否则给字段名加一层间接（传变量）就能让本闸静默失效。
 * E1 拒绝路径：两条带日期参数的统计端点，真实控制器是 `codeError(DATE_PARAM_INVALID /`
 *    `DATE_RANGE_INVALID)`；本闸把错误码从**控制器源码**里现读，与聚合体现算的 `code` 对拍——
 *    抄成两份口径迟早在某次改动后分叉。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const decoyData = require('../../constants/honeypotDecoyData');
const decoyFiles = require('../../constants/honeypotDecoyFiles');
const decoy = require('../../constants/honeypotDecoy');
const {
  AGGREGATE_ENDPOINTS,
  resolveAggregatePayload,
} = require('../../constants/honeypotDecoyAggregates');

const ROOT = path.resolve(__dirname, '../../..');
const readCode = (rel) => jsCodeOnly(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const SUFFIX = decoyData.OFFSET_SUFFIX;
const SECOND_MS = 1000;
const REQUEST_TIME_KEYS = ['asOf', 'scannedAt']; // 真实链里本来就是请求时刻的字段（已在 NON_DERIVABLE 登记）：允许两次请求不同
const AGGREGATES_SRC = readCode('src/constants/honeypotDecoyAggregates.js');

const ownKeys = (row) => Object.keys(row);

/** 递归收集 exports 里所有以 OFFSET_SUFFIX 结尾的键（值 + 路径） */
const collectOffsets = (node, trail, found) => {
  if (!node || typeof node !== 'object') return found;
  Object.entries(node).forEach(([key, value]) => {
    if (key.endsWith(SUFFIX)) found.push({ path: trail.concat(key).join('.'), value });
    else collectOffsets(value, trail.concat(key), found);
  });
  return found;
};

/** 源码里被引用的字段名：tally(rows, "f") 与 windowRowsOf(table, "k") */
const TALLY_RE = /\btally\(\s*[A-Za-z_$][\w$.]*\s*,\s*'([^']+)'/g;
const WINDOW_RE = /\bwindowRowsOf\(\s*decoy\.(DECOY_[A-Z_]+)\s*,\s*'([^']+)'/g;
const CALL_RE = /\b(tally|windowRowsOf)\(/g;
const TABLE_RE = /decoy\.(DECOY_[A-Z_]+)/g;

const matchesOf = (re) => [...AGGREGATES_SRC.matchAll(re)].map((m) => m[1]);
const tallyFields = () => matchesOf(TALLY_RE);
const windowRefs = () =>
  [...AGGREGATES_SRC.matchAll(WINDOW_RE)].map((m) => ({ table: m[1], field: m[2] }));
const referencedFields = () => [
  ...new Set([...tallyFields(), ...windowRefs().map((ref) => ref.field)]),
];
const callCounts = () => {
  const counts = { tally: 0, windowRowsOf: 0 };
  matchesOf(CALL_RE).forEach((name) => {
    counts[name] += 1;
  });
  return counts;
};

/** 聚合模块引用到的合成表（decoy.DECOY_*），只留「行对象数组」那些 */
const aggregateTables = () =>
  [...new Set(matchesOf(TABLE_RE))]
    .map((name) => ({ name, rows: decoyData[name] }))
    .filter(
      (item) => Array.isArray(item.rows) && item.rows.length && typeof item.rows[0] === 'object'
    );

/** 递归找出两棵 JSON 树所有不同的路径（只用于判定「差异是不是只有请求时刻字段」） */
const diffPaths = (a, b, trail, out) => {
  if (a === b) return out;
  if (Array.isArray(a) && Array.isArray(b) && a.length === b.length) {
    a.forEach((item, i) => diffPaths(item, b[i], trail.concat(String(i)), out));
    return out;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    new Set([...ownKeys(a), ...ownKeys(b)]).forEach((key) =>
      diffPaths(a[key], b[key], trail.concat(key), out)
    );
    return out;
  }
  out.push(trail.join('.'));
  return out;
};

const REQUEST_TIME_MS = new Date('2026-11-01T02:03:04.250Z').getTime();
const REQUEST_TIME_ISO = new Date(REQUEST_TIME_MS).toISOString();

/**
 * 把系统时间钉死（而不是「连点两次去赌同一秒」）。
 * 原写法在秒边界余量为零（凌晨实测出现过假红），而这条闸判的恰恰是时间语义：
 * 时间必须**确定**——冻结 + 显式推进一秒，既没有假红，也把「跨秒平移多少」变成可现算的断言。
 */
const withFrozenClock = (at, fn) => {
  jest.useFakeTimers({ now: at });
  try {
    return fn();
  } finally {
    jest.useRealTimers();
  }
};

/** 递归取某键的值（用于定位请求时刻字段，避免把路径写死在用例里） */
const valuesOfKey = (node, key, out) => {
  if (Array.isArray(node)) node.forEach((item) => valuesOfKey(item, key, out));
  else if (node && typeof node === 'object') {
    Object.entries(node).forEach(([k, v]) => (k === key ? out.push(v) : valuesOfKey(v, key, out)));
  }
  return out;
};

const stampsOf = (node) =>
  (JSON.stringify(node).match(/"\d{4}-\d{2}-\d{2}T[\d:.]+Z"/g) || []).map((raw) =>
    raw.slice(1, -1)
  );

test('合成表里每个 *OffsetMin 都是有限数字（E5 台账）', () => {
  const found = [
    ...collectOffsets(decoyData, ['honeypotDecoyData'], []),
    ...collectOffsets(decoyFiles, ['honeypotDecoyFiles'], []),
  ];
  expect(found.length).toBeGreaterThan(0);
  const bad = found.filter(
    (item) => !(typeof item.value === 'number' && Number.isFinite(item.value))
  );
  expect(bad).toEqual([]);
});

test('materializeRow：非有限数字的回偏移一律给 null，不折成此刻也不抛（E5）', () => {
  const out = decoy.materializeRow({
    aOffsetMin: 42,
    bOffsetMin: null,
    cOffsetMin: undefined,
    dOffsetMin: NaN,
    eOffsetMin: '12',
    fOffsetMin: 0,
    g: null,
  });
  const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
  expect(out.a).toMatch(iso);
  expect(out.f).toMatch(iso);
  expect(out.b).toBeNull();
  expect(out.c).toBeNull();
  expect(out.d).toBeNull();
  expect(out.e).toBeNull();
  expect(out.g).toBeNull();
  expect(ownKeys(out)).not.toContain('cOffsetMin');
});

test('行时钟量化到秒：秒级新鲜（与此刻相差 < 1s），且同一秒内同一请求逐字相同（E3）', () => {
  const clock = decoy.rowClockNow().getTime();
  expect(clock % SECOND_MS).toBe(0);
  // 新鲜度是**需求**（不是副产品）：行时间必须贴着此刻，否则最近的合成行会显示成整点/昨天
  expect(Math.abs(clock - Date.now())).toBeLessThan(SECOND_MS);
  const sample = { method: 'GET', path: '/api/users', query: {} };
  const one = withFrozenClock(REQUEST_TIME_MS, () =>
    JSON.stringify(decoy.resolveDecoyPayload(sample))
  );
  const two = withFrozenClock(REQUEST_TIME_MS, () =>
    JSON.stringify(decoy.resolveDecoyPayload(sample))
  );
  expect(two).toBe(one);
});

/**
 * 这条盯的是**两类字段串台**：行时间列量化到秒（毫秒位恒 .000，跨秒整体平移整数秒），
 * 而 `asOf`/`scannedAt` 是**真·请求时刻**（毫秒必须在位）。复验实测：把它们改喂行时钟后，
 * 原来的「两次调用逐字相同」与「只允许请求时刻字段不同」两条**都照样绿**（冻结后两边一样）——
 * 所以必须直接断言「请求时刻字段 == 冻结的请求时刻（含毫秒）」这一条。
 */
test('请求时刻字段保留毫秒，行时间列量化到秒：两类字段不得串台（E3）', () => {
  const rows = [];
  const request = [];
  withFrozenClock(REQUEST_TIME_MS, () => {
    AGGREGATE_ENDPOINTS.forEach((endpoint) => {
      const payload = resolveAggregatePayload({
        method: 'GET',
        path: endpoint.path,
        query: {},
      });
      if (!payload || payload.kind === 'codeError') return;
      REQUEST_TIME_KEYS.forEach((key) => {
        valuesOfKey(payload.data, key, request).forEach((value) => {
          expect(value).toBe(REQUEST_TIME_ISO);
        });
      });
      stampsOf(payload.data)
        .filter((iso) => iso !== REQUEST_TIME_ISO)
        .forEach((iso) => rows.push(iso));
    });
  });
  expect(request.length).toBeGreaterThan(0); // 端点集里确实有请求时刻字段，否则本判据是空转
  expect(rows.length).toBeGreaterThan(0);
  // 除请求时刻字段外，任何带毫秒的时间戳都意味着请求时钟泄漏到了行时间列（.000Z 才是量化到秒的形状）
  expect(rows.filter((iso) => !iso.endsWith('.000Z'))).toEqual([]);
});

test('跨秒只按整秒平移：行时间列整体 +1000ms，不出现毫秒级抖动（E3）', () => {
  const target = { method: 'GET', path: '/api/devices/reminders', query: {} };
  const at = (ms) =>
    withFrozenClock(ms, () =>
      stampsOf(resolveAggregatePayload(target).data).filter((iso) => iso.endsWith('.000Z'))
    );
  const before = at(REQUEST_TIME_MS);
  const after = at(REQUEST_TIME_MS + SECOND_MS);
  expect(before.length).toBeGreaterThan(0);
  expect(after.map((iso) => Date.parse(iso) - SECOND_MS)).toEqual(
    before.map((iso) => Date.parse(iso))
  );
});

test('asOf/scannedAt 只许由请求时刻供给（NON_DERIVABLE）：改喂行时钟即红（E3）', () => {
  const lines = AGGREGATES_SRC.split('\n').filter((line) => /(asOf|scannedAt)\s*:/.test(line));
  expect(lines.length).toBeGreaterThan(0);
  expect(lines.filter((line) => !/requestNow/.test(line))).toEqual([]);
});

/**
 * 列表面必须共享同一个行时钟基准。
 * 这一条盯的是一个**具体写法**——`.map(materializeRow)`：materializeRow 现在是两参（row, at），
 * 直接把函数引用交给 map 会把**下标**当成基准，第 0 行落到 1970（且形态完全合法、不报错）。
 * 判据用「离此刻 400 天以内」这种粗界：所有合成偏移都在天/月量级，1970 与任何真实偏移都不会撞上。
 */
test('列表/明细面的行时间都贴近此刻：`.map(materializeRow)` 这类下标当基准的写法会立刻被抓住（E3）', () => {
  const isoStamp = /"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"/g;
  const now = Date.now();
  for (const target of ['/api/alarms', '/api/inspections', '/api/devices']) {
    const payload = decoy.resolveDecoyPayload({ method: 'GET', path: target });
    expect(payload.data.length).toBeGreaterThan(0);
    const stamps = JSON.stringify(payload.data).match(isoStamp) || [];
    expect(stamps.length).toBeGreaterThan(0);
    const far = stamps.map((raw) => raw.slice(1, -1)).filter((iso) => !/^20\d\d-/.test(iso));
    expect(far).toEqual([]);
    const near = stamps
      .map((raw) => Date.parse(raw.slice(1, -1)))
      .filter((at) => Math.abs(now - at) <= 45 * 24 * 60 * 60 * 1000);
    expect(near.length).toBeGreaterThan(0);
  }
});

test('聚合面的行时间不随请求时刻平移，只允许请求时刻字段不同（E3）', () => {
  const input = { method: 'GET', path: '/api/users/stats', query: {} };
  const snapshot = () => JSON.parse(JSON.stringify(resolveAggregatePayload(input)));
  const a = withFrozenClock(REQUEST_TIME_MS, snapshot);
  const b = withFrozenClock(REQUEST_TIME_MS, snapshot);
  const moved = diffPaths(a, b, [], []).filter(
    (item) => !REQUEST_TIME_KEYS.includes(item.split('.').pop())
  );
  expect(moved).toEqual([]);
});

test('聚合引用的字段名在合成表里双向成立（E8）', () => {
  const counts = callCounts();
  expect(matchesOf(TALLY_RE).length).toBe(counts.tally);
  expect(matchesOf(WINDOW_RE).length).toBe(counts.windowRowsOf);
  const fields = referencedFields();
  const tables = aggregateTables();
  expect(fields.length).toBeGreaterThan(0);
  expect(tables.length).toBeGreaterThan(0);
  const orphan = fields.filter(
    (field) => !tables.some((table) => table.rows.some((row) => ownKeys(row).includes(field)))
  );
  expect(orphan).toEqual([]);
  // tally 字段只做「存在」判据，不做「每行齐全」：真实 schema 里 result 只在 completed 巡检行上有值，
  // 按行齐全会把合法差异判红。真正必须每行都齐的是**时间列**——windowRowsOf 拿它当过滤键，缺一列就静默丢行。
  const missingTimes = [];
  windowRefs().forEach((ref) => {
    (decoyData[ref.table] || []).forEach((row, index) => {
      const value = row[ref.field];
      if (!(typeof value === 'number' && Number.isFinite(value))) {
        missingTimes.push(ref.table + '[' + index + '].' + ref.field);
      }
    });
  });
  expect(missingTimes).toEqual([]);
});

test('格式错与区间逆序同时出现：格式判在前（E1 判序，复验 M8 之前无判据设防）', () => {
  // 真实控制器是 isValidDateParam → DATE_PARAM_INVALID，然后才 isDateRangeReversed → DATE_RANGE_INVALID。
  // 两个错同时出现时必须回前者：判序倒置（把区间判断挪到格式之前）此前是全绿的。
  [
    ['/api/alarms/stats', '9999'],
    ['/api/inspections/stats', '9999'],
  ].forEach(([target, bad]) => {
    const out = resolveAggregatePayload({
      method: 'GET',
      path: target,
      query: { startDate: bad, endDate: '2020-01-01' },
    });
    expect(out).toEqual({ kind: 'codeError', code: 'DATE_PARAM_INVALID' });
  });
});

test('tally 撞缺失字段给 _id:null（不是 undefined，键也不被 JSON 丢掉）（E5/E8 根因）', () => {
  const { tally } = require('../../constants/honeypotDecoyShape');
  const buckets = tally([{ a: 1 }, { b: 2 }, { a: 1 }], 'a');
  // 缺字段的行必须**入桶**且 _id 为 null：真实 Mongo $group 就是 _id:null，
  // undefined 键会让 JSON.stringify 把 _id 整个丢掉，且桶数多一个
  expect(buckets.length).toBe(2);
  expect(buckets).toEqual(
    expect.arrayContaining([
      { _id: 1, count: 2 },
      { _id: null, count: 1 },
    ])
  );
  const missing = buckets.filter((bucket) => bucket._id === null);
  expect(ownKeys(missing[0])).toContain('_id');
  expect(JSON.parse(JSON.stringify(missing[0]))).toEqual({ _id: null, count: 1 });
});

/** 被扫调用名「除定义/解构那一处外，只准以 `name(` 形式出现」；别名（`const tallyOf = tally;`）会让字段扫描与调用计数**一起缩水**、互相掩护 */
const bareNamesOf = (name) => {
  const re = new RegExp('\\b' + name + '\\b', 'g');
  return [...AGGREGATES_SRC.matchAll(re)].filter(
    (match) => AGGREGATES_SRC[match.index + name.length] !== '('
  ).length;
};

test('被扫调用名不得别名或转手：只准以调用形式出现（E8 有牙，复验 M7b 之前的旁路）', () => {
  expect(callCounts().tally).toBeGreaterThan(0);
  expect(bareNamesOf('tally')).toBe(1); // 只允许 require 解构那一处
  expect(bareNamesOf('windowRowsOf')).toBe(1); // 只允许本模块的定义处
});

test('参数非法的拒绝路径与真实控制器同码（E1）', () => {
  const cases = [
    { path: '/api/alarms/stats', controller: 'src/controllers/alarmController.js' },
    { path: '/api/inspections/stats', controller: 'src/controllers/inspectionController.js' },
  ];
  cases.forEach(({ path: target, controller }) => {
    const src = readCode(controller);
    const bad = resolveAggregatePayload({
      method: 'GET',
      path: target,
      query: { startDate: 'zzz' },
    });
    expect(bad && bad.kind).toBe('codeError');
    // 引号归一：控制器一律单引号，JSON.stringify 产出双引号 ⇒ 旧写法在"代码其实正确"时也会红
    const callOf = (code) =>
      new RegExp('codeError\\(res,\\s*[\\u0022\\u0027]' + code + '[\\u0022\\u0027]\\)');
    expect(src).toMatch(callOf(bad.code));
    const reversed = resolveAggregatePayload({
      method: 'GET',
      path: target,
      query: { startDate: '2026-11-02', endDate: '2026-11-01' },
    });
    expect(reversed && reversed.kind).toBe('codeError');
    expect(reversed.code).toBe('DATE_RANGE_INVALID');
    expect(src).toMatch(callOf(reversed.code));
  });
});
