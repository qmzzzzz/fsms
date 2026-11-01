'use strict';

/**
 * 审计计数断言 × auditBuffer 启动 的配对闸（第 23 轮 Led 指定新增）
 *
 * ## 要防的机制缺口（不是"某个用例写错了"，而是整类假绿）
 *
 * 全局审计中间件把行交给 `auditBuffer.push`，而缓冲**默认不启动**：jest 的
 * globalSetup / setupFiles 都不 start（实测 766 个用例文件里只有 21 个自己 start）。
 * 不启动时 push 出去的行只留在内存里，一条都不落库。于是
 *
 *   expect(await AuditLog.countDocuments({ action: 'hack' })).toBe(0)
 *
 * 永远为真——不是"这次没写审计"，而是"缓冲根本没开"。这类断言自带免检：
 * 它随代码一起进 CI，红了也不会有人回头看，因为它永远不红。
 *
 * ## 为什么判据只能是静态的
 *
 * 运行时无法区分"库里真没有"与"缓冲没开"——两种情形在数据库里长得一模一样。
 * 唯一可靠的证据是源码形态：这个文件既驱动 HTTP（所以全局中间件真的会执行到），
 * 又对审计集合的查询结果做断言，却没有任何"让缓冲动起来"的调用。
 * 判据本体放在 scripts/auditCountAssertionScan.js（同一份口径同时给用例与报告用，
 * 不出现"测试自证一套、判据另一套"）。
 *
 * ## 三条判据
 *
 *   ① 空洞断言硬红（不可豁免）：驱动 HTTP + 对 AuditLog 查询结果做"空/零也满足"的断言
 *      + 没有任何让缓冲动起来的调用 ⇒ 红。空洞断言是唯一能永久假绿的一类，
 *      正断言（toBe(1)/toHaveLength(1)）在行缺失时会大声红，不在本条管辖内。
 *   ② 其余审计断言必须显式声明：命中"驱动 HTTP + 断言审计集合结果 + 没有控制"的文件
 *      必须出现在下面的台账里，且台账的"理由类型"要能被机器复核（verifyLedgerEntry）。
 *      换句话说：要么让缓冲动起来，要么把"断言对象不是中间件产物"这句话落到可核的证据上。
 *   ③ 前提锚点：全局测试装配不得自行启动缓冲——本闸①②的存在前提就是这个。
 *
 * ## 自证（每条判据都有能变红/变绿的反向对照）
 *
 *   · 合成变异："不 start 却断言中间件行"的极小用例喂给同一判据 ⇒ 必须 suspect；
 *   · 反向对照：真树上 20+ 个自己 start()/flush() 的用例一律不得被判红（判据不是恒拒）；
 *   · 注释对照：注释里的 start() 不算控制、注释里的零断言不算断言；
 *   · 台账反向对照：一条 kind 与文件事实不符的台账必须被复核判红。
 */

const fs = require('fs');
const path = require('path');

const scan = require('../../../scripts/auditCountAssertionScan');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const TESTS_DIR = path.join(ROOT, 'src', 'tests');

// 判据对**字符串内容不剥离**（注释才剥），所以本文件里凡是"调用文本"一律运行时拼出来：
// 否则闸会把自己也算成"控制过缓冲"，自检用例就没意义了（见末尾自检）。
const START_CALL = 'auditBuffer' + '.start()';
const FLUSH_CALL = 'await auditBuffer' + '.flush()';

/** 判红时的补救出路：失败信息里必须给出来，否则这个红只能靠猜 */
const REMEDY =
  '补救二选一：① 在用例里显式让缓冲动起来（' +
  START_CALL +
  ' 之后等一次 flush，或直接 ' +
  FLUSH_CALL +
  '）；② 断言对象确实不是中间件产物时，把它登记进 UNCONTROLLED_LEDGER' +
  ' 并写明可被 verifyLedgerEntry 复核的证据。';

/**
 * 已声明的"不受缓冲控制但安全"的用例文件。
 *
 * 每个条目都必须能过 verifyLedgerEntry：理由类型对应一条机器复核，
 * 复核不通过 = 这条声明没有证据 = 本闸判红（清单不能靠自述变宽）。
 * 只允许 kind = direct-fixture-scope / direct-write-under-test / filtered-scope-excludes-middleware 三种；
 * 空洞断言（zeroAssertions > 0）不进台账，一律硬红。
 */
const UNCONTROLLED_LEDGER = [
  {
    file: 'src/tests/controllers/auditExportUsernamePrefixParity.test.js',
    kind: 'direct-fixture-scope',
    reason:
      '断言对象是本文件自己种的行，不是中间件产物：:145 起用 AuditLog.create 造 5 条用户名，' +
      '4 处断言查询全部被 FILTER（kq7tadm 前缀）收窄；导出请求产生的中间件行带的是操作者' +
      ' kq7operator<stamp>，永远匹配不到该前缀 ⇒ 计数与缓冲是否启动无关。',
  },
  {
    file: 'src/tests/controllers/ipListValidationAndConflictGuards.test.js',
    kind: 'direct-write-under-test',
    reason:
      '断言对象是直写产物：src/services/ipListService.js:89-91 recordPrivilegeEscalation →' +
      ' AuditLog.record(doc) → create，不经 auditBuffer.push；文件里的 push 观测子只用来断言' +
      '「控制器已手动留痕时全局派生的那条不得再双写」。',
  },
  {
    file: 'src/tests/controllers/permissionUserValidationGuards.test.js',
    kind: 'direct-write-under-test',
    reason:
      '断言对象是直写产物：src/controllers/userController/delete.js:94 recordDurably →' +
      ' AuditLog.create；同一控制器 :113 置 res.locals.skipGlobalAudit = true，全局中间件对' +
      '这条操作根本不写 ⇒ 缓冲状态与该断言无关。',
  },
  {
    file: 'src/tests/routes/forensicRoutesContract.test.js',
    kind: 'filtered-scope-excludes-middleware',
    reason:
      '断言对象被过滤条件收窄到中间件**不可能**产出的取值：查询用 riskFactors $in 两个字面' +
      '（full_range_cidr_pool_ban_union_prewrite / _rollback），而这两个字面在整个生产代码里' +
      '只有 src/controllers/forensicController.js:126 产出，其写入链是 tracePoolBanUnionRollback →' +
      ' ipListService.recordPrivilegeEscalation → AuditLog.record（直写，不经 auditBuffer.push）。' +
      '中间件行即使被缓冲吞掉也不进该过滤器 ⇒ 计数与缓冲是否启动无关。',
  },
];

/** 遍历测试树收集 *.test.js（跳过 node_modules / coverage） */
function testFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'coverage') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.test.js')) out.push(full);
    }
  };
  walk(TESTS_DIR);
  return out;
}

const relOf = (file) => path.relative(ROOT, file).split(path.sep).join('/');

/** 真树快照：每条都带仓库相对路径与单文件判定结果 */
const SCAN = testFiles().map((file) => ({
  file,
  rel: relOf(file),
  result: scan.analyzeFile(fs.readFileSync(file, 'utf8')),
}));

/**
 * 台账声明的机器复核（纯函数：给定 code 与单文件判定结果即可判），返回缺陷列表。
 * 复核点是"声明类型"对应的、能从文件本身读出来的事实——不是把理由念一遍。
 * @param {{file:string, kind:string, reason:string}} entry
 * @param {string} code 已剥注释的源码
 * @param {object} state scan.analyzeFile 的结果
 * @returns {string[]}
 */
/** 断言实参里的字符串字面（过滤器取值） */
function literalsIn(args) {
  return [...String(args || '').matchAll(/'([^']{4,})'/g)].map((m) => m[1]);
}

/**
 * 被断言查询的过滤条件文本：实参可能直接写得**名字**（`countDocuments(filter)`），
 * 那时把同文件里 `const filter = {...}` 的定义体取出来——判据要看的是过滤器内容，
 * 不是变量名。
 */
function filterTextOf(args, code) {
  const text = String(args || '');
  const bare = /^([A-Za-z_$][\w$]*)$/.exec(text.trim());
  if (!bare) return text;
  const def = new RegExp(
    '(?:const|let|var)\\s+' + bare[1] + '\\s*=\\s*(\\{[\\s\\S]*?\\})\\s*;'
  ).exec(code);
  return def ? def[1] : text;
}

/** 断言实参 + 其过滤器定义体里的字符串字面（过滤器取值） */
function filterLiterals(state, code) {
  const out = [];
  for (const site of state.sites) out.push(...literalsIn(filterTextOf(site.args, code)));
  return [...new Set(out)];
}

/** 直写审计的调用面（`AuditLog.record` 或服务层直写包装） */
const DIRECT_WRITE_RE =
  /(?:AuditLog\s*\.\s*(?:record|create|insertMany)\s*\(|\brecordPrivilegeEscalation\s*\(|\brecordDurably\s*\(|\brecordSensitiveAction\s*\()/;

/** 缓冲写入面：某文件是否把审计行推进 auditBuffer */
const BUFFER_WRITE_RE = /\bauditBuffer\s*\.\s*push\s*\(/;

/**
 * 生产代码（src/**，排除测试树）里含某过滤字面量的文件，按"写入面"分类。
 *
 * 台账要证的不是"这个字面量存在"，而是**产这个取值的写入面不经缓冲**——
 * 所以分别收 direct（直写调用面）与 buffered（auditBuffer.push）两份名单：
 * 只要有任何 buffered 生产者，那条声明的"排除中间件行"就没有证据。
 */
function writersOf(literal) {
  const direct = [];
  const buffered = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'coverage') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.js')) {
        const src = fs.readFileSync(full, 'utf8');
        if (!src.includes(literal)) continue;
        const code = scan.stripComments(src);
        if (BUFFER_WRITE_RE.test(code)) buffered.push(relOf(full));
        if (DIRECT_WRITE_RE.test(code)) direct.push(relOf(full));
      }
    }
  };
  walk(path.join(ROOT, 'src'));
  return { direct, buffered };
}

/** 被断言查询里"整集合范围"的那些（跟随同文件常量时把定义体取出来看） */
function unscopedSites(state, code, followConst) {
  return state.sites.filter(
    (s) =>
      !/[A-Za-z_$][\w$]*\s*:|\$regex|new RegExp/.test(
        followConst ? filterTextOf(s.args, code) : s.args || ''
      )
  );
}

/** 整集合范围的缺陷描述（空数组 = 无缺陷） */
function unscopedDefects(entry, sites) {
  if (sites.length === 0) return [];
  return [
    entry.file +
      '：kind 要求每个被断言的查询都被过滤条件收窄，但 L' +
      sites.map((s) => s.line).join('/L') +
      ' 的实参是整集合范围',
  ];
}

/** 过滤字面取值的缺陷描述：必须各有"不经缓冲"的生产写入面 */
function literalDefects(entry, literals) {
  const defects = [];
  if (literals.length === 0) {
    defects.push(entry.file + '：过滤器里没有任何字符串字面，无法复核"排除中间件行"');
  }
  for (const literal of literals) {
    const { direct, buffered } = writersOf(literal);
    if (direct.length === 0) {
      defects.push(entry.file + '：字面 ' + literal + ' 在生产代码里找不到直写它的文件，无法复核');
    }
    if (buffered.length > 0) {
      defects.push(
        entry.file +
          '：字面 ' +
          literal +
          ' 也被经缓冲的写入面产出（' +
          buffered.join('、') +
          '）⇒ 不能断言"该过滤器排除中间件行"'
      );
    }
  }
  return defects;
}

function verifyLedgerFacts(entry, code, state) {
  const defects = [];
  if (state.zeroAssertions > 0) {
    defects.push(
      entry.file +
        '：含空洞断言 ' +
        state.zeroAssertions +
        ' 处——这一类的补救只有"让缓冲动起来"，不得登记豁免'
    );
  }
  if (entry.kind === 'direct-fixture-scope') {
    const aliases = scan.auditModelAliases(code);
    const seed =
      aliases.length > 0 &&
      new RegExp('(?:' + aliases.join('|') + ')\\s*\\.\\s*(?:create|insertMany)\\s*\\(').test(code);
    if (!seed) {
      defects.push(
        entry.file + '：kind=direct-fixture-scope 却看不到本文件自己 create/insertMany 审计行'
      );
    }
    defects.push(...unscopedDefects(entry, unscopedSites(state, code, false)));
  } else if (entry.kind === 'direct-write-under-test') {
    if (!scan.PUSH_OBSERVED_RE.test(code)) {
      defects.push(
        entry.file + '：kind=direct-write-under-test 却看不到对 auditBuffer.push 的观测（spyOn）'
      );
    }
    if (!/src\/[\w./-]+\.js/.test(entry.reason || '')) {
      defects.push(
        entry.file + '：理由必须点名直写的生产代码文件（形如 src/… .js），否则这条声明无法复核'
      );
    }
  } else if (entry.kind === 'filtered-scope-excludes-middleware') {
    // 事实①：每个被断言的查询都被过滤器收窄（整集合范围的计数没法排除中间件行）
    defects.push(...unscopedDefects(entry, unscopedSites(state, code, true)));
    // 事实②：过滤器里的字面取值必须由**不经缓冲**的写入面产出——否则该取值可能来自
    // 中间件行，"过滤掉了中间件"这句话就没有证据。
    defects.push(...literalDefects(entry, filterLiterals(state, code)));
    if (!/src\/[\w./-]+\.js/.test(entry.reason || '')) {
      defects.push(entry.file + '：理由必须点名产该取值的生产代码文件（形如 src/… .js）');
    }
  } else {
    defects.push(entry.file + '：未知 kind=' + String(entry.kind));
  }
  if ((entry.reason || '').length < 60) {
    defects.push(entry.file + '：理由过短（<60 字），不足以复核');
  }
  return defects;
}

/**
 * 读文件后复核一条台账声明：空数组 = 这条声明有证据。
 * @param {{file:string, kind:string, reason:string}} entry
 * @returns {string[]}
 */
function verifyLedgerEntry(entry) {
  const abs = path.join(ROOT, entry.file.split('/').join(path.sep));
  if (!fs.existsSync(abs)) return [entry.file + '：文件不存在（台账不得指向幽灵文件）'];
  const source = fs.readFileSync(abs, 'utf8');
  return verifyLedgerFacts(entry, scan.stripComments(source), scan.analyzeFile(source));
}

/**
 * 合成一份极小用例源码。
 * 本文件**刻意不写** 'models' + '/' + 'AuditLog' 这种字面量、不写裸的 require('supertest')，
 * 也不写调用文本本身，而是运行时拼出来——判据对字符串内容不剥离，写实了闸会把自己也算成
 * "控制过缓冲"（末尾自检用例钉住这一点）。
 */
const MODELS_SEG = 'models';
const modelRequire = (name) =>
  'const ' + name + " = require('../../" + MODELS_SEG + '/' + name + "');";
const requestRequire = () => "const request = require('" + 'supert' + 'est' + "');";

const fixture = (opts = {}) => {
  const lines = [modelRequire('AuditLog'), requestRequire(), 'const app = {};'];
  if (opts.commentedStart) lines.push('// ' + START_CALL);
  if (opts.start) lines.push("const auditBuffer = require('../../services/auditBuffer');");
  lines.push("test('x', async () => {");
  if (opts.start) lines.push('  ' + START_CALL);
  if (opts.flush) lines.push('  ' + FLUSH_CALL);
  if (opts.commentedAssert) {
    lines.push('  // expect(await AuditLog.countDocuments({ action: "x" })).toBe(0);');
  } else {
    lines.push('  const n = await AuditLog.countDocuments({ action: "x" });');
    lines.push(opts.zero ? '  expect(n).toBe(0);' : '  expect(n).toBe(1);');
  }
  lines.push('});');
  return lines.join('\n');
};

/** 失败信息里要能看出"哪一条事实判红了"，不要只报一个 false */
const pick = (r) => ({
  httpDriven: r.httpDriven,
  asserted: r.assertedQueries,
  control: r.bufferControl,
  zero: r.zeroAssertions,
  suspect: r.suspect,
});

describe('前提自证：判据在真树上真的取到了样本', () => {
  test('规模 / 控制样本 / 断言样本都非空（否则下面几条会恒绿）', () => {
    const controlled = SCAN.filter((s) => s.result.bufferControl);
    const asserted = SCAN.filter((s) => s.result.assertedQueries > 0);
    expect({
      scanned: SCAN.length > 700,
      controlled: controlled.length >= 10,
      asserted: asserted.length >= 20,
      httpDrivenAndAsserted: SCAN.some((s) => s.result.httpDriven && s.result.assertedQueries > 0),
    }).toEqual({
      scanned: true,
      controlled: true,
      asserted: true,
      httpDrivenAndAsserted: true,
    });
  });
});

describe('判据可失败（红先证据）与反向对照', () => {
  test('不 start 却断言中间件行 ⇒ 同一判据必须 suspect', () => {
    expect(pick(scan.analyzeFile(fixture({})))).toEqual({
      httpDriven: true,
      asserted: 1,
      control: false,
      zero: 0,
      suspect: true,
    });
  });

  test('同一份文件只加一行 start()+flush() 就翻绿（判据盯的是"缓冲动没动"）', () => {
    expect(pick(scan.analyzeFile(fixture({ start: true, flush: true })))).toEqual({
      httpDriven: true,
      asserted: 1,
      control: true,
      zero: 0,
      suspect: false,
    });
  });

  test('注释对照：注释里的 start() 不算控制、注释里的断言不算断言', () => {
    expect(scan.analyzeFile(fixture({ commentedStart: true })).suspect).toBe(true);
    expect(scan.analyzeFile(fixture({ commentedAssert: true })).assertedQueries).toBe(0);
  });

  test('反向对照（真树）：自己 start()/flush() 的用例一律不得被判红', () => {
    const controlled = SCAN.filter((s) => s.result.bufferControl);
    expect(controlled.length).toBeGreaterThanOrEqual(10);
    expect(controlled.filter((s) => s.result.suspect).map((s) => s.rel)).toEqual([]);
  });

  test('反向对照（别的模型）：同名查询方法在非审计集合上不进判据', () => {
    const other = [
      modelRequire('IPBlacklist'),
      requestRequire(),
      "test('x', async () => {",
      '  const n = await IPBlacklist.countDocuments({ ip: "1.1.1.1" });',
      '  expect(n).toBe(0);',
      '});',
    ].join('\n');
    const r = scan.analyzeFile(other);
    expect({
      aliases: scan.auditModelAliases(scan.stripComments(other)),
      q: r.assertedQueries,
    }).toEqual({
      aliases: [],
      q: 0,
    });
  });
});

describe('①空洞断言硬红（不可豁免）', () => {
  test('真树：驱动 HTTP + 空洞断言 + 无控制 = 0 处（本闸要保住这个 0）', () => {
    const offenders = SCAN.filter(
      (s) => s.result.httpDriven && s.result.zeroAssertions > 0 && !s.result.bufferControl
    ).map(
      (s) =>
        s.rel +
        '：空洞断言 ' +
        s.result.zeroAssertions +
        ' 处（L' +
        s.result.sites
          .filter((x) => x.zero)
          .map((x) => x.line)
          .join('/L') +
        '）——这些断言在缓冲没开时也会通过，必须让缓冲动起来'
    );
    expect(offenders.join('\n')).toBe('');
  });

  test('合成对照：正断言改成空洞断言 ⇒ 空洞计数 1 且仍 suspect', () => {
    expect(pick(scan.analyzeFile(fixture({ zero: true })))).toEqual({
      httpDriven: true,
      asserted: 1,
      control: false,
      zero: 1,
      suspect: true,
    });
  });

  test('空洞断言不得登记豁免：复核函数必须把带零断言的声明判红', () => {
    const zeroSource = fixture({ zero: true });
    const defects = verifyLedgerFacts(
      {
        file: '<合成>',
        kind: 'direct-write-under-test',
        reason: 'src/services/x.js 直写' + 'x'.repeat(60),
      },
      scan.stripComments(zeroSource),
      scan.analyzeFile(zeroSource)
    );
    expect(defects.join(' | ')).toMatch(/含空洞断言/);
  });
});

describe('②其余审计断言必须显式声明', () => {
  test('suspect 集合与台账一一对应（新增未声明 / 台账陈旧都会报出）', () => {
    const suspects = SCAN.filter((s) => s.result.suspect)
      .map((s) => s.rel)
      .sort();
    const ledger = UNCONTROLLED_LEDGER.map((e) => e.file).sort();
    const missing = suspects.filter((f) => !ledger.includes(f));
    const stale = ledger.filter((f) => !suspects.includes(f));
    const dup = ledger.filter((f, i) => ledger.indexOf(f) !== i);
    expect(
      [
        ...missing.map((f) => '新增未声明：' + f + ' ⇒ ' + REMEDY),
        ...stale.map(
          (f) => '台账陈旧：' + f + ' 已不再是 suspect ⇒ 从台账删掉（多余的声明等于放宽判据）'
        ),
        ...dup.map((f) => '台账重复条目：' + f),
      ].join('\n')
    ).toBe('');
  });

  test('台账可复核：真实条目零缺陷，伪造声明会被同一条复核判红', () => {
    expect(UNCONTROLLED_LEDGER.flatMap((entry) => verifyLedgerEntry(entry)).join('\n')).toBe('');
    // 反向对照①：本文件不种审计行，却声称 direct-fixture-scope
    const forgedScope = {
      file: relOf(__filename),
      kind: 'direct-fixture-scope',
      reason: 'x'.repeat(80),
    };
    expect(verifyLedgerEntry(forgedScope).join(' | ')).toMatch(/direct-fixture-scope/);
    // 反向对照②：直写声明点不出生产代码文件
    const forgedNoPath = {
      file: UNCONTROLLED_LEDGER[1].file,
      kind: 'direct-write-under-test',
      reason: 'x'.repeat(80),
    };
    expect(verifyLedgerEntry(forgedNoPath).join(' | ')).toMatch(/点名直写的生产代码文件/);
    // 反向对照③：理由过短
    const forgedShort = {
      file: UNCONTROLLED_LEDGER[0].file,
      kind: 'direct-fixture-scope',
      reason: '短',
    };
    expect(verifyLedgerEntry(forgedShort).join(' | ')).toMatch(/理由过短/);
    // 反向对照④：幽灵文件
    const ghost = {
      file: 'src/tests/ci/__nonexistent__.test.js',
      kind: 'direct-fixture-scope',
      reason: 'x'.repeat(80),
    };
    expect(verifyLedgerEntry(ghost).join(' | ')).toMatch(/文件不存在/);
  });
});

describe('③前提锚点：本闸的存在前提是"缓冲默认不启动"', () => {
  test('全局测试装配（setupFiles / globalSetup）不得自行启动缓冲', () => {
    const cfg = fs.readFileSync(path.join(ROOT, 'jest.config.js'), 'utf8');
    for (const rel of ['src/tests/setup.js', 'src/tests/globalSetup.js']) {
      const wired =
        cfg.includes(rel) || cfg.includes(rel.replace('src/tests/', '<rootDir>/src/tests/'));
      expect({ rel, wired }).toEqual({ rel, wired: true });
      const code = scan.stripComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
      expect({ rel, controls: scan.CONTROL_RE.test(code) }).toEqual({ rel, controls: false });
    }
  });

  test('自检：本闸自己也在同一判据之下，不得被判红', () => {
    const self = SCAN.find((s) => s.file === __filename);
    expect(Boolean(self)).toBe(true);
    expect(pick(self.result)).toEqual({
      httpDriven: false,
      asserted: 0,
      control: false,
      zero: 0,
      suspect: false,
    });
  });
});
