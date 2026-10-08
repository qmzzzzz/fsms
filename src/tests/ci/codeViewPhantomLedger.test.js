/**
 * 代码视图零幻影（第 10 把元门禁）
 *
 * 【这条闸在防什么】
 * 文本型闸门一律跑在 `src/tests/helpers/jsCodeOnly.js` 的「只剩代码」视图上。只要那个视图
 * 会把**真实代码行**整行抹成空白，判据就出现"注释看得见、代码看不见"的盲区，假绿可以双向
 * 制造，而且不需要任何人在注释里写反例。历史形状是"先全局剥块注释、后按行剥行注释"：
 * 一行 `//` 注释里只要出现块的起始两字符（本仓真实写法是给 glob 打比方，例如
 * `// 口径同 scripts/*.js 的维护脚本`），从这个起始到**下一个**真正的块结尾之间的代码会被整段吞掉。
 * helper 已在第 25 轮改成单遍状态机；本闸从"记账"改成"根治后的零命中断言"。
 *
 * 【台账去哪了】
 * 修复前它是 10 个文件 / 308 行的豁免台账（当时口径还是错的，见下）。修复后实测命中 0，
 * 所以**不再设豁免集**：新出现的任一命中一律红。要消红只有两条路 —— 要么 helper 又坏了（修 helper），
 * 要么那行确实是散文却没按本仓约定写成 ` * ` 续行（给注释补星号）。不设"第三条路"（登记豁免），
 * 因为豁免集会把闸的面积悄悄缩小，而面积就是闸的全部价值（第 5 族）。
 *
 * 【旧口径为什么不可信（本轮重测的结论）】
 * 旧采集器问的是"这一行的**文本**在视图里还出现吗"，两个方向都会错：
 *  1) 假阳 —— 一行代码带行尾注释，视图把注释抹了、代码还在，整行文本对不上 ⇒ 报"被吞"。
 *     我把 `src/middleware/rateLimit.js` 报成 10 行，逐下标真值是 1 行（只有定义那行真被吞），
 *     其余 9 行是"尾注释被正确抹掉"的普通代码行；
 *  2) 假阴 —— 同样文本在文件别处出现，includes 命中，真被吞的那行就隐身。
 * 新判据只问一件事：**同一行号上原始行有内容、视图行全是空白**。它与视图怎么产生无关，
 * 所以能拿去对手写的坏视图做正/负对照（见"采集器带电"那条腿）。
 *
 * 【实测基数】（判据=本文件的 naive 口径，口径改动必须同时重报两侧基数）
 *  范围 src + scripts + e2e + migrations，763 个 .js / 190321 行：
 *  修复前视图抹掉 431 行真实代码，修复后 0 行。
 *
 * 【已知边界】块注释续行按本仓约定以 ` * ` 开头，这类行不算代码；没打星号的散文行会被
 * 当成代码行报红。这是**有意的**：宁可让文档格式挨一下，也不要在判据里内嵌第二套"什么算注释"。
 */

const fs = require('fs');
const path = require('path');

const { jsCodeOnly, jsCodeOnlyKeepingLines } = require('../helpers/jsCodeOnly');

const ROOT = path.resolve(__dirname, '../../..');
const SCAN_DIRS = ['src', 'scripts', 'e2e', 'migrations'];
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage', 'build']);

/** 注释续行：行首只有空白，再跟 两个斜杠 / 星号 / 块起始 —— 这些行不参与"代码被抹"判定 */
const COMMENT_CONT = /^(\/\/|\*|\/\*)/;

const lines = (s) => String(s).replace(/\r\n/g, '\n').split('\n');

/**
 * 采集器：纯函数，只吃 (原始源码, 视图) 两个字符串。
 * 刻意不接受文件名、不自己求视图 —— 视图从外面传进来，才能拿手写的坏视图给它做对照，
 * 而不必在本闸里内嵌第二份注释剥离（那正是本闸要防的东西）。
 */
const erasedLines = (raw, viewText) => {
  const L = lines(raw);
  const V = lines(viewText);
  const out = [];
  for (let i = 0; i < L.length; i += 1) {
    const t = L[i].trim();
    if (!t || COMMENT_CONT.test(t)) continue;
    const v = V[i] === undefined ? '' : V[i];
    if (v.trim() === '') out.push(i + 1);
  }
  return out;
};

/** 把指定 1 基行号整行抹成等长空白，其余原样 —— 造"坏视图"用的夹具，不是注释剥离 */
const blankAt = (raw, oneBaseIdxs) => {
  const set = new Set(oneBaseIdxs);
  return lines(raw)
    .map((l, i) => (set.has(i + 1) ? ' '.repeat(l.length) : l))
    .join('\n');
};

const jsFiles = (relDir) => {
  const abs = path.join(ROOT, relDir);
  if (!fs.existsSync(abs)) return [];
  const out = [];
  for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    // 一律用 `/` 拼相对路径：Windows 上 path.join 给的是 `\`，而全仓其它闸的报告口径是 `/`
    const child = `${relDir}/${e.name}`;
    if (e.isDirectory()) out.push(...jsFiles(child));
    else if (e.name.endsWith('.js')) out.push(child);
  }
  return out;
};

/**
 * 一次扫描同时产出三类事实：命中行（判据面积）、视图是否真的动了手（掩码率）、
 * 以及"整行注释会被删掉"这条路是否还活着。后两项是第一条腿的地面：
 * 采集器只要采不到文件、或 helper 退化成"原样返回"，命中数就天然是 0，全绿毫无意义。
 */
const scan = () => {
  const rows = [];
  let files = 0;
  let masked = 0;
  let dropped = 0;
  for (const d of SCAN_DIRS) {
    for (const rel of jsFiles(d)) {
      files += 1;
      const raw = fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');
      const keep = jsCodeOnlyKeepingLines(raw);
      if (keep !== raw) masked += 1;
      if (lines(jsCodeOnly(raw)).length < lines(keep).length) dropped += 1;
      const hit = erasedLines(raw, keep);
      if (hit.length) {
        const L = lines(raw);
        rows.push({ rel, lines: hit, texts: hit.map((n) => L[n - 1].trim()) });
      }
    }
  }
  return { rows, files, masked, dropped };
};

const REMEDY =
  '（两种可能：helper 又回到"先剥块后剥行"的顺序 ⇒ 修 helper；或这行是块注释里没打星号的散文 ⇒ 按本仓约定写成 " * " 续行）';

test('视图零幻影｜没有任何真实代码行从「只剩代码」视图里消失', () => {
  const { rows } = scan();
  expect(
    rows.map(
      (r) => `${r.rel} 第 ${r.lines.join(',')} 行在视图里整行空白：${r.texts.join(' ⏎ ')} ${REMEDY}`
    )
  ).toEqual([]);
});

test('采集器带电｜同一判据对手写的坏视图必须逐行命中，对散文行必须放过', () => {
  const RAW = [
    'const A = 1; // 说明：口径同 scripts/*.js 的维护脚本', // 1：历史上的缺陷触发行
    'const ERASED = 2;', //                     2：坏视图里被吞掉的代码
    'function tail() {', //                     3
    '  return 3;', //                           4：坏视图里被吞掉的代码
    '}', //                                    5
    '/* 真块注释', //                           6
    ' *  块内散文（按约定打了星号）', //         7：注释续行 ⇒ 永远不该报
    ' */', //                                  8
    'const B = 9;', //                           9
  ].join('\n');

  // 正对照：把 2、4、7 三行抹成空白，判据必须报出 2 和 4，且不报 7（星号续行）
  expect(erasedLines(RAW, blankAt(RAW, [2, 4, 7]))).toEqual([2, 4]);
  // 负对照：视图与原文一致 ⇒ 零命中（否则"零幻影"那条腿会被采集器自己制造）
  expect(erasedLines(RAW, RAW)).toEqual([]);
  // 面积对照：整片抹光 ⇒ 报出的必须是全部代码行，且一条不少
  expect(erasedLines(RAW, blankAt(RAW, [1, 2, 3, 4, 5, 6, 7, 8, 9]))).toEqual([1, 2, 3, 4, 5, 9]);
});

test('指纹｜现网 helper 保留缺陷形状里的真代码，同时照抹真块注释与行注释', () => {
  const DEFECT = [
    '// 说明：口径同 scripts/*.js 的维护脚本，别处不要重复实现（sentinel_line_note）',
    'const MUST_SURVIVE = sentinel_keep_me;',
    '/* 真块',
    '   sentinel_block_body',
    '*/',
    'const ALSO_SURVIVES = sentinel_keep_too;',
  ].join('\n');
  const v = jsCodeOnlyKeepingLines(DEFECT);
  expect(v).toContain('MUST_SURVIVE');
  expect(v).toContain('ALSO_SURVIVES');
  // 少抹不等于不抹：真块内容与行注释仍要照抹
  expect(v).not.toContain('sentinel_block_body');
  expect(v).not.toContain('sentinel_line_note');
});

test('判据归一处｜视图一律来自共享 helper，本闸不自带第二份注释剥离', () => {
  const src = fs.readFileSync(__filename, 'utf8');
  // 只有一个 helper 取用点（数 require 语句本身，不数文档里提到的文件名），且没有本地同名实现
  expect((src.match(/require\('\.\.\/helpers\/jsCodeOnly'\)/g) || []).length).toBe(1);
  expect(src).not.toMatch(
    /function\s+(maskComments|stripComments|view|jsCodeOnly|jsCodeOnlyKeepingLines)\s*\(/
  );
  // 采集器必须是纯函数：它的源码里没有 helper，只有传进来的视图
  const body = Function.prototype.toString.call(erasedLines);
  expect(body).toContain('viewText');
  expect(body).not.toContain('jsCodeOnly');
  expect(body).not.toContain('readFileSync');
});

test('扫描面地面｜目录存在、文件数与掩码率都不塌', () => {
  for (const d of SCAN_DIRS) expect(fs.existsSync(path.join(ROOT, d))).toBe(true);
  const { files, masked, dropped } = scan();
  // 下界取自实测（763 / 758 / 715）留足余量：允许并行会话删并文件，但不允许扫描面塌成空集
  expect(files).toBeGreaterThanOrEqual(700);
  expect(masked).toBeGreaterThanOrEqual(650);
  expect(dropped).toBeGreaterThanOrEqual(600);
});
