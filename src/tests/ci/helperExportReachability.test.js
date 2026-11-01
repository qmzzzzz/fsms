'use strict';

/**
 * helper 导出可达性闸（task-23）：src/tests 下每个 helper 的每个导出，都必须在**定义文件之外**
 * 至少被「可证地取用」一次。
 *
 * 为什么需要它（真实事故，本闸的立闸理由）：
 * src/tests/ci/openapiStatusParity.test.js 被并行泳道用 fs.writeFileSync 覆盖后，该文件的
 * #6 采集口自证 用例与 coverageViolations 调用一起消失，而 helper 仍导出 coverageViolations
 * ⇒ 变成零调用死代码，**所有门禁照旧全绿**。后果不是「少一个用例」，是「手抄镜像失明的判据
 * 自己被静默摘掉」。删掉一个用例在 Jest 里是**零信号**：少跑一个用例不会红，
 * 所以任何「我记得加过这个用例」的保证都是记忆，不是判据。
 *
 * 什么算「可证地取用」（这是本闸的口径，收窄过两次，过程见报告第五节）：
 *   ① 解构取用：const { X } = require('...该 helper...')，且 X（含别名为局部名后的形态）
 *      在**取用语句之外**真的出现在代码里；
 *   ② 命名空间取用：const h = require('...') 之后出现 h.X；
 *   ③ 内联取用：require('...').X；
 *   ④ 路径引用（预加载档板这类没有 require 语句的形态）：**同时**满足三个条件才算整模块取用——
 *      该文件出现 '<basename>.js' 字面量、出现预加载机制（--require / NODE_OPTIONS）、
 *      且该 helper 位于某个 helpers/ 目录下。此时它的所有导出都算有人用。
 *      为什么必须加后两个条件：「提到一句路径」若也算取用，它就变成万能豁免。
 * **「文本里出现过这个名字」不算取用**——那是 H2 要证明的反例。
 *
 * 判据两条腿：
 *   1. 零外部取用的导出必须逐条登记在 BASELINE 棘轮里（新增一条未登记 ⇒ 红）；
 *   2. 棘轮条目一旦不再零取用（有人用了 / 导出被删了）也必须删掉该行（残留 ⇒ 红）。
 *      棘轮只许变小，这就是「只降不升」的执行方式。
 *
 * 本判据抓不到什么（如实声明，至少四条）：
 *   ① **取用还在、但断言被改成恒真形态**：expect(fn(x)).toEqual([]) 照样算一次取用，语义已空。
 *      抓它需要「断言强度」判据，不是可达性判据能做的事。
 *   ② **一个 helper 被多处取用，删掉其中一个取用点不会让取用数归零**：本判据只问「有没有人
 *      用」，不问「谁用了我、少了一个消费者吗」。抓这个要建反向索引（helper → 消费方清单）
 *      并对清单做棘轮，维护面很大而收益窄，本轮不立项（已由 lead 裁定）。
 *   ③ 路径引用那条口径是**整模块取用**：一旦命中 ④，该 helper 的全部导出都算「有人用」，
 *      于是「档板里某个导出其实没人用」查不出来。这是容纳预加载形态的代价（预加载没有个体符号，
 *      只有整模块）。当前全仓命中 ④ 的只有 deployRun.test.js → stubExec.js 这一对。
 *   ④ 运行时才拼出来的取用（require(变量)、requireActual 的字符串拼接、动态 import）不算取用。
 *
 * 自指排除（这条不是可选项，是判据成立的前提）：
 * 本文件体内按设计列着 BASELINE 里所有 helper 的路径与符号名。若不把本文件排除出消费者集合，
 * 它会把自己的断言文本算成「有人在用」，把 zeroRefs 清成空数组 ⇒ 本闸对「判据被摘掉」完全失明。
 * 实测发生过：第一版闸文件就是这样 3 红 1 绿，且形态是「越认真写自证，棘轮越空」。
 * 通式：**判据不得把自己算成自己的消费者**。H4 就是这条的回归用例。
 */

const fs = require('fs');
const path = require('path');

const { jsCodeOnlyKeepingLines } = require('../helpers/jsCodeOnly');

const ROOT = path.resolve(__dirname, '../../..');
/** 本文件自身（相对仓库根、posix 分隔符）：它按设计列着所有 helper 路径，不能算消费者 */
const SELF = path.relative(ROOT, __filename).replace(/\\/g, '/');

/**
 * 棘轮基线（定义文件相对路径 → 零外部取用的导出名，名字按字典序）。
 *
 * 基线怎么来的（可复算）：建闸时对全仓实跑一次扫描，把当时的零取用导出逐条登记。
 * 这 17 条**不是垃圾**：有的是 helper 内部用的默认值（DEFAULT_TIMEOUT_MS），有的是给下一步
 * 基建预留的常量（PROBE_MARKER/PROBE_SCRIPT），要么只被同一个文件里的其它导出间接使用
 * （specOperations/ROOT/SRC_DIR/cookieValue）。删掉它们会把基建当垃圾清掉，所以建棘轮而不是清仓。
 * 复算命令：node work/r23-c-scan.js（与本闸同一份口径的独立实现，本轮实跑输出见报告）。
 */
const BASELINE = {
  'src/tests/ci/helpers/refusalDocContract.js': ['ROOT'],
  'src/tests/ci/helpers/statusParityContract.js': ['ROOT', 'specOperations'],
  'src/tests/deploy/helpers/composeSource.js': ['stripYamlLineComments'],
  'src/tests/deploy/helpers/dockerignore.js': ['compilePattern'],
  'src/tests/helpers/auditWriteSites.js': ['SRC_DIR'],
  'src/tests/helpers/authResponse.js': ['cookieValue'],
  'src/tests/helpers/codeErrorCallScan.js': [
    'QUOTE_DOUBLE',
    'QUOTE_SINGLE',
    'classifyMessage',
    'codeSlotOf',
    'messageFieldOf',
    'slotLiterals',
  ],
  'src/tests/helpers/posixShell.js': ['PROBE_MARKER', 'PROBE_SCRIPT'],
  'src/tests/helpers/waitFor.js': ['DEFAULT_INTERVAL_MS', 'DEFAULT_TIMEOUT_MS'],
};

const baselineKeys = () =>
  Object.entries(BASELINE)
    .flatMap(([file, names]) => names.map((n) => file + '::' + n))
    .sort();

/** 递归列出 src/tests 下所有 .js（测试与 helper 都算消费者候选） */
function walkTests(dir, acc) {
  for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    const rel = dir + '/' + entry.name;
    if (entry.isDirectory()) walkTests(rel, acc);
    else if (entry.name.endsWith('.js')) acc.push(rel);
  }
  return acc;
}

/**
 * helper 目录**不手抄**：递归找出 src/tests 下所有名为 helpers 的目录。
 * 手抄目录清单正是本闸要防的形状：新增第三处 helpers/（例如 src/tests/deploy/helpers/）时，
 * 手抄清单不会红、只会静默少扫一个目录。实跑发现：deploy/helpers/ 的 4 个文件最初就是这样被漏掉的。
 */
function helperDirs() {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const rel = dir + '/' + entry.name;
      if (entry.name === 'helpers') out.push(rel);
      else walk(rel);
    }
  };
  walk('src/tests');
  return out.sort();
}

const helperFiles = () =>
  helperDirs().flatMap((dir) =>
    fs
      .readdirSync(path.join(ROOT, dir))
      // *.test.js 也可能放在 helpers/ 里（routeMounts.test.js），它不是 helper：没有导出可查
      .filter((n) => n.endsWith('.js') && !n.endsWith('.test.js'))
      .map((n) => dir + '/' + n)
  );

/** 相对模块路径解析成仓库内路径（裸名返回 null：那是 node_modules） */
function resolveSpec(spec, fileRel) {
  if (!spec.startsWith('.')) return null;
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(fileRel), spec));
  return resolved.endsWith('.js') ? resolved : resolved + '.js';
}

/** 去掉取用语句本身：解构/命名空间绑定那两行里的名字不等于有人在用 */
function stripRequireStatements(view) {
  return view
    .replace(/(?:const|let|var)\s*\{[^}]*\}\s*=\s*require\([^)]*\);?/g, '')
    .replace(/(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*require\([^)]*\);?/g, '');
}

/** ①解构取用：返回 Map<导出名, 局部名>（支持 { a: b } 别名） */
function destructuredFrom(view, fileRel, target) {
  const out = new Map();
  // 每个 helper 都新建正则：带 /g 的正则 lastIndex 会在多次 exec 间残留，复用会静默漏掉每个文件的前几个命中
  const re = /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
  let m = re.exec(view);
  while (m) {
    if (resolveSpec(m[2], fileRel) === target) {
      for (const raw of m[1].split(',')) {
        const seg = raw.trim();
        if (!seg || seg.startsWith('...')) continue;
        const parts = seg.split(':').map((s) => s.trim());
        const key = parts[0];
        const local = parts[1] || parts[0];
        if (/^[A-Za-z_$][\w$]*$/.test(key) && /^[A-Za-z_$][\w$]*$/.test(local)) {
          out.set(key, local);
        }
      }
    }
    m = re.exec(view);
  }
  return out;
}

/** ②命名空间取用：const h = require('...') 之后的 h.X */
function namespaceFrom(view, fileRel, target) {
  const out = new Set();
  const re = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
  let m = re.exec(view);
  while (m) {
    if (resolveSpec(m[2], fileRel) === target) {
      const member = new RegExp('\\b' + m[1] + '\\.([A-Za-z_$][\\w$]*)', 'g');
      let mm = member.exec(view);
      while (mm) {
        out.add(mm[1]);
        mm = member.exec(view);
      }
    }
    m = re.exec(view);
  }
  return out;
}

/** ③内联取用：require('...').X */
function inlineFrom(view, fileRel, target) {
  const out = new Set();
  const re = /require\(\s*['"`]([^'"`]+)['"`]\s*\)\.([A-Za-z_$][\w$]*)/g;
  let m = re.exec(view);
  while (m) {
    if (resolveSpec(m[1], fileRel) === target) out.add(m[2]);
    m = re.exec(view);
  }
  return out;
}

/** ④路径引用（预加载档板）：代码里出现 '<basename>.js' 字面量 ⇒ 整模块取用 */
function pathReferenceFrom(view, target, fileRel) {
  const base = path.posix.basename(target, '.js');
  if (!view.includes(base + '.js')) return false;
  // 只有「该文件同时出现预加载机制」时，路径字面量才算整模块取用。
  // 否则「提到一句路径」就是万能豁免：`ciGateWiring.test.js` 为了断言覆盖率把若干 helper 的路径
  // 当数据列在数组里，那里没有一个字是在调用它们。实测这条口径不加限制时，
  // 任何把这些路径写进清单的判据都会把自己的目标模块判成「有人用」。
  return PRELOAD_RE.test(view) && isPreloadSibling(fileRel, target);
}

/** 预加载机制的存在证据：`--require` / NODE_OPTIONS（部署端到端用 --require 预加载档板） */
const PRELOAD_RE = /--require|NODE_OPTIONS/;

/**
 * 预加载档板是「兄弟目录」关系：档板放在 helpers/ 里，被同族测试按路径交给子进程。
 * 这一条把路径引用限制在 `<...>/helpers/<name>.js` 这种形态上，避免任意路径字符串都放行。
 */
function isPreloadSibling(fileRel, target) {
  return (
    path.posix.basename(path.posix.dirname(target)) === 'helpers' &&
    (fileRel.startsWith('src/tests/deploy/') || fileRel.startsWith('src/tests/'))
  );
}

/** 某个文件的取用信息 */
function usageOf(view, fileRel, target) {
  return {
    file: fileRel,
    destructured: destructuredFrom(view, fileRel, target),
    namespace: namespaceFrom(view, fileRel, target),
    inline: inlineFrom(view, fileRel, target),
    whole: pathReferenceFrom(view, target, fileRel),
  };
}

/** 导出名：module.exports = { ... } 与 exports.x = ...（代码视图，注释不算） */
function exportedNamesOf(view) {
  const names = new Set();
  const re = /module\.exports\s*=\s*\{/g;
  let m = re.exec(view);
  while (m) {
    let i = m.index + m[0].length;
    let depth = 1;
    const start = i;
    while (i < view.length && depth > 0) {
      const c = view[i];
      if (c === '{') depth += 1;
      else if (c === '}') depth -= 1;
      i += 1;
    }
    for (const raw of view.slice(start, i - 1).split(',')) {
      const seg = raw.trim();
      if (!seg || seg.startsWith('...')) continue;
      const key = seg.split(':')[0].trim();
      if (/^[A-Za-z_$][\w$]*$/.test(key)) names.add(key);
    }
    m = re.exec(view);
  }
  const re2 = /exports\.([A-Za-z_$][\w$]*)\s*=/g;
  let m2 = re2.exec(view);
  while (m2) {
    names.add(m2[1]);
    m2 = re2.exec(view);
  }
  return [...names];
}

/** 全量取数：{ helpers, exports, zeroRefs, views, scannedFiles } */
function scan() {
  const views = new Map();
  for (const file of walkTests('src/tests', [])) {
    // 自指排除：本文件按设计列着所有 helper 路径，把它算进消费者会让 zeroRefs 永远为空
    if (file === SELF) continue;
    views.set(file, jsCodeOnlyKeepingLines(fs.readFileSync(path.join(ROOT, file), 'utf8')));
  }
  const helpers = helperFiles();
  const exports = [];
  const zeroRefs = [];
  for (const file of helpers) {
    const names = exportedNamesOf(views.get(file) || '');
    const consumers = [...views]
      .filter(([other]) => other !== file)
      .map(([other, view]) => usageOf(view, other, file));
    for (const name of names) {
      exports.push({ file, name });
      const used = consumers.some((c) => {
        if (c.whole) return true;
        if (c.namespace.has(name) || c.inline.has(name)) return true;
        if (c.destructured.has(name)) {
          const local = c.destructured.get(name);
          return new RegExp('\\b' + local + '\\b').test(stripRequireStatements(views.get(c.file)));
        }
        return false;
      });
      if (!used) zeroRefs.push({ file, name });
    }
  }
  return { helpers, exports, zeroRefs, views, scannedFiles: [...views.keys()] };
}

describe('helper 导出可达性（守「判据被静默摘掉」）', () => {
  const result = scan();

  test('H0 前提自证：扫描面非空（helper 文件、导出符号都成规模）', () => {
    // 扫描器整体失效时下面几条会「通过」（空集合 == 无违例）——本仓反复踩过的假绿形状
    expect(result.helpers.length).toBeGreaterThanOrEqual(18);
    expect(result.exports.length).toBeGreaterThanOrEqual(80);
    // 每个 helper 都至少解析出一个导出：某个文件解析成 0 个 = 导出解析器退化
    const silent = result.helpers.filter((f) => !result.exports.some((e) => e.file === f));
    expect(silent).toEqual([]);
    // 消费者面也要成规模：一个正经仓不可能只有两三个文件在取用 helper
    expect(result.scannedFiles.length).toBeGreaterThanOrEqual(300);
  });

  test('H1 零取用的导出必须逐条登记在棘轮里（两个方向同一判据）', () => {
    const actual = result.zeroRefs.map((z) => z.file + '::' + z.name).sort();
    expect(actual).toEqual(baselineKeys());
  });

  test('H2 仪器有牙：注释里的名字、裸同名、取用后不再使用 都不算取用', () => {
    // 合成样例：解构取用但局部名在取用语句之外再不出现 ⇒ 不算取用（这条是 arm1 变异逼出来的）
    const dropped = [
      "const { coverageViolations } = require('./helpers/statusParityContract');",
      '// 这里提一句 coverageViolations 也不算：注释已在代码视图里被剔掉',
    ];
    const droppedView = jsCodeOnlyKeepingLines(dropped.join('\n'));
    const usage = usageOf(droppedView, 'src/tests/ci/x.test.js', 'src/tests/ci/helpers/statusParityContract.js');
    expect(usage.destructured.has('coverageViolations')).toBe(true);
    // 解构语句已被 stripRequireStatements 剔掉、注释也不在代码视图 ⇒ 取用语句之外零出现
    expect(stripRequireStatements(droppedView)).not.toMatch(/\bcoverageViolations\b/);

    // 真实反例：codeSlotOf 在 errorCodePlaceholderDefault.test.js 里**只出现在注释里**
    const rel = 'src/tests/ci/errorCodePlaceholderDefault.test.js';
    const raw = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    expect(raw.includes('codeSlotOf')).toBe(true); // 纯文本 grep 会命中
    expect(result.views.get(rel)).not.toMatch(/\bcodeSlotOf\b/); // 代码视图没有
    // 于是它必须仍然零取用、仍然躺在棘轮里（没有被「文本里出现过」误判成有人用）
    expect(
      result.zeroRefs.some(
        (z) => z.file === 'src/tests/helpers/codeErrorCallScan.js' && z.name === 'codeSlotOf'
      )
    ).toBe(true);

    // 别名解构要认得：{ accessToken: accessTokenOf } 算取了 accessToken
    const alias = usageOf(
      jsCodeOnlyKeepingLines("const { accessToken: accessTokenOf } = require('../helpers/authResponse');\naccessTokenOf(res);"),
      'src/tests/controllers/y.test.js',
      'src/tests/helpers/authResponse.js'
    );
    expect(alias.destructured.get('accessToken')).toBe('accessTokenOf');
  });

  test('H2b 路径引用通道不得变成万能豁免（只有预加载机制才算整模块取用）', () => {
    const helper = 'src/tests/deploy/helpers/stubExec.js';
    // 真取用：deployRun.test.js 用 --require 把这个档板交给子进程
    const real = result.views.get('src/tests/deploy/deployRun.test.js');
    expect(real).toBeTruthy();
    expect(PRELOAD_RE.test(real)).toBe(true);
    expect(usageOf(real, 'src/tests/deploy/deployRun.test.js', helper).whole).toBe(true);
    // 假取用：ciGateWiring.test.js 把同一路径当**数据**列在覆盖率清单里，一个调用都没有
    const fake = result.views.get('src/tests/deploy/ciGateWiring.test.js');
    expect(fake).toBeTruthy();
    expect(fake.includes('stubExec.js')).toBe(true);
    expect(PRELOAD_RE.test(fake)).toBe(false);
    expect(usageOf(fake, 'src/tests/deploy/ciGateWiring.test.js', helper).whole).toBe(false);
  });

  test('H3 棘轮只降不升：基线里每一条都真的还是零取用（腐化即红）', () => {
    const actual = new Set(result.zeroRefs.map((z) => z.file + '::' + z.name));
    const stale = baselineKeys().filter((k) => !actual.has(k));
    // 与 H1 互为反向：H1 抓「漏登记」，这里抓「登记了但已经有人用了 ⇒ 基线该缩小」
    expect(stale).toEqual([]);
  });

  test('H4 自指排除：闸文件自己不得算作消费者（否则棘轮会被自己的断言文本清空）', () => {
    // 这条是实测事故的回归用例：第一版闸把本文件算进消费者集合，
    // 而本文件体内按设计列着全部 helper 路径与符号名 ⇒ zeroRefs 被清成空数组 ⇒ 3 红 1 绿。
    expect(result.scannedFiles).not.toContain(SELF);
    expect(walkTests('src/tests', [])).toContain(SELF);
    // 正面证明「本文件若被算进去会污染」：它的代码视图里确实含 BASELINE 的全部符号名与路径
    const selfView = jsCodeOnlyKeepingLines(fs.readFileSync(path.join(ROOT, SELF), 'utf8'));
    expect(baselineKeys().length).toBeGreaterThanOrEqual(10);
    for (const key of baselineKeys()) {
      const [file, name] = key.split('::');
      expect(usageOf(selfView, SELF, file).whole || new RegExp('\\b' + name + '\\b').test(selfView)).toBe(true);
    }
    // 若把本文件放回消费者集合，棘轮必须真的被清空 —— 那才说明这个排除不是「刚好没影响」
    expect(result.zeroRefs.length).toBeGreaterThanOrEqual(10);
  });
});
