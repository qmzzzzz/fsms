/**
 * 注释块完整性（删除注释操作的零信号失败模式）
 *
 * 【为什么需要这条闸】2026-11-02 的注释清理里，fix-r2-privilege 删了 47 行整行注释，其中 6 处
 * 留下了语法合法、语义断裂的残骸：三处块首行被删后，续行缩进比上下文多 2~6 格；一处删掉
 * 块首后，末行以冒号结尾却没有下文；一处删掉续行后，末行以逗号结尾却直接接了代码。
 * 当时全仓 20+ 条闸门一条都没红：
 *   · 密度闸只数「整行注释的行数」——缩进错位不改行数，悬空标点也不改行数；
 *   · 锚点闸只看 file:line 是否指得到声明的符号——残骸行本身仍是一个合法注释行。
 * 也就是说，这类破坏没有任何信号。删注释是本仓正在大规模进行的操作（棘轮、锚点整改、
 * 变更史清理），所以这个缺口不是理论风险：它已经发生过一次，靠人肉眼发现的。
 *
 * 【四条判据，与「修复前形态」一一对应】
 *   1. 悬空收尾：注释块最后一行以全角冒号/逗号/顿号/左括号结尾 ⇒ 这一行显然还要接下文，
 *      但下文没了（块已结束、下一行是代码或空行）。
 *      只认全角标点：ASCII 的冒号/逗号/分号/括号在注释里描述代码片段时极常见
 *      （实测 1,161 个文件里 9 处，其中 8 处是「描述代码形态」而非残骸），全收会假红。
 *   2. 缩进断裂：同一种注释标记（行注释或星号行）构成的连续块内，标记列极差 ≥ 2 ⇒ 有一行被
 *      孤立地多缩进了几格。这是「删掉块首行、续行没跟着回退」的指纹。
 *   3. 孤儿续行：块首行以「续」+标点开头 ⇒ 它上一行的注释已被删掉，它自己在接着一段不存在的上文。
 *   4. 代码行孤峰缩进：某代码行比上下最近的代码行多缩进 ≥4 格，而上下两行彼此齐平 ⇒ 事故。
 *      （这一条不在三个「注释」判据里，但它和它们同源：删掉注释后**紧随其后的代码行**被带偏。
 *      实测 eslint 的 recommended 全量配置不含 indent 规则，所以这一类目前只有本闸看得见。）
 *
 * 【强度分档：2 与 4 是硬判据，1 与 3 用棘轮】
 * 2 在全仓实测为 0（10,455 个纯同标记注释块，零例外），4 在全仓实测也为 0（1,161 个文件），
 * 所以这两条不设基线：任何一处立红。
 * 1 与 3 有既存违例，其中多数是有意为之的写法：以冒号收尾的块后面紧跟一个缩进更深的代码块
 * （枚举、对象字面量、逐项清单），这一行是「下面是清单」的引导句，不是残骸。判据区分不了
 * 「引导句」与「残骸」，而区分它们需要语义理解。所以按本仓既有做法（ADR-011 §28-30 的棘轮）：
 * 把当前既存违例逐文件计数登记为基线，只许降不许升。
 *
 * 【基线是怎么来的、为什么不一次性清零】
 * 基线 = 2026-11-02 04:31 全仓实测（src/ 下 1,161 个 .js，15,254 个注释块，56,971 行整行注释）
 * 里 8 个文件的 8 处违例，逐处人工读过：全部是「引导句」形态，删掉会丢一条判据（它们的作用是
 * 告诉读者「下面这几项是同一族的」）。一次性清零的唯一办法是删掉这 8 行，那正好是这条闸要防的事。
 * 所以不清零，登记为欠账。欠账不许增长，也不许用「把标点改成句号」来消账 —— 那只是让数字变绿。
 * 什么时候可以消：把引导句改成「标题行 + 空行 + 清单」的形态时，那一行自然不再以标点收尾，
 * 计数随之下降，基线跟着降。这是真的改善了，不是把标点藏起来。
 *
 * 【自证：这条闸必须能抓到我那 6 处】
 * 最后一组用例把 6 处修复前形态逐字写成字符串常量喂给判据函数，断言每一处都被判红。
 * 这是本闸唯一有效的证明：抓不到那 6 处，就是判据写错了（而不是「当时恰好没有违例」）。
 * 第 6 处是 `securityController/account.js:194` 的**代码行**缩进 10 → 18（见判据 4）。
 * 其中 middleware/security/index.js 那处（末行以冒号结尾）修复时被改成句号，所以它只存在于样张里；
 * 样张钉住的正是曾经发生过的形态，而不是当前工作区。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { jsCodeOnlyKeepingLines } = require('../helpers/jsCodeOnly');

const SRC_DIR = path.join(__dirname, '../../');
const ROOT_DIR = path.join(__dirname, '../../../');

/** 仓库相对路径（统一正斜杠，带 src/ 前缀，与 commentDensity 的键口径一致） */
const relOf = (f) => path.relative(ROOT_DIR, f).replace(/\\/g, '/');

const collectSourceFiles = (dir, acc = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      collectSourceFiles(full, acc);
    } else if (entry.name.endsWith('.js')) {
      acc.push(full);
    }
  }
  return acc;
};

/**
 * 取出全部「整行注释」行号，并切成连续块。
 *
 * 「什么算注释」的口径不在这里重写：一律取 helpers/jsCodeOnly 的保行号视图
 * （它是本仓唯一实现，见该文件头注）。这里只做「这一行还有没有代码」的判定：
 * 原文非空、而剥注释后为空 ⇒ 整行注释。
 * 之所以不自己写状态机：本仓已有四份复制品各自漂移过（jsCodeOnly 头注记了这段历史），
 * 再抄一份就是第五份。
 *
 * @param {string} src JS 源码
 * @returns {Array<Array<{line: number, raw: string}>>} 注释块数组，每块是连续的行
 */
const commentBlocksOf = (src) => {
  const lf = src.replace(/\r\n/g, '\n');
  const rawLines = lf.split('\n');
  const codeView = jsCodeOnlyKeepingLines(src).split('\n');
  const isCommentOnly = rawLines.map(
    (raw, i) => raw.trim() !== '' && (codeView[i] || '').trim() === ''
  );
  const blocks = [];
  let i = 0;
  while (i < rawLines.length) {
    if (!isCommentOnly[i]) {
      i += 1;
      continue;
    }
    let j = i;
    while (j + 1 < rawLines.length && isCommentOnly[j + 1]) j += 1;
    const block = [];
    for (let k = i; k <= j; k += 1) block.push({ line: k + 1, raw: rawLines[k] });
    blocks.push(block);
    i = j + 1;
  }
  return blocks;
};

/** 注释标记（行注释两斜杠 / 星号 / 块开）的起始列；行首 BOM 先剥掉再算 */
const markerColOf = (raw) => {
  const m = /^(\s*)(\/\/|\*|\/\*)/.exec(raw.replace(/^\uFEFF/, ''));
  return m ? m[1].length : -1;
};

/** 注释正文：剥掉标记与收尾的块闭合符后 trim */
const textOf = (raw) =>
  raw
    .replace(/^\uFEFF/, '')
    .replace(/^\s*(?:\/\/|\/\*+|\*+)\s*/, '')
    .replace(/\*\/\s*$/, '')
    .trim();

/** 悬空收尾的标点集合：这一行显然还要接下文 */
const DANGLING_TAIL = /[：，、（]$/;

/** 孤儿续行的开头：续+标点 之类 */
const ORPHAN_HEAD = /^[（(]?续[：:，,、）)]/;

/**
 * 判据 4：代码行的「孤峰缩进」——某代码行比它**上下最近的代码行**多缩进 ≥4 格，而上下两行彼此齐平。
 *
 * 为什么它必须在这条闸里，而不是交给 eslint：实测 eslint 的 recommended 全量配置**不含 indent**，
 * 所以我 2026-11-02 把 `controllers/securityController/account.js:194` 的代码行从 10 格改成 18 格后，
 * `npx eslint <file>` 退出码仍是 0。而这类破坏恰恰是「删注释」的典型副作用：
 * 删掉一行注释后，紧随其后的代码行若被顺手带偏，语法依然合法、语义（此处）依然正确，
 * 于是**没有任何现有信号**。
 *
 * 为什么「上下齐平 + 本行高出 ≥4」而不是「与上下任一不同」：
 * 行内排版本来就有大量合法的高缩进（续行、链式调用、多行三元、传入多行字面量），
 * 逐条判「与上一行不同」会红掉几千处。而「上下齐平、唯独本行高出 4 格以上」是**排版事故**的形态：
 * 正常的多行结构里，上下邻居不会同时齐平——它们本来就在同一层（比如两个兄弟属性、两条语句）。
 *
 * 全仓实测 **0**（1,161 个文件）：所以和判据 2 一样是硬判据，不设基线。
 *
 * @param {string} src JS 源码
 * @returns {number[]} 孤峰缩进的代码行行号
 */
const codeIndentPeaksOf = (src) => {
  const raw = src.replace(/\r\n/g, '\n').split('\n');
  const kept = jsCodeOnlyKeepingLines(src).split('\n');
  const isCode = raw.map((r, i) => r.trim() !== '' && (kept[i] || '').trim() !== '');
  const peaks = [];
  for (let i = 0; i < raw.length; i += 1) {
    if (!isCode[i]) continue;
    const indent = /^(\s*)/.exec(raw[i])[1].length;
    let up = -1;
    for (let j = i - 1; j >= 0; j -= 1)
      if (isCode[j]) {
        up = j;
        break;
      }
    let down = -1;
    for (let j = i + 1; j < raw.length; j += 1)
      if (isCode[j]) {
        down = j;
        break;
      }
    if (up < 0 || down < 0) continue;
    const upIndent = /^(\s*)/.exec(raw[up])[1].length;
    const downIndent = /^(\s*)/.exec(raw[down])[1].length;
    if (upIndent === downIndent && indent - upIndent >= 4) peaks.push(i + 1);
  }
  return peaks;
};

/**
 * 判据本体：一个文件里的全部违例。纯函数，供真实扫描与自证样张共用。
 *
 * @param {string} src JS 源码
 * @returns {{dangling: number[], indentBreak: number[], orphan: number[]}} 各类违例的行号
 */
const violationsOf = (src) => {
  const dangling = [];
  const indentBreak = [];
  const orphan = [];
  for (const block of commentBlocksOf(src)) {
    // 判据 1：块末行以悬空标点结尾
    const last = block[block.length - 1];
    const lastText = textOf(last.raw);
    if (lastText && DANGLING_TAIL.test(lastText)) dangling.push(last.line);

    // 判据 2：同一标记构成的连续块内，标记列极差 >= 2
    // 只在「整块都是行注释」或「块内有 >=2 个星号行」时判：混排块（块开 + 星号续 + 块闭）的列本来就不齐。
    const allSlash = block.every((x) => /^\s*\/\//.test(x.raw));
    const starRows = block.filter((x) => /^\s*\*/.test(x.raw) && !/^\s*\*\//.test(x.raw));
    let cols = null;
    let rows = null;
    if (allSlash && block.length >= 2) {
      rows = block;
      cols = block.map((x) => markerColOf(x.raw));
    } else if (starRows.length >= 2) {
      rows = starRows;
      cols = starRows.map((x) => markerColOf(x.raw));
    }
    if (cols && Math.max(...cols) - Math.min(...cols) >= 2) {
      const base = Math.min(...cols);
      rows.forEach((x) => {
        if (markerColOf(x.raw) !== base) indentBreak.push(x.line);
      });
    }

    // 判据 3：块首行是「续…」
    if (ORPHAN_HEAD.test(textOf(block[0].raw))) orphan.push(block[0].line);
  }
  return { dangling, indentBreak, orphan };
};

const files = collectSourceFiles(SRC_DIR);
const survey = new Map();
const codePeaks = {};
for (const f of files) {
  const text = fs.readFileSync(f, 'utf8');
  survey.set(relOf(f), violationsOf(text));
  const peaks = codeIndentPeaksOf(text);
  if (peaks.length > 0) codePeaks[relOf(f)] = peaks.length;
}

/** 逐文件计数（只保留 > 0 的，便于与基线逐字比对） */
const tallyOf = (key) => {
  const out = {};
  for (const [f, v] of survey) if (v[key].length > 0) out[f] = v[key].length;
  return out;
};

const totalOf = (key) => {
  let n = 0;
  for (const v of survey.values()) n += v[key].length;
  return n;
};

/**
 * 悬空收尾的既存基线（2026-11-02 04:31 实测，逐处人工读过，全部是「引导句」形态）。
 * 见头注「基线是怎么来的、为什么不一次性清零」。只许降不许升。
 */
const DANGLING_BASELINE = {
  'src/constants/audit.js': 1,
  'src/tests/architecture/layeringRatchet.test.js': 1,
  'src/tests/constants/permissionStatusSingleSource.test.js': 1,
  'src/tests/imageDigestGate.test.js': 1,
  'src/tests/nodeEnvGateFailsClosed.test.js': 1,
  'src/tests/services/auditUsernameCastGate.test.js': 1,
  'src/tests/utils/mongoFailureAttribution.test.js': 1,
};

/** 孤儿续行的既存基线（同刻实测为 0；留空表而不是省略，让「将来出现第一处」有地方登记） */
const ORPHAN_BASELINE = {};

/** 逐文件比对：now 不得大于 base，且 base 里的文件不许静默消失 */
const compareToBaseline = (now, base) => {
  const over = [];
  for (const [f, n] of Object.entries(now)) {
    const cap = base[f] || 0;
    if (n > cap) over.push({ file: f, base: cap, now: n });
  }
  const shrunk = [];
  for (const [f, n] of Object.entries(base)) {
    if ((now[f] || 0) < n) shrunk.push({ file: f, base: n, now: now[f] || 0 });
  }
  return { over, shrunk };
};

describe('注释块完整性（删注释不得留下断裂残骸）', () => {
  test('前提自证：扫描面非空、注释块数量在合理量级（防扫描路径漂移导致假绿）', () => {
    expect(files.length).toBeGreaterThan(800);
    let blockCount = 0;
    let commentLineCount = 0;
    for (const f of files) {
      const blocks = commentBlocksOf(fs.readFileSync(f, 'utf8'));
      blockCount += blocks.length;
      commentLineCount += blocks.reduce((n, b) => n + b.length, 0);
    }
    // 地板取自实测 15,254 块 / 56,971 行：口径漂移（把注释当代码）会先在这里掉下来
    expect(blockCount).toBeGreaterThan(10000);
    expect(commentLineCount).toBeGreaterThan(40000);
  });

  test('判据 2（缩进断裂）无例外：任何一处立红', () => {
    // 全仓实测 0：10,455 个纯同标记注释块，标记列无一例外地齐平。
    // 不设基线是因为「齐平」本来就是写注释的默认形态，一处不齐就说明有人删漏了。
    expect(tallyOf('indentBreak')).toEqual({});
  });

  test('判据 1（悬空收尾）只许降不许升，且基线不许静默缩小', () => {
    const now = tallyOf('dangling');
    const { over, shrunk } = compareToBaseline(now, DANGLING_BASELINE);
    expect(over).toEqual([]);
    // 反向：基线里的文件若一条都不剩，说明有人真的修好了 —— 那必须同批把基线改小，
    // 否则这张表会慢慢退化成一张永远绿的废纸。
    expect(shrunk).toEqual([]);
    expect(totalOf('dangling')).toBe(Object.values(DANGLING_BASELINE).reduce((a, b) => a + b, 0));
  });

  test('判据 3（孤儿续行）只许降不许升', () => {
    const { over } = compareToBaseline(tallyOf('orphan'), ORPHAN_BASELINE);
    expect(over).toEqual([]);
  });
});

describe('自证：这条闸必须能抓到 2026-11-02 那 6 处修复前形态', () => {
  // 每一条都是真实事故的逐字形态（见头注）。抓不到就是判据错了。
  const CASES = [
    {
      what: 'auditLogHooks.js：删掉块首行后，续行缩进 4 → 8（孤峰）',
      expect: 'indentBreak',
      src: [
        'const applyHooks = (schema) => {',
        '  schema.pre(HOOKS, function (next) {',
        '    if (!enforced) return next();',
        '        // 现收紧为「仅测试环境 + 显式传入布尔 true」才放行：',
        '    //   - 未传 / 传 false / 非布尔一律拦截；',
        '    //   - 生产环境无论传什么都不放行。',
        '    return next();',
        '  });',
        '};',
      ].join('\n'),
    },
    {
      what: 'authService/token.js：同上，缩进 2 → 4（孤峰）',
      expect: 'indentBreak',
      src: [
        'async function revoke() {',
        '  // 属主预检：任何一枚不是当前操作者的 refresh 串都整次失败。',
        '    // 预检必须走在任何 blacklistToken 之前。',
        '  return null;',
        '}',
      ].join('\n'),
    },
    {
      what: 'securityController/overview.js：同上，缩进 6 → 12（孤峰）',
      expect: 'indentBreak',
      src: [
        'const build = () => {',
        '      // 现在读挂载态，判据与邻居同口径。',
        '            // 合规面板是这些指标唯一该有的地方：任何一项 >0 都意味着缺口。',
        '      // 完整性缺口（各键含义见下方逐项注释）。',
        '  return null;',
        '};',
      ].join('\n'),
    },
    {
      what: 'middleware/security/index.js：删掉块首行后，末行以冒号结尾却没有下文',
      expect: 'dangling',
      src: [
        '  // 映射后必与 allowedTypes 等长（上面已保证无未映射项），故此处不再 filter(Boolean)：',
        '  const allowedExts = allowedTypes.map((t) => MIME_TO_EXT[t]);',
      ].join('\n'),
    },
    {
      what: 'controllers/reportController.js：删掉续行后，末行以逗号结尾却直接接了代码',
      expect: 'dangling',
      src: [
        'const exportReport = asyncHandler(async (req, res) => {',
        '  // audit 分支补 ip/userId 筛选参数（与 /security/audit-logs 查询接口同参），',
        '  const query = req.query;',
        '});',
      ].join('\n'),
    },
  ];

  test.each(CASES.map((c) => [c.what, c]))('%s ⇒ 必须判红', (what, c) => {
    const v = violationsOf(c.src);
    expect({ what, hits: v[c.expect] }).toEqual({ what, hits: expect.any(Array) });
    expect(v[c.expect].length).toBeGreaterThan(0);
  });

  test('反向对照：修复后的形态必须判绿（否则判据会把正常写法也打死）', () => {
    const fixed = [
      'const applyHooks = (schema) => {',
      '  schema.pre(HOOKS, function (next) {',
      '    if (!enforced) return next();',
      '    // 现收紧为「仅测试环境 + 显式传入布尔 true」才放行：',
      '    //   - 未传 / 传 false / 非布尔一律拦截；',
      '    //   - 生产环境无论传什么都不放行。',
      '    return next();',
      '  });',
      '};',
    ].join('\n');
    expect(violationsOf(fixed)).toEqual({ dangling: [], indentBreak: [], orphan: [] });
  });

  test('前提自证：判据对「本来就没有残骸」的写法不误报', () => {
    const clean = [
      '/**',
      ' * 正常块注释。',
      ' *',
      ' * 下面是清单：',
      ' *   - 第一项',
      ' *   - 第二项',
      ' */',
      'const x = 1;',
    ].join('\n');
    // 块末行是块闭合符而不是冒号，所以不算悬空；块内星号行列齐平，所以不算断裂
    expect(violationsOf(clean).dangling).toEqual([]);
    expect(violationsOf(clean).indentBreak).toEqual([]);
  });

  test('真文件变异自证：把一处真实注释行多缩进 4 格 ⇒ 判据 2 必须当场红', () => {
    // 上面 5 条样张是「事故的逐字形态」，这一条补的是「判据对真文件也生效」：
    // 样张走的是同一套 violationsOf，但只有真文件能证明扫描面真的扫到了这些行。
    const file = 'src/middleware/security/index.js';
    const src = fs.readFileSync(path.join(ROOT_DIR, file), 'utf8');
    expect(violationsOf(src).indentBreak).toEqual([]);
    // 取块内第 2 行（与第 1 行同缩进），人为多缩进 4 格 —— 这正是「删掉块首、续行没回退」的形态
    const rows = src.replace(/\r\n/g, '\n').split('\n');
    const idx = rows.findIndex(
      (l, i) =>
        /^\s*\/\/ \S/.test(l) &&
        i + 1 < rows.length &&
        /^\s*\/\/ \S/.test(rows[i + 1]) &&
        /^(\s*)/.exec(l)[1].length === /^(\s*)/.exec(rows[i + 1])[1].length
    );
    expect(idx).toBeGreaterThanOrEqual(0);
    rows[idx + 1] = '    ' + rows[idx + 1];
    expect(violationsOf(rows.join('\n')).indentBreak.length).toBeGreaterThan(0);
  });

  test('判据 4（代码行孤峰缩进）无例外：任何一处立红（eslint 不管这一格）', () => {
    // 全仓实测 0。2026-11-02 我把 account.js:194 的代码行缩进从 10 改成 18，
    // `npx eslint <该文件>` 退出码是 0 —— 这条判据补的就是这个缺口。
    expect(codePeaks).toEqual({});
  });

  test('自证：account.js 那次代码行缩进事故的形态必须被判红', () => {
    // 下面这段是还原的**事故形态**：上一行代码 10 格、本行 18 格、下一行代码 10 格，
    // 属性名与值都对，语法合法，因此除了「孤峰」没有任何信号。
    const damaged = [
      '  const bindings = {',
      '    email: {',
      "      value: user.email || '',",
      '      verified: !!user.email,',
      '                  verified: !!user.department,',
      '      required: false,',
      '    },',
      '  };',
    ].join('\n');
    expect(codeIndentPeaksOf(damaged)).toEqual([5]);
    // 修复后的形态必须判绿
    const fixed = damaged.replace(/\n {18}/, '\n      ');
    expect(codeIndentPeaksOf(fixed)).toEqual([]);
  });

  test('前提自证：合法的多行排版（续行/链式调用/多行字面量）不误报', () => {
    // 判据为什么是「上下齐平 + 本行高出 ≥4」而不是「与上下不同」：这段里每一行都与上一行不同，
    // 但没有任何一行是孤峰 —— 上下邻居同时齐平才是事故形态。
    const legit = [
      'const rows = items',
      '  .filter((x) => x.ok)',
      '  .map((x) => ({',
      '    id: x.id,',
      '    name: x.name,',
      '  }));',
      'const label =',
      '  cond',
      "    ? 'a'",
      "    : 'b';",
    ].join('\n');
    expect(codeIndentPeaksOf(legit)).toEqual([]);
  });
  test('前提自证：混排块（块开 + 星号续 + 块闭）不因列不齐而误报', () => {
    const mixed = ['  /**', '   * 缩进 2 的块。', '   */', '  const y = 2;'].join('\n');
    expect(violationsOf(mixed).indentBreak).toEqual([]);
  });
});
