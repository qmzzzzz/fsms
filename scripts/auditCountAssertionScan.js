'use strict';

/**
 * 审计计数断言的静态扫描器（测试基建，非生产代码；只读文件，不连 DB）
 *
 * 要防的失效形态（第 23 轮审计报的机制级缺口）：`auditBuffer` 未 start() 时，
 * **中间件**产生的审计只留在内存缓冲里，一行都不落库。于是用例里
 *   expect(await AuditLog.countDocuments({ action: 'x' })).toBe(0)
 * 永远为真——不是"这次没写审计"，而是"缓冲根本没开"。这类假绿会永久成立并随用例进 CI。
 *
 * 为什么是静态判据：运行时**无法**区分"真 0 条"与"缓冲没开"，两者在库里长得一模一样。
 * 唯一可靠的证据是源码形态——这个文件既驱动 HTTP（所以全局审计中间件真的会执行到），
 * 又对审计集合的查询结果做断言，却没有任何"让缓冲动起来"的调用。
 *
 * 三种事实各自只在这里实现一次，供用例侧断言（避免"测试自证一套、产品用另一套"）：
 *   - httpDriven    ：supertest / createApp / request(app)，即请求会经过全局审计中间件；
 *   - bufferControl ：auditBuffer.start / flush / flushAndStop / __waitForFlushIdle；
 *   - auditQuery    ：对 AuditLog 模型发起 countDocuments/find/findOne/aggregate/…，
 *                     且该查询的结果在断言窗口内被 expect 断言。
 *
 * 注释必须剥掉再判，两个方向都要：
 *   - 注释里写一句 auditBuffer.start() 不算"让缓冲动起来"（否则一行注释就能解锁门禁）；
 *   - 注释里写一句 expect(...).toBe(0) 不算断言（否则解释性注释会把文件误判成闸对象）。
 */

const fs = require('fs');
const path = require('path');

/** 断言窗口：查询调用之后多少行内出现的 expect 视为"在断言这个查询的结果" */
const ASSERT_WINDOW = 15;

/** 断言链开窗长度（字符）：覆盖 `expect(x)\n  .toHaveLength(0)` 这类换行写法 */
const ASSERT_CHAIN_CHARS = 240;

/**
 * 空洞断言（结果为空/为零时也满足）：这正是"缓冲没开"能**永久假绿**的那一类。
 * 正断言（toBe(1)/toHaveLength(1)…）在行缺失时会大声红，不产生假绿——两类必须分开判。
 *
 * 必须逐个子看 `.not` 修饰子，不能拿一条大正则去测整条链：
 *   `expect(audit).not.toBeNull()` 是**存在性**断言（行不存在就红），
 *   而 `expect(audit).toBeNull()` 才是空洞断言；两者文本只差一个 not，
 *   一刀切会把 ipList 那两个真实的"越权审计必须落库"断言读成空洞断言（实测已发生，见下）。
 */
const MATCHER_RE =
  /(\.not\s*\.)?\s*(toBe|toEqual|toHaveLength|toBeFalsy|toBeNull|toBeUndefined|toBeDefined|toBeGreaterThanOrEqual|toBeLessThanOrEqual)\s*\(\s*([^)]*)\)/g;

/**
 * 单条断言链里是否存在空洞断言。
 * @param {string} chain 从 `expect(` 到本条语句结束的文本
 * @returns {boolean}
 */
function matcherIsVacuous(name, arg, negated) {
  // `.not.toBeDefined()` 是"不存在" ⇒ 空洞；`.not.toBeNull()/.not.toBeUndefined()` 是"存在" ⇒ 不是。
  if (name === 'toBeDefined') return negated;
  if (negated) return false;
  if (name === 'toBe' || name === 'toEqual') return arg === '0' || arg === '[]';
  if (name === 'toHaveLength') return arg === '0';
  if (name === 'toBeFalsy' || name === 'toBeNull' || name === 'toBeUndefined') return true;
  if (name === 'toBeGreaterThanOrEqual' || name === 'toBeLessThanOrEqual') return /^-?0$/.test(arg);
  return false;
}

function isZeroAssertion(chain) {
  MATCHER_RE.lastIndex = 0;
  let m;
  while ((m = MATCHER_RE.exec(chain)) !== null) {
    if (matcherIsVacuous(m[2], m[3].trim(), Boolean(m[1]))) return true;
  }
  return false;
}

/**
 * 剥掉注释、保留字符串，输出与输入**逐行对齐**（注释位换成空格、换行原样保留）。
 * 逐字符状态机而不是正则替换：`//` 会出现在 URL 字符串里，而块注释内的 `*` + `/`
 * 又会提前结束——两种都得靠状态机，正则做不到。
 * @param {string} text
 * @returns {string}
 */
function consumeBlockComment(text, i, out, st) {
  if (text[i] === '*' && text[i + 1] === '/') {
    st.inBlock = false;
    out.push(' ', ' ');
    return i + 1;
  }
  out.push(text[i] === '\n' ? '\n' : ' ');
  return i;
}

/** 字符串内的字符原样保留；反斜杠转义与未闭合换行都要按原文对齐 */
function consumeQuoted(text, i, out, st) {
  const ch = text[i];
  out.push(ch);
  if (ch === '\\') {
    out.push(text[i + 1] === undefined ? ' ' : text[i + 1]);
    return i + 1;
  }
  if (ch === st.quote || ch === '\n') st.quote = null; // 未闭合字符串不得吞掉后续整段代码
  return i;
}

/** 行注释整段抹成空格（保留行尾换行，行号才不会漂） */
function consumeLineComment(text, i, out) {
  let j = i;
  while (j < text.length && text[j] !== '\n') {
    out.push(' ');
    j += 1;
  }
  if (j < text.length) out.push('\n');
  return j;
}

function stripComments(text) {
  const out = [];
  const st = { quote: null, inBlock: false };
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (st.inBlock) {
      i = consumeBlockComment(text, i, out, st);
      continue;
    }
    if (st.quote) {
      i = consumeQuoted(text, i, out, st);
      continue;
    }
    if (ch === '/' && next === '/') {
      i = consumeLineComment(text, i, out);
      continue;
    }
    if (ch === '/' && next === '*') {
      st.inBlock = true;
      out.push(' ', ' ');
      i += 1;
      continue;
    }
    if (ch === '\'' || ch === '"' || ch === '`') {
      st.quote = ch;
      out.push(ch);
      continue;
    }
    out.push(ch);
  }
  return out.join('');
}

/** 引号字符（避免在本文件里同时出现两种引号的字面量，正则才读得清） */
const QS = '\'' + '"';

/** 该文件是否驱动 HTTP ⇒ 全局审计中间件真的会被执行到 */
const HTTP_RE = new RegExp(
  'require\\s*\\(\\s*[' + QS + ']supertest[' + QS + ']\\s*\\)' +
    '|createApp\\s*\\(' +
    '|\\brequest\\s*\\(\\s*(?:app|server|expressApp)\\b'
);

/** 该文件是否在**观测**缓冲写入路径（spy 记录 push）：不是控制，但说明作者知道这条路径存在 */
const PUSH_OBSERVED_RE = /jest\s*\.\s*spyOn\s*\(\s*auditBuffer\s*,\s*['"]push['"]/;

/** 该文件是否让缓冲动起来（启动 / 显式 flush / 等 flush 空闲） */
const CONTROL_RE = /\bauditBuffer\s*\.\s*(?:start|flush|flushAndStop|__waitForFlushIdle)\s*\(/;

/** 审计集合上的"取证型"查询方法（写操作不算：写操作不依赖缓冲是否启动） */
/**
 * 取方法调用**第一个实参**的文本（括号/方括号/花括号配平；字符串里的括号不处理，
 * 只用于判"这个计数是不是被过滤条件收窄过"，不追求完整语法树）。
 * @param {string} source
 * @param {number} openParenAt 左括号在 source 中的下标
 * @returns {string|null}
 */
function firstArgumentText(source, openParenAt) {
  let depth = 0;
  for (let i = openParenAt; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(openParenAt + 1, i);
    } else if (ch === ',' && depth === 1) {
      return source.slice(openParenAt + 1, i);
    }
  }
  return null;
}

/** 审计集合上的"取证型"查询方法（写操作不算：写操作不依赖缓冲是否启动） */
const QUERY_METHODS = [
  'countDocuments',
  'estimatedDocumentCount',
  'find',
  'findOne',
  'aggregate',
  'distinct',
];

/**
 * 从 require 行抽出 AuditLog 模型的本地别名（含解构），只认 models/AuditLog 这条路径。
 * 不加这层会误伤：任意对象上的同名方法（IPBlacklist.countDocuments(...)）
 * 也在断言窗口里，但与本闸要防的"缓冲没开"无关。
 * @param {string} source 已剥注释的源码
 * @returns {string[]}
 */
function auditModelAliases(source) {
  const alias = new Set();
  const q = '[' + QS + ']';
  const direct = new RegExp(
    'const\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\s*\\(\\s*' +
      q +
      '[^' +
      QS +
      ']*models/AuditLog' +
      q +
      '\\s*\\)',
    'g'
  );
  for (const m of source.matchAll(direct)) alias.add(m[1]);
  const decomp = new RegExp(
    'const\\s*\\{([^}]*)\\}\\s*=\\s*require\\s*\\(\\s*' +
      q +
      '[^' +
      QS +
      ']*models/AuditLog' +
      q +
      '\\s*\\)',
    'g'
  );
  for (const m of source.matchAll(decomp)) {
    for (const part of m[1].split(',')) {
      const name = part.split(':').pop().trim();
      if (name) alias.add(name);
    }
  }
  return [...alias];
}

/** 断言链只到**本条语句结束**为止：240 字的裸窗口会跨到下一条语句去，把邻居的 toHaveLength(0)
 * 读成"这个查询的空洞断言"。链式写法（expect(x)\n .toHaveLength(0)）仍被覆盖，因为切点是分号。 */
function chainFrom(source, idx) {
  const semi = source.indexOf(';', idx);
  const stop = semi === -1 ? idx + ASSERT_CHAIN_CHARS : Math.min(semi + 1, idx + ASSERT_CHAIN_CHARS);
  return source.slice(idx, stop);
}

/**
 * 内联形态：查询本身就写在某个 expect( 的实参里 ⇒ 断言对象就是这个查询。
 * 必须真的在实参里：查询之前若已出现语句结束符（或已挂上链式匹配子），那只是"上一条
 * 无关断言离得近"（ipList 的 `expect(res.status).toBe(403);` 与后面的 findOne 就是这种距离误判）。
 * @returns {number|null} 命中的 expect( 下标（取最近的一个）
 */
function inlineExpectAtFrom(source, expectAt, absIdx) {
  let inlineAt = null;
  for (const idx of expectAt) {
    if (idx >= absIdx || absIdx - idx >= ASSERT_CHAIN_CHARS) continue;
    if (/;|\)\s*\./.test(source.slice(idx, absIdx))) continue;
    inlineAt = idx;
  }
  return inlineAt;
}

/** 站点是否"空洞断言"：内联链里带空洞匹配子，或绑定的变量在空洞链里出现过 */
function zeroForSite(source, inlineAt, bound) {
  if (inlineAt !== null && isZeroAssertion(chainFrom(source, inlineAt))) return true;
  return bound.used && bound.zero;
}

/**
 * 找出文件里"对 AuditLog 的查询"及其断言形态。
 * asserted：该查询所在行之后 ASSERT_WINDOW 行内出现了 expect（覆盖 `await` 后直接 toBe 的写法）；
 * zero    ：该窗口里出现了零值断言（toBe(0) / toHaveLength(0) / toEqual([]) / toBeFalsy()）。
 * @param {string} source 已剥注释的源码
 * @returns {{aliases: string[], sites: {line:number, method:string, asserted:boolean, zero:boolean}[]}}
 */
function auditQuerySites(source) {
  const aliases = auditModelAliases(source);
  const sites = [];
  if (aliases.length === 0) return { aliases, sites };
  const lines = source.split(/\r?\n/);
  // 行首绝对偏移：把"行内匹配"换算成"整串偏移"，才能判"查询是否落在某个 expect 的开窗内"。
  // 必须按**原文**的换行下标算：本仓的用例是 CRLF，而 split(/\r?\n/) 已经把 \r 吃掉了，
  // 拿"行长 +1"累加会让每一行偏移 1 字符、越往后越飘（实测第一版把 args 取成了别的行）。
  const lineStart = [];
  {
    let acc = 0;
    for (const line of lines) {
      lineStart.push(acc);
      acc += line.length;
      if (source[acc] === '\r' && source[acc + 1] === '\n') acc += 2;
      else if (source[acc] === '\n') acc += 1;
    }
  }
  // 全部 expect( 的位置：断言必须与「查询结果」绑定，而不是"附近恰好有个 expect"。
  // 窗口式的旧写法把 reportExportTruncationHeader 的 spy 断言、permissionUser 的
  // push 数组断言都算成了"在断言这个查询"，本闸上线时那 4 个文件就会被无理由判红。
  const expectAt = [];
  for (const m of source.matchAll(/\bexpect\s*\(/g)) expectAt.push(m.index);
  const aliasAlt = '(?:' + aliases.map((a) => a.replace(/[$]/g, '\\$')).join('|') + ')';
  const methodAlt = '(?:' + QUERY_METHODS.join('|') + ')';
  /** 结果被绑到哪个变量上（含 `const x = await Alias.find(` 的跨行链式写法） */
  const boundNameAt = (i) => {
    const pat = new RegExp(
      // 声明或**纯赋值**都算结果绑定：`audit = await Alias.findOne(` 是 waitFor 轮询里最常见的写法
      '(?:const\\s+|let\\s+|var\\s+)?([A-Za-z_$][\\w$]*)\\s*=\\s*\\(?\\s*(?:await\\s+)?' +
        aliasAlt +
        '\\s*\\.\\s*' +
        methodAlt
    );
    for (let k = 0; k <= 2; k += 1) {
      const idx = i - k;
      if (idx < 0) break;
      const m = pat.exec(lines[idx]);
      if (m) return m[1];
    }
    return null;
  };
  /** 某个变量在哪些 expect 链里出现过；出现过即为"真被断言"，链里带空洞匹配子即为"空洞断言" */
  const verdictForName = (name) => {
    const useRe = new RegExp('\\b' + name + '\\b');
    let used = false;
    let zero = false;
    for (const idx of expectAt) {
      const win = chainFrom(source, idx);
      if (!useRe.test(win)) continue;
      used = true;
      if (isZeroAssertion(win)) zero = true;
    }
    return { used, zero };
  };
  const re = new RegExp(
    '(?:' + aliases.map((a) => a.replace(/[$]/g, '\\$')).join('|') + ')\\s*\\.\\s*(' +
      QUERY_METHODS.join('|') +
      ')\\b',
    'g'
  );
  for (let i = 0; i < lines.length; i += 1) {
    re.lastIndex = 0;
    const m = re.exec(lines[i]);
    if (!m) continue;
    // `Alias.method.bind(Alias)` 只是取函数引用（spy 包装用），不是一次查询 ⇒ 不是断言对象。
    // 不排除它会把 "const original = AuditLog.countDocuments.bind(AuditLog)" 这类
    // 纯脚手架算成查询点，给将来安全的文件制造假红。
    if (/^\s*\.\s*bind\s*\(/.test(lines[i].slice(m.index + m[0].length))) continue;
    const absIdx = lineStart[i] + m.index;
    // ① 内联：查询本身就写在某个 expect( 的开窗里 ⇒ 断言对象就是这个查询
    const inlineAt = inlineExpectAtFrom(source, expectAt, absIdx);
    // ② 绑定：`const docs = await AuditLog.find(...)` ⇒ 之后对 docs 的 expect 是断言对象
    const name = boundNameAt(i);
    const bound = name ? verdictForName(name) : { used: false, zero: false };
    const asserted = inlineAt !== null || bound.used;
    const zero = zeroForSite(source, inlineAt, bound);
    const paren = lines[i].indexOf('(', m.index + m[0].length);
    sites.push({
      line: i + 1,
      method: m[1],
      binding: name,
      asserted,
      zero,
      args: paren === -1 ? null : firstArgumentText(source, lineStart[i] + paren),
    });
  }
  return { aliases, sites };
}

/**
 * 单文件判定。
 * @param {string} source 文件原文
 * @returns {{httpDriven:boolean, bufferControl:boolean, assertedQueries:number, zeroAssertions:number, suspect:boolean}}
 *   suspect=true 即「驱动 HTTP + 断言审计集合结果 + 没让缓冲动起来」——本闸的红条件。
 */
function analyzeFile(source) {
  const code = stripComments(String(source));
  const { sites } = auditQuerySites(code);
  const asserted = sites.filter((s) => s.asserted);
  const httpDriven = HTTP_RE.test(code);
  const bufferControl = CONTROL_RE.test(code);
  return {
    httpDriven,
    bufferControl,
    pushObserved: PUSH_OBSERVED_RE.test(code),
    assertedQueries: asserted.length,
    zeroAssertions: asserted.filter((s) => s.zero).length,
    sites: asserted.map((s) => ({
      line: s.line,
      method: s.method,
      binding: s.binding,
      zero: s.zero,
      args: s.args,
    })),
    suspect: httpDriven && asserted.length > 0 && !bufferControl,
  };
}

/**
 * 扫描一棵测试树，只返回 suspect 条目。
 * @param {string} dir 绝对路径
 * @param {string} root 仓库根（用于产出仓库相对路径）
 * @returns {{rel:string, file:string, result:object}[]}
 */
function scanTree(dir, root) {
  const out = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'coverage') continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.test.js')) {
        const result = analyzeFile(fs.readFileSync(full, 'utf8'));
        if (result.suspect) {
          out.push({
            rel: path.relative(root, full).split(path.sep).join('/'),
            file: full,
            result,
          });
        }
      }
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return out;
}

module.exports = {
  stripComments,
  auditModelAliases,
  auditQuerySites,
  analyzeFile,
  scanTree,
  HTTP_RE,
  CONTROL_RE,
  PUSH_OBSERVED_RE,
  isZeroAssertion,
  MATCHER_RE,
  firstArgumentText,
  QUERY_METHODS,
  ASSERT_WINDOW,
  ASSERT_CHAIN_CHARS,
};
