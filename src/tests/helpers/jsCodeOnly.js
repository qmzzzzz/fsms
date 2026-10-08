/**
 * 「只剩代码」视图（测试辅助）
 *
 * 为什么要抽出来：本仓已有四份逐字复制的实现（shutdownBudgetContract、
 * shutdownBudget 的兄弟套件、logShipperShutdownWiring、websocketAuthGhostConnection 等）。
 * 文本型闸门的语义全在这十几行里，复制一份就等于复制一份"到底什么算注释"的口径 ——
 * 任一处改坏，另一处仍然绿。新写的闸一律从这里取。
 * （既有四份暂不合并：其中一份是并行会话的文件，避免顺手改别人的在途测试。）
 *
 * 用途：任何"按源码文本判定"的闸门都必须跑在这个视图上，否则注释可以双向骗它：
 *  1) 骗绿 —— 在注释里补一个被要求的调用串，然后把真实调用删掉；
 *  2) 骗红 —— 在注释里写下本仓惯例要记录的反例（F-145 两向实测）。
 *
 * 【实现形状：单遍状态机，而不是两次 replace】
 * 曾经这里是"先全局剥块注释、再按行剥行注释"。那个顺序不安全：行注释里只要出现
 * 块的起始两字符（本仓真实写法是给通配模式打比方，例如说明某脚本的 glob），
 * 从这个起始到**下一个真正的块结尾**之间的真实代码会被整段抹成空格 ——
 * 判据看不见代码、注释却看得见，假绿可以双向制造，而且不需要任何人在注释里写反例。
 * 反过来"先剥行注释"也不安全：块注释里的 URL（http 协议前缀）会被行注释规则吃掉，
 * 块反而永不闭合，之后的代码同样整段消失。
 * 唯一稳的做法是**一次扫描带状态**：代码 / 行注释 / 块注释 / 字符串 / 模板串（含 `${}` 嵌套）/
 * 正则字面量。本文件的判据口径就以此为准，任何复制品都只是在复制一份可能改坏的口径。
 *
 * 【保留的现网契约】
 *  1. 块注释按**等长空格**抹（保行保列），与 deploy/nginxProxyContract.test.js:53-61 同口径；
 *  2. 整行行注释：jsCodeOnly 连行一起删，jsCodeOnlyKeepingLines 抹成空行保行号；
 *     判定用**原始行**（行首只有空白再跟两个斜杠），不看屏蔽后的视图，避免行号口径漂移；
 *  3. 入口处先把 CRLF 归一成 LF（本仓 core.autocrlf=true 且 prettier 是 endOfLine:"auto"，
 *     Windows 工作区是 CRLF 而 CI 是 LF；不归一的话每行尾部挂一个回车，
 *     锚到行尾的判据只在其中一侧成立）。
 *
 * 【相对旧实现的唯一行为改进】字符串 / 模板文本 / 正则字面量里的"两个斜杠"不再被当成注释，
 * 所以早先那条「涉及 URL 字面量的判定不要用本视图」的限制已解除。方向上本视图**只会少抹、
 * 不会多抹**：正则字面量的起始按经典启发式判定（前一个有效字符不是标识符 / 数字 / 右括号 /
 * 右方括号，或前一个关键字是 return / typeof / instanceof / in / of / void / delete / case /
 * do / else / yield / await 之一），且到行尾找不到未转义的收尾斜杠就退回普通字符。
 * 两处退化都只可能"少抹"，绝不会把真代码误当注释吃掉。
 * 模板插值里的起始两字符（美元加左花括号）原样保留：它是语法不是注释 ——
 * 实测有站点计数判据就匹配模板插值前缀，把它抹掉会静默改变判据面积。
 *
 * @param {string} src JS 源码
 * @returns {string} 抹掉块注释、整行注释（**连行一起删**）与行尾注释后的 LF 视图
 */
function jsCodeOnly(src) {
  return view(src, false);
}

/**
 * 同一套"什么算注释"的口径，但**行号保持不变**：整行注释被抹成空行而不是删掉。
 *
 * 为什么要有第二个视图：jsCodeOnly 的整行注释是直接 filter 掉的——于是它的返回值行数
 * 一定 ≤ 源码行数，偏移量正好等于被删掉的注释行数。只做"某个串在不在"的判据不受影响，
 * 但**任何要报告 file:line 的判据用它就会报错行号**：本仓第 15 轮写 stubReturnTypeParity 时
 * 用 jsCodeOnly 扫桩站点，报出来的行号比真实行号小了 55（那 55 行是前面的注释），
 * 照着它给的红讯去改代码会改到别处。判据口径仍然只有一份（view），只是多一个视图。
 *
 * @param {string} src JS 源码
 * @returns {string} 行号与 src 一一对应的「只剩代码」LF 视图
 */
function jsCodeOnlyKeepingLines(src) {
  return view(src, true);
}

const REGEX_ALLOWED_PREV = new Set([
  '(',
  ',',
  '=',
  ':',
  '!',
  '&',
  '|',
  '?',
  '{',
  '}',
  '[',
  ';',
  '+',
  '-',
  '*',
  '%',
  '~',
  '^',
  '<',
  '>',
  '/',
]);

const REGEX_ALLOWED_KEYWORDS = new Set([
  'return',
  'typeof',
  'instanceof',
  'in',
  'of',
  'void',
  'delete',
  'case',
  'do',
  'else',
  'yield',
  'await',
]);

/** 前一个有效字符 / 关键字决定了这个斜杠是"除"还是"正则开头" */
function regexMayStart(prevSig, prevWord) {
  if (prevSig === undefined) return true;
  if (REGEX_ALLOWED_KEYWORDS.has(prevWord)) return true;
  return REGEX_ALLOWED_PREV.has(prevSig);
}

/** 从 start 起找未转义的收尾斜杠（跳过字符类）；跨行则返回 -1（那多半不是正则） */
function findRegexClose(src, start) {
  let inClass = false;
  for (let k = start; k < src.length; k += 1) {
    const c = src[k];
    if (c === '\n') return -1;
    if (c === '\\') {
      k += 1;
      continue;
    }
    if (c === '[') {
      inClass = true;
      continue;
    }
    if (c === ']') {
      inClass = false;
      continue;
    }
    if (c === '/' && !inClass) return k;
  }
  return -1;
}

/**
 * 扫描态：out 与输入逐位对齐，stack 承载 字符串/模板/正则/插值 的嵌套
 */
function newState(n) {
  return { out: new Array(n), stack: [], mode: 'code', prevSig: undefined, prevWord: '' };
}

function put(st, k, ch) {
  st.out[k] = ch;
}

/** 记录「前一个有效字符」：空白与注释不计；非标识符字符清空 prevWord */
function sig(st, ch) {
  if (ch === undefined) return;
  if (/\s/.test(ch)) return;
  st.prevSig = ch;
  st.prevWord = /[A-Za-z0-9_$]/.test(ch) ? st.prevWord + ch : '';
}

/** 原样抄写：字符串 / 模板 / 正则的**内容**不屏蔽，里面的两个斜杠不是注释 */
function copyChar(st, i, c) {
  put(st, i, c);
  return i + 1;
}

function copyEscaped(st, i, src) {
  put(st, i, src[i]);
  put(st, i + 1, src[i + 1]);
  return i + 2;
}

function stepLine(st, i, src) {
  if (src[i] === '\n') {
    put(st, i, '\n');
    st.mode = 'code';
    return i + 1;
  }
  put(st, i, ' ');
  return i + 1;
}

function stepBlock(st, i, src) {
  if (src[i] === '*' && src[i + 1] === '/') {
    put(st, i, ' ');
    put(st, i + 1, ' ');
    st.mode = 'code';
    return i + 2;
  }
  put(st, i, src[i] === '\n' ? '\n' : ' ');
  return i + 1;
}

function stepString(st, i, src) {
  const c = src[i];
  if (c === '\\') return copyEscaped(st, i, src);
  // 未闭合的串：就地放弃，绝不吃掉整行代码
  if (c === '\n') {
    st.stack.pop();
    st.mode = 'code';
    return i + 1;
  }
  if (c === st.stack[st.stack.length - 1].quote) {
    st.stack.pop();
    st.mode = 'code';
    sig(st, c);
  }
  return copyChar(st, i, c);
}

function stepRegex(st, i, src) {
  const c = src[i];
  const frame = st.stack[st.stack.length - 1];
  if (c === '\\') return copyEscaped(st, i, src);
  if (c === '[') {
    frame.inClass = true;
    return copyChar(st, i, c);
  }
  if (c === ']') {
    frame.inClass = false;
    return copyChar(st, i, c);
  }
  if (c === '/' && !frame.inClass) return closeRegex(st, i, src);
  // 判定失误（那其实不是正则）⇒ 退回普通字符，从这根斜杠重新开始判
  if (c === '\n') {
    st.stack.pop();
    st.mode = 'code';
    return i;
  }
  return copyChar(st, i, c);
}

/** 收尾斜杠 + 标志位（g/i/m…）；标志位只在 src 上读，out 里那些位置还是空的 */
function closeRegex(st, i, src) {
  let k = copyChar(st, i, '/');
  while (k < src.length && /[a-z]/.test(src[k])) k = copyChar(st, k, src[k]);
  st.stack.pop();
  st.mode = 'code';
  st.prevSig = '/';
  st.prevWord = '';
  return k;
}

function stepTemplate(st, i, src) {
  const c = src[i];
  if (c === '\\') return copyEscaped(st, i, src);
  if (c === '`') {
    st.stack.pop();
    st.mode = 'code';
    sig(st, c);
    return copyChar(st, i, c);
  }
  // 插值起始两字符是语法不是注释：原样保留（实测有站点计数判据就匹配这个前缀）
  if (c === '$' && src[i + 1] === '{') {
    st.stack.push({ kind: 'interp' });
    put(st, i, '$');
    put(st, i + 1, '{');
    st.mode = 'code';
    st.prevSig = '{';
    st.prevWord = '';
    return i + 2;
  }
  return copyChar(st, i, c);
}

function stepCode(st, i, src) {
  const c = src[i];
  if (c === '/') return stepSlash(st, i, src);
  if (c === '"' || c === "'") {
    st.stack.push({ kind: 'string', quote: c });
    st.mode = 'string';
    sig(st, c);
    return copyChar(st, i, c);
  }
  if (c === '`') {
    st.stack.push({ kind: 'template' });
    st.mode = 'template';
    sig(st, c);
    return copyChar(st, i, c);
  }
  if (c === '}' && st.stack.length && st.stack[st.stack.length - 1].kind === 'interp') {
    st.stack.pop();
    st.mode = 'template';
  }
  sig(st, c);
  return copyChar(st, i, c);
}

function stepSlash(st, i, src) {
  if (src[i + 1] === '/') {
    put(st, i, ' ');
    put(st, i + 1, ' ');
    st.mode = 'line';
    return i + 2;
  }
  if (src[i + 1] === '*') {
    put(st, i, ' ');
    put(st, i + 1, ' ');
    st.mode = 'block';
    return i + 2;
  }
  if (regexMayStart(st.prevSig, st.prevWord) && findRegexClose(src, i + 1) > 0) {
    st.stack.push({ kind: 'regex', inClass: false });
    st.mode = 'regex';
    return copyChar(st, i, '/');
  }
  sig(st, '/');
  return copyChar(st, i, '/');
}

const STEPS = {
  line: stepLine,
  block: stepBlock,
  string: stepString,
  regex: stepRegex,
  template: stepTemplate,
  code: stepCode,
};

/**
 * 单遍扫描：注释字符→空格（换行保留），其它字符原样；行号与列位与输入逐字符一致。
 * 未闭合的串/正则就地放弃、未闭合的块注释吃到 EOF —— 两者都是「真实语法就是这样」，
 * 本仓 js 文件上实测无一命中（块注释不闭合本身就是语法错误）。
 *
 * 拆成一堆 step* 不是为了抽象：整段塞进一个 while 会把判据口径摊到 41 个分支里
 * （棘轮按函数计复杂度，超限即红），而这份口径是全仓文本闸门的地基，必须能逐条对着读。
 */
function maskComments(src) {
  const st = newState(src.length);
  let i = 0;
  while (i < src.length) i = STEPS[st.mode](st, i, src);
  const n = src.length;
  for (let k = 0; k < n; k += 1) if (st.out[k] === undefined) st.out[k] = '';
  st.out.length = n;
  return st.out.join('');
}

/** 唯一的注释屏蔽实现：keepLineNumbers=true 时整行注释抹成空行而非删除 */
function view(src, keepLineNumbers) {
  const lf = String(src).replace(/\r\n/g, '\n');
  const rawLines = lf.split('\n');
  const viewLines = maskComments(lf).split('\n');
  const kept = [];
  for (let k = 0; k < viewLines.length; k += 1) {
    const raw = rawLines[k] === undefined ? '' : rawLines[k];
    if (/^\s*\/\//.test(raw)) {
      if (keepLineNumbers) kept.push('');
      continue;
    }
    kept.push(viewLines[k]);
  }
  return kept.join('\n');
}

module.exports = { jsCodeOnly, jsCodeOnlyKeepingLines };
