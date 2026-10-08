/**
 * `codeError` 调用点与错误码注册表的文本扫描器（测试辅助，第 28 轮）
 *
 * 为什么抽出来：这把闸的**全部**判据面积都由"扫描得到什么"决定，扫描器一错，判据就
 * 错得无声无息（第 3 族：仪器比判据宽松）。抽成单点实现后，门禁可以用合成样例直接打它，
 * 变异台账也能把靶打在扫描器上，而不是打在"顺手抄了一份"的门禁正文里。
 *
 * 三条口径：
 *  1. 只认 `<点号>codeError(` 形式的调用——`static codeError(` 这类定义点/裸名不算调用，
 *     否则"码表里有这个码"会被误判成"有调用点"；
 *  2. 括号配对必须跳过字符串、模板串（含 `${}` 嵌套）里的假括号——本仓真实调用点里
 *     就同时存在 `'}'` 与 `` `${'y}'}` `` 两种诱饵（实测）；
 *  3. 一律跑在 helpers/jsCodeOnly 的"只剩代码"视图上（注释里的示例文本不算靶），
 *     且用 KeepingLines 视图，红讯报的 file:line 才对得上。
 */
const fs = require('fs');
const path = require('path');
const { jsCodeOnlyKeepingLines } = require('./jsCodeOnly');

const BACKTICK = '`';
const QUOTE_SINGLE = "'";
const QUOTE_DOUBLE = '"';

const skipQuoted = (text, i) => {
  const quote = text[i];
  let j = i + 1;
  while (j < text.length) {
    if (text[j] === '\\') j += 2;
    else if (text[j] === quote) return j + 1;
    else j += 1;
  }
  return j;
};

const skipTemplate = (text, i) => {
  let j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === '\\') j += 2;
    else if (c === BACKTICK) return j + 1;
    else if (c === '$' && text[j + 1] === '{') j = skipInterp(text, j + 1);
    else j += 1;
  }
  return j;
};

/** `${` 起始的插值段：内部可以再有引号、模板、花括号 */
const skipInterp = (text, i) => {
  let depth = 1;
  let j = i + 1;
  while (j < text.length && depth > 0) {
    const c = text[j];
    if (c === QUOTE_SINGLE || c === QUOTE_DOUBLE) {
      j = skipQuoted(text, j);
      continue;
    }
    if (c === BACKTICK) {
      j = skipTemplate(text, j);
      continue;
    }
    if (c === '{') depth += 1;
    else if (c === '}') depth -= 1;
    j += 1;
  }
  return j;
};

/** 取 `codeError(` 之后的参数段（open 指向左括号后的第一个字符） */
const readArgs = (text, open) => {
  let depth = 1;
  let j = open;
  while (j < text.length) {
    const c = text[j];
    if (c === QUOTE_SINGLE || c === QUOTE_DOUBLE) {
      j = skipQuoted(text, j);
      continue;
    }
    if (c === BACKTICK) {
      j = skipTemplate(text, j);
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) return { args: text.slice(open, j), end: j + 1 };
    }
    j += 1;
  }
  return null;
};

/**
 * 参数段按**顶层逗号**切分（引号、模板串、括号内部的分隔符不算）。
 * 存在的理由：`codeError(res, X, …)` 的"码槽"只能是第二参数段。若在整段参数里正则找
 * 第一个 `'UPPER_SNAKE'`，就会把 `codeError(res, dyn, { message: 'SOME_CODE' })` 这种
 * 站点误记成"SOME_CODE 的字面量调用点且它传了 message"——凭空造出一条调用点证据，
 * 既能把孤儿（#12）压掉，也能把泄漏（#11）判成安全。
 */
const splitArgs = (args) => {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let j = 0; j < args.length; j += 1) {
    const c = args[j];
    if (c === QUOTE_SINGLE || c === QUOTE_DOUBLE) {
      j = skipQuoted(args, j) - 1;
      continue;
    }
    if (c === BACKTICK) {
      j = skipTemplate(args, j) - 1;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) {
      parts.push(args.slice(start, j));
      start = j + 1;
    }
  }
  parts.push(args.slice(start));
  return parts.map((p) => p.replace(/\s+/g, ' ').trim());
};

/** 取 codeError 第二参数段作为码槽；退化（参数不足）时返回空串 */
const codeSlotOf = (args) => {
  const parts = splitArgs(args);
  return parts.length >= 2 ? parts[1] : '';
};

/**
 * 参数段里 `message:` 值的引号类型与内容；值不是字面量时 content 为空。
 *
 * `falsyLiteral` 是本轮补的一格：响应侧取的是 `options.message || def.message`，所以
 * `message: undefined` / `message: null` / `message: ''` 这三种"写了但等于没写"的赋值
 * **仍然会**回退到注册表默认消息。旧实现只看"`message:` 这个键在不在"，会把它们判成
 * passesMessage=true —— 一条恰好会泄漏占位符的调用点被读成安全（第 3 族：仪器比判据宽松）。
 * 实测本仓生产代码今天零处这种写法，所以修的是仪器的牙，不是仓库的病；牙齿由门禁的
 * 合成样例腿（#14 的 falsy 臂）钉住，两条真值腿（#15/#16）负责"今天仍然没有"。
 */
const FALSY_VALUE = /^(undefined|null)(?![\w$])|^(['"])\2/;

const messageFieldOf = (args) => {
  const hit = /\bmessage\s*:\s*/.exec(args);
  if (!hit) return null;
  const j = hit.index + hit[0].length;
  const q = args[j];
  const falsyLiteral = FALSY_VALUE.test(args.slice(j));
  if (q === QUOTE_SINGLE || q === QUOTE_DOUBLE) {
    const close = skipQuoted(args, j);
    return { quote: q, content: args.slice(j + 1, close - 1), falsyLiteral };
  }
  if (q === BACKTICK) {
    const close = skipTemplate(args, j);
    return { quote: BACKTICK, content: args.slice(j + 1, close - 1), falsyLiteral };
  }
  return { quote: 'expr', content: '', falsyLiteral };
};

/**
 * 两个判据位：
 *  - passesMessage：调用点自己给了**真会生效**的 message（写了 falsy 字面量等于没给）
 *  - literalPlaceholder：给的那份是**单/双引号**字符串且里面带占位符前缀
 *    （模板串里的占位符是真插值，不算缺陷）
 */
const classifyMessage = (args, placeholder) => {
  const field = messageFieldOf(args);
  const passesMessage = field !== null && field.falsyLiteral === false;
  const literalPlaceholder =
    Boolean(field) &&
    (field.quote === QUOTE_SINGLE || field.quote === QUOTE_DOUBLE) &&
    field.content.indexOf(placeholder) >= 0;
  return { passesMessage, literalPlaceholder };
};

/**
 * 扫出一段代码里的全部 codeError 调用。
 *
 * 码槽口径（本轮实测改过，理由见 splitArgs 的注释）：只有**第二参数段整体是一个
 * `'UPPER_SNAKE'` 字面量**时才算"这个码的字面量调用点"。旧实现在整段参数里正则取第一个
 * `'UPPER_SNAKE'`，会把两类站点读歪：
 *  - `codeError(res, dyn, { message: 'SOME_CODE' })` ⇒ 凭空给 SOME_CODE 造一条"且传了 message"
 *    的调用点（既能让 #11 把泄漏判成安全，也能让 #12 把孤儿压掉）；
 *  - `codeError(res, flag ? 'A' : 'B')` ⇒ 只收到 A，B 的调用点被吞掉。
 * 新口径把非纯字面量的槽拆成两类：
 *  - `slotCodes` 非空（槽里写着字面量分支）⇒ 这些码照常进索引，泄漏判据看得见；
 *  - `slotCodes` 为空（纯变量/属性访问）⇒ opaque 站点，"能取到哪些码"不在调用点文本里，
 *    必须由门禁侧逐条登记闭合码集（dynamicIndex 就是给它用的）。
 * 实测改动前后：站点数 367→367、索引码集合 188→188 且双向差集为空、孤儿集不变；
 * 唯一新增的可见面是 `src/middleware/logoutAuth.js:45` 的 `AUTH_TOKEN_MISSING`（此前被吞）。
 */
const LITERAL_SLOT = /^(['"])([A-Z0-9_]{3,})\1$/;
const SLOT_LITERAL = /['"]([A-Z0-9_]{3,})['"]/g;

/** 码槽里的全部字面量码（`a ? 'X' : 'Y'` 这种闭合表达式） */
const slotLiterals = (slot) => {
  const out = [];
  SLOT_LITERAL.lastIndex = 0;
  let m;
  while ((m = SLOT_LITERAL.exec(slot)) !== null) out.push(m[1]);
  return out;
};

const scanCalls = (text, placeholder) => {
  const needle = 'codeError(';
  const found = [];
  let from = 0;
  for (;;) {
    const at = text.indexOf(needle, from);
    if (at < 0) break;
    const open = at + needle.length;
    let k = at - 1;
    while (k >= 0 && (text[k] === ' ' || text[k] === '\t')) k -= 1;
    if (text[k] !== '.') {
      from = open;
      continue;
    }
    const parsed = readArgs(text, open);
    if (!parsed) {
      from = open;
      continue;
    }
    const line = text.slice(0, at).split('\n').length;
    const slot = codeSlotOf(parsed.args);
    const pure = LITERAL_SLOT.exec(slot);
    const code = pure ? pure[2] : null;
    const slotCodes = code ? [] : slotLiterals(slot);
    found.push({
      code,
      slot,
      slotCodes,
      dynamic: !code,
      opaque: !code && slotCodes.length === 0,
      line,
      ...classifyMessage(parsed.args, placeholder),
    });
    from = parsed.end;
  }
  return found;
};

/**
 * 注册表解析：顶层码 + 每条默认消息的引号类型与内容。
 *
 * 一律按**偏移量**扫，不按行扫再取行尾。原因（实测踩过）：`src/utils/errorCodes.js` 里有 3 条
 * 写成
 *     message:
 *       '全网段（${normalizedIP}）…',
 * 即 `message:` 后面本行没有值。旧的分行实现把 content 取成空串，于是**整整 3 个占位符码从判据
 * 面积里消失**（15 vs 真值 18），而"解析条数 == message 行数"这条自洽检查照样通过——条数对得上，
 * 内容取错了。`\s*` 跨换行取值就不再关心排版。
 */
const parseRegistry = (text) => {
  const messages = [];
  const keys = [];
  const keyRe = /^ {2}([A-Z0-9_]+): \{/gm;
  const marks = [];
  let km;
  for (;;) {
    km = keyRe.exec(text);
    if (!km) break;
    marks.push({ key: km[1], pos: km.index });
    keys.push(km[1]);
  }
  const msgRe = /\bmessage:/g;
  let mm;
  for (;;) {
    mm = msgRe.exec(text);
    if (!mm) break;
    // 跳过冒号后任意空白（含换行）再取值的引号
    let j = mm.index + mm[0].length;
    while (j < text.length && /\s/.test(text[j])) j += 1;
    const q = text[j];
    let quote = 'expr';
    let content = '';
    if (q === QUOTE_SINGLE || q === QUOTE_DOUBLE) {
      const close = skipQuoted(text, j);
      quote = q;
      content = text.slice(j + 1, close - 1);
    } else if (q === BACKTICK) {
      const close = skipTemplate(text, j);
      quote = BACKTICK;
      content = text.slice(j + 1, close - 1);
    }
    const owner = marks.filter((m) => m.pos < mm.index).pop();
    messages.push({
      key: owner ? owner.key : null,
      line: text.slice(0, mm.index).split('\n').length,
      quote,
      content,
    });
    msgRe.lastIndex = j;
  }
  return { messages, keys };
};

const placeholderCodesOf = (messages, placeholder) =>
  messages.filter((m) => m.content.indexOf(placeholder) >= 0);

/**
 * 某个对象属性名被赋的**字符串字面量**值（闭合集提取器）。
 *
 * 为什么需要它：opaque 动态站点（`codeError(res, forbiddenCode)`）"能取到哪些码"不在调用点
 * 文本里，但如果那些码是**按属性名逐字传入**的（`guardRoleWithinOperatorLevel({…,
 * forbiddenCode: 'ROLE_UPDATE_FORBIDDEN'})`、`REPORT_TARGET_KINDS` 里的 `notFound: '…'`），
 * 那这个可达集就能从源码里现采，而不是靠门禁正文手抄一份。手抄的那份会在"表加了条目"之后
 * 静默失真（第 1 族）；现采 + 与登记值对账，两个方向都能红。
 *
 * `nonLiteral` 是与闭合并列的另一半：一旦有人把值换成变量（`forbiddenCode: pick(req)`），
 * 提取器就说不出可达集了——这时必须让腿响，而不是把"看不见"当成"没有"。
 */
const literalValuesForProps = (text, names) => {
  const values = [];
  const nonLiteral = [];
  for (const name of names) {
    const re = new RegExp(`\\b${name}\\s*:\\s*([^,}\\r\\n]+)`, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      const raw = m[1].trim();
      const lit = /^(['"])([A-Z0-9_]{3,})\1$/.exec(raw);
      if (lit) values.push(lit[2]);
      else nonLiteral.push(`${name}: ${raw}`);
    }
  }
  return { values: [...new Set(values)].sort(), nonLiteral };
};

/** 孤儿：有占位符默认消息、却没有任何生产调用点的码 */
const orphansOf = (codes, index) => codes.filter((code) => (index.get(code) || []).length === 0);

/**
 * 泄漏：占位符码的调用点里没传 message 的那些。
 * `code` 必须写在展开之后（覆盖 call 自带的那份）：索引的键才是"哪个占位符码在泄漏"的权威，
 * 而动态分支站点自带的 `call.code` 是 `null`。旧写法 `{ code, ...call }` 会让红讯报成
 * `null @ file:line`，把最关键的一格信息丢掉——判据全绿时看不见（今天泄漏集为空，这个字段
 * 从来没被打印过），是 #14 的合成分支样例把它抓出来的。
 */
const leaksOf = (codes, index) => {
  const rows = [];
  for (const code of codes) {
    for (const call of index.get(code) || []) {
      if (!call.passesMessage) rows.push({ ...call, code });
    }
  }
  return rows;
};

/** 生产代码文件清单（src 全量减 src/tests，再加 scripts） */
const listProductionFiles = (root) => {
  const acc = [];
  const walk = (relDir) => {
    const abs = path.join(root, relDir);
    if (!fs.existsSync(abs)) return;
    for (const name of fs.readdirSync(abs).sort()) {
      if (name === 'node_modules' || name === '.git') continue;
      const rel = `${relDir}/${name}`;
      if (rel === 'src/tests') continue;
      if (fs.statSync(path.join(root, rel)).isDirectory()) walk(rel);
      else if (name.endsWith('.js')) acc.push(rel);
    }
  };
  walk('src');
  walk('scripts');
  return acc;
};

const codeOnlyFrom = (root, rel) =>
  jsCodeOnlyKeepingLines(fs.readFileSync(path.join(root, rel), 'utf8'));

/**
 * 把"每个文件扫到的调用点"建成 code -> calls 索引。
 * 抽成纯函数的理由（第 2 族）：合成样例必须能走**同一条**接线，否则"动态槽里的字面量分支
 * 要进索引"这类新增臂只有真树一条腿守着，门禁正文里抄一份对拍等于没抄。
 * 输入项：`{ file, calls }`（calls 来自 scanCalls）。
 */
const buildIndex = (items) => {
  const index = new Map();
  const dynamic = [];
  let total = 0;
  let scannedFiles = 0;
  for (const item of items) {
    if (item.calls.length === 0) continue;
    scannedFiles += 1;
    total += item.calls.length;
    for (const call of item.calls) {
      const site = { ...call, file: item.file };
      if (call.dynamic) {
        dynamic.push(site);
        // 槽里写着字面量分支 ⇒ 可达码集是文本可判的，照常进索引，泄漏判据覆盖得到；
        // opaque（纯变量）⇒ 只进 dynamic 数组，由门禁侧的闭合码集登记腿负责。
        for (const code of call.slotCodes) {
          if (!index.has(code)) index.set(code, []);
          index.get(code).push(site);
        }
        continue;
      }
      if (!index.has(call.code)) index.set(call.code, []);
      index.get(call.code).push(site);
    }
  }
  return {
    index,
    dynamic,
    opaque: dynamic.filter((c) => c.opaque),
    total,
    files: scannedFiles,
  };
};

/**
 * 全仓生产调用点索引（= 读文件 + buildIndex）。
 */
const indexProductionCalls = ({ root, files, placeholder }) =>
  buildIndex(
    files.map((rel) => ({ file: rel, calls: scanCalls(codeOnlyFrom(root, rel), placeholder) }))
  );

/**
 * 独立口径的占位符面积：**加载**码表后看每条 message 的真值里有没有占位符前缀。
 * 为什么要有第二套口径：本文件的判据面积完全来自 parseRegistry 的文本解析，而"解析条数 ==
 * 视图里的 message 行数"这种自洽检查**只保证条数**，不保证内容取对了（分行实现把 3 条换行排版
 * 的 message 取成空串时，条数照样相等）。真值口径来自另一条通路（模块加载后的字符串），两者
 * 必须双向相等，差集非空就是解析器有洞。循环依赖风险：errorCodes.js 目前是纯常量表；若将来它
 * 需要环境才能加载，这条腿会**响**而不是静默变绿，可以接受。
 */
const loadedPlaceholderCodes = (root, rel, placeholder) => {
  const mod = require(path.join(root, rel));
  const table = mod.ERROR_CODES || mod.default || mod;
  return Object.entries(table)
    .filter(
      ([, def]) => def && typeof def.message === 'string' && def.message.indexOf(placeholder) >= 0
    )
    .map(([key]) => key)
    .sort();
};

module.exports = {
  BACKTICK,
  QUOTE_SINGLE,
  QUOTE_DOUBLE,
  readArgs,
  splitArgs,
  codeSlotOf,
  slotLiterals,
  literalValuesForProps,
  scanCalls,
  classifyMessage,
  messageFieldOf,
  parseRegistry,
  placeholderCodesOf,
  orphansOf,
  leaksOf,
  buildIndex,
  listProductionFiles,
  indexProductionCalls,
  loadedPlaceholderCodes,
  codeOnlyFrom,
};
