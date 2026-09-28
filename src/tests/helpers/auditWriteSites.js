/**
 * 审计写入点扫描器（测试基建，非生产代码）
 *
 * 为什么抽出来共用（F-201b）：仓里有**两个**闸都依赖同一个事实——「src/ 里哪些 action
 * 真的会被写进审计集合」：
 *   · auditActionReconciliation.test.js —— 正向：写入集合 ⊆ 白名单（漏登记 ⇒ 库里查不出来）
 *   · auditActionReachability.test.js  —— 反向：白名单 ⊆ 路由派生 ∪ 写入集合 ∪ 永不产生清单
 * 两处各写一份判据时，两闸必然对「什么算写入」给出不同答案，而对账闸的结论只强于
 * 「两个实现都同意」的那部分。实测过的两种分叉：
 *   1) 反向闸原先用**裸正则**全文扫 `action: '...'`，于是
 *      `AuditLog.countDocuments({ action: 'login_failed' })`（securityController.js:306、
 *      securityAlert.js:399）这类**只读**上下文被当成写入点计入 —— 把源码里的
 *      'login_failed' 改成未登记的名字，反向闸照样判绿（正向闸 2 例转红）。
 *   2) 正向闸原先只认 `AuditLog.` / `auditBuffer.` 前缀，看不见模型静态方法**自身**
 *      决定的 action（recordLogin 的 `this.create({ action: 三元 })`）。
 * 判据只在这里实现一次；两个闸各自负责断言，不再各自负责取数。
 *
 * 口径与失败形态（改动前请先读 auditActionReconciliation.test.js 的文件头）：
 *   · 只认 WRITE_CALLS 五类调用形态，括号配平取实参，注释里的同形调用点跳过；
 *   · action 表达式解析不出来 ⇒ 进 unresolved **硬失败**，不得静默跳过；
 *   · 转发型（action 由调用方决定）进 forwarded 账，由用例钉死精确清单。
 */

const fs = require('fs');
const path = require('path');

const SRC_DIR = path.resolve(__dirname, '../..');
const REPO_ROOT = path.resolve(__dirname, '../../..');

/** 扫描目标：src/ 下全部生产代码（跳过 tests，测试自身的探针 action 不属生产写入） */
function listSourceFiles(dir = SRC_DIR, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listSourceFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/**
 * 判断 text 中 idx 处的字符是否落在**注释**里。
 *
 * 本扫描器用字符串 indexOf 认"写入调用点"，于是**注释里提到** `AuditLog.record(...)`
 * 也会被当成一个调用点：它解析不出 action（实参为空/不是对象），按"解析失败即硬失败"的
 * 口径直接记进 unresolved，把一条解释性注释变成 CI 红灯。
 * 那种红灯唯一的"便宜修法"是删掉注释——与本仓"WHY 必须写在代码旁边"的口径相反。
 *
 * 所以这里只加**注释识别**，不放宽任何代码判据：可执行的调用点仍按原口径解析，
 * 解析不出来照旧硬失败。
 */
function isInsideComment(text, idx) {
  const lineStart = text.lastIndexOf('\n', idx - 1) + 1;
  const prefix = text.slice(lineStart, idx);
  let quote = null;
  for (let i = 0; i < prefix.length; i += 1) {
    const ch = prefix[i];
    if (quote) {
      if (ch === '\\') i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      continue;
    }
    // 同一行里注释起始符之后的内容都不是代码
    if (ch === '/' && prefix[i + 1] === '/') return true;
  }
  // 行首即注释，或块注释的续行（'   // x'、' * x'、'/* x'）
  return /^\s*(?:\/\/|\*|\/\*)/.test(prefix);
}

/**
 * 从 src 文本中取出 openIdx（指向 '('）起配平括号的实参文本。
 * 配平期间正确跳过字符串/模板串与转义，避免实参里的括号造成提前截断。
 */
function readCallArgs(src, openIdx) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let i = openIdx; i < src.length; i += 1) {
    const ch = src[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return src.slice(openIdx + 1, i);
    }
  }
  return null;
}

/** 顶层（不在任何括号/字符串内）逗号切分实参 */
function splitTopLevelArgs(argsText) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let escaped = false;
  let buf = '';
  for (const ch of argsText) {
    if (escaped) {
      buf += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      buf += ch;
      escaped = true;
      continue;
    }
    if (quote) {
      buf += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      buf += ch;
      continue;
    }
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) depth -= 1;
    if (ch === ',' && depth === 0) {
      parts.push(buf);
      buf = '';
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) parts.push(buf);
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** 从 openIdx（指向 open 字符）起找配对的 close 字符位置；未闭合返回 -1 */
function findBalancedEnd(text, openIdx, open, close) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let i = openIdx; i < text.length; i += 1) {
    const ch = text[i];
    if (escaped) {
      escaped = false;
    } else if (ch === '\\') {
      escaped = true;
    } else if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
    } else if (ch === open) {
      depth += 1;
    } else if (ch === close) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** 取实参中第一个顶层对象字面量的内部文本（跳过嵌套括号与字符串） */
function firstObjectLiteral(argsText) {
  const openIdx = argsText.indexOf('{');
  if (openIdx === -1) return null;
  const endIdx = findBalancedEnd(argsText, openIdx, '{', '}');
  return endIdx === -1 ? null : argsText.slice(openIdx + 1, endIdx);
}

/** 顶层属性切分（按逗号），并取出名为 action 的属性值表达式 */
function extractActionExpr(argsText, mode) {
  if (mode === 'positional-2') return splitTopLevelArgs(argsText)[2] ?? null;
  const inner = firstObjectLiteral(argsText);
  if (inner == null) return null;
  for (const prop of splitTopLevelArgs(inner)) {
    const m = /^action\s*:\s*([\s\S]+)$/.exec(prop);
    if (m) return m[1].trim();
  }
  return null;
}

/** 解析 action 取值表达式 → 字面量数组；无法解析返回 null（调用方报错） */
function resolveActionExpr(expr, ctx, src) {
  if (expr == null) return null;
  const literal = /^'([^']*)'$/.exec(expr) || /^"([^"]*)"$/.exec(expr);
  if (literal) return [literal[1]];
  const ternary = /\?\s*'([^']+)'\s*:\s*'([^']+)'/.exec(expr);
  if (ternary) return [ternary[1], ternary[2]];
  const alertConst = /^ALERT_TYPES\.([A-Z_]+)$/.exec(expr);
  if (alertConst) {
    const value = ctx.ALERT_TYPES[alertConst[1]];
    return value ? [value] : null;
  }
  if (expr === 'meta.action') return [...ctx.earlyRejectionActions];
  // 同文件的字符串常量间接层：`const ACTION = 'x'; ... push({ action: ACTION })`。
  // 不认这一形态，写入点会从对账里**整个消失**（errorHandler 的截断更正事件就是这么溜过的：
  // 正向对账看不见它，反向可达性也看不见它，于是不登记的 action 双向都判"没问题"）。
  const ident = /^([A-Za-z_$][\w$]*)$/.exec(expr);
  if (ident && src) {
    const def = new RegExp(`const\\s+${ident[1]}\\s*=\\s*'([^']+)'`).exec(src);
    if (def) return [def[1]];
  }
  return null;
}

/**
 * `recordEarlyRejection` 的**一跳转发别名**。
 *
 * 实测存在两例，都是为了让"审计写入晚于本中间件"的顺序问题不成立而延迟 require 的同层包装：
 *   - `middleware/queryLimit.js:40` 的
 *     `const recordQueryRejection = (req, meta) => { require('./security').recordEarlyRejection(req, meta); }`
 *   - `middleware/originCheck.js:29` 的**同名**包装 `const recordEarlyRejection = ...`
 *     （按名字全文匹配调用点，故它对 action 收集是幂等的；别名清单仍把它列出，见对账闸用例）。
 * 只认「实参整体是标识符」的转发定义：一个恰好给 recordEarlyRejection 传字面量的普通函数
 * 不算别名（那样别名集会随写法无限长大，反而把打孔面扩大）。
 * 不认别名 ⇒ 它的 action 字面量对正向对账完全隐形：实测把 `'query_param_rejected'` 改名，
 * 白名单里的旧条目无人写入、新条目不在白名单，两向都判绿（F-201 的同一类，下一层）。
 */
function collectEarlyRejectionAliases() {
  const aliases = new Set();
  const source =
    /(?:const|let|var)\s+(\w+)\s*=[\s\S]{0,200}?\brecordEarlyRejection\(\s*[^,()]*,\s*([A-Za-z_$][\w$]*)\s*\)/g;
  for (const file of listSourceFiles()) {
    const src = fs.readFileSync(file, 'utf8');
    // 每份文件重新起一个带 g 的正则实例：lastIndex 是实例状态，跨文件复用会漏扫
    const re = new RegExp(source.source, 'g');
    let m;
    while ((m = re.exec(src)) !== null) {
      if (!isInsideComment(src, m.index)) aliases.add(m[1]);
    }
  }
  return aliases;
}

/** 从 src 目录静态收集 recordEarlyRejection（含一跳别名）各调用点传入的 action 字面量 */
function collectEarlyRejectionActions() {
  const actions = new Set();
  const names = ['recordEarlyRejection', ...collectEarlyRejectionAliases()];
  for (const file of listSourceFiles()) {
    const src = fs.readFileSync(file, 'utf8');
    for (const name of names) {
      let from = 0;
      let idx = src.indexOf(`${name}(`);
      while (idx !== -1) {
        from = idx + 1;
        if (!isInsideComment(src, idx)) {
          const args = readCallArgs(src, idx + name.length);
          const expr = args == null ? null : extractActionExpr(args, 'object');
          const literal = expr && /^'([^']*)'$/.exec(expr);
          if (literal) actions.add(literal[1]);
        }
        idx = src.indexOf(`${name}(`, from);
      }
    }
  }
  return actions;
}

/**
 * 写入点形态。`re` 而不是 `token`：内联 require 的写法（`require('../services/auditBuffer').push(`）
 * 与直接调用之间隔着引号和括号，字面量 token 匹配不到 ⇒ 那条写入点整个不在对账范围内。
 * `kind` 用来标"审计缓冲"这一族（其中路由派生型走 deriveAuditMeta，见排除说明）
 * 与"模型静态方法自身"这一族（转发判据只对后者成立）。
 */
const WRITE_CALLS = [
  { re: /AuditLog\.record\(/g, kind: 'record', mode: 'object' },
  { re: /AuditLog\.create\(/g, kind: 'record', mode: 'object' },
  { re: /AuditLog\.recordSensitiveAction\(/g, kind: 'record', mode: 'positional-2' },
  { re: /auditBuffer\.push\(/g, kind: 'auditBuffer', mode: 'object' },
  { re: /auditBuffer['"]\s*\)\s*\.push\(/g, kind: 'auditBuffer', mode: 'object' },
  // F-201：模型静态方法**自身**决定 action 的写入点（recordLogin 的三元）。
  // 前四类都以 `AuditLog.` / `auditBuffer.` 为前缀，于是这类写入整个不在对账范围内。
  { re: /\bthis\.create\(/g, kind: 'modelStatic', mode: 'object' },
];

/** 取 idx 之前最近的 `schema.statics.<name> =`，用来给转发点命名（比行号稳） */
function enclosingStaticName(src, idx) {
  let name = '(module-level)';
  for (const m of src.slice(0, idx).matchAll(/\bschema\.statics\.(\w+)\s*=/g)) name = m[1];
  return name;
}

/**
 * 静态方法体内 `this.create(...)` 的**转发型**写法识别：action 由调用方决定，
 * 本处不存在命名字面量，其取值由对应的调用点形态负责（AuditLog.record /
 * AuditLog.recordSensitiveAction）。返回转发形态标签（进 forwarded 账）或 null。
 *
 * 只在"确实是转发"的两种形态上放行，其余一律 null → 走 unresolved 硬失败：
 *   - `this.create(entry)`：实参整体是一个标识符（静态方法的入参）；
 *   - `{ action, ... }`：action 是对象简写（值即同名入参）。
 * 而 `{ action: someVar }` 既不是转发形态也解析不出字面量 → 必须响，不能被
 * "跳过转发"这条新规则顺手洗掉（那正是本条规则自己可能造成的下一个盲区）。
 */
function forwardingReason(kind, argsText, expr) {
  if (kind !== 'modelStatic' || argsText == null) return null;
  if (/^[A-Za-z_$][\w$]*$/.test(argsText.trim())) return 'forward-arg';
  if (expr == null && /(^|[{,]\s*)action\s*(?:,|$)/.test(argsText)) return 'shorthand-action';
  return null;
}

/**
 * 扫描 src/ 全部写入点。返回三份账：
 *   written    action -> [调用点]（正向对账与反向可达性共用的"写入集合"）
 *   unresolved 解析不出 action 的调用点（硬失败，新写法不得悄悄逃出范围）
 *   forwarded  转发型静态方法写入点（跳过必须留名，见 forwardingReason）
 */
function scanWriteSites(rootDir = SRC_DIR) {
  const { ALERT_TYPES } = require('../../services/securityAlert');
  const ctx = { ALERT_TYPES, earlyRejectionActions: collectEarlyRejectionActions() };

  const unresolved = [];
  const forwarded = [];
  const written = new Map(); // action -> [调用点]
  for (const file of listSourceFiles(rootDir)) {
    const src = fs.readFileSync(file, 'utf8');
    const rel = path.relative(REPO_ROOT, file).replace(/\\/g, '/');
    for (const { re, kind, mode } of WRITE_CALLS) {
      // 每份文件重新起一个带 g 的正则实例：lastIndex 是实例状态，跨文件复用会漏扫
      const pattern = new RegExp(re.source, 'g');
      let m;
      while ((m = pattern.exec(src)) !== null) {
        const idx = m.index;
        const from = idx + m[0].length;
        if (isInsideComment(src, idx)) continue;
        const line = src.slice(0, idx).split('\n').length;
        const args = readCallArgs(src, from - 1);
        const expr = args == null ? null : extractActionExpr(args, mode);
        const values = resolveActionExpr(expr, ctx, src);
        if (values == null) {
          const fwd = forwardingReason(kind, args, expr);
          if (fwd) {
            forwarded.push(`${rel}<${enclosingStaticName(src, idx)}>:${fwd}`);
            continue;
          }
          // 路由派生型批量写（middleware/security.js 的 auditBuffer.push 用
          // deriveAuditMeta(req) 派生 action）不在本对账范围，见排除说明
          if (kind === 'auditBuffer' && /deriveAuditMeta/.test(src)) continue;
          unresolved.push(`${rel}:${line} expr=${JSON.stringify(expr)}`);
        } else {
          for (const v of values) {
            if (!written.has(v)) written.set(v, []);
            written.get(v).push(`${rel}:${line}`);
          }
        }
      }
    }
  }
  return { written, unresolved, forwarded };
}

/**
 * 回球面：src 生产代码里每一处 `action:'字面量'` 的出现（含读写两侧、含各种调用形态）。
 *
 * 为什么需要它（F-203）：`scanWriteSites` 的覆盖面 = `WRITE_CALLS` 认得的形态，
 * 一个不认得的形态（`AuditLog.insertMany([{action:'x'}])`、`const log = AuditLog.record`
 * 之后再 `log({action:'x'})`、`AuditLog['record']({action:'x'})`、数组里第二个对象字面量…）
 * 是**静默**消失的：正向对账看不见它，反向对账只问"白名单里的动作有没有人写"，
 * 于是"写进库却没登记"这一整类（P1-11）从两侧都查不出来。
 * 本函数把判据反过来：**凡是代码里的 action 字面量都必须被某个形态认领**，
 * 认不出来就是新形态，必须显式判定（要么补进 WRITE_CALLS，要么进对账闸的排除清单）。
 *
 * 注释排除故意**不用** `isInsideComment`，只按"整行行首形态"排除。理由是方向不对称：
 * `isInsideComment` 有可能被判错（实测：行内正则字面量 `/^https?:\/\//` 里的 `//`
 * 会被它当成行尾注释，于是它**后面**的真实写入整个被跳过），而回球闸复用同一个易骗的
 * 判定就等于两个闸一起被骗。判据换成"这一行有代码"，被伪注释吃掉的写入仍会留在结果里
 * ⇒ 无认领 ⇒ 判红。
 *
 * @param {string} [rootDir] 覆盖扫描根目录（用例指向临时夹具，用来证明本函数确实
 *   比 `scanWriteSites` 看得宽；默认 `SRC_DIR`）
 * @returns {Array<{file:string,line:number,action:string}>}
 */
function scanActionLiterals(rootDir = SRC_DIR) {
  const out = [];
  const re = /action:\s*(?:'([^']+)'|"([^"]+)")/g;
  for (const file of listSourceFiles(rootDir)) {
    const rel = path.relative(REPO_ROOT, file).replace(/\\/g, '/');
    fs.readFileSync(file, 'utf8')
      .split('\n')
      .forEach((line, i) => {
        const t = line.trim();
        // 只排"整行注释 / JSDoc 续行 / 块注释起始行"；行尾注释不做判断（见上）
        if (/^(?:\/\/|\*|\/\*)/.test(t)) return;
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(line)) !== null) {
          out.push({ file: rel, line: i + 1, action: m[1] || m[2] });
        }
      });
  }
  return out;
}

module.exports = {
  SRC_DIR,
  scanWriteSites,
  scanActionLiterals,
  isInsideComment,
  resolveActionExpr,
  forwardingReason,
  collectEarlyRejectionAliases,
};
