'use strict';

/**
 * 文档成功码 ↔ 实现实际返回 的对账取数（openapiStatusParity 的判据本体）
 *
 * 为什么需要它：`scripts/check-openapi-drift.js` 只对账「生成器 ↔ 产物」——两边都写 201
 * 就自洽；`emittedErrorCodeCoverage` 只对账错误码集合。两边都不与**控制器实现**对照，
 * 于是「文档 201 / 实现 200」可以长期共存（第 22 轮普查实测 3 处 + ip-list 共 4 处，
 * 见 work/audit-round22-doc-2xx-census.md）。更隐蔽的是：既有回归用例把实现的 200 钉死了
 * （permissionBatchCreateSemantics:120、securityDeep:156、forensicRoutesContract:204），
 * 于是漂移的两侧**各有守卫、互不看对方**，谁都不会红。
 *
 * 取数口径（如实声明边界）：
 *  1. 路由 → (method, 完整路径)：前缀由 helpers/routeMounts 解析（app.js 顶层挂载 +
 *     路由文件嵌套挂载），同一套取数被审计白名单闸与可达性闸共用，避免第三份前缀规则；
 *     另外把 app.js 里直接写的 `app.<verb>('<path>', ...)` 端点也收进来（/health、/api
 *     这类没有路由文件）。
 *  2. 处理函数 → 文件：路由表里的处理器可能是 `controller.fn` 或解构后的 `fn`。
 *     门面目录（controllers/authController/index.js 只做 re-export）要顺 require 往下找
 *     真正的定义处，否则函数体截不出来 —— 截不出来会被误判成"没有成功码"。
 *  3. 成功码 = 函数体里**静态可见**的：`ApiResponse.success` 的第 4 个字面量参数（缺省 200）、
 *     `ApiResponse.created`(201) / `noContent`(204)、`res.status(<2xx|3xx>)`。
 *     `.status(503)` 这类失败码不计（本仓真实写法：改密成功但吊销失败时先把状态置 503
 *     再写审计，那不是成功码）。
 *  4. 判据只覆盖「静态可见」：成功码在别处（service 层 / 共享发送助手）决定的端点，
 *     一律登记进 OPAQUE_SUCCESS 台账，**不许**靠默认 200 蒙混 —— 否则"抽不到"与
 *     "就是 200"无法区分，正是本仓反复踩过的假绿形状。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../../..');
const ROUTES_DIR = path.join(ROOT, 'src/routes');
const APP_FILE = path.join(ROOT, 'src/app.js');

const { readMounts, readNestedMounts, makePrefixOf } = require('../../helpers/routeMounts');
const { jsCodeOnlyKeepingLines } = require('../../helpers/jsCodeOnly');
const { readArgs, splitArgs } = require('../../helpers/codeErrorCallScan');

/** 去引号：'x' / "x" / `x` → x（路由字面量只有这三种形状） */
const unquote = (value) => {
  const text = String(value).trim();
  const m = /^(['"`])([\s\S]*)\1$/.exec(text);
  return m ? m[2] : text;
};

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
    else if (c === '`') return j + 1;
    else if (c === '$' && text[j + 1] === '{') {
      let depth = 1;
      j += 2;
      while (j < text.length && depth > 0) {
        const c2 = text[j];
        if (c2 === "'" || c2 === '"') {
          j = skipQuoted(text, j);
          continue;
        }
        if (c2 === '`') {
          j = skipTemplate(text, j);
          continue;
        }
        if (c2 === '{') depth += 1;
        else if (c2 === '}') depth -= 1;
        j += 1;
      }
    } else j += 1;
  }
  return j;
};

/** 从 open 处（左花括号后的第一个字符）截出配对的 {...} 函数体 */
const braceBodyAt = (view, from) => {
  const start = view.indexOf('{', from);
  if (start < 0) return null;
  let depth = 0;
  for (let j = start; j < view.length; j += 1) {
    const c = view[j];
    if (c === "'" || c === '"') {
      j = skipQuoted(view, j) - 1;
      continue;
    }
    if (c === '`') {
      j = skipTemplate(view, j) - 1;
      continue;
    }
    if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) return view.slice(start, j + 1);
    }
  }
  return null;
};

const resolveModuleFile = (baseDir, spec) => {
  const base = path.resolve(baseDir, spec);
  for (const candidate of [base, `${base}.js`, path.join(base, 'index.js')]) {
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      /* 下一个候选 */
    }
  }
  return null;
};

const isDefined = (view, name) =>
  new RegExp(`(?:const|let|var)\\s+${name}\\s*[=:]|(?:async\\s+)?function\\s+${name}\\s*\\(`).test(
    view
  );

/**
 * 一个模块里的 require 索引：
 *   named         —— `const X = require('spec')`
 *   destructured  —— `const { 别名: 成员 } = require('spec')`（裸 require 解构别名）
 * app.js 与 routes/*.js 的解析器原来各写一份，两份都会在"新增一种 require 形状"时漏掉另一边。
 */
const moduleIndex = (view) => {
  const named = new Map();
  const destructured = new Map();
  for (const m of view.matchAll(/const\s+(\w+)\s*=\s*require\('([^']+)'\)/g)) named.set(m[1], m[2]);
  for (const m of view.matchAll(/const\s*\{([^}]+)\}\s*=\s*require\('([^']+)'\)/g)) {
    for (const part of m[1].split(',')) {
      const pieces = part
        .trim()
        .split(':')
        .map((s) => s.trim());
      const alias = pieces[0];
      const inner = (pieces[1] || pieces[0] || '').trim();
      if (alias && inner) destructured.set(alias, { spec: m[2], inner });
    }
  }
  return { named, destructured };
};

/**
 * 门面文件（controllers/xxxController/index.js 只做 re-export）→ 真正持有函数体的模块。
 *
 * **不做**"顺所有 require 深度优先找同名函数"：那样找出来的是**同名不同源**的实现。
 * 实测反例：securityController/index.js 的 getSecurityOverview 被解析到
 * services/securityAlert.js 的同名函数（它有 getSecurityOverview，但它返回数据、
 * 不发响应），于是 j 判据把"发了什么状态码"判成"空"，与"该端点没有成功码"混同。
 * 只认三类**显式别名**：export 表里的 `导出名: 变量.成员`、`const { 名 } = require()`
 * 解构、以及本文件自身定义。
 */
/** `module.exports = { 导出名: 变量.成员, 导出名, ... }` 里查 name 的来源 */
const exportSourcesOf = (view, name, index) => {
  const block = /module\.exports\s*=\s*\{([\s\S]*?)\n\};/.exec(view);
  if (!block) return [];
  const out = [];
  for (const m of block[1].matchAll(/([\w$]+)\s*:\s*([\w$]+)\.([\w$]+)/g)) {
    const [, exported, holder, member] = m;
    if (exported !== name) continue;
    const spec = index.named.get(holder);
    if (spec) out.push({ spec, inner: member });
  }
  // 简写导出 `name,`：源在解构 require 里
  if (index.destructured.has(name)) {
    for (const m of block[1].matchAll(/(?:^|,)\s*([\w$]+)\s*(?:,|$)/g)) {
      if (m[1] === name) out.push(index.destructured.get(name));
    }
  }
  return out;
};

const resolveOwner = (file, name, depth = 0) => {
  if (!file || depth > 3) return null;
  const view = jsCodeOnlyKeepingLines(fs.readFileSync(file, 'utf8'));
  if (isDefined(view, name)) return { file, view };
  const index = moduleIndex(view);
  const sources = index.destructured.has(name)
    ? [index.destructured.get(name), ...exportSourcesOf(view, name, index)]
    : exportSourcesOf(view, name, index);
  for (const { spec, inner } of sources) {
    const target = resolveModuleFile(path.dirname(file), spec);
    const hit = resolveOwner(target, inner, depth + 1);
    if (hit) return hit;
  }
  return null;
};

/** 从 from 处的 `(` 找到配对的 `)`（跳过字符串/模板），返回其后的下标 */
const afterParenGroup = (view, from) => {
  const open = view.indexOf('(', from);
  if (open < 0) return -1;
  let depth = 0;
  for (let j = open; j < view.length; j += 1) {
    const c = view[j];
    if (c === "'" || c === '"') {
      j = skipQuoted(view, j) - 1;
      continue;
    }
    if (c === '`') {
      j = skipTemplate(view, j) - 1;
      continue;
    }
    if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) return j + 1;
    }
  }
  return -1;
};

/**
 * 处理函数体：`const fn = ...` / `function fn(...)` 之后的**真正函数体**花括号块。
 *
 * 为什么不能"从赋值号后面直接找第一个 {`：本仓的编排函数普遍带解构形参
 * （`const queryAuditOffsetPage = async (req, res, query, { pageNum, limitNum, collation }) => {`，
 * auditQueryService.js:60），第一个 `{` 是**形参解构**，截出来的"函数体"只有 32 个字符、
 * 一个成功码都抽不到——端点于是被记成"没有成功码"，与"该端点不发 2xx"不可区分。
 * 所以先跳形参括号组、再看后面是不是 `=>`；不是（`asyncHandler(...)` 这类包装器）时
 * 才回退到"往后找第一个够长的花括号块"。
 */
const handlerBodyOf = (view, name) => {
  const patterns = [
    new RegExp(`(?:const|let|var)\\s+${name}\\s*=\\s*`),
    new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`),
  ];
  for (const re of patterns) {
    const m = re.exec(view);
    if (!m) continue;
    const from = m.index + m[0].length;
    // ① 形参括号组 + `=>` 之后的块（解构形参也走这条）
    const afterParams = afterParenGroup(view, from);
    if (afterParams > 0) {
      const rest = view.slice(afterParams, afterParams + 40);
      const arrow = /^\s*(?::\s*[^=]+)?=>/.exec(rest);
      if (arrow) {
        const body = braceBodyAt(view, afterParams + arrow[0].length);
        if (body) return body;
      }
    }
    // ② 包装器（`asyncHandler(async (req, res) => {...})`）：往后找第一个"像函数体"的块。
    // 判"像"的依据：块里出现了 res 或长度超过 40 字符——形参解构块两者都不满足。
    let cursor = from;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const body = braceBodyAt(view, cursor);
      if (!body) return null;
      if (body.length > 40 || /\bres\b/.test(body)) return body;
      cursor += 1;
    }
  }
  return null;
};

/** 取某次调用的第 pos 个实参（0 基）；是 3 位字面量就当状态码，否则记账 */
const takeStatusArg = (body, parts, pos, codes, dynamic) => {
  if (parts.length <= pos) {
    codes.add(200); // 省略状态码参数 ⇒ 默认 200（ApiResponse.success 的默认值）
    return;
  }
  if (/^\d{3}$/.test(parts[pos])) codes.add(Number(parts[pos]));
  else dynamic.push(parts[pos]);
};

/** 只认 2xx/3xx：`.status(503)` 是失败响应（本仓真实写法见 authController/profile.js:70） */
const addExplicitStatuses = (body, codes, dynamicStatus) => {
  for (const m of body.matchAll(/\.status\(([^)]*)\)/g)) {
    const arg = m[1].trim();
    if (/^\d{3}$/.test(arg)) {
      const code = Number(arg);
      if (code >= 200 && code < 400) codes.add(code);
      continue;
    }
    // 动态表达式（`ready ? 200 : 503`，app.js:477）：抽不出来就记账，
    // 绝不当成"没有成功码"，也不能默认 200 —— 两种退化都会让判据静默放行。
    // 里面出现的 2xx/3xx 字面量算候选成功码，原文整段进台账供人复核：
    // "可能返回 200 或 503"不能化简成"只返回 200"。
    dynamicStatus.push(arg);
    for (const lit of arg.matchAll(/(?<![\d.])([23]\d{2})(?![\d.])/g)) codes.add(Number(lit[1]));
  }
};

/** 没有显式状态码时的默认 200（express 语义） */
const addImplicitSuccess = (body, codes) => {
  if (/\.status\(/.test(body)) return;
  // 裸 `res.json/send/end`；有显式状态码时不能再加 200，
  // 否则 `res.status(204).end()` 会被误记成 200/204 两个码。
  if (/res\.(json|send|end)\s*\(/.test(body)) codes.add(200);
  // 流式写出（res.setHeader + res.write/pipe，reportWorkbookService）：同样走默认 200，
  // 但绝不会有 res.json —— 漏掉这一格会把两个导出端点记成"没有成功码"。
  else if (/res\.(setHeader|write|pipe)\s*\(/.test(body)) codes.add(200);
};

/** 函数体里静态可见的成功码 + 抽不出的状态码实参（后者进台账，不许静默按 200 算） */
const successCodesOf = (body) => {
  const codes = new Set();
  const dynamicFourthArg = [];
  const dynamicStatus = [];
  // ApiResponse.success(res, data, message, statusCode=200)：第 4 参（下标 3）
  for (const m of body.matchAll(/ApiResponse\.success\(/g)) {
    const got = readArgs(body, m.index + m[0].length);
    if (!got) continue;
    takeStatusArg(body, splitArgs(got.args), 3, codes, dynamicFourthArg);
  }
  for (const m of body.matchAll(/ApiResponse\.(created|noContent)\(/g)) {
    codes.add(m[1] === 'created' ? 201 : 204);
  }
  // ApiResponse.successWithMeta(res, data, meta, message, statusCode=200)：第 5 参（下标 4）
  for (const m of body.matchAll(/ApiResponse\.successWithMeta\(/g)) {
    const got = readArgs(body, m.index + m[0].length);
    if (!got) continue;
    takeStatusArg(body, splitArgs(got.args), 4, codes, dynamicFourthArg);
  }
  // paginated(res, data, pagination, message)：内部固定 res.status(200)
  if (/ApiResponse\.paginated\(/.test(body)) codes.add(200);
  addExplicitStatuses(body, codes, dynamicStatus);
  addImplicitSuccess(body, codes);
  return { codes: [...codes].sort((a, b) => a - b), dynamicFourthArg, dynamicStatus };
};

/** routes/*.js（跳过 index.js 纯导出）里的操作 */
const parseRouteFileOps = (file, prefix) => {
  const view = jsCodeOnlyKeepingLines(fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8'));
  const required = new Map();
  const destructured = new Map();
  for (const m of view.matchAll(/const\s+(\w+)\s*=\s*require\('([^']+)'\)/g))
    required.set(m[1], m[2]);
  for (const m of view.matchAll(/const\s*\{([^}]+)\}\s*=\s*require\('([^']+)'\)/g)) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(':').pop().trim();
      if (name) destructured.set(name, m[2]);
    }
  }
  const ops = [];
  for (const m of view.matchAll(/router\.(get|post|put|patch|delete)\(/g)) {
    const open = view.indexOf('(', m.index + m[0].length - 1);
    const got = readArgs(view, open + 1);
    if (!got) continue;
    const parts = splitArgs(got.args);
    const routePath = unquote(parts[0] || '');
    const handler = parts[parts.length - 1] || '';
    const full =
      ((prefix.replace(/\/+$/, '') || '') + '/' + routePath.replace(/^\/+/, ''))
        .replace(/\/+/g, '/')
        .replace(/\/$/, '') || '/';
    let moduleSpec = null;
    let fn = null;
    const dotted = /^(\w+)\.(\w+)$/.exec(handler);
    if (dotted) {
      moduleSpec = required.get(dotted[1]);
      fn = dotted[2];
    } else if (/^\w+$/.test(handler)) {
      moduleSpec = destructured.get(handler);
      fn = handler;
    }
    ops.push({
      source: `src/routes/${file}`,
      method: m[1].toUpperCase(),
      path: full,
      moduleSpec,
      fn,
      handler,
    });
  }
  return ops;
};

/** app.js 里直接写的端点（/health、/api 这类没有路由文件的） */
const parseAppOps = () => {
  const view = jsCodeOnlyKeepingLines(fs.readFileSync(APP_FILE, 'utf8'));
  const required = new Map();
  for (const m of view.matchAll(/const\s+(\w+)\s*=\s*require\('([^']+)'\)/g))
    required.set(m[1], m[2]);
  // 解构 require：`const { metricsEndpoint } = require('./middleware/metrics')`，
  // 不收的话 /metrics 会被记成"处理函数定位不到"，与"真的没有成功码"混同。
  for (const m of view.matchAll(/const\s*\{([^}]+)\}\s*=\s*require\('([^']+)'\)/g)) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(':').pop().trim();
      if (name) required.set(name, m[2]);
    }
  }
  const ops = [];
  for (const m of view.matchAll(/(?:^|\n)\s*app\.(get|post|put|patch|delete)\(/g)) {
    const open = view.indexOf('(', m.index + m[0].length - 1);
    const got = readArgs(view, open + 1);
    if (!got) continue;
    const parts = splitArgs(got.args);
    const routePath = unquote(parts[0] || '');
    const handler = parts[parts.length - 1] || '';
    // 处理器是裸标识符（`app.get('/metrics', metricsAuth, metricsEndpoint)`）时，
    // 它可能是本文件的模块级常量，也可能是解构 require 进来的实现
    const bare = /^\w+$/.test(handler) ? required.get(handler) : null;
    ops.push({
      source: 'src/app.js',
      method: m[1].toUpperCase(),
      path: routePath.replace(/\/+/g, '/') || '/',
      moduleSpec: bare,
      fn: bare ? handler : null,
      handler,
    });
  }
  return ops;
};

const buildRouteOps = () => {
  const prefixOf = makePrefixOf(readMounts(), readNestedMounts());
  const ops = [];
  for (const file of fs.readdirSync(ROUTES_DIR)) {
    if (!file.endsWith('.js') || file === 'index.js') continue;
    const prefix = prefixOf(file.replace(/\.js$/, ''));
    ops.push(...parseRouteFileOps(file, prefix));
  }
  ops.push(...parseAppOps());
  return ops;
};

/** express ':id' ↔ OpenAPI '{id}' 归一（否则同一端点会被记成两条） */
const normalizePath = (p) => p.replace(/:([A-Za-z_]\w*)/g, '{$1}');

const specOperations = (spec) =>
  Object.entries(spec.paths).flatMap(([p, item]) =>
    Object.entries(item).map(([method, op]) => ({
      key: `${method.toUpperCase()} ${normalizePath(p)}`,
      method: method.toUpperCase(),
      path: p,
      op,
    }))
  );

/**
 * 函数体里「把 res 交给别的函数」的站点（本仓惯例 res 在前 3 个实参里）。
 */
const resDelegationsOf = (body) => {
  const out = [];
  for (const m of body.matchAll(/(?:([\w$]+)\.)?([\w$]+)\s*\(/g)) {
    const got = readArgs(body, m.index + m[0].length);
    if (!got) continue;
    const parts = splitArgs(got.args);
    if (!parts.slice(0, 3).some((p) => p === 'res')) continue;
    out.push({ holder: m[1] || null, name: m[2] });
  }
  return out;
};

/**
 * 委派链：沿 `res` 实参找真正发响应的函数，最多 3 跳。
 * 只在直连函数体抽不到成功码时才用（否则会去追一遍无关调用）。
 */
const delegatedSuccessOf = (file, view, body, depth) => {
  if (depth > 2) return null;
  for (const t of resDelegationsOf(body)) {
    const files = [file];
    if (t.holder) {
      const specRe = new RegExp(`const\\s+${t.holder}\\s*=\\s*require\\('([^']+)'\\)`);
      const found = specRe.exec(view);
      if (found) {
        const target = resolveModuleFile(path.dirname(file), found[1]);
        if (target) files.push(target);
      }
    }
    for (const candidate of files) {
      const target = resolveOwner(candidate, t.name);
      if (!target) continue;
      const inner = handlerBodyOf(target.view, t.name);
      if (!inner) continue;
      const direct = successCodesOf(inner);
      if (direct.codes.length > 0) {
        return { ...direct, via: path.relative(ROOT, target.file).split(path.sep).join('/') };
      }
      const deeper = delegatedSuccessOf(target.file, target.view, inner, depth + 1);
      if (deeper) return deeper;
    }
  }
  return null;
};

/**
 * 端点 → 静态可见成功码（定位不到处理函数时返回 null，由台账接住）。
 * 三种处理器形状都要覆盖，少一种就会把「抽不到」记成「默认 200」：
 *   ① 内联箭头/函数表达式（app.js 的 /health、wellKnownRoutes 的两个 204 上报端点）；
 *   ② `module.fn` —— 顺 require 找定义处；
 *   ③ 裸名 `fn` —— 可能是解构自别的模块，也可能就定义在本路由文件里（serveSecurityTxt）。
 */
const relOf = (file) => path.relative(ROOT, file).split(path.sep).join('/');

/** 内联处理器（`(req, res) => {...}` / 表达式体）的成功码；识别不了返回 null */
const inlineSuccessOf = (handler, source) => {
  const at = handler.indexOf('{');
  const body = at >= 0 ? braceBodyAt(handler, at) : null;
  if (body) return { ...successCodesOf(body), file: source };
  // 表达式体：`(req, res) => res.json(swagger.openapiSpec)`
  if (/res\.(json|send|end)\s*\(/.test(handler)) {
    return { codes: [200], dynamicFourthArg: [], dynamicStatus: [], file: source };
  }
  return null;
};

/** 处理器是具名函数时的成功码：先看函数体本身，抽不到再追 res 委派链 */
const namedSuccessOf = (route) => {
  const baseDir = route.source === 'src/app.js' ? ROOT : path.join(ROOT, relOf(ROUTES_DIR));
  const candidates = [];
  if (route.moduleSpec) {
    const file = resolveModuleFile(baseDir, route.moduleSpec);
    if (file) candidates.push(file);
  }
  // 裸名：先看路由文件自己（serveSecurityTxt 就定义在 wellKnownRoutes.js 里）
  candidates.push(path.join(ROOT, route.source));
  for (const file of candidates) {
    const owner = route.fn ? resolveOwner(file, route.fn) : null;
    if (!owner) continue;
    const body = handlerBodyOf(owner.view, route.fn);
    if (!body) continue;
    const direct = successCodesOf(body);
    const rel = relOf(owner.file);
    if (direct.codes.length > 0) return { ...direct, file: rel };
    // 编排形函数：自己不发响应，把 res 交给被委派者（writeExportWorkbook / queryAuditOffsetPage）。
    // 不追进去就会把端点记成"没有成功码"，与"该端点不发 2xx"不可区分。
    const delegated = delegatedSuccessOf(owner.file, owner.view, body, 0);
    if (delegated) return { ...delegated, file: rel, via: delegated.via };
    return { ...direct, file: rel };
  }
  return inlineSuccessOf(route.handler, route.source);
};

const implOf = (route) => {
  if (!route.moduleSpec && !route.fn) return inlineSuccessOf(route.handler, route.source);
  return namedSuccessOf(route);
};

/**
 * 判据：文档声明的 2xx/3xx 集合必须等于实现静态可见的成功码集合。
 * @returns {Array<{key: string, declared: number[], impl: number[], why: string}>}
 */
const statusViolations = (spec, routeOps) => {
  const byKey = new Map(routeOps.map((o) => [`${o.method} ${normalizePath(o.path)}`, o]));
  const violations = [];
  for (const { key, op } of specOperations(spec)) {
    const declared = Object.keys(op.responses || {})
      .filter((c) => /^[23]\d\d$/.test(c))
      .map(Number)
      .sort((a, b) => a - b);
    const route = byKey.get(key);
    if (!route) continue; // 反向漂移由 undocumentedEndpoints 负责
    const impl = implOf(route);
    if (!impl) {
      violations.push({ key, declared, impl: null, why: '处理函数体未定位（判据看不见这个端点）' });
      continue;
    }
    // 抽成空集合**不能**默认成 200：那是"抽取器退化了"而不是"实现只回 200"。
    // 默认成 200 会让判据在退化时静默全绿——本仓反复踩过的假绿形状。
    if (impl.codes.length === 0) {
      violations.push({
        key,
        declared,
        impl: [],
        why: '实现里抽不到任何成功码（抽取器退化，需人复核）',
      });
      continue;
    }
    const implCodes = impl.codes;
    if (JSON.stringify(declared) !== JSON.stringify(implCodes)) {
      violations.push({
        key,
        declared,
        impl: implCodes,
        why: `文档 ${declared.join('/')} vs 实现 ${implCodes.join('/')}`,
      });
    }
  }
  return violations;
};

/**
 * 采集口自证（lead 提醒的"手抄镜像双向失明"模式）：
 *   · 每个 routes/*.js（index.js 是纯导出，跳过）都必须至少贡献一个端点——
 *     某个文件被解析器整体漏掉时，#1 的"总数 > 120"仍然成立，只有本判据看得见；
 *   · app.js 的内联端点也必须至少有一个（否则 app.js 解析分支整段退化）；
 *   · 具名处理器的实现来源必须**不是路由文件本身**：落到路由文件说明没定位到定义处，
 *     只是拿路由文件里的一段文本冒充控制器实现（wellKnownRoutes 的 serveSecurityTxt 例外，
 *     它确实定义在路由文件里）。
 * @returns {Array<{kind: string, detail: string}>}
 */
const coverageViolations = (routeOps) => {
  const problems = [];
  const files = fs.readdirSync(ROUTES_DIR).filter((n) => n.endsWith('.js') && n !== 'index.js');
  const seen = new Set(routeOps.map((o) => path.basename(o.source)));
  for (const name of files) {
    if (!seen.has(name)) problems.push({ kind: 'route-file-silent', detail: name });
  }
  if (!routeOps.some((o) => o.source === 'src/app.js')) {
    problems.push({ kind: 'app-inline-silent', detail: 'src/app.js' });
  }
  for (const o of routeOps) {
    if (!o.fn) continue;
    const impl = implOf(o);
    if (!impl || !impl.file) {
      problems.push({ kind: 'impl-unlocated', detail: `${o.method} ${normalizePath(o.path)}` });
      continue;
    }
    if (!fs.existsSync(path.join(ROOT, impl.file))) {
      problems.push({
        kind: 'impl-file-missing',
        detail: `${o.method} ${normalizePath(o.path)} → ${impl.file}`,
      });
      continue;
    }
    // 落到路由文件本身**不一定是错**：wellKnownRoutes 的 serveSecurityTxt 就定义在路由文件里。
    // 真错的是"那个名字在路由文件里根本没定义"——说明解析器没找到定义处，拿路由文件的一段
    // 文本冒充实现（那时 impl.codes 来自 inline 兜底，判据等于在自证）。
    if (impl.file === o.source) {
      const view = jsCodeOnlyKeepingLines(fs.readFileSync(path.join(ROOT, o.source), 'utf8'));
      if (!isDefined(view, o.fn)) {
        problems.push({
          kind: 'impl-fell-back-to-route-file',
          detail: `${o.method} ${normalizePath(o.path)} → ${impl.file}（${o.fn} 在路由文件里没有定义）`,
        });
      }
    }
  }
  return problems;
};

/** 反向漂移：实现里有、文档里没有的端点（整份文档缺这一条，不是状态码写错） */
const undocumentedEndpoints = (spec, routeOps) => {
  const documented = new Set(specOperations(spec).map((o) => o.key));
  return routeOps
    .map((o) => `${o.method} ${normalizePath(o.path)}`)
    .filter((key) => !documented.has(key))
    .sort();
};

module.exports = {
  ROOT,
  buildRouteOps,
  specOperations,
  normalizePath,
  successCodesOf,
  implOf,
  statusViolations,
  undocumentedEndpoints,
  coverageViolations,
};
