/**
 * 路由声明表 ↔ 真实路由的双向判据（P2-2）
 *
 * constants/honeypotRouteTable.js 是「app 里到底有哪些路由」的**唯一声明**，而声明只有在能被
 * 现算校验时才有价值：本闸把 src/app.js 的挂载表 × src/routes/*.js 的声明 × app.js 内联路由
 * 重新解析一遍，与表双向比对（多一条少一条、权限码/认证/敏感标记任一处不符都红），
 * 再把每一行的回答类别（TRAP_HANDLING）交给真实判定链现算对拍。
 *
 * 为什么值得一个闸：改道点只挂在 authenticate 上，所以**未声明路径**在真实链和陷阱里都必须落到
 * app.js 的兜底 404。判定层过去把「前缀之外的一切」写成 DENY(403)——HTTP 上不可达，却误导了维护者，
 * 也让 P1c 台账里两条「不模拟」写错。表把三件事分开：已声明路由 / 聚合子路径 / 未知路径。
 *
 * 允许「暂时不一致」，但不许**静默**不一致：不一致必须逐条登记在下面的 BACKLOG 里，
 * 而双向判据（现算的不一致集 === 登记集）保证登记集只能变小、不会变多。
 *
 * 第三条轴是**授权轴**：读侧回答必须能由「呈现身份持有的权限（精确 / `*:*` / `module:*`，
 * 规则取真实链那一份实现）+ 真实链有没有第二道闸（requireReauthTicket）」解释。判据第一版只做
 * 精确匹配，把 5 条 security:audit 端点误记成越权开口；口径同源之后真正的分歧只剩 6 条，
 * 逐条登记方向与理由（见 READ_DIVERGENCE_BACKLOG）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { jsCodeOnly } = require('../helpers/jsCodeOnly');
// 判据用的匹配规则必须是真实链那一份（O-3：「精确 / *:* / module:*」的唯一实现），
// 不许在本文件里再写一份——第一版判据自己写了「精确匹配」，于是把 5 条合法 200 记成了越权开口。
const { matchesPermissionCodes } = require('../../utils/permissionHelper');
const { ROUTE_TABLE, TRAP_HANDLING, matchRoute } = require('../../constants/honeypotRouteTable');
const {
  DECOY_PERMISSIONS,
  HONEYPOT_VERDICT,
  PASSTHROUGH_ROUTES,
  WRITE_METHODS,
  resolveDecoyPayload,
  resolveDecoyVerdict,
} = require('../../constants/honeypotDecoy');
const { resolveFileResponse } = require('../../services/honeypotDecoyFiles');
const { resolveSelfResponse } = require('../../services/honeypotDecoySelf');
const {
  AGGREGATE_ENDPOINTS,
  NON_DERIVABLE,
  resolveAggregatePayload,
} = require('../../constants/honeypotDecoyAggregates');
const { resolveMetricsPayload } = require('../../constants/honeypotDecoyMetrics');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => jsCodeOnly(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const keyOf = (row) => row.method + ' ' + row.path;
const asList = (value) =>
  value === null || value === undefined ? [] : Array.isArray(value) ? [...value] : [value];

const ROUTE_CALL_RE = /(?:^|[^\w.$])(?:app|router)\.(get|post|put|patch|delete|all)\s*\(/g;

/** 取一次路由调用的实参（多行、数组参数、模板串都要吃得下），返回 top-level 逗号切开的片段 */
const OPENERS = new Set(['(', '[', '{']);
const CLOSERS = new Set([')', ']', '}']);

/**
 * 从字符串内部的 i 起跳到闭引号，返回闭引号下标（转义符吞掉下一个字符）。
 * 单独拆出来是为了把 splitArgs 的圈复杂度压到门禁阈值内：
 * 引号状态机与括号/逗号切分本来就是两件事，混在一个循环里既难读也过不了 complexity ≤15。
 */
const skipString = (source, i, quote) => {
  for (let j = i; j < source.length; j += 1) {
    if (source[j] === '\\') j += 1;
    else if (source[j] === quote) return j;
  }
  return source.length; // 引号未闭合（源码本身有问题）：吃到文件尾，由调用方按剩余片段处理
};

const splitArgs = (source, open) => {
  const args = [];
  let depth = 0;
  let start = open + 1;
  for (let i = open; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "'" || ch === '"' || ch === '`') {
      i = skipString(source, i + 1, ch);
      continue;
    }
    if (OPENERS.has(ch)) {
      depth += 1;
      continue;
    }
    if (!CLOSERS.has(ch)) {
      if (ch === ',' && depth === 1) {
        args.push(source.slice(start, i));
        start = i + 1;
      }
      continue;
    }
    depth -= 1;
    if (depth === 0) {
      args.push(source.slice(start, i));
      return args;
    }
  }
  return args;
};

const declarations = (source) => {
  const found = [];
  for (const match of source.matchAll(ROUTE_CALL_RE)) {
    const open = match.index + match[0].length - 1;
    const args = splitArgs(source, open)
      .map((arg) => arg.trim())
      .filter(Boolean);
    found.push({ method: match[1].toUpperCase(), path: args[0] || null, args: args.slice(1) });
  }
  return found;
};

const quoted = (expr) => {
  const match = /^'([^']*)'$/.exec(String(expr || '').trim());
  return match ? match[1] : null;
};

// 一行可能挂多个 checkPermission（串联 = 全过），也可能是一个 OR 数组。表把两者都记成数组：
// 这个区别对「陷阱该回什么」没有影响，故不建模；要建模就得给表加一列，收益不抵成本。
const permOf = (args) => {
  const codes = [];
  for (const arg of args) {
    const match = /checkPermission\(([\s\S]*?)\)/.exec(arg);
    if (!match) continue;
    const inner = match[1].trim();
    if (inner.startsWith('[')) codes.push(...[...inner.matchAll(/'([^']+)'/g)].map((x) => x[1]));
    else codes.push(quoted(inner));
  }
  if (codes.length === 0) return null;
  return codes.length === 1 ? codes[0] : codes;
};

const factsOf = (args) => {
  const joined = args.join(',');
  const auth = /\bauthenticateForLogout\b/.test(joined)
    ? 'authenticateForLogout'
    : /\bauthenticate\b/.test(joined)
      ? 'authenticate'
      : null;
  return { perm: permOf(args), auth, viewSensitive: /checkViewSensitivePermission/.test(joined) };
};

/**
 * 二次验证闸（requireReauthTicket）的现算。它**不进路由表**：表声明的是「有哪些路由」，
 * 而票据面对陷阱的回答没有影响（陷阱从不发票据）。判据需要它，只是为了把读侧回答的分歧
 * 归因清楚——有闸 ⇒ 真实链缺票时回 REAUTH_TICKET_REQUIRED，没闸 ⇒ 真实链直接进控制器。
 */
const reauthOf = (args) => /requireReauthTicket\s*\(/.test(args.join(','));

const joinPath = (prefix, routePath) => {
  const tail = String(routePath || '');
  if (tail === '/' || tail === '') return prefix;
  return prefix === '/' ? tail : prefix + tail;
};

const mountInfo = () => {
  const appSrc = read('src/app.js');
  const indexSrc = read('src/routes/index.js');
  const fileOf = new Map(
    [...indexSrc.matchAll(/const\s+([\w$]+)\s*=\s*require\('\.\/([\w-]+)'\)/g)].map((m) => [
      m[1],
      m[2],
    ])
  );
  const mounts = [...appSrc.matchAll(/app\.use\('([^']+)',\s*([\w$]+)\)/g)].map((m) => ({
    prefix: m[1],
    ident: m[2],
  }));
  return { appSrc, fileOf, mounts };
};

/** 真实路由清单：挂载前缀 × 路由文件声明 + app.js 内联路由，权限码/认证/敏感标记逐行取 */
const actualRoutes = () => {
  const { appSrc, fileOf, mounts } = mountInfo();
  const found = [];
  for (const { prefix, ident } of mounts) {
    const file = fileOf.get(ident);
    if (!file) continue;
    for (const decl of declarations(read('src/routes/' + file + '.js'))) {
      found.push({
        method: decl.method,
        path: joinPath(prefix, quoted(decl.path)),
        ...factsOf(decl.args),
        reauth: reauthOf(decl.args),
        where: 'routes/' + file + '.js',
      });
    }
  }
  for (const decl of declarations(appSrc)) {
    found.push({
      method: decl.method,
      path: quoted(decl.path),
      ...factsOf(decl.args),
      reauth: reauthOf(decl.args),
      where: 'app.js',
    });
  }
  return found;
};

const diffInventory = (actual, table) => {
  const actualKeys = actual.map(keyOf);
  const tableKeys = table.map(keyOf);
  return {
    missingInTable: actualKeys.filter((key) => !tableKeys.includes(key)),
    zombieInTable: tableKeys.filter((key) => !actualKeys.includes(key)),
  };
};

const diffFacts = (actual, table) => {
  const byKey = new Map(actual.map((row) => [keyOf(row), row]));
  const bad = [];
  for (const row of table) {
    const real = byKey.get(keyOf(row));
    if (!real) continue;
    if (asList(row.perm).join('|') !== asList(real.perm).join('|')) {
      bad.push(
        keyOf(row) + ' 权限码 ' + JSON.stringify(row.perm) + ' ≠ ' + JSON.stringify(real.perm)
      );
    }
    if ((row.auth || null) !== (real.auth || null)) {
      bad.push(keyOf(row) + ' 认证 ' + row.auth + ' ≠ ' + real.auth);
    }
    if (Boolean(row.viewSensitive) !== Boolean(real.viewSensitive)) {
      bad.push(keyOf(row) + ' 敏感标记 ' + row.viewSensitive + ' ≠ ' + real.viewSensitive);
    }
  }
  return bad;
};

/** 明细行要用合成世界自己的 id 去问，否则「查不到」是采样错误而不是缺陷 */
const SAMPLE_ID = Object.freeze({
  '/api/users': 'hp-u1',
  '/api/roles': 'hp-r1',
  '/api/permissions': 'hp-p1',
  '/api/devices': 'hp-d1',
  '/api/alarms': 'hp-a1',
  '/api/inspections': 'hp-i1',
});
const samplePathOf = (row) => {
  const prefix = Object.keys(SAMPLE_ID).find(
    (item) => row.path === item || row.path.startsWith(item + '/')
  );
  return row.path.replace(/:[A-Za-z]\w*/g, prefix ? SAMPLE_ID[prefix] : 'hp-u1');
};

/** 按 steer 的真实顺序现算一行路由的回答类别：判决 → 文件面 → 本人面 → 合成载荷 */
const liveHandlingOf = (row) => {
  const method = row.method;
  const target = samplePathOf(row);
  const verdict = resolveDecoyVerdict({ method, path: target });
  if (verdict === HONEYPOT_VERDICT.PASSTHROUGH) return TRAP_HANDLING.PASSTHROUGH;
  if (verdict === HONEYPOT_VERDICT.NOT_FOUND) return 'route-not-found';
  if (verdict === HONEYPOT_VERDICT.DENY) return TRAP_HANDLING.DENY;
  if (resolveFileResponse({ method, path: target, query: {} })) return TRAP_HANDLING.FILE;
  const session = { userId: 'hp-u1', username: 'sample' };
  if (resolveSelfResponse({ method, path: target, query: {}, session })) return TRAP_HANDLING.SELF;
  if (resolveAggregatePayload({ method, path: target, query: {} })) return TRAP_HANDLING.AGGREGATE; // 聚合读面：与列表同前缀、不同语义（接线在 steer 的通用载荷之前）
  if (resolveMetricsPayload({ method, path: target })) return TRAP_HANDLING.METRICS; // 运行时指标快照面：单端点，同样接在 steer 的通用载荷之前
  const payload = resolveDecoyPayload({ method, path: target, user: session });
  if (!payload) return 'decoy-none';
  if (payload.kind === 'list') return TRAP_HANDLING.LIST;
  if (payload.kind === 'summary') return TRAP_HANDLING.SUMMARY;
  if (payload.kind === 'detail') return TRAP_HANDLING.DETAIL;
  if (payload.kind === 'codeError') return 'decoy-not-found';
  return 'decoy-unknown';
};

/**
 * 现算一行在陷阱里落地的**授权轴**回答：data / permission-denied / not-found / passthrough / decoy-none。
 * 类别走 liveHandlingOf（steer 的真实顺序只写一份，两处各写一遍必漂），只在文件面上多看一眼
 * 是 404 还是 403：文件面的两种拒绝都是 codeError，类别名相同而授权含义相反。
 */
const trapReadAnswerOf = (row) => {
  const handling = liveHandlingOf(row);
  if (handling === TRAP_HANDLING.DENY) return 'permission-denied';
  if (handling === TRAP_HANDLING.PASSTHROUGH) return 'passthrough';
  if (handling === 'route-not-found' || handling === 'decoy-not-found') return 'not-found';
  if (handling !== TRAP_HANDLING.FILE) return handling === 'decoy-none' ? 'decoy-none' : 'data';
  const file = resolveFileResponse({ method: row.method, path: samplePathOf(row), query: {} });
  if (file && file.kind === 'workbook') return 'data';
  if (file && file.options && file.options.statusCode === 404) return 'not-found';
  return 'permission-denied';
};

/** 二次验证端点集：从源码现算（路由表不建模票据面，理由见 reauthOf 的注释） */
const gatedKeys = () =>
  new Set(
    actualRoutes()
      .filter((row) => row.reauth)
      .map(keyOf)
  );

/**
 * 真实链对**呈现身份**的授权轴应然回答：权限码（精确 / `*:*` / `module:*`）→ 二次验证票据 → 控制器。
 * presented 可注入，作为反向自证的入口（摘掉一行通配符，看判据会不会跟着变）。
 */
const realReadAnswerOf = (row, presented, gated) => {
  const perms = asList(row.perm);
  if (perms.length > 0 && !perms.every((code) => matchesPermissionCodes(presented, code))) {
    return 'permission-denied';
  }
  return gated.has(keyOf(row)) ? 'reauth-ticket-required' : 'data';
};

/** 读侧「未持有该权限却拿到数据」的行（登记项二） */
const unheldButOpenOf = (rows, presented) =>
  rows
    .filter((row) => asList(row.perm).length > 0 && trapReadAnswerOf(row) === 'data')
    .filter((row) => !asList(row.perm).every((code) => matchesPermissionCodes(presented, code)))
    .map(keyOf);

/**
 * 读侧回答与真实链应然回答的分歧（登记项三）：只判授权轴——404 是内容判定（无头像 / 查无此 id），
 * 放行白名单另有判据；写方法一律 DENY 的口径由 honeypotDecoyLedger 与 honeypotAuthOnlyLedger 判
 * （诱饵不许产生任何真实写副作用），本判据不重复声明。
 */
const readDivergenceOf = (rows, presented, gated) =>
  rows
    .filter((row) => !WRITE_METHODS.includes(row.method))
    .map((row) => ({
      key: keyOf(row),
      real: realReadAnswerOf(row, presented, gated),
      trap: trapReadAnswerOf(row),
    }))
    .filter(
      (item) =>
        !['not-found', 'passthrough', 'decoy-none'].includes(item.trap) && item.real !== item.trap
    );

const LIVE_OF_DECLARED = Object.freeze({
  [TRAP_HANDLING.PUBLIC]: [TRAP_HANDLING.PASSTHROUGH],
  [TRAP_HANDLING.PASSTHROUGH]: [TRAP_HANDLING.PASSTHROUGH],
  [TRAP_HANDLING.LIST]: [TRAP_HANDLING.LIST],
  [TRAP_HANDLING.DETAIL]: [TRAP_HANDLING.DETAIL],
  [TRAP_HANDLING.AGGREGATE]: [TRAP_HANDLING.AGGREGATE],
  [TRAP_HANDLING.SUMMARY]: [TRAP_HANDLING.SUMMARY],
  [TRAP_HANDLING.SELF]: [TRAP_HANDLING.SELF],
  [TRAP_HANDLING.FILE]: [TRAP_HANDLING.FILE],
  [TRAP_HANDLING.METRICS]: [TRAP_HANDLING.METRICS],
  [TRAP_HANDLING.DENY]: [TRAP_HANDLING.DENY],
});

/**
 * 登记项一：聚合读端点的合成体。批次 B 接线后**已清空**——这里空着不是「没有欠账」，而是
 * 「欠账已被判据吃掉」：把任意一条从 AGGREGATE_ENDPOINTS 里删掉，现算立刻落回 decoy-none，
 * 双向判据（现算的不一致集 === 本数组）随即变红。
 */
const AGGREGATE_BACKLOG = [];

/** 呈现身份在 /api/auth/me 里**声称持有**的全部权限码（判据的输入，不是从结论抄的） */
const PRESENTED_PERMISSIONS = asList(DECOY_PERMISSIONS);
const heldByPresented = (code) => matchesPermissionCodes(PRESENTED_PERMISSIONS, code);

/**
 * 登记项二：读侧「未持有该权限却拿到 200/文件」。
 *
 * 判据第一版只做**精确**匹配，于是把 5 条 security:audit 端点记成「越权开口」（旧名
 * PERM_OUTSIDE_CATALOG_BACKLOG）。而真实链的规则是「精确 → `*:*` → `module:*`」，
 * 呈现目录里那行 security:*（安全管理菜单）已经覆盖 security:audit——**旧登记项是把判据的
 * 口径错当成了行为**：那 5 条对呈现身份本来就是合法 200。口径改同源之后现算为空。
 * 反向自证在下面的用例里：摘掉 security:*，4 条 200 面必须立刻落进本集合（登记空间只有这一格，
 * 判据不许放水）。
 */
const UNHELD_BUT_OK_BACKLOG = [];

/**
 * 读侧回 404 的行：内容语义（无头像），授权轴判不了它——但也不许**悄悄多出**一条，
 * 所以同样钉死清单。判据只判「数据 / 权限拒绝 / 缺票」三种回答，剩下那一类在这里点名。
 */
const READ_NOT_FOUND_ROWS = ['GET /api/avatars/:userId'];

/**
 * 登记项三：读侧回答与真实链**应然**回答的分歧，逐条给出方向（real/trap）与理由。
 * 只判授权轴；404（内容判定：无头像/查无此 id）与放行白名单各有判据，不在这里混算。
 *
 * 三类归因，都能只凭现有事实复算：
 * - real=reauth-ticket-required / trap=data：真实链在权限码过闸后还要 requireReauthTicket()
 *   （票据由 POST /api/security/reauth 换取），陷阱没有票据面 ⇒ **少一道闸**，回的是合成数据。
 * - real=reauth-ticket-required / trap=permission-denied：状态同、**理由不同**——对方拿着
 *   /api/auth/me 的权限表能算出「我该过权限闸」，却收到权限不足。
 * 第三类（real=data / trap=permission-denied：GET /api/metrics 没有第二道闸，而呈现身份经
 * security:* 持有 security:audit ⇒ 真实链是 200）是**唯一一条纯自相矛盾**——不需要知道票据闸的
 * 存在，只比对两次响应即可发现。它已在 2026-11-02 收口：路由表把该行改成 decoy-metrics，
 * 判定层回同键集的合成快照（见 constants/honeypotDecoyMetrics.js 与其形态闸），本数组随之少一条。
 * 剩下 5 条全是票据面（同一道闸的两种表现），收口方向写在下面。
 *
 * 收口方向（留给下一次增量，不在这里顺手改行为）：票据面要么整体不建模（保持合成面，但登记项
 * 只许变少），要么把 requireReauthTicket 声明进路由表、给缺票会话回逐字相同的
 * REAUTH_TICKET_REQUIRED。**不能**改成把 security:* 从呈现目录里摘掉：那时越权开口会立刻变成
 * 5 条（见下一个用例的反向自证），比现状更差。
 */
const READ_DIVERGENCE_BACKLOG = [
  {
    key: 'GET /api/security/alerts',
    real: 'reauth-ticket-required',
    trap: 'data',
    why: '真实链过权限闸后还要求步进票据；陷阱没有票据面，回的是合成告警列表',
  },
  {
    key: 'GET /api/security/audit-logs/verify',
    real: 'reauth-ticket-required',
    trap: 'data',
    why: '同上：真实链缺票时连「检测器是否在线」都问不到，陷阱回合成校验结果',
  },
  {
    key: 'GET /api/security/audit-logs/export',
    real: 'reauth-ticket-required',
    trap: 'permission-denied',
    why: '状态同、理由不同：真实链缺票回 REAUTH_TICKET_REQUIRED，陷阱回 PERMISSION_DENIED',
  },
  {
    key: 'GET /api/security/audit-logs',
    real: 'reauth-ticket-required',
    trap: 'data',
    why: '同上：真实链要票据，陷阱回合成审计列表',
  },
  {
    key: 'GET /api/security/stuffing-profile',
    real: 'reauth-ticket-required',
    trap: 'permission-denied',
    why: '同上：本行原有的「零权限会话该看到的 403」在呈现身份持有 security:audit 之后不再成立',
  },
];

describe('路由声明表（P2-2）：与真实路由、真实判定链双向对拍', () => {
  test('前提自证：解析器吃得下多行实参、OR 数组、串联权限与敏感标记（正反样本）', () => {
    const sample = [
      "router.get('/x/:id', authenticate, checkPermission(['a:read', 'b:read']), checkViewSensitivePermission, handler);",
      'router.post(',
      "  '/y',",
      '  authenticateForLogout,',
      "  checkPermission('c:read'),",
      '  handler',
      ');',
    ].join('\n');
    expect(
      declarations(sample).map((item) => [item.method, quoted(item.path), factsOf(item.args)])
    ).toEqual([
      ['GET', '/x/:id', { perm: ['a:read', 'b:read'], auth: 'authenticate', viewSensitive: true }],
      ['POST', '/y', { perm: 'c:read', auth: 'authenticateForLogout', viewSensitive: false }],
    ]);
    expect(read('src/app.js').length).toBeGreaterThan(1000);
  });

  test('路由清单双向：app.js 挂载 × routes/*.js 声明 × 内联路由 === 声明表', () => {
    const actual = actualRoutes();
    const actualKeys = actual.map(keyOf);
    expect(actualKeys.length).toBeGreaterThanOrEqual(120);
    expect(new Set(actualKeys).size).toBe(actualKeys.length);
    expect(diffInventory(actual, ROUTE_TABLE)).toEqual({ missingInTable: [], zombieInTable: [] });
    expect(ROUTE_TABLE.length).toBe(actualKeys.length);
  });

  test('逐行事实：权限码 / 认证中间件 / 敏感标记都必须与源码逐字一致', () => {
    expect(diffFacts(actualRoutes(), ROUTE_TABLE)).toEqual([]);
  });

  test('反向自证（判据有牙）：清单多一条/少一条、权限码/认证/敏感标记写错都必须被点名', () => {
    const actual = actualRoutes();
    const ghost = {
      method: 'GET',
      path: '/api/ghost',
      perm: 'ghost:read',
      auth: 'authenticate',
      viewSensitive: false,
    };
    expect(diffInventory([...actual, ghost], ROUTE_TABLE).missingInTable).toEqual([
      'GET /api/ghost',
    ]);
    expect(diffInventory(actual.slice(1), ROUTE_TABLE).zombieInTable).toEqual([
      keyOf(ROUTE_TABLE[0]),
    ]);
    const tampered = (patch) => ROUTE_TABLE.map((row) => Object.assign({}, row, patch));
    expect(diffFacts(actual, tampered({ perm: 'ghost:read' })).length).toBeGreaterThan(50);
    expect(diffFacts(actual, tampered({ auth: 'authenticateForLogout' })).length).toBeGreaterThan(
      50
    );
    const vsensRow = ROUTE_TABLE.find((row) => row.viewSensitive);
    expect(vsensRow).toBeTruthy();
    expect(
      diffFacts(
        actual,
        ROUTE_TABLE.map((row) =>
          row === vsensRow ? Object.assign({}, row, { viewSensitive: false }) : row
        )
      )
    ).toEqual([keyOf(vsensRow) + ' 敏感标记 false ≠ true']);
  });

  test('回答类别现算 === 声明：登记项以外的每一行都必须现算出声明的那一类（双向）', () => {
    const mismatches = ROUTE_TABLE.filter(
      (row) => !(LIVE_OF_DECLARED[row.handling] || []).includes(liveHandlingOf(row))
    ).map(keyOf);
    expect(mismatches.sort()).toEqual([...AGGREGATE_BACKLOG].sort());
  });

  test('聚合读面双向：AGGREGATE_ENDPOINTS 的每一条都必须是表里的 decoy-aggregate，反之亦然', () => {
    const declared = ROUTE_TABLE.filter((row) => row.handling === TRAP_HANDLING.AGGREGATE).map(
      keyOf
    );
    const implemented = AGGREGATE_ENDPOINTS.map(keyOf);
    expect(implemented.sort()).toEqual(declared.sort());
    expect(AGGREGATE_BACKLOG).toEqual([]);
    for (const endpoint of AGGREGATE_ENDPOINTS) {
      expect(endpoint.method).toBe('GET');
      // 现算一发：端点表里登记了却解析不出载荷，等于「声明有、给不出」——静默 404 比没有更糟
      const payload = resolveAggregatePayload({
        method: endpoint.method,
        path: endpoint.path,
        query: {},
      });
      expect(payload).toBeTruthy();
      expect(payload.endpoint).toBe(endpoint.id);
      expect(payload.envelope).toBe(endpoint.envelope);
      // 信封必须与 ApiResponse 的两个真实构造器对得上，否则接线处只能自己拼响应体
      expect(['success', 'paginated']).toContain(payload.envelope);
      if (payload.envelope === 'paginated') expect(payload.pagination).toBeTruthy();
      else expect(payload.pagination).toBeUndefined();
    }
  });

  test('不可派生登记双向：NON_DERIVABLE 覆盖的端点集 === 聚合端点集，且每条都写明为什么', () => {
    const registered = [...new Set(NON_DERIVABLE.map((item) => item.endpoint))].sort();
    const endpoints = AGGREGATE_ENDPOINTS.map((item) => item.path).sort();
    expect(registered).toEqual(endpoints);
    for (const item of NON_DERIVABLE) {
      expect(typeof item.field).toBe('string');
      expect(item.field.length).toBeGreaterThan(0);
      expect(typeof item.why).toBe('string');
      expect(item.why.length).toBeGreaterThan(10);
    }
    // 反向自证：把一条端点从登记里抽走必须被点名（否则「登记」会退化成装饰）
    const dropped = NON_DERIVABLE.filter((item) => item.endpoint !== AGGREGATE_ENDPOINTS[0].path);
    expect([...new Set(dropped.map((item) => item.endpoint))].sort()).not.toEqual(endpoints);
  });

  test('聚合体的回答不回落到通用载荷：把聚合接线摘掉，那 10 条必须立刻现算成别的类别（判据有牙）', () => {
    for (const endpoint of AGGREGATE_ENDPOINTS) {
      const row = ROUTE_TABLE.find((item) => keyOf(item) === keyOf(endpoint));
      const fallback = resolveDecoyPayload({
        method: endpoint.method,
        path: endpoint.path,
        user: { userId: 'hp-u1', username: 'sample' },
      });
      // 通用载荷对这些路径只会给「查无此 id」的 404（或干脆 null）：正是 AGGREGATE_BACKLOG 的由来
      expect(fallback === null || fallback.kind === 'codeError').toBe(true);
      expect(row.handling).toBe(TRAP_HANDLING.AGGREGATE);
    }
  });

  test('前提：判据用的权限口径 === 真实链的口径（精确 / *:* / module:*），呈现目录确实含 security:*', () => {
    expect(matchesPermissionCodes(['security:*'], 'security:audit')).toBe(true);
    expect(matchesPermissionCodes(['security:stats'], 'security:audit')).toBe(false);
    expect(matchesPermissionCodes(['*:*'], 'pii:export')).toBe(true);
    expect(matchesPermissionCodes([], 'security:audit')).toBe(false);
    // 真实链的规则钉在源码上：精确 → 全局通配 → 模块通配。少一环，下面两条判据就换成另一个口径。
    const rbac = read('src/middleware/rbac.js');
    expect(rbac).toMatch(/includes\('\*:\*'\)/);
    expect(rbac).toMatch(/const moduleWildcard =/);
    expect(rbac).toMatch(/includes\(moduleWildcard\)/);
    // 呈现身份 = /api/auth/me 里那张权限表，现算一次（不从常量抄结论）
    const me = resolveSelfResponse({
      method: 'GET',
      path: '/api/auth/me',
      query: {},
      session: { userId: 'hp-u1', username: 'sample' },
    });
    expect(me.data.permissions).toEqual(PRESENTED_PERMISSIONS);
    expect(heldByPresented('security:audit')).toBe(true);
    expect(heldByPresented('pii:export')).toBe(false);
  });

  test('读侧「未持有却开口」双向：现算 === 登记（空）；摘掉 security:* 后 5 条 200 面立刻落网', () => {
    expect(unheldButOpenOf(ROUTE_TABLE, PRESENTED_PERMISSIONS).sort()).toEqual([
      ...UNHELD_BUT_OK_BACKLOG,
    ]);
    // 反向自证（判据有牙）：通配符那行一摘，合法 200 立刻变成越权开口——现算集随输入变，
    // 说明现在的空集不是「判据没牙」，而是这 5 条（4 条 security 面 + /api/metrics 合成快照面）
    // 在真实链口径下确实合法
    expect(
      unheldButOpenOf(
        ROUTE_TABLE,
        PRESENTED_PERMISSIONS.filter((code) => code !== 'security:*')
      ).sort()
    ).toEqual([
      'GET /api/metrics',
      'GET /api/security/alerts',
      'GET /api/security/audit-logs',
      'GET /api/security/audit-logs/verify',
      'GET /api/security/overview',
    ]);
  });

  test('读侧回答 vs 真实链应然回答：分歧逐条登记（键 + 方向一起比，不许只比条数）', () => {
    const byKey = (list) => [...list].sort((a, b) => (a.key < b.key ? -1 : 1));
    const shape = (item) => ({ key: item.key, real: item.real, trap: item.trap });
    const computed = readDivergenceOf(ROUTE_TABLE, PRESENTED_PERMISSIONS, gatedKeys());
    expect(byKey(computed).map(shape)).toEqual(byKey(READ_DIVERGENCE_BACKLOG).map(shape));
    for (const item of READ_DIVERGENCE_BACKLOG) {
      expect(item.why.length).toBeGreaterThan(10);
    }
    // 404 那一类不许悄悄多出来（授权轴判不了它，所以用清单兜住）
    const notFound = ROUTE_TABLE.filter(
      (row) => !WRITE_METHODS.includes(row.method) && trapReadAnswerOf(row) === 'not-found'
    )
      .map(keyOf)
      .sort();
    expect(notFound).toEqual([...READ_NOT_FOUND_ROWS].sort());
    // 反向自证（两个方向一起翻）：摘掉 security:* 之后，5 条票据分歧全部消失（真实链也变成
    // 权限拒绝，与陷阱的拒绝同形），但代价是冒出 5 条越权开口——所以「摘通配符」不是收口方向
    const reduced = readDivergenceOf(
      ROUTE_TABLE,
      PRESENTED_PERMISSIONS.filter((code) => code !== 'security:*'),
      gatedKeys()
    );
    expect(reduced.map((item) => item.key).sort()).toEqual([
      'GET /api/metrics',
      'GET /api/security/alerts',
      'GET /api/security/audit-logs',
      'GET /api/security/audit-logs/verify',
      'GET /api/security/overview',
    ]);
    expect(reduced.every((item) => item.real === 'permission-denied' && item.trap === 'data')).toBe(
      true
    );
  });

  test('前提：二次验证闸从源码现算，恰好这 5 条（正反样本都吃得下）', () => {
    expect(
      reauthOf(['authenticate', "checkPermission('security:audit')", 'requireReauthTicket()'])
    ).toBe(true);
    expect(reauthOf(['authenticate', "checkPermission('security:audit')", 'strictLimiter'])).toBe(
      false
    );
    expect([...gatedKeys()].sort()).toEqual([
      'GET /api/security/alerts',
      'GET /api/security/audit-logs',
      'GET /api/security/audit-logs/export',
      'GET /api/security/audit-logs/verify',
      'GET /api/security/stuffing-profile',
    ]);
  });

  test('前提：authenticate 只逐路由挂，绝不 router.use / app.use 整段挂（否则未声明路径真会进改道点）', () => {
    const appSrc = read('src/app.js');
    expect(appSrc).not.toMatch(/app\.use\([^)]*\bauthenticate\b/);
    const offenders = [...mountInfo().fileOf.keys()].filter((ident) =>
      /router\.use\([^)]*\bauthenticate\b/.test(read('src/routes/' + ident + '.js'))
    );
    expect(offenders).toEqual([]);
    expect(/router\.use\([^)]*\bauthenticate\b/.test('router.use(authenticate);')).toBe(true);
  });

  test('未声明路径的 404 与 app.js 兜底逐字相同（同一句模板 + 同一个打码函数）', () => {
    const lineOf = (source) => {
      const at = source.indexOf('接口不存在：');
      expect(at).toBeGreaterThan(0);
      const from = source.lastIndexOf('\n', at) + 1;
      const to = source.indexOf('\n', at);
      return source.slice(from, to === -1 ? undefined : to).trim();
    };
    const appLine = lineOf(read('src/app.js'));
    const trapLine = lineOf(read('src/services/honeypotDecoy.js'));
    expect(trapLine).toBe(appLine);
    expect(appLine).toContain('redactUrlQuery(req.originalUrl || req.url)');
    expect(read('src/services/honeypotDecoy.js')).toMatch(/require\('\.\.\/utils\/helpers'\)/);
    expect(read('src/app.js')).toMatch(/require\('\.\/utils\/helpers'\)/);
  });

  test('放行白名单与表一致：表里 passthrough 的行 === PASSTHROUGH_ROUTES（多一条少一条都红）', () => {
    const declared = ROUTE_TABLE.filter((row) => row.handling === TRAP_HANDLING.PASSTHROUGH).map(
      keyOf
    );
    const pinned = PASSTHROUGH_ROUTES.map(keyOf);
    expect(declared.sort()).toEqual(pinned.sort());
    for (const route of PASSTHROUGH_ROUTES) {
      expect(matchRoute({ method: route.method, path: route.path })).toBeTruthy();
    }
  });

  test('matchRoute 与 Express 同口径：大小写、一个尾斜杠、HEAD 回退 GET，双斜杠与多余段不算', () => {
    const users = matchRoute({ method: 'GET', path: '/api/users' });
    expect(users).toBeTruthy();
    expect(matchRoute({ method: 'get', path: '/API/Users/' })).toBe(users);
    expect(matchRoute({ method: 'HEAD', path: '/api/users' })).toBe(users);
    expect(matchRoute({ method: 'GET', path: '/api//users' })).toBe(null);
    expect(matchRoute({ method: 'GET', path: '/api/users/extra/deep' })).toBe(null);
    // :参数 匹配任意非空段，所以「多余的一个段」会命中 /api/users/:id——形状判定到此为止；
    // 真实链上它其实被 ObjectId 参数闸拦在改道点之前（见 ADR-013 的「不可达」表）
    expect(matchRoute({ method: 'DELETE', path: '/api/users/extra' })).toBe(
      matchRoute({ method: 'DELETE', path: '/api/users/:id' })
    );
    expect(matchRoute({ method: 'DELETE', path: '/api/ghost/x' })).toBe(null);
  });
});
