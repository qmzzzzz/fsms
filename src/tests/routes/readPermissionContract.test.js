/**
 * 读接口（GET）鉴权契约门禁（F-196）
 *
 * 已有写侧闸门 writePermissionContract.test.js 的抓取正则是
 * `/router\.(post|put|delete|patch)\s*\(/g`——GET 一条都不在里面。
 * 后果：新增一条 `router.get('/xxx', ctrl.list)` 而忘记 authenticate 时，
 * 全套 CI 不会有任何一声告警，这条路由就是匿名可读的越权面。
 * 写侧有闸、读侧无闸，正是"半个契约＝没有契约"。
 *
 * 契约（三条，全部可证伪，见下方"变异臂"）：
 *   ① 每条 GET 必须显式挂 authenticate，否则必须落在 PUBLIC_GET_ALLOWLIST / APP_GET_GUARDS 里并写明理由；
 *   ② 挂了 authenticate 但无权限中间件的，必须落在 SELF_ONLY_ALLOWLIST（操作对象恒为调用者本人）；
 *   ③ 白名单都不许留失效条目（路由删了/改名了，白名单必须同轮瘦身）。
 *
 * 注册面有**两个**（写侧闸门都数不清的那一个）：`src/routes/*.js` 的 `router.get(...)` 48 条，
 * 以及 `src/app.js` 里 `app.get(...)` 直挂的 6 条（/health /readyz /metrics /api/metrics /api
 * /api-docs.json）。只扫 routes 目录的闸门看不见后者——实测把 `metricsAuth` 从 /metrics 删掉、
 * 或在 app.js 里裸新增一条 GET，只扫 routes 的版本全程绿。所以两条都各设了变异臂。
 *
 * 判定用"代码视图"（先剥注释再匹配中间件名），理由与本仓 F-128 同源：
 * 注释里出现 `authenticate` 不得让一条裸路由过关。实测：当前 48 条 GET 在
 * 剥注释前后分类完全一致（0 处差异），所以这条收紧不会误伤，只会堵住未来的假绿。
 *
 * 静态扫描而非遍历 app._router：漏挂标记时能直接指到文件与路由，且不受挂载顺序影响
 * （与写侧闸门同一实现取向；写侧注释里已记录选择理由）。
 */

const fs = require('fs');
const path = require('path');

const ROUTES_DIR = path.join(__dirname, '../../routes');

/** 剥注释（F-128 同法）：块注释、整行注释、行尾注释 */
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/([^:])\/\/.*$/gm, '$1');

/**
 * 抓取 GET 路由块。块边界 = 下一条任意动词声明（app/router 均算）或顶层块收尾 `\n}`，
 * 取两者较早者，文件末尾兜底。
 *
 * 为什么要自己算声明索引而不是 `indexOf('\nrouter.')`：本仓的 HTTP 端点有**两个注册面**，
 * `src/routes/*.js` 里的 `router.get(...)` 顶格写，而 `src/app.js` 里的 `app.get(...)`
 * 缩进在 createApp 函数体内——按 `\nrouter.` 切块会整体看不见 app.js（实测 6 条 GET），
 * 那正是本闸门要堵的那一类"闸门自己的视野里少了一整类"的缺陷。
 * `\n}` 这条边界是为 app.js 准备的：它最后一条 GET（/api-docs.json）之后没有别的声明了，
 * 不截断就会把 createApp 尾巴一并算进块。
 */
const ANY_DECL_RE = /(?<![\w.])(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(/g;
const GET_HEAD_RE = /^(?:app|router)\.get\s*\(/;

const extractGetBlocks = (source) => {
  const decls = [];
  let match;
  ANY_DECL_RE.lastIndex = 0;
  while ((match = ANY_DECL_RE.exec(source)) !== null) decls.push(match.index);
  const blocks = [];
  for (const idx of decls) {
    if (!GET_HEAD_RE.test(source.slice(idx, idx + 40))) continue;
    const end = blockEndOf(source, idx);
    const raw = source.slice(idx, end);
    const m = raw.match(/['"`](\/[^'"`]*)/);
    blocks.push({ route: m ? m[1] : '(未解析路径)', raw, code: stripComments(raw) });
  }
  return blocks;
};

/** 单块分类：只看代码视图，注释里的中间件名不作数 */
const classify = (block) => ({
  authenticated: /\bauthenticate\b/.test(block.code),
  permission: /checkPermission\s*\(|checkViewSensitivePermission/.test(block.code),
  exempt: /PERMISSION-EXEMPT:\s*\S/.test(block.code),
});

/**
 * 匿名可读的 GET（实测 2026-09-26：6 条）。每条都要有"为什么匿名可读不泄露"的理由，
 * 且必须与路由文件里的实际端点一一对应——多一条、少一条都转红（见③）。
 */
const PUBLIC_GET_ALLOWLIST = {
  'authRoutes.js /captcha': '登录前置：验证码图片本身就是给未登录页用的',
  'authRoutes.js /captcha-status': '同上，只回布尔开关',
  'authRoutes.js /login-public-key': '加密登录用的公钥，公钥本就需匿名可得（私钥永不下发）',
  'authRoutes.js /session':
    '只回 { authenticated }，由调用者自己的 cookie 推导，不接受任何身份入参（authController.js:554-569）',
  'wellKnownRoutes.js /.well-known/security.txt': 'RFC 9116 公共安全联系信息',
  'wellKnownRoutes.js /security.txt': '同上的历史别名',
};

/**
 * 已鉴权但不挂权限中间件的 GET（实测 2026-09-26：6 条）——操作对象恒为 req.user 本人。
 * 逐条核实过 handler 入参：userId 一律取自 req.user，不接受 ?userId= 之类的目标入参，
 * 所以"本人资源"这条理由是实测而非命名推断。
 */
const SELF_ONLY_ALLOWLIST = {
  'authRoutes.js /me': '本人资料，userId 取自令牌',
  'authRoutes.js /mfa/status': '本人 MFA 绑定状态',
  'authRoutes.js /sessions': '本人活跃会话（listSessions 显式不接受 userId 入参）',
  'securityRoutes.js /my-info': '本人安全设置（getMySecurityInfo: req.user.userId）',
  'securityRoutes.js /bindings': '本人邮箱/手机绑定（getAccountBindings: req.user.userId）',
  'securityRoutes.js /my-logs': '本人操作日志（getMyLogs 只接 days/limit/category）',
};

/**
 * src/app.js 上直接挂 app.get(...) 的端点（实测 2026-09-26：6 条），第二个注册面。
 * 值 = 该端点依赖的守卫标识符（`public` 表示确实要匿名，需在理由里说清）。
 * 关键约束：写了标识符的，标识符必须**真的出现在该声明的代码视图里**——
 * 否则"删掉 metricsAuth"这种变异就能靠一条旧白名单条目继续蒙过闸门（见 ⑤ 那条用例）。
 */
const APP_GET_GUARDS = {
  'app.js /health': { guard: 'public', reason: '存活探针，只回 {status:ok}，刻意不含版本/DB 状态' },
  'app.js /readyz': {
    guard: 'public',
    reason: '就绪探针，对外只暴露固定枚举 ok/disconnected/timeout/unreachable/error（M-1）',
  },
  'app.js /metrics': {
    guard: 'metricsAuth',
    reason: 'Prometheus 抓取端点：内网/回环放行 + 可选 METRICS_TOKEN Bearer，fail-safe 到拒绝',
  },
  'app.js /api/metrics': {
    guard: 'authenticate',
    reason: '管理面指标快照，走 authenticate + security:audit',
  },
  'app.js /api': {
    guard: 'public',
    reason: '只回一句系统名，接口清单已刻意不再返回（避免匿名信息暴露）',
  },
  'app.js /api-docs.json': {
    guard: 'swagger.basicAuth',
    reason: '文档默认关闭，开启时 docsLimiter 在 basicAuth 之前（P2-30 顺序要求）',
  },
};

const keyOf = (file, block) => `${file} ${block.route}`;

/** 块尾索引：下一条任意动词声明、顶层块收尾 `\n}`、文件末尾，取最早者 */
const blockEndOf = (source, start) => {
  ANY_DECL_RE.lastIndex = start + 1;
  const next = ANY_DECL_RE.exec(source);
  let end = next ? next.index : source.length;
  const topClose = source.indexOf('\n}', start + 1);
  if (topClose !== -1 && topClose < end) end = topClose;
  return end;
};

/** 把真实源码里某个路由块内的某个标识符抹掉——用于"变异臂"（不碰仓库文件） */
const stripMiddlewareInBlock = (source, route, name) => {
  const re = new RegExp(
    `(?:app|router)\\.get\\s*\\(\\s*['"\`]${route.replace(/[.\\]/g, '\\$&')}['"\`]`
  );
  const found = re.exec(source);
  if (!found) throw new Error(`变异臂前提失效：源码里找不到 GET ${route}`);
  const start = found.index;
  const end = blockEndOf(source, start);
  const mutated = source.slice(start, end).replace(new RegExp(`\\b${name}\\b`), '');
  return source.slice(0, start) + mutated + source.slice(end);
};

/** 扫描一组（文件名 → 源码），返回四类违规 + 规模计数 */
const scan = (sources) => {
  const found = [];
  const anonymous = [];
  const unscoped = [];
  const guardMissing = [];
  let scannedFiles = 0;
  for (const [file, source] of Object.entries(sources)) {
    const blocks = extractGetBlocks(source);
    if (blocks.length > 0) scannedFiles += 1;
    for (const block of blocks) {
      const key = keyOf(file, block);
      const c = classify(block);
      found.push(key);
      if (!c.authenticated) {
        const entry = APP_GET_GUARDS[key] || PUBLIC_GET_ALLOWLIST[key];
        if (!entry) {
          anonymous.push(key);
        } else if (typeof entry === 'object' && entry.guard !== 'public') {
          // 白名单声称靠某个守卫兜底，就必须能在代码视图里看到它
          if (!new RegExp(`\\b${entry.guard.replace(/\./g, '\\.')}`).test(block.code)) {
            guardMissing.push(`${key} 声称由 ${entry.guard} 保护，但声明里没有它`);
          }
        }
      } else if (!c.permission && !c.exempt && !SELF_ONLY_ALLOWLIST[key]) {
        unscoped.push(key);
      }
    }
  }
  return {
    found,
    anonymous,
    unscoped,
    guardMissing,
    scannedFiles,
    total: found.length,
  };
};

describe('GET 接口鉴权契约（F-196：写侧有闸，读侧不能没有）', () => {
  const routeFiles = fs
    .readdirSync(ROUTES_DIR)
    .filter((f) => f.endsWith('.js') && f !== 'index.js')
    .sort();

  /** 真实的（文件名 → 源码）集合：两个注册面——routes 目录 + app.js 直挂 */
  const APP_JS = path.join(__dirname, '../../app.js');
  const REAL = {
    ...Object.fromEntries(
      routeFiles.map((f) => [f, fs.readFileSync(path.join(ROUTES_DIR, f), 'utf8')])
    ),
    'app.js': fs.readFileSync(APP_JS, 'utf8'),
  };

  test('计数判据自证：合成源里 3 条 GET 必须分类正确，且注释里的 authenticate 不作数', () => {
    const synthetic = [
      "router.get('/a', authenticate, checkPermission('x:y'), ctrl.a);",
      "router.get('/b', ctrl.b); // authenticate 在这里只是注释",
      "router.get('/c', authenticate, /* checkPermission 也是注释 */ ctrl.c);",
      '',
      "router.post('/p', ctrl.p); // 写路由不归本闸方管",
    ].join('\n');
    const blocks = extractGetBlocks(synthetic);
    expect(blocks.map((b) => b.route)).toEqual(['/a', '/b', '/c']);
    const cs = blocks.map(classify);
    expect(cs[0]).toEqual({ authenticated: true, permission: true, exempt: false });
    // 这一条就是本闸门存在的意义：注释里写了 authenticate 也不得判为已鉴权
    expect(cs[1].authenticated).toBe(false);
    expect(cs[2].permission).toBe(false);
  });

  test('规模地板：两个注册面都必须被扫到（防扫描路径漂移导致整体假绿）', () => {
    const r = scan(REAL);
    // 实测 54 条 GET = routes 目录 48（securityRoutes 14 / authRoutes 7 / device 5 / report 5 …）
    // + app.js 直挂 6。分面各自设地板：只看总数会漏掉"整个 app.js 不见了"这种失效。
    expect(r.total).toBeGreaterThan(50);
    expect(r.scannedFiles).toBeGreaterThanOrEqual(11);
    expect(extractGetBlocks(REAL['app.js'])).toHaveLength(6);
  });

  test('① 每条 GET 要么挂 authenticate，要么在白名单里写明理由', () => {
    expect(scan(REAL).anonymous).toEqual([]);
  });

  test('② 已鉴权但未收口到"本人资源"的 GET，必须落在 SELF_ONLY_ALLOWLIST', () => {
    expect(scan(REAL).unscoped).toEqual([]);
  });

  test('③ 三张白名单都不许留失效条目（路由改名/下线必须同轮瘦身）', () => {
    const found = new Set(scan(REAL).found);
    for (const list of [PUBLIC_GET_ALLOWLIST, SELF_ONLY_ALLOWLIST, APP_GET_GUARDS]) {
      expect(Object.keys(list).filter((k) => !found.has(k))).toEqual([]);
    }
  });

  test('③ 白名单条目必须带理由（防止注释流于形式）', () => {
    const thin = [];
    for (const [key, reason] of Object.entries({
      ...PUBLIC_GET_ALLOWLIST,
      ...SELF_ONLY_ALLOWLIST,
    })) {
      if (reason.trim().length <= 4) thin.push(key);
    }
    for (const [key, entry] of Object.entries(APP_GET_GUARDS)) {
      if (!entry.reason || entry.reason.trim().length <= 4) thin.push(key);
    }
    expect(thin).toEqual([]);
  });

  test('④ app.js 侧白名单声称的守卫必须真的出现在声明里（否则白名单替变异背书）', () => {
    expect(scan(REAL).guardMissing).toEqual([]);
  });

  test('挂了权限中间件的 GET 不可能绕过 authenticate（否则 RBAC 跑在匿名请求上）', () => {
    const violations = [];
    for (const [file, source] of Object.entries(REAL)) {
      for (const block of extractGetBlocks(source)) {
        const c = classify(block);
        if (c.permission && !c.authenticated) violations.push(keyOf(file, block));
      }
    }
    expect(violations).toEqual([]);
  });

  test('可证伪性：把真实 /me 的 authenticate 抹掉，本闸必须只报出这一条', () => {
    const before = scan(REAL);
    expect(before.anonymous).toEqual([]);

    const sources = {
      ...REAL,
      'authRoutes.js': stripMiddlewareInBlock(REAL['authRoutes.js'], '/me', 'authenticate'),
    };
    const after = scan(sources);
    expect(after.anonymous).toEqual(['authRoutes.js /me']);
    expect(after.total).toBe(before.total);
  });

  test('可证伪性：app.js 侧删掉 metricsAuth，白名单不得替这条变异背书', () => {
    const sources = {
      ...REAL,
      'app.js': stripMiddlewareInBlock(REAL['app.js'], '/metrics', 'metricsAuth'),
    };
    const r = scan(sources);
    expect(r.anonymous).toEqual([]); // 仍在白名单里，所以"匿名"这一类不该膨胀
    expect(r.guardMissing).toEqual(['app.js /metrics 声称由 metricsAuth 保护，但声明里没有它']);
  });

  test('可证伪性：在 app.js 里新增一条裸 GET 也必须被拦（第二个注册面不是法外之地）', () => {
    const sources = {
      ...REAL,
      'app.js': `${REAL['app.js']}\napp.get('/admin/dump-all', ctrl.dump);\n`,
    };
    expect(scan(sources).anonymous).toEqual(['app.js /admin/dump-all']);
  });

  test('可证伪性：新增一条裸 GET 必须被拦；删掉路由则白名单必须同轮瘦身', () => {
    const withNewRoute = {
      ...REAL,
      'userRoutes.js': `${REAL['userRoutes.js']}\nrouter.get('/export-all', ctrl.exportAll);\n`,
    };
    expect(scan(withNewRoute).anonymous).toEqual(['userRoutes.js /export-all']);

    const meBlock = extractGetBlocks(REAL['authRoutes.js']).find((b) => b.route === '/me');
    const withoutMe = { ...REAL, 'authRoutes.js': REAL['authRoutes.js'].replace(meBlock.raw, '') };
    const r = scan(withoutMe);
    expect(Object.keys(SELF_ONLY_ALLOWLIST).filter((k) => !r.found.includes(k))).toEqual([
      'authRoutes.js /me',
    ]);
  });
});
