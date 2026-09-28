/**
 * 数据范围契约测试（ADR-008）
 *
 * 契约：`src/routes/*.js` 中所有写路由（POST/PUT/PATCH/DELETE）必须满足
 * 三者之一——
 *   1. 对应 controller handler 体内出现范围判定调用（显式调用 rbac helper，
 *      或本文件内定义的 `is*InScope` 之类包装函数）；
 *   2. 路由块内声明 `SCOPE-EXEMPT: <理由>`（理由不可为空）；
 *   3. handler 体内出现自作用域引用（`req.user.userId` / `req.user.id`），
 *      即操作对象恒为调用者本人。
 *
 * 目的：2026-09-16 审计报告 §5.1 的核心结论是「104 条路由 dataScope 挂载数 = 0，
 * 且没有任何自动化手段能发现遗漏」——P0-1 跨部门越权正是这种「没人想过范围问题」
 * 的产物。本测试不能证明范围逻辑**正确**（那需要逐条业务审查），但能阻止
 * 「新增写路由时根本没考虑过范围」。任何新路由若三者皆不满足即 CI 红，
 * 必须显式登记自己的范围策略。
 *
 * 为什么不是路由级中间件：见 docs/adr/ADR-008-数据范围强制方式.md。
 * 简述：范围策略按 handler 内分支决定（本人/他人、列表过滤/单文档判定），
 * 且单文档判定需先加载文档，路由中间件不在那个位置。
 *
 * 实现：静态扫描。与 writePermissionContract.test.js 同款做法——
 * 能在标记缺失时直接指出文件与路由，且不受挂载顺序影响。
 */

const fs = require('fs');
const path = require('path');

const ROUTES_DIR = path.join(__dirname, '../../routes');
const CONTROLLERS_DIR = path.join(__dirname, '../../controllers');

/**
 * 范围判定的判据（宽松，宁可漏报也不误报）：
 *   - `xxxScope(xxx)` / `isXxxInScope(xxx)`：含 scope 字样的函数调用
 *   - 已知 rbac helper 名（即使调用形式被改写也能命中）
 */
const SCOPE_CALL_RE =
  /\b\w*[Ss]cope\w*\s*\(|assertRecordInScope|getDataScope|applyDataScopeToQuery|buildDataScopeFilter|isRecordInScope|applyRoleScopeToQuery|checkDataScopeForDoc/;

/** 自作用域：操作对象恒为调用者本人 */
const SELF_SCOPE_RE = /req\.user\.userId|req\.user\.id/;

/** 豁免标记：`SCOPE-EXEMPT: 理由` */
const EXEMPT_RE = /SCOPE-EXEMPT:\s*(\S+)/;

/**
 * 提取路由块源码。
 * 块边界 = 下一个顶层 `router.` 声明或文件末尾。不用 `\n);` 收尾判断——
 * 单行声明 + 多行 handler 体（如 wellKnownRoutes）会让 `\n);` 落错位置。
 * 豁免标记约定放在路由块内（收尾 `});` 之前的注释行）。
 */
const extractRouteBlocks = (source) => {
  const blocks = [];
  const re = /router\.(post|put|delete|patch)\s*\(/g;
  let match;
  while ((match = re.exec(source)) !== null) {
    const start = match.index;
    const next = source.indexOf('\nrouter.', start + 1);
    const end = next === -1 ? source.length : next;
    blocks.push({
      method: match[1].toUpperCase(),
      source: source.slice(start, end),
      line: source.slice(0, start).split('\n').length,
    });
  }
  return blocks;
};

const routeOf = (blockSource) => {
  const m = blockSource.match(/['"`](\/[^'"`]*)/);
  return m ? m[1] : '(未解析路径)';
};

/** 取 handler 函数体（从 `const <name> = asyncHandler(` 到下一个同形态声明） */
const handlerBody = (cache, controller, handler) => {
  const key = `${controller}.js`;
  if (!cache.has(key)) {
    const file = path.join(CONTROLLERS_DIR, key);
    cache.set(key, fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null);
  }
  const src = cache.get(key);
  if (!src) return null;
  const re = new RegExp(`^const ${handler} = asyncHandler\\(`, 'm');
  const idx = src.search(re);
  if (idx === -1) return null;
  const rest = src.slice(idx + 1);
  const nextIdx = rest.search(/^const \w+ = asyncHandler\(/m);
  return nextIdx === -1 ? rest : rest.slice(0, nextIdx);
};

describe('数据范围契约（ADR-008：写路由必须显式登记范围策略）', () => {
  const routeFiles = fs
    .readdirSync(ROUTES_DIR)
    .filter((f) => f.endsWith('.js') && f !== 'index.js')
    .sort();

  const collectWriteRoutes = () => {
    const cache = new Map();
    const rows = [];
    for (const file of routeFiles) {
      const source = fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8');
      for (const block of extractRouteBlocks(source)) {
        const hm = /(\w+Controller)\.(\w+)/.exec(block.source);
        if (!hm) continue; // 内联 handler（如 wellKnownRoutes）由各自专项测试覆盖
        rows.push({
          file,
          method: block.method,
          route: routeOf(block.source),
          line: block.line,
          controller: hm[1],
          handler: hm[2],
          block: block.source,
          body: handlerBody(cache, hm[1], hm[2]),
        });
      }
    }
    return rows;
  };

  test('路由目录存在且写路由数量合理（防扫描路径漂移导致假绿）', () => {
    expect(routeFiles.length).toBeGreaterThan(3);
    const rows = collectWriteRoutes();
    // 阈值防假绿：当前规模 54 条，显著低于该值说明扫描正则失效
    expect(rows.length).toBeGreaterThan(40);
  });

  test('每个写路由的范围策略可判定（范围调用 / 豁免声明 / 自作用域）', () => {
    // 自防御锚点（本次改动收紧）：本用例的绿色完全依赖 collectWriteRoutes() 有产出——
    // 若扫描正则退化返回空数组，循环零执行、violations=[] 仍绿（只能靠上一个
    // 用例兜底）。此处独立钉死扫描规模（与上一用例同口径），让「扫描器整体
    // 失效」在本用例内部也必然转红。
    const rows = collectWriteRoutes();
    expect(rows.length).toBeGreaterThan(40);
    const violations = [];
    for (const r of rows) {
      if (r.body === null) {
        violations.push(
          `${r.file}:${r.line} ${r.method} ${r.route} → 找不到 handler ${r.controller}.${r.handler}`
        );
        continue;
      }
      const hasScope = SCOPE_CALL_RE.test(r.body);
      const hasSelf = SELF_SCOPE_RE.test(r.body);
      const exempt = EXEMPT_RE.exec(r.block);
      if (!hasScope && !hasSelf && !exempt) {
        violations.push(
          `${r.file}:${r.line} ${r.method} ${r.route} → ${r.controller}.${r.handler}`
        );
      }
    }
    // 缺失时给出可操作的修复指引，而不是只有一句「不相等」
    expect({
      violations,
      hint: violations.length
        ? '补范围判定（rbac helper / 本文件内包装），或在该路由块内加注释 `SCOPE-EXEMPT: <理由>`。见 docs/adr/ADR-008'
        : undefined,
    }).toEqual({ violations: [] });
  });

  test('豁免标记必须给出非空理由（防止注释流于形式）', () => {
    const emptyMarkers = [];
    for (const file of routeFiles) {
      const source = fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8');
      const re = /SCOPE-EXEMPT:\s*(\S*)/g;
      let m;
      while ((m = re.exec(source)) !== null) {
        if (!m[1]) emptyMarkers.push(file);
      }
    }
    expect(emptyMarkers).toEqual([]);
  });

  test('已知待定项已显式登记（防未来有人把豁免当默认做法）', () => {
    // 这 5 条在 2026-09-17 评估中确认**无真缺口**（权限定义属全局管理面；
    // 创建巡检的归属由 assignedTo 白名单限定），但外在表现与真缺口一致，
    // 故必须留下登记痕迹。若其中任何一条被删除或改写，本断言会红，
    // 强制后来者重新评估而不是静默继承结论。
    const rows = collectWriteRoutes();
    const registered = rows
      .filter((r) => EXEMPT_RE.test(r.block))
      .map((r) => `${r.file} ${r.method} ${r.route}`);
    // 至少应覆盖：权限 CRUD 4 条 + 巡检创建 1 条
    expect(registered).toEqual(
      expect.arrayContaining([
        'permissionRoutes.js POST /',
        'permissionRoutes.js POST /batch',
        'permissionRoutes.js PUT /:id',
        'permissionRoutes.js DELETE /:id',
        'inspectionRoutes.js POST /',
      ])
    );
  });
});
