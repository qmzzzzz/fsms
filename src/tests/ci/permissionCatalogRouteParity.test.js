'use strict';

/**
 * 权限码三侧对齐：目录 ↔ 后端强制点 ↔ 前端路由声明（机器差集）
 *
 * 起因：第 8 轮审计代理报「后端强制而前端无入口 / 目录可授予而两侧都不强制」一类问题。
 * 目测的差集不可复现，所以这里把它做成用例：以 `initData.defaultPermissions`（导出的那份，
 * 不是从注释里抄的）为目录，以全仓 `checkPermission(...)` 的实参为强制点，两个方向都算。
 *
 * 为什么这个方向值得钉：
 *   - **路由要了目录里没有的码** ⇒ 这条能力谁都授不出去（`initRoles` 按码取权限、
 *     管理面按目录勾选），只有 `*:*` 的超管能用；一旦是拼写错误，表现为"功能对所有人 403"，
 *     而错误信息是通用的 PERMISSION_DENIED，排查时看不出是码不存在。这个方向今天为零，
 *     所以按**严格相等**钉死（新增一个未入库的码必须响）。
 *   - **目录里有、没有任何路由强制** ⇒ 授予了却不接线：角色权限列表里显示"有设备报废权限"，
 *     实际那条接口要的是 `device:update`。这是**治理面失真**（审计/交接时读角色权限清单会得出
 *     错误结论），不是即时漏洞。修法要么改路由收口、要么从目录删除，两者都会动既有种子数据
 *     与依赖它的夹具，属产品决策，不由这条用例单方面拍板 ⇒ 与
 *     `models/builtInRoleCodeSource.test.js` 的 `KNOWN_LEGACY_MINT_CODES` 同一档：
 *     **钉"不许再多一个"，而不是"应当为 0"**。
 *
 * 每条 reason 都是实测（对应接口的真实 checkPermission 实参），不是推测：
 *   - `device:scrap`   → `PUT /api/devices/:id/scrap` 实为 `device:update`（routes/deviceRoutes.js:362）
 *   - `device:stats`   → `GET /api/devices/stats` 实为 `device:read`（routes/deviceRoutes.js:240）
 *   - `alarm:stats`    → `GET /api/alarms/stats` 实为 `alarm:read`（routes/alarmRoutes.js:125）
 *   - `user:assign_role` → `PUT /api/users/:id/roles` 实为 `role:assign`（routes/userRoutes.js:214）
 *
 * 扫描口径（三条都是必要的，缺一条就会得出错的差集）：
 *   1. `checkPermission('a')` 与 `checkPermission(['a','b'])` 两种形态都要收——数组形态是
 *      "或"语义（middleware/rbac.js:64 `permissions.some`），漏收会把 `permission:tree`
 *      误判成未接线；
 *   2. 注释必须剥掉——`services/initData.js:172` 的历史注释里就写着一条
 *      `checkPermission('permission:create|update|delete')`，不剥注释会把这条**根本不存在**的
 *      码算成强制点（实测：不剥时 [未入库] 由 0 变 1，且 rbac 并不按 `|` 切分）；
 *   3. 目录里的 `*:*` 与 `module:*` 是**授予侧通配**，永远不会出现在强制点里，
 *      必须单独排除，否则 10 条通配全被算成"未接线"。
 *
 * 反向对照也做成用例（见 R8-D4 的变异台账）：往路由文件加一行
 * `// checkPermission('bogus:…')` 注释，本套件必须**保持全绿**——
 * 否则上面第 2 条只是注释里的承诺。
 */
const fs = require('fs');
const path = require('path');

const { defaultPermissions } = require('../../services/initData');

const SRC_DIR = path.resolve(__dirname, '../..');

/** 生产码文件（跳过 tests 与 node_modules），与仓内其余静态闸同口径 */
function listProdFiles(dir = SRC_DIR, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listProdFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/** 行注释与块注释都剥掉（见文件头第 2 条） */
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*)/.test(line))
    .join('\n');

/** code -> 出现它的文件集合（相对 src/，便于失败时直接定位） */
function collectEnforced() {
  const map = new Map();
  const add = (code, rel) => {
    if (!map.has(code)) map.set(code, new Set());
    map.get(code).add(rel);
  };
  for (const file of listProdFiles()) {
    const rel = path.relative(SRC_DIR, file).replace(/\\/g, '/');
    const src = stripComments(fs.readFileSync(file, 'utf8'));
    for (const m of src.matchAll(/checkPermission\(\s*'([^']+)'/g)) add(m[1], rel);
    for (const m of src.matchAll(/checkPermission\(\s*\[([^\]]*)\]/g))
      for (const one of m[1].matchAll(/'([^']+)'/g)) add(one[1], rel);
  }
  return map;
}

const enforced = collectEnforced();
const catalogCodes = [...new Set(defaultPermissions.map((p) => p.code))];
// 通配（`*:*` 与 `module:*`）只存在于授予侧，不参与"是否被强制"的比对
const isWildcard = (code) => code.endsWith(':*');
const concreteCatalog = catalogCodes.filter((c) => !isWildcard(c));
const wildcardCatalog = catalogCodes.filter((c) => isWildcard(c));

// 登记表见文件头：钉"不许再多一个"，不是"应当为 0"。
const KNOWN_UNENFORDED = ['alarm:stats', 'device:scrap', 'device:stats', 'user:assign_role'];

describe('权限目录与路由强制点的差集（授予即生效）', () => {
  // 反向闸的自证：扫描器本身不能是"扫不到就当通过"的形状
  test('扫描器前提自证：确实扫到了足量强制点', () => {
    expect(enforced.size).toBeGreaterThanOrEqual(30);
    // 两个已知点：一个字符串形态、一个数组形态（漏收数组形态会让 permission:tree 假死）
    expect(enforced.has('inspection:review')).toBe(true);
    expect(enforced.has('permission:tree')).toBe(true);
    // 注释里的历史形态绝不能混进来
    expect(enforced.has('permission:create|update|delete')).toBe(false);
    expect(defaultPermissions.length).toBeGreaterThan(0);
    expect(wildcardCatalog.length).toBeGreaterThan(0);
  });

  test('方向一（严格）：路由要的每一个码都必须在目录里，否则谁也授不出去', () => {
    const ungrantable = [...enforced.keys()]
      .filter((code) => !catalogCodes.includes(code))
      .map((code) => `${code} ← ${[...enforced.get(code)].join(', ')}`)
      .sort();
    expect(ungrantable).toEqual([]);
  });

  test('方向二（冻结）：目录里"授予了但无路由强制"的清单不得再增长', () => {
    const dead = concreteCatalog.filter((code) => !enforced.has(code)).sort();
    expect(dead).toEqual([...KNOWN_UNENFORDED].sort());
  });

  test('方向二的后果属实：这四条码对应的能力各由另一条码把关', () => {
    // 若哪天有人把路由改成用这些码，本条与上一条会同时要求更新登记表——
    // 这正是我们希望的"改一处必须看见另一处"。
    const read = (rel) =>
      stripComments(fs.readFileSync(path.join(SRC_DIR, rel), 'utf8')).replace(/\s+/g, ' ');
    expect(read('routes/deviceRoutes.js')).toContain(
      "'/:id/scrap', authenticate, checkPermission('device:update')"
    );
    expect(read('routes/deviceRoutes.js')).toContain(
      "'/stats', authenticate, checkPermission('device:read')"
    );
    expect(read('routes/alarmRoutes.js')).toContain(
      "'/stats', authenticate, checkPermission('alarm:read')"
    );
    expect(read('routes/userRoutes.js')).toContain(
      "'/:id/roles', authenticate, checkPermission('role:assign')"
    );
  });

  test('目录内部一致性：码唯一，且每条都带非空 module（授予面按 module 分组）', () => {
    const dup = catalogCodes.filter(
      (c) => c !== '' && catalogCodes.indexOf(c) !== catalogCodes.lastIndexOf(c)
    );
    expect(dup).toEqual([]);
    for (const p of defaultPermissions) {
      expect(typeof p.code).toBe('string');
      expect(p.code).toMatch(/^(\*|[a-z][\w]*):[\w*]+$/);
      expect(p.module).toBeTruthy();
    }
  });
});

/**
 * 第三侧：前端路由表声明的 `meta.permission`
 *
 * 前端守卫写的是 `if (requiredPermission && ...)`——**空串等于不设闸**，而既有
 * `web-admin/src/tests/router/routeTable.test.js` 只按 `meta.permission` 真值筛过再验形状，
 * 于是把某条改成 `permission: ''` 会让那个页面壳对零权限用户敞开、却一行测试都不红
 * （第 8 轮前端审计代理给出的变异与"预期全绿"结论，这里独立复核成立）。
 * 更值钱的是方向：声明的码必须在**目录**里（否则守卫拒掉所有人 ⇒ 页面永久不可达，
 * 而提示只有通用的一句"没有权限"），且必须**真被某条后端路由强制**（否则前端放行的是
 * 一道不存在的门，实际接口由另一条码把关）。
 *
 * 登记表按「路径 → 码」整表钉死，不是只钉非空：换档、置空、新增页面忘声明权限都会红。
 * 与上面几条同一档纪律——两侧各写一份而无人对齐，就是 layout/index.vue:273-291
 * 那份自建 hasPerm 名单能悄悄漂移的原因。
 */
const FE_ROUTER = path.resolve(SRC_DIR, '../web-admin/src/router/index.js');

const FE_PROTECTED = {
  devices: 'device:read',
  alarms: 'alarm:read',
  users: 'user:read',
  roles: 'role:read',
  inspections: 'inspection:read',
  reports: 'report:read',
  'audit-logs': 'security:audit',
  'ip-list': 'security:config',
};
// 有 meta 但不设权限闸的页面：登录/注册是 requiresAuth:false，其余三页只要登录态
const FE_NO_GATE_WITH_META = ['/login', '/register', 'dashboard', 'profile', 'about'];
// 整条没有 meta 的路由（根布局与 404 兜底），解析器要能区分"没有 meta"与"meta 里没有权限"
const FE_NO_META = ['/', '/:pathMatch(.*)*'];

describe('前端路由声明的权限码与后端目录/强制点对齐', () => {
  /**
   * 按「path 出现位置 → 其后、下一个 path 之前的第一个 meta」配对。
   * 不能用 `path: '...', ... meta: {...}` 一条正则扫：根路由 `/` 自己没有 meta，
   * 那种写法会把它的子路由 dashboard 的 meta 记到 `/` 头上（实测 13 条 vs 真实 15 条），
   * 于是"漏声明权限"这类错误恰好会被解析器吞掉。
   */
  function parseFeRoutes(src) {
    const paths = [...src.matchAll(/path:\s*'([^']+)'/g)].map((m) => ({ path: m[1], at: m.index }));
    const metas = [...src.matchAll(/meta:\s*\{([^}]*)\}/g)].map((m) => ({
      meta: m[1],
      at: m.index,
    }));
    return paths.map((p, i) => {
      const next = i + 1 < paths.length ? paths[i + 1].at : src.length;
      const mm = metas.find((x) => x.at > p.at && x.at < next);
      const pm = mm ? /permission:\s*'([^']*)'/.exec(mm.meta) : null;
      return { path: p.path, permission: pm ? pm[1] : null, hasMeta: Boolean(mm) };
    });
  }

  const fe = parseFeRoutes(stripComments(fs.readFileSync(FE_ROUTER, 'utf8')));

  test('解析器前提自证：路由表被完整读到，且三种形态分得开', () => {
    expect(fe).toHaveLength(
      Object.keys(FE_PROTECTED).length + FE_NO_GATE_WITH_META.length + FE_NO_META.length
    );
    expect(
      fe
        .filter((r) => r.permission)
        .map((r) => r.path)
        .sort()
    ).toEqual(Object.keys(FE_PROTECTED).sort());
    // "没有 meta"与"meta 里没权限"是两件事，混了就等于给漏声明开了后门
    expect(
      fe
        .filter((r) => !r.hasMeta)
        .map((r) => r.path)
        .sort()
    ).toEqual([...FE_NO_META].sort());
  });

  test('闸：受保护页面声明的码逐一等于登记表', () => {
    const actual = {};
    for (const r of fe) if (r.permission) actual[r.path] = r.permission;
    expect(actual).toEqual(FE_PROTECTED);
  });

  test('声明的码必须在目录里，且确实被某条路由强制（否则前端这道门是空的）', () => {
    const ungrantable = Object.entries(FE_PROTECTED)
      .filter(([, code]) => !catalogCodes.includes(code))
      .map(([p, c]) => `${p} → ${c}`);
    expect(ungrantable).toEqual([]);

    const decorative = Object.entries(FE_PROTECTED)
      .filter(([, code]) => !enforced.has(code))
      .map(([p, c]) => `${p} → ${c}`);
    expect(decorative).toEqual([]);
  });

  test('反向对照：不设权限闸的页面清单不得增长（新增页面要么声明权限，要么在这里说明理由）', () => {
    const noGate = fe
      .filter((r) => !r.permission)
      .map((r) => r.path)
      .sort();
    expect(noGate).toEqual([...FE_NO_GATE_WITH_META, ...FE_NO_META].sort());
  });
});
