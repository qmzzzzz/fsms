'use strict';

/**
 * 全局通配权限编码 `*:*` 与它的权威常量是否还是同一个值
 *
 * `src/utils/superAdmin.js` 导出 `RESERVED_WILDCARD_PERMISSION`，本意是给全仓当唯一权威值。
 * 实测（2026-09-27）生产代码里引用该常量的只有 3 个文件（roleController /
 * rolePermissionController / permissionService），另有 9 个 src 下的文件把 `'*:*'` 当字面量
 * 各写一遍、合计 18 处。这 18 处是"剥注释后按 `'*:*'` 完整字面量"计的代码视图；未剥注释的
 * 文本视图是 10 文件 20 处，多出来的两处位于 permissionService.js 与 permissionController.js
 * 的注释里（那两处不构成第二份真源，但也说明文本视图会把闸读宽）。这个分叉的危险不是"读起来难看"：
 *
 * - **判定侧**（rbac 早放行、permissionHelper 的两套匹配、roleGuards 的层级豁免、
 *   userPermissionService.hasPermission）认的是**字面量**；
 * - **保护侧**（`permissionRoutes` 的 `.not().equals('*:*')` 铸造/删除闸、
 *   `permissionController` 的停用闸、`permissionService` 的停用闸）认的是**各自的值**。
 *
 * 一旦有人"重构"了常量值（比如改成 `'*'`），判定侧仍只认 `'*:*'`、保护侧改认 `'*'`，
 * 于是库里那条真实存在的 `'*:*'` 权限**不再受任何保护**：可以被停用、被删除，
 * 而全体超管照旧通过它放行 ⇒ 一次改名就能把"保留权限不可动"这条不变量打穿。
 * 反方向同理（改字面量不改常量）。
 *
 * 本文件因此不写"字面量出现次数必须为 0"那种今天不可能绿的判据，而是把判据写成
 * **以常量为输入的差分**：把常量的当前值喂进每一个判定实现，要求它按"全局通配"行事；
 * 同时喂一个不相干的编码，要求它不放行。常量一旦被改名，任何还在硬编码旧串的实现
 * 立刻在"通配"这一格翻成 false ⇒ 红会点名到具体哪一臂。
 * 保护侧无法这样喂（它是 express-validator 链与控制器分支），改用同一条思路的文本判据：
 * 用常量值去源码里找那个 `.equals('…')`，找不到就红——同样能抓住改名。
 */

const fs = require('fs');
const path = require('path');
const User = require('../../models/User');
const { RESERVED_WILDCARD_PERMISSION, SUPER_ADMIN_ROLE_CODE } = require('../../utils/superAdmin');
const {
  matchesPermissionCodes,
  hasPermission: hasPermissionViaHelper,
} = require('../../utils/permissionHelper');
const { checkPermission } = require('../../middleware/rbac');
const { guardRoleLevelTarget } = require('../../controllers/roleGuards');
const roleService = require('../../services/roleService');
const ApiResponse = require('../../utils/apiResponse');
const { defaultPermissions } = require('../../services/initData');

const SRC_ROOT = path.join(__dirname, '..', '..');

// 探针编码：模块名 zz 在全仓不存在，因此不会被任何 `module:*` 通配意外命中
const PROBE = 'zz:probe_not_granted';
const UNRELATED = 'zz:some_other_perm';

/**
 * 今天实测的字面量手抄分布：`src/` 下非测试目录（155 个 js）里，剥注释后
 * `'*:*'` 完整字面量的逐文件出现次数，合计 18 处 / 9 个文件。
 *
 * 冻到**精确相等**而不是"每文件上限"：后者在扫描器自己坏掉时（walkJs 返回目录空集、
 * stripComments 误吞全文）会静默恒绿，前者会立刻红成 `Received: {}`。对端把某处改用
 * 常量后这里会红一次，那是"把新分布显式写回来"的提醒，不是回归。
 *
 * 权威常量的定义点（utils/superAdmin.js）与种子数据（services/initData.js）各占 1、2 处，
 * 是**合法**的字面量：前者是定义本身，后者是真正落库的那条权限文档与其授予表。
 */
const WILDCARD_LITERAL_CENSUS = {
  'controllers/permissionController.js': 1,
  'controllers/roleGuards.js': 1,
  'controllers/userController.js': 4,
  'middleware/rbac.js': 2,
  'routes/permissionRoutes.js': 2,
  'services/initData.js': 2,
  'services/userPermissionService.js': 1,
  'utils/permissionHelper.js': 4,
  'utils/superAdmin.js': 1,
};

const stripComments = (code) => code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

const walkJs = (dir, acc = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkJs(full, acc);
    else if (entry.name.endsWith('.js')) acc.push(full);
  }
  return acc;
};

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const countLiteralIn = (file, value) =>
  (stripComments(fs.readFileSync(file, 'utf8')).match(new RegExp(escapeRe(value), 'g')) || [])
    .length;

/** rbac 中间件：req.userPermissions 预置即可绕开 DB（同一请求内复用权限结果的优化） */
const rbacVerdict = (held) =>
  new Promise((resolve, reject) => {
    const req = { user: { userId: 'u1', username: 'zz' }, userPermissions: [held] };
    const res = {
      status: (code) => ({ json: () => resolve(`denied:${code}`) }),
      json: () => resolve('denied:json'),
    };
    checkPermission(PROBE, 'OR')(req, res, () => resolve('allow')).catch(reject);
  });

/** permissionHelper.hasPermission 走 User.findById(...).populate().select()，只喂一条文档 */
const withUserHolding = (held) => {
  const doc = {
    _id: 'u1',
    roles: [{ status: 'active', level: 5, permissions: [{ code: held, status: 'active' }] }],
  };
  const chain = { populate: () => chain, select: () => Promise.resolve(doc) };
  jest.spyOn(User, 'findById').mockReturnValue(chain);
};

/** 层级守卫：全局管理员豁免那一臂；返回 true 表示"被放行（没被拦）" */
const levelGuardVerdict = async (held) => {
  jest.spyOn(roleService, 'getOperatorPermissions').mockResolvedValue([held]);
  const codeError = jest.spyOn(ApiResponse, 'codeError').mockReturnValue({});
  const blocked = await guardRoleLevelTarget({
    req: { user: { userId: 'u1', username: 'zz' } },
    res: {},
    role: { code: 'ZZ_ROLE', level: 2 },
    level: 9, // 高于操作者层级（3），非全局管理员必须被拦
    authority: { maxLevel: async () => 3 },
  });
  return { blocked, blockedBy: codeError.mock.calls.map((c) => c[1]) };
};

/** 假通配令牌：`'*'` 不是任何实现的通配令牌，四臂都必须把它当普通编码对待 */
const DECOY = '*';

/**
 * 期望值逐臂声明，不用同一套模板套四臂。
 * 前三臂是"按编码授权"的匹配器，持有并请求同一编码时必须放行（精确=true）；
 * 第四臂（层级豁免）压根不看请求要什么编码、只区分是不是全局管理员，
 * 所以"非全局管理员改高层级被拦"是它的正确行为，精确格实测为 false（2026-09-27）。
 * 把常量改名会让"通配"格翻成 false 而"假通配"格照旧 false ⇒ 红直接点名哪一臂还在硬编码。
 */
const ARMS = [
  {
    name: 'rbac.checkPermission 早放行',
    exact: true,
    decide: async (held) => (await rbacVerdict(held)) === 'allow',
  },
  {
    name: 'permissionHelper.matchesPermissionCodes（数组形）',
    exact: true,
    decide: async (held) => matchesPermissionCodes([held], PROBE),
  },
  {
    name: 'permissionHelper.hasPermission（Set 形 → matchesPermission）',
    exact: true,
    decide: async (held) => {
      withUserHolding(held);
      return hasPermissionViaHelper('u1', PROBE);
    },
  },
  {
    name: 'roleGuards.guardRoleLevelTarget 的全局管理员豁免',
    exact: false,
    decide: async (held) => (await levelGuardVerdict(held)).blocked === false,
  },
];

describe('全局通配权限编码与权威常量的一致性', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('常量的值与定义点：它是落库身份，不是可重命名的内部名', () => {
    // 改名＝换身份：库里已有的 '*:*' 文档、以及所有硬编码判定，都会与常量指向不同的行。
    // 所以这里直接钉取值；真要换值必须连带一次数据迁移，那时这条用例就是迁移的提醒。
    expect(RESERVED_WILDCARD_PERMISSION).toBe('*:*');
    // 定义点只有一处（`src/utils/` 里唯一的 `= '*:*'` 赋值）
    const defs = walkJs(path.join(SRC_ROOT, 'utils')).filter(
      (f) => countLiteralIn(f, "const RESERVED_WILDCARD_PERMISSION = '*:*'") > 0
    );
    expect(defs.map((f) => path.basename(f))).toEqual(['superAdmin.js']);
    // 种子数据里它有且仅有一条权限文档
    expect(
      defaultPermissions.filter((p) => p.code === RESERVED_WILDCARD_PERMISSION).map((p) => p.name)
    ).toEqual(['全部权限']);
    // 超管角色编码同样只有一份权威值（与内置角色名单闸互补，不重复其判据）
    expect(SUPER_ADMIN_ROLE_CODE).toBe('SUPER_ADMIN');
  });

  test('判定侧差分：把常量的值喂进每一个全局通配实现，四臂必须同进同退', async () => {
    const rows = [];
    for (const arm of ARMS) {
      const asWildcard = await arm.decide(RESERVED_WILDCARD_PERMISSION);
      const asExact = await arm.decide(PROBE); // 精确命中：证明这一臂不是"恒不放行"
      const asNothing = await arm.decide(UNRELATED); // 反向对照：证明不是"恒放行"
      const asDecoy = await arm.decide(DECOY); // 单星不是通配令牌
      rows.push(
        `${arm.name} 通配=${asWildcard} 精确=${asExact} 无关=${asNothing} 假通配=${asDecoy}`
      );
    }
    expect(rows).toEqual(
      ARMS.map((a) => `${a.name} 通配=true 精确=${a.exact} 无关=false 假通配=false`)
    );
  });

  test('保护侧：路由的铸造/修改闸认的就是常量那个值', () => {
    const routesCode = stripComments(
      fs.readFileSync(path.join(SRC_ROOT, 'routes', 'permissionRoutes.js'), 'utf8')
    );
    const equalsRe = new RegExp(`\\.equals\\('${escapeRe(RESERVED_WILDCARD_PERMISSION)}'\\)`, 'g');
    // 今天实测：创建与改状态两条链各一处
    expect(routesCode.match(equalsRe) || []).toHaveLength(2);
    // 反向：换成别的值就找不到 ⇒ 常量改名后这条判据会红，而不是静默放行
    expect(routesCode.match(/\.equals\('zz:renamed_reserved'\)/g) || []).toHaveLength(0);
    // 控制器侧的停用闸同理（'*' 权限停用会让全体超管失去权限）
    const ctrlCode = stripComments(
      fs.readFileSync(path.join(SRC_ROOT, 'controllers', 'permissionController.js'), 'utf8')
    );
    expect(
      ctrlCode.match(new RegExp(`code === '${escapeRe(RESERVED_WILDCARD_PERMISSION)}'`, 'g')) || []
    ).toHaveLength(1);
  });

  test('手抄分布冻结：src 生产代码里字面量的逐文件出现次数与实测一致', () => {
    const counts = {};
    for (const file of walkJs(SRC_ROOT)) {
      const n = countLiteralIn(file, `'${RESERVED_WILDCARD_PERMISSION}'`);
      if (n > 0) counts[path.relative(SRC_ROOT, file).replace(/\\/g, '/')] = n;
    }
    expect(counts).toEqual(WILDCARD_LITERAL_CENSUS);
  });
});
