'use strict';

/**
 * 授权判定量的单一事实来源：角色层级 + 数据范围字段名
 *
 * 两条判据同族——都是"同一个授权量在多处各写一遍"，且都是**改了常量不会红、
 * 只会静默分叉**的那类：
 *
 * 1) 角色层级 maxRoleLevel：`permissionHelper.js` 是权威实现（空角色集返回 -Infinity，
 *    该语义其文件注释明确标为 fail-closed，不可写成 0）。历史上 userController /
 *    rolePermissionController / securityController / authService 各有一份内联展开
 *    `roles.length > 0 ? Math.max(...roles.map(r => r.level || 0)) : 0`。
 *    两份实现对**空角色集**的返回值相差一个 -Infinity/0，对 **null 洞**一个是抛错一个是跳过：
 *    平时判据恰好等价（见下方"前提自证"那条：Role.level 最小值是 1），
 *    一旦有人把 level 下限降到 0，两套口径立刻给出不同的放行结论——而任何行为测试都不会红。
 *
 * 2) 数据范围字段名 DATA_SCOPE_FIELDS.user：constants 里声明一次，
 *    userController 的 5 处范围闸曾手写 'createdBy'/'department'，同文件的统计接口却引用常量。
 *    改常量 ⇒ 列表/详情/写路径按旧字段、统计按新字段，正是该常量当初要消灭的 P2-20。
 *
 * 本文件是**写法漂移守卫**：扫描前先剥注释（文本判据在注释上假绿过，本仓有前科），
 * 所以第 1 条用例先自证提取器"抓得到合成脏样本、不误伤合法样本、注释里的不算"。
 */

const fs = require('fs');
const path = require('path');
const { maxRoleLevel } = require('../../utils/permissionHelper');
const { DATA_SCOPE_FIELDS } = require('../../constants/dataScopeFields');
const Role = require('../../models/Role');

const SRC_ROOT = path.join(__dirname, '..', '..');
const LEVEL_CANONICAL = 'src/utils/permissionHelper.js';
const SCOPE_CANONICAL = 'src/constants/dataScopeFields.js';

const stripComments = (code) => code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

/**
 * 内联展开的层级式子：同一个语句（以 ; 为界）里 Math.max( 后面跟着 .map( 和 .level。
 * 用 ; 划界而不是允许任意括号嵌套：rbac.js 的 `levels = roles.map(...level || 1);`
 * 与下一行 `Math.max(...levels)` 是两条语句、且默认值/语义都不同（那里 1 是兜底层级），
 * 不该被当作本判据的命中。
 */
const INLINE_LEVEL_RE = /Math\.max\([^;]*?\.map\([^;]*?\.level[^;]*?\)/g;
/** user 资源的两个字段名被并排抄成字面量（参数位/数组位都算） */
const SCOPE_PAIR_RE = /['"]createdBy['"]\s*,\s*['"]department['"]/g;

const walkJs = (dir, acc = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // tests 目录里的合成样本与夹具是**测试数据**，不参与"生产代码只有一份"的判据
      if (entry.name === 'tests' || entry.name === 'node_modules') continue;
      walkJs(full, acc);
    } else if (entry.name.endsWith('.js')) {
      acc.push(full);
    }
  }
  return acc;
};

/** 返回 [{file, hit}]：命中原文片段一并带回，失败时能看出扫到了什么 */
const scan = (re, allowedFile) => {
  const hits = [];
  for (const file of walkJs(SRC_ROOT)) {
    const rel = path.relative(path.join(SRC_ROOT, '..'), file).split(path.sep).join('/');
    if (rel === allowedFile) continue;
    const code = stripComments(fs.readFileSync(file, 'utf8'));
    for (const m of code.matchAll(re)) hits.push({ file: rel, hit: m[0] });
  }
  return hits;
};

describe('授权判定量的单一事实来源', () => {
  test('提取器自证：抓得到合成脏样本，不误伤合法样本，注释里的不算', () => {
    // 脏样本：内联展开（这正是被折叠掉的 4 处的原样写法）
    expect(
      stripComments(
        'const x = roles.length > 0 ? Math.max(...roles.map((r) => r.level || 0)) : 0;'
      ).match(INLINE_LEVEL_RE)
    ).toHaveLength(1);
    // 合法样本：rbac.js 的先 map 后 max（分两行、默认值 1），不是同一式子，不该误伤
    expect(
      stripComments(
        'const levels = roles.map((r) => r.level || 1);\nconst maxLevel = Math.max(...levels);'
      ).match(INLINE_LEVEL_RE)
    ).toBeNull();
    // 只在注释里 ⇒ 不算（否则守卫会被文档措辞牵着红）
    expect(
      stripComments('// 原来写着 Math.max(...roles.map(r => r.level || 0))\nconst a = 1;').match(
        INLINE_LEVEL_RE
      )
    ).toBeNull();
    // 范围字段：并排两个字面量才算，单独一个 'createdBy' 不算
    expect(
      stripComments("f(req, doc, 'createdBy', 'department')").match(SCOPE_PAIR_RE)
    ).toHaveLength(1);
    expect(stripComments("f(req, doc, 'createdBy')").match(SCOPE_PAIR_RE)).toBeNull();
    expect(
      stripComments('const { ownerField } = DATA_SCOPE_FIELDS.user;').match(SCOPE_PAIR_RE)
    ).toBeNull();
  });

  test('全仓生产代码里，内联层级展开只允许出现在 permissionHelper.js', () => {
    expect(scan(INLINE_LEVEL_RE, LEVEL_CANONICAL)).toEqual([]);
  });

  test('全仓生产代码里，createdBy/department 字面量对只允许出现在 dataScopeFields.js', () => {
    expect(scan(SCOPE_PAIR_RE, SCOPE_CANONICAL)).toEqual([]);
  });

  test('权威实现本身：空角色集 -Infinity、缺参 0、null 洞跳过、正常取最大', () => {
    expect(maxRoleLevel([{ level: 3 }, { level: 7 }])).toBe(7);
    expect(maxRoleLevel([])).toBe(-Infinity);
    expect(maxRoleLevel(undefined)).toBe(0);
    expect(maxRoleLevel(null)).toBe(0);
    expect(maxRoleLevel([null, { level: 2 }])).toBe(2);
  });

  /**
   * 今天把 4 处内联展开折进权威实现的前提：两者只在"空角色集"上结论不同
   * （0 vs -Infinity），而 Role.level 下限是 1 ⇒ 任何真实角色层级都 ≥1，
   * 0 与 -Infinity 在与 operatorMaxLevel（同为 canonical）比较时给出同一判据。
   * 有人把 min 降到 0（或允许负层级）时该前提失效，折叠点需要重新推导 ⇒ 本条必须红。
   */
  test('折叠前提仍在：真实角色层级下界 > 0，故 0 与 -Infinity 判定等价', () => {
    const { min, max } = Role.schema.path('level').options;
    expect(min).toBeGreaterThan(0);
    expect(max).toBeGreaterThanOrEqual(min);
    expect(DATA_SCOPE_FIELDS.user.ownerField).toBe('createdBy');
    expect(DATA_SCOPE_FIELDS.user.departmentField).toBe('department');
  });

  test('消费方写法：从 permissionHelper 引用 maxRoleLevel，不得就地重定义', () => {
    const consumers = [
      'src/controllers/userController.js',
      'src/controllers/securityController.js',
      'src/controllers/rolePermissionController.js',
      'src/services/authService.js',
    ];
    for (const rel of consumers) {
      const code = stripComments(readSource(rel));
      expect({ rel, imported: /maxRoleLevel/.test(code) }).toEqual({ rel, imported: true });
      expect({ rel, ref: /require\([^)]*permissionHelper[^)]*\)/.test(code) }).toEqual({
        rel,
        ref: true,
      });
      expect(code).not.toMatch(/(const|let|var|function)\s+maxRoleLevel\s*[=(]/);
    }
  });
});

function readSource(rel) {
  return fs.readFileSync(path.join(SRC_ROOT, '..', rel), 'utf8');
}
