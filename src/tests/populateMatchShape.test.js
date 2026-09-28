/**
 * populate + match 的真实数组形状（本仓两份文档互相矛盾，实测定分止争）
 *
 * 冲突点：
 *  - `utils/permissionHelper.js` 的 L-15 注释：populate 带 `match` 时，未命中的引用
 *    **在原位保留 null、数组不压缩**（并说这就是历史上多处 `r.code` 直接 map 抛
 *    TypeError → 500 的根因）；
 *  - 我此前的实测笔记：数组路径上"match 未命中 / ref 指向已删文档"
 *    都是**元素被丢弃**。
 * 两者对代码安全都"无所谓"（各处都有 `filter(Boolean)` / `r &&` 兜底），
 * 但有一个地方**不是**无所谓：`middleware/rbac.js` 的 deny 分支依赖
 * "roles 全被剔除 ⇒ length===0 ⇒ 返回 {type:'none'}"。若 Mongoose 实际是留 null，
 * `length` 就不为 0 —— 那条 fail-closed 分支可能根本不触发。
 * 所以这里既测形状，也直接测那条安全后果。
 */

const mongoose = require('mongoose');
const User = require('../models/User');
const Role = require('../models/Role');
const { getDataScope } = require('../middleware/rbac');

const TAG = `zzpm_${Date.now()}`;
const PASSWORD = 'Zz!1234567890abcdef';

const populateActive = (userId) =>
  User.findById(userId).populate({ path: 'roles', match: { status: 'active' }, select: 'code' });

describe('populate+match 的数组形状与失效角色 deny', () => {
  let activeRole;
  let inactiveRole;
  const createdUsers = [];
  const createdRoles = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    activeRole = await Role.create({
      name: `${TAG}_on`,
      code: `${TAG}_ON`,
      level: 8,
      status: 'active',
    });
    inactiveRole = await Role.create({
      name: `${TAG}_off`,
      code: `${TAG}_OFF`,
      level: 3,
      status: 'inactive',
    });
    createdRoles.push(activeRole, inactiveRole);
  });

  afterAll(async () => {
    await User.deleteMany({ username: new RegExp(`^${TAG}`) });
    await Role.deleteMany({ code: new RegExp(`^${TAG}_`, 'i') });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  async function mkUser(label, roleIds) {
    const u = await User.create({
      username: `${TAG}_${label}`,
      email: `${TAG}_${label}@example.com`,
      password: PASSWORD,
      roles: roleIds,
    });
    createdUsers.push(u._id);
    return u;
  }

  test('形状定案：Mongoose 8.24.1 是**压缩数组**（丢弃未命中元素），不是留 null 占位', async () => {
    const u = await mkUser('mix', [activeRole._id, inactiveRole._id, activeRole._id]);
    const raw = (await populateActive(u._id)).roles;
    // 这三行是**定案断言**：permissionHelper.js 的 L-15 注释写着"match 未命中会在原位
    // 保留 null、数组不压缩"，实测并非如此（8.24.1 直接丢弃：stored=3 → length=2、nulls=0）。
    // 两处代码都做了 filter(Boolean) 兜底所以行为安全；但 rbac.js 的 deny 分支依赖
    // length===0，一旦 mongoose 升级改成"留 null"，那条分支就会失真 —— 故把形状钉住，
    // 让升级时这条用例先红，而不是让 fail-closed 悄悄失效。
    // 【2026-09-24 追记】上面提到的 permissionHelper.js L-15 错误注释已按台账 §36.5 口径
    // 改写（改为「防御性冗余，实测 8.24.1 丢弃未命中元素」）。本条用例**照旧保留**——
    // 它现在是该形状的唯一守护者，且是改写后注释所引用的权威出处。
    expect(raw.length).toBe(2);
    expect(raw.filter((r) => r === null)).toHaveLength(0);
    expect(raw.map((r) => r.code)).toEqual([activeRole.code, activeRole.code]);
  });

  test('安全后果：唯一角色被停用的用户，数据范围必须 deny', async () => {
    const u = await mkUser('onlyoff', [inactiveRole._id]);
    const scope = await getDataScope(String(u._id));
    // rbac.js:「roles 全被剔除 ⇒ {type:'none'}」这条 fail-closed 分支
    expect(scope.type).toBe('none');
    const populated = await populateActive(u._id);
    expect(populated.roles).toHaveLength(0);
  });

  test('安全后果：active+inactive 并存时层级只取生效角色', async () => {
    const u = await mkUser('both', [activeRole._id, inactiveRole._id]);
    const scope = await getDataScope(String(u._id));
    // active 角色 level=8 ⇒ 部门档；停用的 level=3 不得参与，也不得因"全失效"而 deny
    expect(scope.type).toBe('department');
    const { getOperatorMaxLevel } = require('../utils/permissionHelper');
    expect(await getOperatorMaxLevel(String(u._id))).toBe(activeRole.level);
  });

  test('ref 指向已删文档：同样是丢弃而非 null 占位', async () => {
    const ghost = new mongoose.Types.ObjectId();
    const u = await mkUser('ghost', [activeRole._id, ghost]);
    const raw = (await populateActive(u._id)).roles;
    expect(raw).toHaveLength(1);
    expect(raw[0].code).toBe(activeRole.code);
  });
});
