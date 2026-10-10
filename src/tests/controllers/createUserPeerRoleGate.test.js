/**
 * 建号轨与改角色轨必须同尺：同级角色归属闸（findForeignPeerRoles / rejectForeignPeerRoles）
 *
 * 【为什么要在控制器层测这条】同级角色的归属校验原先只挂在 assignRoles 上。
 * 同一个操作者、同一个"自己不持有的同级角色"：
 *   - `PUT /api/users/:id/roles` ⇒ 403 ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN
 *   - `POST /api/users`（把这个角色挂给新建账户）⇒ 一路放行，201
 * 两条轨口径不一致时，实际口径就是松的那条——闸门等于没有。
 *
 * 【危害的准确形状】不是"当场提权"：建号路径上一层的权限子集闸已经保证
 * 新账户权限 ⊆ 操作者自身权限。真实后果有两面——
 *   (a) 角色继承型扩权：新账户成了那个同级角色的**合法持有者**，日后该角色被补任何权限，
 *       新账户（以及掌握其口令的操作者）自动获得，而这条增量从未触过任何授权判定；
 *   (b) 审计归因：所有动作记在另一个用户名下。
 *
 * 【判据为什么必须点名错误码】同级层级闸、权限子集闸、数据范围闸都回 403。
 * 只断 status 的用例在任何一道闸被换掉时都仍然绿。因此每条拒绝用例都断 `errorCode`，
 * 并且把"权限子集闸先拦"与"归属闸才拦"两条并排放：夹具里 ZZB_PEER_B 的权限集与操作者
 * 自持的 ZZB_PEER_A **完全相同**（只有 code/name 不同），所以它只能被归属闸拦下。
 * 这是本文件唯一能让"摘掉归属闸"变红的构造方式。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const PEER_LEVEL = 6;
// 口令必须过 validatePasswordStrength 的"常见泄露口令"表：`Test@1234567` 在表内，
// 走模型直建（User.create）的用例感觉不到，走 HTTP 建号则先被校验器 400，
// 请求根本到不了角色闸（实测：6 条用例全部以 VALIDATION_FAILED 收场）。
const PWD = 'xK9!vQz2Lm7#ra';

describe('建号轨的同级角色归属闸（与 assignRoles 同尺）', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let peerA; // 操作者自持的同级角色
  let peerB; // 同级、权限集与 A 相同、但操作者不持有 ⇒ 只有归属闸能拦
  let peerWide; // 同级且权限更宽 ⇒ 权限子集闸先拦（顺序对照）
  let lowRole; // 低级角色 ⇒ 归属闸按设计不该管（否则"给新人挂 GUEST"被封死）
  let peerToken; // level 6 操作者
  let wildToken; // 持 *:* 的操作者（豁免面与 assignRoles 一致）
  let victim; // 归属闸反向对照用的目标用户（走 assignRoles 轨）

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');

    // 路由级闸口是 checkPermission('user:create')：操作者角色必须真的带它，
    // 否则请求在进控制器之前就被 rbac 拦掉，本文件测的就不是归属闸。
    const createPerm = await Permission.findOneAndUpdate(
      { code: 'user:create' },
      {
        $setOnInsert: { name: '创建用户', code: 'user:create', type: 'api', module: 'system' },
      },
      { upsert: true, new: true }
    );
    const extraPerm = await Permission.findOneAndUpdate(
      { code: 'device:delete' },
      {
        $setOnInsert: { name: '删除设备', code: 'device:delete', type: 'api', module: 'device' },
      },
      { upsert: true, new: true }
    );
    // 反向对照走的是 assignRoles 轨，其路由闸是 checkPermission('role:assign')：
    // 操作者角色不带它 ⇒ 请求进不了控制器，"两条轨同尺"那条会拿 PERMISSION_DENIED 假绿/假红
    const assignPerm = await Permission.findOneAndUpdate(
      { code: 'role:assign' },
      {
        $setOnInsert: { name: '分配角色', code: 'role:assign', type: 'api', module: 'system' },
      },
      { upsert: true, new: true }
    );
    // *:* 用 upsert：其它套件也播种同一条，create 会撞 unique 索引
    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );

    peerA = await Role.create({
      name: 'ZZB 同级管理员A',
      code: 'ZZB_PEER_A',
      level: PEER_LEVEL,
      permissions: [createPerm._id, assignPerm._id],
    });
    peerB = await Role.create({
      name: 'ZZB 同级管理员B',
      code: 'ZZB_PEER_B',
      level: PEER_LEVEL,
      // 权限集与 A **完全相同**（只有 code/name 不同）：见文件头——这是唯一能让
      // "摘掉归属闸"变红的夹具形状，多挂任何一个 A 没有的权限都会先被子集闸拦下
      permissions: [createPerm._id, assignPerm._id],
    });
    peerWide = await Role.create({
      name: 'ZZB 同级管理员-宽权限',
      code: 'ZZB_PEER_WIDE',
      level: PEER_LEVEL,
      permissions: [createPerm._id, assignPerm._id, extraPerm._id],
    });
    lowRole = await Role.create({
      name: 'ZZB 低级访客',
      code: 'ZZB_LOW',
      level: 1,
      permissions: [],
    });
    // 豁免面操作用一个自定义的 *:* 角色（level 与操作者相同），而不是内置超管：
    // 建号路径上有一道"新账户不得携带超管角色"的闸，用真超管角色当夹具会先撞上它。
    const wildRole = await Role.create({
      name: 'ZZB 全权限同级角色',
      code: 'ZZB_WILD',
      level: PEER_LEVEL,
      permissions: [wildcardPerm._id],
    });

    const peerAdmin = await User.create({
      username: 'zzb_peer_a',
      email: 'zzb_peer_a@example.com',
      password: PWD,
      roles: [peerA._id],
    });
    const wildAdmin = await User.create({
      username: 'zzb_wild_a',
      email: 'zzb_wild_a@example.com',
      password: PWD,
      roles: [wildRole._id],
    });
    victim = await User.create({
      username: 'zzb_victim',
      email: 'zzb_victim@example.com',
      password: PWD,
      // level 6 的操作者数据范围是 self：反向对照用的目标必须是其本人创建，
      // 否则范围闸先拒，测不到本该测的那道闸
      createdBy: peerAdmin._id,
      roles: [],
    });

    const sign = (u, name) =>
      jwt.sign({ userId: String(u._id), username: name, tokenVersion: 0 }, process.env.JWT_SECRET, {
        expiresIn: '24h',
      });
    peerToken = sign(peerAdmin, 'zzb_peer_a');
    wildToken = sign(wildAdmin, 'zzb_wild_a');

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 建号请求：不带 department ⇒ guardCreateUserScope 直接放行，判据落在角色闸上 */
  const createUser = (token, username, roles) =>
    request(app)
      .post('/api/users')
      .set('Authorization', `Bearer ${token}`)
      .send({ username, email: `${username}@example.com`, password: PWD, roles });

  // 不写 res.body.errors.errorCode：放行时响应体根本没有 errors，直接取属性会抛
  // TypeError（用例照样红，但失败签名是"测试崩了"而不是"闸门判定变了"，
  // 读起来像夹具坏了）。取空对象兜底后，误放行与误拒绝都表现为一次可比对的 diff。
  const errorCodeOf = (res) => (res.body.errors || {}).errorCode;

  const rolesOf = async (username) => {
    const u = await User.findOne({ username }).select('roles').lean();
    return u ? u.roles.map(String) : null;
  };

  test('建号挂"自己不持有的同级角色"被拒，且不留下孤儿账户', async () => {
    const res = await createUser(peerToken, 'zzb_new_peer_foreign', [String(peerB._id)]);

    expect({ status: res.status, code: errorCodeOf(res) }).toEqual({
      status: 403,
      // 必须点名归属闸：层级闸放行（6 不大于 6）、权限子集闸也放行（B 的权限集与 A 相同），
      // 因此这一枪只能来自归属闸
      code: 'ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN',
    });
    // 回显必须点名是哪个角色：操作者据此判断"该角色谁持有"，
    // 只回一句"无权分配同级角色"会让使用者以为是层级问题而去要更高层级的账号。
    // 两个位置都要钉：message 是给人看的，errors.foreignRoles 是给程序用的
    // （前端按它高亮具体角色，见 web-admin/src/utils/api.js 的错误码映射）。
    expect(res.body.message).toContain('ZZB_PEER_B');
    expect((res.body.errors || {}).foreignRoles).toBe('ZZB_PEER_B');
    // 闸在 userService.createUser 之前 ⇒ 拒绝不该留下任何账户
    expect(await rolesOf('zzb_new_peer_foreign')).toBeNull();
  });

  test('反向对照：同级且权限更宽时由权限子集闸先拦（闸门顺序是钉住的事实）', async () => {
    // 与上一条只差"角色多带一个自己没有的权限"。两条并排放，才能证明上一条
    // 红的是归属闸而不是子集闸；将来有人调整顺序或删掉其中一道，必有一条红。
    const res = await createUser(peerToken, 'zzb_new_peer_wide', [String(peerWide._id)]);

    expect({ status: res.status, code: errorCodeOf(res) }).toEqual({
      status: 403,
      code: 'PERMISSION_GRANT_FORBIDDEN',
    });
    expect(await rolesOf('zzb_new_peer_wide')).toBeNull();
  });

  test('低级角色不受归属闸影响（"给新人挂低权限角色"是合法操作）', async () => {
    const res = await createUser(peerToken, 'zzb_new_low', [String(lowRole._id)]);

    expect({
      status: res.status,
      code: errorCodeOf(res),
      roles: await rolesOf('zzb_new_low'),
    }).toEqual({
      status: 201,
      // 放行侧也点名错误码：归属闸若误伤低级角色，diff 直接给出是哪道闸拒的，
      // 不必回头猜"这个 403 从哪来"
      code: undefined,
      roles: [String(lowRole._id)],
    });
  });

  test('自持的同级角色可以挂给新账户（归属闸只要求"自己持有"）', async () => {
    const res = await createUser(peerToken, 'zzb_new_own', [String(peerA._id)]);

    expect({
      status: res.status,
      code: errorCodeOf(res),
      roles: await rolesOf('zzb_new_own'),
    }).toEqual({
      status: 201,
      code: undefined,
      roles: [String(peerA._id)],
    });
  });

  test('持 *:* 的操作者豁免，与 assignRoles 的豁免面一致', async () => {
    const res = await createUser(wildToken, 'zzb_new_by_wild', [String(peerB._id)]);

    expect({
      status: res.status,
      code: errorCodeOf(res),
      roles: await rolesOf('zzb_new_by_wild'),
    }).toEqual({
      status: 201,
      code: undefined,
      roles: [String(peerB._id)],
    });
  });

  test('同一个操作者、同一个角色：两条轨的判定必须相同（口径不分裂）', async () => {
    // 这条才是本文件真正的不变量：把同一个"非自持同级角色"分别送进两条轨，
    // 两边的错误码必须一致。单边实现（只修一条轨）时这条必红——
    // 上面几条各自看一条轨，看不出"两条轨不一样"。
    const created = await createUser(peerToken, 'zzb_new_cross', [String(peerB._id)]);
    const assigned = await request(app)
      .put(`/api/users/${victim._id}/roles`)
      .set('Authorization', `Bearer ${peerToken}`)
      .send({ roles: [String(peerB._id)] });

    expect({
      createCode: errorCodeOf(created),
      assignCode: errorCodeOf(assigned),
    }).toEqual({
      createCode: 'ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN',
      assignCode: 'ROLE_ASSIGN_FOREIGN_PEER_FORBIDDEN',
    });
    expect(await rolesOf('zzb_new_cross')).toBeNull();
    expect((await rolesOf('zzb_victim')) || []).toEqual([]);
  });
});
