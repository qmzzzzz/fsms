/**
 * POST /api/roles：提交的权限 ID 必须**真的存在**
 *
 * 【缺陷形状】createRole 把 `findPermissionsByIds(permissions)` 的结果只用于两件事
 * ——「有没有混进保留通配」和「操作员有没有这些权限」，**没有比对查到的条数与
 * 提交的条数**。于是格式合法但库里没有的权限 ID 会被静默丢弃：
 *   · 请求方提交 N 条 → 落库的角色带着 N-1 条实权 + 1 条悬空引用 → 回 201；
 *   · 悬空引用经 populate 直接消失，`getOperatorPermissions` 少算一条，
 *     持有人以为自己拿到了某项权限而实际没有（授予类接口的"假成功"）。
 * 同族的**分配**路径（PUT /api/roles/:id/permissions）早就有这条判据
 * （rolePermissionController.js 的 `validPerms.length !== uniquePermIds.length`
 * ⇒ PERMISSION_ID_INVALID），本处是缺的那一处。
 *
 * 【路由层的格式闸挡不住这一维】`body('permissions.*').isMongoId()` 只保证它是
 * 合法 ObjectId（见 routes/roleRoutes.js:58-59 与其注释），不保证有文档。
 *
 * 【判据】除"反向对照/正例"（3、4）外，每条都在"只比子集、不比条数"的实现下为红。
 * 另钉住分支位置两向：5 = 超管轨不得跳过（校验写进 !isSuperAdmin 分支即红），
 * 6 = 非超管轨同样受约束（校验写进 isSuperAdmin 分支即红）。
 * 说明：本接口对"ID 不存在"与"无权授予"给的是不同错误码，因此无论这条判据
 * 排在越权判定之前还是之后，都留有一个存在性探针（错误码差异本身）。收口要
 * 统一成一个错误码，属于接口口径变更、需与另一会话对齐，本批不动。
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

const stamp = `rpe${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
const PASSWORD = randomPassword();
// Role.code 形状 ^[A-Z_]+$（roleRoutes.js:37）：stamp 里数字映射成小写字母，必须整体大写
const roleCode = (suffix) => `${stamp}${suffix}`.toUpperCase();
const auth = (token) => ({ Authorization: `Bearer ${token}` });

describe('POST /api/roles 的权限 ID 存在性', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let superToken;
  let midToken;
  let realIds;

  const errorCode = (res) => res.body?.errors?.errorCode;

  /** 合法格式、但 Permission 集合里不存在 */
  const danglingId = () => String(new mongoose.Types.ObjectId());

  const create = (token, permissions, code) =>
    request(app)
      .post('/api/roles')
      .set(auth(token))
      .send({ name: `${stamp}角色${code}`, code: roleCode(code), permissions });

  const madeRole = (code) => Role.findOne({ code: roleCode(code) }).lean();

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    require('../../models/FireDevice');

    const wildcard = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!superRole) {
      superRole = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcard._id],
      });
    }
    const mkUser = async (username, roles) => {
      const u = await User.create({
        username: `${stamp}${username}`,
        email: `${stamp}${username}@example.com`,
        password: PASSWORD,
        roles,
      });
      return jwt.sign(
        { userId: String(u._id), username: u.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
    };
    superToken = await mkUser('super', [superRole._id]);

    // 中级操作员：有 role:create，但不含 *:*，也不含下面要提交的真实权限
    const createPerm = await Permission.findOneAndUpdate(
      { code: 'role:create' },
      { $setOnInsert: { name: '创建角色', code: 'role:create', type: 'api', module: 'role' } },
      { upsert: true, new: true }
    );
    const midRole = await Role.create({
      name: `${stamp}中级`,
      code: roleCode('MID'),
      level: 5,
      permissions: [createPerm._id],
    });
    midToken = await mkUser('mid', [midRole._id]);

    const mkPerm = (suffix) =>
      Permission.create({
        name: `${stamp}权限${suffix}`,
        code: `${stamp}:read${suffix}`,
        type: 'api',
        module: stamp,
      });
    realIds = [(await mkPerm('a'))._id, (await mkPerm('b'))._id].map(String);

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`^${stamp.toUpperCase()}`) }).catch(() => {});
      await Permission.deleteMany({ module: stamp }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('1 全是悬空 ID：400 PERMISSION_ID_INVALID，且角色一条都不建', async () => {
    const res = await create(superToken, [danglingId()], 'DANGLE');
    expect(res.status).toBe(400);
    expect(errorCode(res)).toBe('PERMISSION_ID_INVALID');
    expect(await madeRole('DANGLE')).toBeNull();
  });

  test('2 混合（一条真实 + 一条悬空）：同样拒绝，不得"少授一条还报成功"', async () => {
    const res = await create(superToken, [realIds[0], danglingId()], 'MIX');
    expect(errorCode(res)).toBe('PERMISSION_ID_INVALID');
    expect(await madeRole('MIX')).toBeNull();
  });

  test('3 反向对照（应当恒绿的正例）：两条真实权限 ⇒ 201 且逐条落库', async () => {
    const res = await create(superToken, realIds, 'GOOD');
    expect(res.status).toBe(201);
    const created = await madeRole('GOOD');
    expect(created.permissions.map(String).sort()).toEqual([...realIds].sort());
  });

  test('4 同一真实权限提交两次：201 且落库去重（校验与写入必须同源）', async () => {
    const res = await create(superToken, [realIds[0], realIds[0]], 'DUP');
    expect(res.status).toBe(201);
    const created = await madeRole('DUP');
    expect(created.permissions.map(String)).toEqual([realIds[0]]);
  });

  test('5 超管轨不得豁免：通配持有者也拿不到悬空 ID 的"部分成功"', async () => {
    // 超管会跳过下面的越权判定，若存在性校验被写进 `if (!isSuperAdmin)` 分支，
    // 这条就会变 201 —— 而缺陷的实际危害（悬空引用）恰恰在超管轨最容易发生：
    // 一次批量脚本传错一个 ID 就静默少授一条。
    const res = await create(superToken, [realIds[0], danglingId()], 'SUPERMIX');
    expect(errorCode(res)).toBe('PERMISSION_ID_INVALID');
    expect(await madeRole('SUPERMIX')).toBeNull();
  });

  test('6 非超管轨同样受约束：存在性校验不得只挂在超管分支上', async () => {
    const res = await create(midToken, [danglingId()], 'PROBE');
    expect(errorCode(res)).toBe('PERMISSION_ID_INVALID');
    expect(await madeRole('PROBE')).toBeNull();
  });

  test('7 既有防线未被新增分支挤掉：通配权限 ID 仍然拒绝铸造', async () => {
    const wildcardDoc = await Permission.findOne({ code: '*:*' }).lean();
    const res = await create(superToken, [String(wildcardDoc._id)], 'WILD');
    expect(errorCode(res)).toBe('CANNOT_GRANT_WILDCARD_PERMISSION');
    expect(await madeRole('WILD')).toBeNull();
  });
});
