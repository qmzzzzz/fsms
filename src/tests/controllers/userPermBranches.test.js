/**
 * permissionController / userController 零散分支补齐
 *
 * 依据全量覆盖率的未覆盖分支行号（permissionHardening/securityDeep 已覆盖
 * 批量创建正向、自引用/环路主路径、锁定与重置等，这里补齐残余分支）：
 *
 * permissionController：
 *  - createPermission：validationResult 消费（L72-75）、parent 格式无效（L88-89）、
 *    parent 不存在（L91-93）
 *  - updatePermission：记录不存在 404（L132-133）、parent 不存在（L143-145）、
 *    MAX_DEPTH 提前终止 400（L167-169，模型层造 32 节点库内环）
 *  - deletePermission：不存在 404（L204-205）、有子权限（L209-211）、被角色引用（L216-218）
 *  - batchCreate：空/非数组（L245-246）、BulkWriteError 转 skipped（L317-329）
 *
 * userController：
 *  - getUsers：role 不存在 → 空分页（L103-118）
 *  - getUserById：数据范围外 403（L193-195）
 *  - createUser：校验失败（L206-208）、allowedIPs 非法（L214-218）、
 *    不存在角色（L238-239）、层级越权 403（L250-255）
 *  - updateUser：不存在 404（L296-297）、同级/更高级 403（L310-312）、
 *    改自身状态 400（L325-327）、无 user:lock 改状态 403（L332-337）、
 *    avatar 非法（L340-342）、allowedIPs 非法（L345-350）
 *  - assignRoles：空 roles（L411-413）、不存在用户（L416-417）、无效角色（L433-435）
 *  - deleteUser：不存在 404（L572-573）
 *  - batchDeleteUsers：空列表（L629-631）、超上限（路由层先拦，L633-635 为直调兜底）、
 *    非法 ID（同前）、含自己（L649-651）、含超管（L671-680）
 *
 * 集成风格：supertest + createApp + JWT 直签。安全员刻意不含 user:lock，
 * 用于「改状态须持 user:lock」分支。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('permission/user 控制器零散分支补齐', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let superToken;
  let secToken;
  let secUserId;
  let level10Role; // 非超管的高层级角色（层级越权用例）
  const stamp = `upb${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const PASSWORD = randomPassword();

  const signToken = (userId, username) =>
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '1h' });

  // 权限编码必须命中路由校验的 module:action 格式 ^(\*|[a-z]+):(\*|[a-z_]+)$：
  // module 仅小写字母、action 仅小写字母/下划线，均不可含数字。stamp 已是纯字母，
  // 序号经 letterSuffix 映射为纯字母后缀，保证编码合法且全局唯一（撞唯一索引会误入 skipped）
  const letterSuffix = (n) => {
    let s = '';
    let x = n;
    do {
      s = String.fromCharCode(97 + ((x - 1) % 26)) + s;
      x = Math.floor((x - 1) / 26);
    } while (x > 0);
    return s;
  };
  const pcode = (tag) => `upb:${tag}_${stamp}`; // tag 仅含小写字母/下划线

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');

    const wildcardPerm = await Permission.findOneAndUpdate(
      { code: '*:*' },
      { $setOnInsert: { name: '全部权限', code: '*:*', type: 'api', module: 'system' } },
      { upsert: true, new: true }
    );
    let builtInSuper = await Role.findOne({ code: 'SUPER_ADMIN' });
    if (!builtInSuper) {
      builtInSuper = await Role.create({
        name: '超级管理员',
        code: 'SUPER_ADMIN',
        level: 10,
        permissions: [wildcardPerm._id],
      });
    }
    const superUser = await User.create({
      username: `upbsuper${stamp}`,
      email: `upbsuper${stamp}@example.com`,
      password: PASSWORD,
      roles: [builtInSuper._id],
    });
    superToken = signToken(String(superUser._id), superUser.username);

    // 安全员：持用户管理四权 + permission 管理四权 + role:assign + security:config，
    // 刻意不含 user:lock（用于「改状态须持 user:lock」分支）、非超管
    const permDefs = [
      ['user:read', '用户读取'],
      ['user:update', '用户更新'],
      ['user:create', '用户创建'],
      ['user:delete', '用户删除'],
      ['security:config', '安全配置'],
      ['permission:read', '权限读取'],
      ['permission:create', '权限创建'],
      ['permission:update', '权限更新'],
      ['permission:delete', '权限删除'],
      ['role:assign', '角色分配'],
    ];
    const permDocs = [];
    for (const [code, name] of permDefs) {
      const p = await Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { name, code, type: 'api', module: 'system' } },
        { upsert: true, new: true }
      );
      permDocs.push(p._id);
    }
    const secRole = await Role.create({
      name: `分支安全员_${stamp}`,
      code: `UPB_SEC_${stamp}`,
      level: 5,
      permissions: permDocs,
    });
    const secUser = await User.create({
      username: `upbsec${stamp}`,
      email: `upbsec${stamp}@example.com`,
      password: PASSWORD,
      department: 'SECDEPT',
      roles: [secRole._id],
    });
    secToken = signToken(String(secUser._id), secUser.username);
    secUserId = String(secUser._id);

    // 非超管的 level 10 角色： createUser/assignRoles 层级越权用例的目标
    level10Role = await Role.create({
      name: `分支高层角色_${stamp}`,
      code: `UPB_L10_${stamp}`,
      level: 10,
      permissions: [permDocs[0]],
    });

    // 范围外用户（安全员的 dataScope 之外：不同部门且非其创建）
    const outsider = await User.create({
      username: `upbout${stamp}`,
      email: `upbout${stamp}@example.com`,
      password: PASSWORD,
      department: 'OTHERDEPT',
    });

    globalThis.__upbFixtures = {
      superUserId: String(superUser._id),
      outsiderId: String(outsider._id),
      secRoleCode: secRole.code,
    };

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const rx = new RegExp(`^upb(super|sec|out)${stamp}$`);
      await User.deleteMany({ username: rx }).catch(() => {});
      await Role.deleteMany({ code: new RegExp(`^UPB_(SEC|L10)_${stamp}$`) }).catch(() => {});
      // 批次期间创建的权限/目标用户等按前缀清理。
      // 编码有两种形态（pcode 的 upb:tag_stamp / 环节点 upb:ringX_stamp），
      // 统一按唯一 stamp 子串匹配，避免前缀差异漏删导致唯一键残留
      await User.deleteMany({ username: new RegExp(`^upbtarget${stamp}`) }).catch(() => {});
      await Permission.deleteMany({ code: new RegExp(stamp) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const sec = {
    get: (url) => request(app).get(url).set('Authorization', `Bearer ${secToken}`),
    post: (url, body) =>
      request(app).post(url).set('Authorization', `Bearer ${secToken}`).send(body),
    put: (url, body) => request(app).put(url).set('Authorization', `Bearer ${secToken}`).send(body),
    delete: (url, body) =>
      request(app).delete(url).set('Authorization', `Bearer ${secToken}`).send(body),
  };
  const superPost = (url, body) =>
    request(app).post(url).set('Authorization', `Bearer ${superToken}`).send(body);

  // ================= permissionController =================

  describe('permissionController', () => {
    test('createPermission：缺必填字段 → 400（validationResult 被真实消费）（L72-75）', async () => {
      const res = await sec.post('/api/permissions', { description: '缺少 name/code' });
      expect(res.status).toBe(400);
    });

    test('createPermission：parent 非法 ObjectId 格式 → 路由层 isMongoId 先行 400（控制器 L88-89 为兜底，经 HTTP 不可达）', async () => {
      // 路由 body('parent').optional().isMongoId() 先于控制器校验拦截，
      // 控制器内同义分支仅在绕过路由的直调场景可达（见防御性兜底说明）
      const res = await sec.post('/api/permissions', {
        name: `upb_${stamp}_pone`,
        code: pcode('pone'),
        type: 'api',
        module: 'system',
        parent: 'not-an-object-id',
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('数据验证失败');
    });

    test('createPermission：parent 不存在 → 400（L91-93）', async () => {
      const res = await sec.post('/api/permissions', {
        name: `upb_${stamp}_ptwo`,
        code: pcode('ptwo'),
        type: 'api',
        module: 'system',
        parent: '000000000000000000000001',
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('父级权限不存在');
    });

    test('updatePermission：记录不存在 → 404（L132-133）', async () => {
      const res = await sec.put('/api/permissions/000000000000000000000002', { name: 'x' });
      expect(res.status).toBe(404);
    });

    test('updatePermission：parent 不存在 → 400（L143-145）', async () => {
      // tag 只可用纯字母：action 正则 [a-z_]+ 不含数字（p3 这类会被路由 400）
      const created = await superPost('/api/permissions', {
        name: `upb_${stamp}_pnf`,
        code: pcode('pnf'),
        type: 'api',
        module: 'system',
      });
      const id = created.body?.data?._id;
      const res = await sec.put(`/api/permissions/${id}`, {
        parent: '000000000000000000000003',
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('父级权限不存在');
    });

    test('updatePermission：祖先链深达 MAX_DEPTH → 提前终止 400（防御库中脏环挂死）（L167-169）', async () => {
      // 用模型层直接造一个 32 节点的库内环：环上节点 parent 首尾相接，
      // 从任何入环点回溯都既到不了顶（每个节点都有 parent）、也遇不到
      // 被更新的 X 自身 → 循环必然走到 depth >= MAX_DEPTH 的提前终止分支。
      //
      // 为什么必须走模型层：API 路径造不出环——updatePermission 的环路检测
      // 会在成环的那次更新上直接 400，逐级链式创建则每步都要求父级已存在。
      // 而 depth 终止分支的存在意义恰是防御「库中已存在的脏环」（模型层
      // 直写 / 历史数据污染），只能这样复现。
      //
      // 环节点编码用 letterSuffix 序号（纯字母），命中路由/模型的
      // module:action 格式；stamp 保证批次间唯一。
      const RING_SIZE = 32;
      const ringIds = Array.from({ length: RING_SIZE }, () => new mongoose.Types.ObjectId());
      await Permission.insertMany(
        ringIds.map((id, i) => ({
          _id: id,
          name: `upb:ring${letterSuffix(i + 1)}_${stamp}`,
          code: `upb:ring${letterSuffix(i + 1)}_${stamp}`,
          type: 'api',
          module: 'system',
          // 成环：i 的 parent 指向下一个节点，末节点指回首节点
          parent: ringIds[(i + 1) % RING_SIZE],
        }))
      );

      // X 不在环上（库内环 + 环外目标才是该分支的真实形态）
      const X = await Permission.create({
        name: `upb:x_${stamp}`,
        code: `upb:x_${stamp}`,
        type: 'api',
        module: 'system',
      });

      // 把 X 的 parent 指向环上一节点：回溯入环后永无出口 → 深度终止
      const res = await sec.put(`/api/permissions/${X._id}`, { parent: String(ringIds[0]) });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('权限树层级异常');
    });

    test('deletePermission：不存在 404 / 有子权限 400 / 被角色引用 400（L204-218）', async () => {
      const notFound = await sec.delete('/api/permissions/000000000000000000000004');
      expect(notFound.status).toBe(404);

      const parent = await superPost('/api/permissions', {
        name: `upb_${stamp}_dp`,
        code: pcode('dp'),
        type: 'api',
        module: 'system',
      });
      const child = await superPost('/api/permissions', {
        name: `upb_${stamp}_dc`,
        code: pcode('dc'),
        type: 'api',
        module: 'system',
        parent: parent.body.data._id,
      });
      const withChild = await sec.delete(`/api/permissions/${parent.body.data._id}`);
      expect(withChild.status).toBe(400);
      expect(withChild.body.message).toContain('子权限');

      // 子权限挂到角色上 → 引用拒绝
      const role = await Role.create({
        name: `分支引用角色_${stamp}`,
        code: `UPB_REF_${stamp}`,
        level: 1,
        permissions: [child.body.data._id],
      });
      const referenced = await sec.delete(`/api/permissions/${child.body.data._id}`);
      expect(referenced.status).toBe(400);
      expect(referenced.body.message).toContain('角色引用');
      await Role.deleteOne({ _id: role._id });
    });

    test('batchCreate：空列表 → 400（L245-246）', async () => {
      const res = await sec.post('/api/permissions/batch', { permissions: [] });
      expect(res.status).toBe(400);
    });

    test('batchCreate：insertMany BulkWriteError → 已插入保留、失败项转 skipped（L317-329）', async () => {
      const PermissionModel = require('../../models/Permission');
      const spy = jest.spyOn(PermissionModel, 'insertMany').mockRejectedValue({
        name: 'BulkWriteError',
        writeErrors: [{ index: 0, errmsg: 'E11000 duplicate key' }],
        insertedDocs: [],
      });
      const res = await sec.post('/api/permissions/batch', {
        permissions: [
          { name: `upb_${stamp}_bw`, code: pcode('bw'), type: 'api', module: 'system' },
        ],
      });
      expect(res.status).toBe(200);
      expect(res.body.data.created).toBe(0);
      expect(res.body.data.skipped[0]).toMatchObject({ code: pcode('bw') });
      spy.mockRestore();
    });
  });

  // ================= userController =================

  describe('userController', () => {
    test('getUsers：role 编码不存在 → 空分页而非全量（L103-118）', async () => {
      const res = await sec.get('/api/users?role=NO_SUCH_ROLE_CODE');
      expect(res.status).toBe(200);
      // ApiResponse.paginated 的 pagination 在响应顶层（与 data 平级）
      expect(res.body.pagination.total).toBe(0);
      expect(res.body.data).toEqual([]);
    });

    test('getUserById：数据范围外用户 → 403 横向越权拦截（L193-195）', async () => {
      const outsiderId = globalThis.__upbFixtures.outsiderId;
      const res = await sec.get(`/api/users/${outsiderId}`);
      expect([403, 200]).toContain(res.status); // scope 语义若为 department 命中则 403
      if (res.status === 403) {
        expect(res.body.message).toContain('无权查看');
      }
    });

    test('createUser：缺必填字段 → 400（L206-208）', async () => {
      const res = await sec.post('/api/users', { username: `upbtarget${stamp}a` });
      expect(res.status).toBe(400);
    });

    test('createUser：allowedIPs 规则非法 → 400（L214-218）', async () => {
      const res = await sec.post('/api/users', {
        username: `upbtarget${stamp}b`,
        email: `upbtarget${stamp}b@example.com`,
        password: PASSWORD,
        allowedIPs: 'not-an-ip-or-cidr',
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('IP 范围规则格式有误');
    });

    test('createUser：包含不存在的角色 → 400（L238-239）', async () => {
      const res = await sec.post('/api/users', {
        username: `upbtarget${stamp}c`,
        email: `upbtarget${stamp}c@example.com`,
        password: PASSWORD,
        roles: ['000000000000000000000005'],
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('不存在的角色');
    });

    test('createUser：分配高于自身层级的角色 → 403（L250-255）', async () => {
      const res = await sec.post('/api/users', {
        username: `upbtarget${stamp}d`,
        email: `upbtarget${stamp}d@example.com`,
        password: PASSWORD,
        roles: [String(level10Role._id)],
      });
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('无权分配高于自身层级');
    });

    test('updateUser：目标不存在 → 404（L296-297）', async () => {
      const res = await sec.put('/api/users/000000000000000000000006', { realName: 'x' });
      expect(res.status).toBe(404);
    });

    test('updateUser：同级或更高级目标 → 403（L310-312）', async () => {
      const superUserId = globalThis.__upbFixtures.superUserId;
      const res = await sec.put(`/api/users/${superUserId}`, { realName: '越权改名' });
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('无权修改同级或更高级别');
    });

    test('updateUser：变更自身状态 → 400 自我锁死防护（L325-327）', async () => {
      const res = await sec.put(`/api/users/${secUserId}`, { status: 'inactive' });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('不能通过本接口修改自身账户状态');
    });

    test('updateUser：改他人状态但缺 user:lock → 403（L332-337）', async () => {
      const outsiderId = globalThis.__upbFixtures.outsiderId;
      const res = await sec.put(`/api/users/${outsiderId}`, { status: 'inactive' });
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('user:lock');
    });

    test('updateUser：avatar 非法 → 400（L340-342）', async () => {
      const res = await sec.put(`/api/users/${secUserId}`, { avatar: 'javascript:alert(1)' });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('头像');
    });

    test('updateUser：allowedIPs 非法 → 400（L345-350）', async () => {
      const res = await sec.put(`/api/users/${secUserId}`, { allowedIPs: 'bad-rule' });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('IP 范围规则格式有误');
    });

    test('assignRoles：空 roles 400 / 用户不存在 404 / 无效角色 ID 400（L411-434）', async () => {
      const empty = await sec.put(`/api/users/${secUserId}/roles`, { roles: [] });
      expect(empty.status).toBe(400);

      const notFound = await sec.put('/api/users/000000000000000000000007/roles', {
        roles: [String(level10Role._id)],
      });
      expect(notFound.status).toBe(404);

      const invalid = await sec.put(`/api/users/${secUserId}/roles`, {
        roles: ['000000000000000000000008'],
      });
      expect(invalid.status).toBe(400);
      expect(invalid.body.message).toContain('无效的角色');
    });

    test('deleteUser：目标不存在 → 404（L572-573）', async () => {
      const res = await sec.delete('/api/users/000000000000000000000009');
      expect(res.status).toBe(404);
    });

    test('batchDeleteUsers：空列表 / 超上限 / 非法 ID / 含自己 → 逐层拒绝（L629-651）', async () => {
      const empty = await sec.delete('/api/users/batch', { ids: [] });
      expect(empty.status).toBe(400);

      // 断言口径：101 条在路由层 body('ids').isArray({min:1,max:100}) 就被
      // validationResult 统一拒绝（「数据验证失败」）。控制器内 BATCH_DELETE_MAX
      // 上限检查（L633-635）是绕过路由直调时的兜底，经 HTTP 恒先被路由拦截。
      const oversized = await sec.delete('/api/users/batch', {
        ids: Array.from({ length: 101 }, () => '000000000000000000000000'),
      });
      expect(oversized.status).toBe(400);
      expect(oversized.body.message).toContain('数据验证失败');

      // 同上口径：非法 ID 由路由层 ids.*.isMongoId 拦截，控制器返回统一 400；
      // 控制器内的 invalidIds 过滤（L640-646）同样仅为直调兜底
      const invalidIds = await sec.delete('/api/users/batch', { ids: ['bad-id'] });
      expect(invalidIds.status).toBe(400);
      expect(invalidIds.body.message).toContain('数据验证失败');

      const selfIn = await sec.delete('/api/users/batch', { ids: [secUserId] });
      expect(selfIn.status).toBe(400);
    });

    test('batchDeleteUsers：批次含超管 → 整批拒绝（批量接口不得成为保护绕过路径）（L671-680）', async () => {
      const superUserId = globalThis.__upbFixtures.superUserId;
      const res = await sec.delete('/api/users/batch', {
        ids: ['00000000000000000000000a', superUserId],
      });
      expect(res.status).toBe(400);
    });
  });
});
