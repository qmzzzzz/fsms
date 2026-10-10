/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：permissionController / userController 的零散校验分支
 * 守护的不变式：validationResult 必须被消费；parent 不存在 / MAX_DEPTH 必须提前终止；批量写错误必须转 skipped
 * 可证伪性：本轮未做变异实测
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [已修复·P1-29] `:350-357` **双可能断言** `expect([403,200]).toContain(res.status)`——用例名声称验证越权拦截，实际允许 200 通过（原出处 2026-09-16 全面代码审计报告；**该报告已删除**，问题编号保留原样）
 *     复核：`:423` 已注释「P1-29 修复：原为 expect([403,200]).toContain —— 允许越权成功通过」，现为实测确定行为断言。
 *
 * 命名沿革：2026-09-20 由 `userPermBranches.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * permissionController / userController 零散分支补齐
 *
 * 【行号说明】本文件早期版本按「全量覆盖率的未覆盖分支行号」逐条标注 `L<行号>`。
 * 2026-09-16 的多轮修复（控制器抽服务、安全加固）使 userController.js 行号整体漂移，
 * 标注大量指向注释或空白行而失实。按「注释必须与实现同步」的要求，现改为语义描述、
 * 不再写行号——函数名与行为描述是稳定锚点，行号不是。
 *
 * permissionController：
 *  - createPermission：validationResult 消费、parent 格式无效、parent 不存在
 *  - updatePermission：记录不存在 404、parent 不存在、MAX_DEPTH 提前终止 400
 *    （模型层造 32 节点库内环）
 *  - deletePermission：不存在 404、有子权限、被角色引用
 *  - batchCreate：空/非数组、驱动级 MongoBulkWriteError 转 skipped
 *
 * userController：
 *  - getUsers：role 不存在 → 空分页
 *  - getUserById：数据范围外 403
 *  - createUser：校验失败、allowedIPs 非法、不存在角色、层级越权 403
 *  - updateUser：不存在 404、同级/更高级 403、改自身状态 400、
 *    无 user:lock 改状态 403、avatar 非法、allowedIPs 非法
 *  - assignRoles：空 roles、不存在用户、无效角色
 *  - deleteUser：不存在 404
 *  - batchDeleteUsers：空列表、超上限（路由层先拦，控制器内为直调兜底）、
 *    非法 ID（同前）、含自己、含超管（整批拒绝；层级闸平时遮蔽该分支，
 *    用例通过下调 SUPER_ADMIN 的 level 构造可达状态）
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
    jwt.sign({ userId, username, tokenVersion: 0 }, process.env.JWT_SECRET, { expiresIn: '24h' });

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
      // 与操作者同部门：范围闸放行，才测得到『超管不可删』这条单例守卫本身
      department: 'SECDEPT',
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

    // 安全员是 level 5 ⇒ 数据范围为 self，只能管"自己创建"的账户；生产里 self 档管理员
    // 走 POST /api/users 建号，createdBy 由服务端写入（userController.js:343）。
    // 不给这层归属，范围闸会先拒，本该被测的层级闸/单例守卫根本走不到。
    await User.findByIdAndUpdate(superUser._id, { $set: { createdBy: secUser._id } });

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
    test('createPermission：缺必填字段 → 400（validationResult 被真实消费）', async () => {
      const res = await sec.post('/api/permissions', { description: '缺少 name/code' });
      expect(res.status).toBe(400);
      // 「被真实消费」的判据是字段明细透传，不是 400（路由挡住同样是 400）
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(res.body.errors.fieldErrors.length).toBeGreaterThan(0);
    });

    test('createPermission：parent 非法 ObjectId 格式 → 路由层 isMongoId 先行 400（控制器内为兜底，经 HTTP 不可达）', async () => {
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

    test('createPermission：parent 不存在 → 400', async () => {
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

    test('updatePermission：非法字段值 → 400（控制器自身消费 validationResult，非仅靠路由）', async () => {
      // 路由层 updatePermissionValidation 只挂链不消费；控制器里的 validationResult
      // 是唯一的直接消费点。这里刻意构造「能过路由链、控制器必须读出错误」的输入——
      // 实际做法：name 超长同时命中路由链的 withMessage 与控制器透传。
      // 变异验证：把控制器里的 'VALIDATION_FAILED' 换成别的已注册 400 码，本用例必须转红。
      const created = await superPost('/api/permissions', {
        name: `upb_${stamp}_uval`,
        code: pcode('uval'),
        type: 'api',
        module: 'system',
      });
      const id = created.body?.data?._id;
      const res = await sec.put(`/api/permissions/${id}`, { name: 'A'.repeat(51) });
      expect(res.status).toBe(400);
      // 明细必须透传：字段名与错误信息同时可见，前端才能定位到具体输入框
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(res.body.errors.fieldErrors[0].path).toBe('name');
    });

    test('updatePermission：记录不存在 → 404', async () => {
      const res = await sec.put('/api/permissions/000000000000000000000002', { name: 'x' });
      expect(res.status).toBe(404);
      expect(res.body.errors.errorCode).toBe('PERMISSION_NOT_FOUND');
    });

    test('updatePermission：parent 不存在 → 400', async () => {
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

    test('updatePermission：祖先链深达 MAX_DEPTH → 提前终止 400（防御库中脏环挂死）', async () => {
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

    test('deletePermission：不存在 404 / 有子权限 400 / 被角色引用 400', async () => {
      const notFound = await sec.delete('/api/permissions/000000000000000000000004');
      expect(notFound.status).toBe(404);
      expect(notFound.body.errors.errorCode).toBe('PERMISSION_NOT_FOUND');

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

    test('batchCreate：空列表 → 400', async () => {
      const res = await sec.post('/api/permissions/batch', { permissions: [] });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
    });

    test('batchCreate：驱动级真实重名错误 → 已插入保留、失败项转 skipped', async () => {
      // 本用例原先注入的是 `{name:'BulkWriteError'}`，而驱动实际抛出的类名是
      // MongoBulkWriteError（①里对真库造一次冲突、断言实际 name）。也就是说旧用例
      // 在为一条「生产必然 500」的死路径发绿灯，任何人把服务侧的判断改成正确的
      // 类名反而会让它变红。现改为：先从真库取得**驱动产生的错误对象**，再投给服务。
      const dupCode = pcode('realbulk');
      const dupDoc = (n) => ({
        name: `upb_${stamp}_${n}`,
        code: dupCode,
        type: 'api',
        module: 'system',
      });
      let realError;
      try {
        await Permission.insertMany([dupDoc('a'), dupDoc('b')], { ordered: false });
      } catch (e) {
        realError = e;
      }
      expect(realError).toBeInstanceOf(Error);
      expect(realError.name).toBe('MongoBulkWriteError');
      expect(Array.isArray(realError.writeErrors)).toBe(true);
      expect(realError.writeErrors).toHaveLength(1);
      // ordered:false 下第一条已真落库，mongoose 把未失败文档挂在 insertedDocs
      expect(realError.insertedDocs).toHaveLength(1);
      await Permission.deleteMany({ code: dupCode });

      const spy = jest.spyOn(Permission, 'insertMany').mockRejectedValue(realError);
      try {
        const res = await sec.post('/api/permissions/batch', {
          permissions: [
            { name: `upb_${stamp}_rb1`, code: pcode('rbone'), type: 'api', module: 'system' },
            { name: `upb_${stamp}_rb2`, code: pcode('rbtwo'), type: 'api', module: 'system' },
          ],
        });
        expect(res.status).toBe(200);
        expect(res.body.data.created).toBe(1);
        expect(res.body.data.skipped).toHaveLength(1);
        // writeErrors[0].index 已由 mongoose 重映射回入参下标 → 第二条
        expect(res.body.data.skipped[0].code).toBe(pcode('rbtwo'));
      } finally {
        spy.mockRestore();
      }
    });
  });

  // ================= userController =================

  describe('userController', () => {
    test('getUsers：role 编码不存在 → 空分页而非全量', async () => {
      const res = await sec.get('/api/users?role=NO_SUCH_ROLE_CODE');
      expect(res.status).toBe(200);
      // ApiResponse.paginated 的 pagination 在响应顶层（与 data 平级）
      expect(res.body.pagination.total).toBe(0);
      expect(res.body.data).toEqual([]);
    });

    test('getUserById：数据范围外用户 → 403 横向越权拦截', async () => {
      const outsiderId = globalThis.__upbFixtures.outsiderId;
      const res = await sec.get(`/api/users/${outsiderId}`);
      // 实测确定行为（P1-29 修复：原为 expect([403,200]).toContain —— 允许越权成功通过）；
      // 安全员（level 5 → dataScope=self）读其他部门用户 → assertRecordInScope 拒绝
      expect(res.status).toBe(403);
      expect(res.body.errors.errorCode).toBe('USER_VIEW_FORBIDDEN');
    });

    test('createUser：缺必填字段 → 400', async () => {
      const res = await sec.post('/api/users', { username: `upbtarget${stamp}a` });
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(res.body.errors.fieldErrors.length).toBeGreaterThan(0);
    });

    test('createUser：allowedIPs 规则非法 → 400', async () => {
      const res = await sec.post('/api/users', {
        username: `upbtarget${stamp}b`,
        email: `upbtarget${stamp}b@example.com`,
        password: PASSWORD,
        allowedIPs: 'not-an-ip-or-cidr',
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('IP 范围规则格式有误');
    });

    test('createUser：包含不存在的角色 → 400', async () => {
      const res = await sec.post('/api/users', {
        username: `upbtarget${stamp}c`,
        email: `upbtarget${stamp}c@example.com`,
        password: PASSWORD,
        roles: ['000000000000000000000005'],
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('不存在的角色');
    });

    test('createUser：分配高于自身层级的角色 → 403', async () => {
      const res = await sec.post('/api/users', {
        username: `upbtarget${stamp}d`,
        email: `upbtarget${stamp}d@example.com`,
        password: PASSWORD,
        roles: [String(level10Role._id)],
      });
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('无权分配高于自身层级');
    });

    test('updateUser：目标不存在 → 404', async () => {
      const res = await sec.put('/api/users/000000000000000000000006', { realName: 'x' });
      expect(res.status).toBe(404);
      // 404 必须点名 USER_NOT_FOUND：与「越权被拒（403）」「校验失败（400）」区分开
      expect(res.body.errors.errorCode).toBe('USER_NOT_FOUND');
    });

    test('updateUser：同级或更高级目标 → 403', async () => {
      const superUserId = globalThis.__upbFixtures.superUserId;
      const res = await sec.put(`/api/users/${superUserId}`, { realName: '越权改名' });
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('无权修改同级或更高级别');
    });

    test('updateUser：变更自身状态 → 400 自我锁死防护', async () => {
      const res = await sec.put(`/api/users/${secUserId}`, { status: 'inactive' });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('不能通过本接口修改自身账户状态');
    });

    test('updateUser：改他人状态但缺 user:lock → 403', async () => {
      // 目标必须在操作者范围内：用范围外的 outsider 会被 self 档范围闸先拒，
      // 得到的是 USER_SCOPE_FORBIDDEN，而不是本用例要测的"缺 user:lock"。
      const User = require('../../models/User');
      const inScope = await User.create({
        username: `upblow${stamp}`,
        email: `upblow${stamp}@example.com`,
        password: PASSWORD,
        createdBy: secUserId,
        roles: [],
      });
      const res = await sec.put(`/api/users/${inScope._id}`, { status: 'inactive' });
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('user:lock');
    });

    test('updateUser：avatar 非法 → 400', async () => {
      const res = await sec.put(`/api/users/${secUserId}`, { avatar: 'javascript:alert(1)' });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('头像');
    });

    test('updateUser：allowedIPs 非法 → 400', async () => {
      const res = await sec.put(`/api/users/${secUserId}`, { allowedIPs: 'bad-rule' });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('IP 范围规则格式有误');
    });

    test('assignRoles：空 roles 400 / 用户不存在 404 / 无效角色 ID 400', async () => {
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

    test('deleteUser：目标不存在 → 404', async () => {
      const res = await sec.delete('/api/users/000000000000000000000009');
      expect(res.status).toBe(404);
      expect(res.body.errors.errorCode).toBe('USER_NOT_FOUND');
    });

    test('deleteUser：目标是超管 → 403 CANNOT_DELETE_SUPER_ADMIN（单例守卫，非层级闸代劳）', async () => {
      // 与 batchDeleteUsers 同因：SUPER_ADMIN 的 level=10 平时恒被层级闸先拦，
      // 该守卫只在「level 被下调」时才是唯一防线（源码注释如此声明）。
      // 变异验证：删掉 targetRoles.some(isSuperAdminRole) 判断，本用例转红。
      const Role = require('../../models/Role');
      const User = require('../../models/User');
      const superUserId = globalThis.__upbFixtures.superUserId;
      const superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
      const originalLevel = superRole.level;
      try {
        superRole.level = 1; // 低于安全员的 5，让层级闸放行
        await superRole.save();

        const res = await sec.delete(`/api/users/${superUserId}`);
        expect(res.status).toBe(403);
        expect(res.body.errors.errorCode).toBe('CANNOT_DELETE_SUPER_ADMIN');
        expect(await User.findById(superUserId)).not.toBeNull(); // 确实没删
      } finally {
        superRole.level = originalLevel;
        await superRole.save();
      }
    });

    test('batchDeleteUsers：空列表 / 超上限 / 非法 ID / 含自己 → 逐层拒绝', async () => {
      const empty = await sec.delete('/api/users/batch', { ids: [] });
      expect(empty.status).toBe(400);

      // 断言口径：101 条在路由层 body('ids').isArray({min:1,max:100}) 就被
      // validationResult 统一拒绝（「数据验证失败」）。控制器内 BATCH_DELETE_MAX
      // 上限检查是绕过路由直调时的兜底，经 HTTP 恒先被路由拦截。
      const oversized = await sec.delete('/api/users/batch', {
        ids: Array.from({ length: 101 }, () => '000000000000000000000000'),
      });
      expect(oversized.status).toBe(400);
      expect(oversized.body.message).toContain('数据验证失败');

      // 同上口径：非法 ID 由路由层 ids.*.isMongoId 拦截，控制器返回统一 400；
      // 控制器内的 invalidIds 过滤同样仅为直调兜底
      const invalidIds = await sec.delete('/api/users/batch', { ids: ['bad-id'] });
      expect(invalidIds.status).toBe(400);
      expect(invalidIds.body.message).toContain('数据验证失败');

      const selfIn = await sec.delete('/api/users/batch', { ids: [secUserId] });
      expect(selfIn.status).toBe(400);
    });

    test('batchDeleteUsers：批次含超管 → 整批拒绝（批量接口不得成为保护绕过路径）', async () => {
      // 本次改动复审重写：原用例传了 ['0000...000a', superUserId] —— 前一个 ID 不存在，
      // 响应在「目标数 != 请求数」处就返回 USER_ID_NOT_FOUND_IN_LIST（实测确认），
      // 超管分支从未被执行。变异验证：把 superTarget 的判断整个删掉，原用例仍全绿。
      //
      // 超管分支平时被层级闸遮蔽（SUPER_ADMIN level=10 恒 >= 操作者层级），
      // 只在「SUPER_ADMIN 的 level 被下调」时生效——源码注释把这条兜底写成了
      // 「若 SUPER_ADMIN 的 level 被下调，层级校验会失效而本判断仍然生效」。
      // 因此这里直接把该角色的 level 下调到操作者之下，构造出层级闸放行、
      // 只有超管兜底能拦住的状态。
      const Role = require('../../models/Role');
      const superUserId = globalThis.__upbFixtures.superUserId;
      const superRole = await Role.findOne({ code: 'SUPER_ADMIN' });
      const originalLevel = superRole.level;
      try {
        superRole.level = 1; // 低于安全员的 5，绕开层级闸
        await superRole.save();

        const res = await sec.delete('/api/users/batch', { ids: [superUserId] });
        // 403 而非 400：必须命中 CANNOT_DELETE_SUPER_ADMIN，而不是别的拒绝路径
        expect(res.status).toBe(403);
        expect(res.body.errors.errorCode).toBe('CANNOT_DELETE_SUPER_ADMIN');

        // 对照组：同一次请求里用户的角色未被删除（整批拒绝，不是部分删除）
        const User = require('../../models/User');
        expect(await User.findById(superUserId)).not.toBeNull();
      } finally {
        superRole.level = originalLevel;
        await superRole.save();
      }
    });
  });
});
