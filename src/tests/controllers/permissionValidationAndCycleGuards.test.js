/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：权限管理接口（P2-23 校验消费 + P3-10 环路检测）
 * 守护的不变式：校验器必须被消费（否则规则全是装饰）；环路必须被拦（否则菜单树无限递归、节点永久消失）
 * 可证伪性：本轮未做变异实测
 *
 * 命名沿革：2026-09-20 由 `permissionHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 权限管理接口加固回归（P2-23 批量创建校验 + P3-10 环路检测）
 *
 * P2-23 的根因是「校验器写了但没人消费」：路由挂了 isArray({max:500})，
 * 控制器却从不读 validationResult —— 于是所有校验规则全是装饰。
 * P3-10 的根因是「只拦了最短的环」：自引用 A→A 被拦，A→B→A 一路放行，
 * 成环后菜单树遍历无限递归、这些节点从权限树中永久消失。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('权限接口加固回归', () => {
  let app;
  let User;
  let Role;
  let Permission;
  let token;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    Permission = require('../../models/Permission');
    require('../../models/TokenBlacklist');
    const { createApp } = require('../../app');
    app = createApp();

    const seedPerm = (code) =>
      Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { code, name: code, type: 'api', module: 'system' } },
        { upsert: true, new: true }
      );
    const perms = await Promise.all([
      seedPerm('permission:create'),
      seedPerm('permission:update'),
      seedPerm('permission:read'),
    ]);
    const role = await Role.findOneAndUpdate(
      { code: 'PERM_ADMIN_ROLE' },
      {
        $setOnInsert: {
          code: 'PERM_ADMIN_ROLE',
          name: '权限管理员',
          level: 6,
          permissions: perms.map((p) => p._id),
        },
      },
      { upsert: true, new: true }
    );
    const operator = await User.create({
      username: 'perm_admin',
      email: 'perm_admin@example.com',
      password: 'Qz7#Lm42vTx9',
      roles: [role._id],
    });
    token = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  const batchCreate = (permissions) =>
    request(app)
      .post('/api/permissions/batch')
      .set('Authorization', `Bearer ${token}`)
      .send({ permissions });

  const rnd = () => Math.random().toString(36).slice(2, 7).replace(/\d/g, 'a');

  // ================= P2-23 =================
  describe('P2-23 batchCreatePermissions 逐条校验', () => {
    test('合法批次正常创建', async () => {
      const code = `batchok:${rnd()}`;
      const res = await batchCreate([{ name: '批量测试', code, type: 'api', module: 'test' }]);
      expect(res.status).toBe(200);
      expect(res.body.data.created).toBe(1);
      expect(await Permission.findOne({ code })).toBeTruthy();
    });

    test('保留通配 *:* 不得被批量铸造（单条路径已拦，批量曾是后门）', async () => {
      const res = await batchCreate([
        { name: '超管通配', code: '*:*', type: 'api', module: 'system' },
      ]);
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('验证失败');
    });

    test('缺少必填字段被拒（控制器现在真正消费 validationResult）', async () => {
      const res = await batchCreate([
        { code: `nofield:${rnd()}`, module: 'test' }, // 缺 name / type
      ]);
      expect(res.status).toBe(400);
      // 「真正消费」的判据不是 400（路由挡住也是 400），而是控制器把
      // validationResult 的字段明细透传了出来。字段名缺失时 express-validator
      // 的 param 为 name/type 之一，这里断言 errors.fieldErrors 非空且含字段信息。
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      const fieldErrors = res.body.errors.fieldErrors;
      expect(Array.isArray(fieldErrors)).toBe(true);
      expect(fieldErrors.length).toBeGreaterThan(0);
      // path 形态为 permissions[<n>].<field>（express-validator 的批量写法）
      const fields = fieldErrors.map((e) =>
        String(e.path || e.param).replace(/^permissions\[\d+\]\./, '')
      );
      expect(fields).toEqual(expect.arrayContaining(['name', 'type']));
    });

    test('非法 code 格式被拒', async () => {
      const res = await batchCreate([
        { name: '格式错误', code: 'NotAValidCode', type: 'api', module: 'test' },
      ]);
      expect(res.status).toBe(400);
      // 被拒的是 code 字段（批量写法的 path 形态为 permissions[<n>].<field>）
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(res.body.errors.fieldErrors[0].path).toBe('permissions[0].code');
    });

    test('超过 500 条被拒（原先 max:500 形同虚设，构成慢速 DoS 面）', async () => {
      // code 必须逐条合法，否则会因格式错误提前 400，验不到条数上限本身
      const toAlpha = (n) => String(n).replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
      const many = Array.from({ length: 501 }, (_, i) => ({
        name: `批量${i}`,
        code: `bulk:n${toAlpha(i)}`,
        type: 'api',
        module: 'test',
      }));
      const res = await batchCreate(many);
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).toContain('最多 500 条');
    });

    test('批内重复 code 提前拒绝（原先撞唯一键只进 skipped，调用方无从察觉）', async () => {
      const code = `dupe:${rnd()}`;
      const res = await batchCreate([
        { name: '第一条', code, type: 'api', module: 'test' },
        { name: '第二条', code, type: 'api', module: 'test' },
      ]);
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('重复编码');
      // 不得半途落库
      expect(await Permission.countDocuments({ code })).toBe(0);
    });

    test('parent 悬空引用进入 skipped 而非静默落库', async () => {
      const code = `orphan:${rnd()}`;
      const ghost = new mongoose.Types.ObjectId();
      const res = await batchCreate([
        { name: '悬空父级', code, type: 'api', module: 'test', parent: String(ghost) },
      ]);
      expect(res.status).toBe(200);
      expect(res.body.data.created).toBe(0);
      expect(res.body.data.skipped[0].reason).toContain('父级权限不存在');
      expect(await Permission.findOne({ code })).toBeNull();
    });

    test('非 ObjectId 的 parent 在校验层就被拒', async () => {
      const res = await batchCreate([
        {
          name: '非法父级',
          code: `badparent:${rnd()}`,
          type: 'api',
          module: 'test',
          parent: 'not-an-id',
        },
      ]);
      expect(res.status).toBe(400);
      expect(res.body.errors.errorCode).toBe('VALIDATION_FAILED');
      expect(res.body.errors.fieldErrors[0].path).toBe('permissions[0].parent');
    });
  });

  // ================= P3-10 =================
  describe('P3-10 权限父级环路检测', () => {
    test('多级环路被拒（A→B→C→A）', async () => {
      const a = await Permission.create({
        name: 'A',
        code: `cyclea:${rnd()}`,
        type: 'api',
        module: 'test',
      });
      const b = await Permission.create({
        name: 'B',
        code: `cycleb:${rnd()}`,
        type: 'api',
        module: 'test',
        parent: a._id,
      });
      const c = await Permission.create({
        name: 'C',
        code: `cyclec:${rnd()}`,
        type: 'api',
        module: 'test',
        parent: b._id,
      });

      // 把 A 的父级设为 C → A→C→B→A 成环
      const res = await request(app)
        .put(`/api/permissions/${a._id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ parent: String(c._id) });

      expect(res.status).toBe(400);
      // A→C→B→A 多级环路：命中环路文案（与自引用文案区分）
      expect(res.body.message).toContain('循环引用');
      const fresh = await Permission.findById(a._id);
      expect(fresh.parent).toBeFalsy();
    });

    test('自引用仍被拦（最短环）', async () => {
      const p = await Permission.create({
        name: 'Self',
        code: `cycleself:${rnd()}`,
        type: 'api',
        module: 'test',
      });
      const res = await request(app)
        .put(`/api/permissions/${p._id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ parent: String(p._id) });
      expect(res.status).toBe(400);
      // 自引用是独立文案（与 A→B→C→A 环路区分）：错的是哪一类必须可断言；且 parent 未被写坏
      expect(res.body.message).toContain('父级权限不能是权限自身');
      const fresh = await Permission.findById(p._id);
      expect(fresh.parent).toBeFalsy();
    });

    test('内置超级通配 *:* 不可被停用（否则全体超管失去 *:* 且无人能改回=DB 级自锁死）', async () => {
      // upsert 防与其它已播种的 *:* 撞唯一码
      const wildcard = await Permission.findOneAndUpdate(
        { code: '*:*' },
        { $setOnInsert: { name: '超级通配', type: 'api', module: 'system', status: 'active' } },
        { upsert: true, new: true }
      );
      const res = await request(app)
        .put(`/api/permissions/${wildcard._id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'inactive' });
      expect(res.status).toBe(400);
      expect((await Permission.findById(wildcard._id)).status).toBe('active');
    });

    test('普通权限仍可改 status（保留码守卫只拦 *:*，不误伤正常维护）', async () => {
      const p = await Permission.create({
        name: 'NormStat',
        code: `normstat:${rnd()}`,
        type: 'api',
        module: 'test',
        status: 'active',
      });
      const res = await request(app)
        .put(`/api/permissions/${p._id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'inactive' });
      expect(res.status).toBe(200);
      expect((await Permission.findById(p._id)).status).toBe('inactive');
    });

    test('合法的父级调整不受影响（非祖先节点可正常挂载）', async () => {
      const root = await Permission.create({
        name: 'Root',
        code: `cycleroot:${rnd()}`,
        type: 'api',
        module: 'test',
      });
      const leaf = await Permission.create({
        name: 'Leaf',
        code: `cycleleaf:${rnd()}`,
        type: 'api',
        module: 'test',
      });
      const res = await request(app)
        .put(`/api/permissions/${leaf._id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ parent: String(root._id) });
      expect(res.status).toBe(200);
      const fresh = await Permission.findById(leaf._id);
      expect(String(fresh.parent)).toBe(String(root._id));
    });

    test('显式清空 parent 置为顶层（不被环路检测误伤）', async () => {
      const root = await Permission.create({
        name: 'R2',
        code: `cyclerr:${rnd()}`,
        type: 'api',
        module: 'test',
      });
      const child = await Permission.create({
        name: 'C2',
        code: `cyclecc:${rnd()}`,
        type: 'api',
        module: 'test',
        parent: root._id,
      });
      const res = await request(app)
        .put(`/api/permissions/${child._id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ parent: '' });
      expect(res.status).toBe(200);
      expect((await Permission.findById(child._id)).parent).toBeFalsy();
    });
  });
});
