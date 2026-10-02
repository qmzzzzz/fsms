/**
 * 用户管理读路径不得下发手机号明文（2026-10-02 审计落地）
 *
 * 缺陷形状：`User.phone` 的 schema getter 会**透明解密**（models/User.js 的 phone 声明），
 * 而对外响应投影 `RESPONSE_EXCLUDE` 当初只排了凭证与内部安全状态，**没排 phone**。
 * 于是 `GET /api/users` 一次请求就把整个可见域的完整手机号交给任何持 `user:read` 的账号：
 * 无二次验证、无 `system:read`、不写 `view_sensitive_data` 审计——仓里专门为此建的合规通道
 * （POST /api/security/view-sensitive：reauthLimiter + requireReAuthentication +
 * 严格更高级别 + 审计写失败即不发明文）被这个默认值整个架空。Alarm 域的同型缺陷
 * （handler.phone / reporter.phone）已分别由 alarmDetailHandlerPii、alarmReporterPhoneEgress 收口。
 *
 * 修法是"默认排除 + 唯一变体 + 当场脱敏"三层：
 *   RESPONSE_EXCLUDE 含 `-phone`（新增用户读路径默认拿不到明文）；
 *   管理员表格要显示脱敏号码，只能取 RESPONSE_EXCLUDE_PHONE_VISIBLE，
 *   且取到后必须过 toMaskedAdminUser —— 明文进、`phoneMasked` 出，`phone` 键被删。
 *
 * 为什么把字段**改名**成 phoneMasked 而不是沿用 my-info 的 `phone: 脱敏值`：
 * 用户列表的值会回填编辑表单，展示值占住可写字段的槽位就只有两条必坏的路——
 * 原样提交会撞上 userRoutes.js:110 的 /^1[3-9]\d{9}$/（400），
 * 而那条校验是 `.optional({ values:'falsy' })`，空串能过、控制器 `if (phone !== undefined)`
 * 会把它写进库（一次"没动手机号"的保存把号码清空）。下面「边界自证」那条用例把这两条
 * 边界钉住：不下发字段 ≠ 清空，下发脱敏串 ≠ 可提交。
 *
 * 变异实测见 CHANGELOG。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const OP_PHONE = '13711112222';
const TARGET_PHONE = '13900001122';
const NEW_PHONE = '13655556666';
const MASK_TARGET = '139****1122';
const MASK_NEW = '136****6666';
const MASK_OP = '137****2222';

describe('用户管理读路径的手机号口径', () => {
  let app;
  let User;
  let operator;
  let target;
  let lowRoleId;
  let operatorToken;
  const stamp = `upm${Date.now().toString(36)}`;
  const password = `Aa1!${stamp}Test`;
  const opName = `upmop${stamp}`;
  const tgName = `upmtg${stamp}`;
  const newName = `upmnew${stamp}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');

    const wildcard = await Permission.create({
      name: '全部权限',
      code: '*:*',
      type: 'api',
      module: 'system',
    });
    const superRole = await Role.create({
      name: '超级管理员',
      code: `UPM_ROLE_${stamp}`,
      level: 10,
      isBuiltIn: true,
      permissions: [wildcard._id],
    });
    // 分配角色那条出口需要一个"可比自己低"的角色：路由要求 roles 至少 1 项
    // （userRoutes.js:131 的 isArray({min:1})），空数组会先撞 400 而走不到回显。
    const lowRole = await Role.create({
      name: '只读观察员',
      code: `UPM_LOW_${stamp}`,
      level: 1,
      permissions: [],
    });
    operator = await User.create({
      username: opName,
      email: `${opName}@example.com`,
      password,
      phone: OP_PHONE,
      roles: [superRole._id],
    });
    target = await User.create({
      username: tgName,
      email: `${tgName}@example.com`,
      password,
      realName: '被管对象甲',
      phone: TARGET_PHONE,
      department: `UPM_DEPT_${stamp}`,
      roles: [],
    });

    operatorToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    lowRoleId = String(lowRole._id);
    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState === 0) return;
    // 前缀含本运行的唯一 stamp，不会碰其它用例的数据
    await User.deleteMany({ username: new RegExp(`^upm(op|tg|new)${stamp}$`) }).catch(() => {});
    await require('../../models/Role')
      .deleteMany({ code: { $in: [`UPM_ROLE_${stamp}`, `UPM_LOW_${stamp}`] } })
      .catch(() => {});
    await require('../../models/Permission')
      .deleteMany({ code: '*:*' })
      .catch(() => {});
    await mongoose.connection.close();
  });

  const authed = (method, url) =>
    request(app)[method](url).set('Authorization', `Bearer ${operatorToken}`);

  // 一条通用判据：`phone` 这个键不存在、`phoneMasked` 是期望的脱敏形态、
  // 序列化后的响应体不含指定明文。三条各有各的用处——只判"不含明文"的话，
  // 把字段整个删掉也能通过，而表格要显示脱敏号码是这次改动的功能的一半。
  // 数组写法是为了失败时能一眼看出是哪条用例、哪个字段。
  const expectMaskedShape = (payload, label, { plain, masked }) => {
    expect([label, 'phone' in payload]).toEqual([label, false]);
    expect([label, payload.phoneMasked]).toEqual([label, masked]);
    expect(JSON.stringify(payload)).not.toContain(plain);
  };

  test('夹具自证：明文确实进了库，且不带投影的读法确实会把明文交出去', async () => {
    // 这是"对侧"证据。没有它，下面的 not.toContain 可能只是因为
    // 手机号压根没写进去，或 getter 根本没解密。
    const stored = await User.collection.findOne({ _id: target._id });
    expect(String(stored.phone)).toMatch(/^enc\./); // at-rest 是密文
    const raw = await User.findById(target._id); // 无投影：正是缺陷的读法
    expect(raw.phone).toBe(TARGET_PHONE); // getter 透明解密
    expect(JSON.stringify(raw.toJSON())).toContain(TARGET_PHONE);
  });

  test('两条响应投影只相差 -phone 一项（变体必须由同一张字段表派生）', () => {
    const excluded = User.RESPONSE_EXCLUDE.split(' ');
    const visible = User.RESPONSE_EXCLUDE_PHONE_VISIBLE.split(' ');
    expect(excluded).toContain('-phone'); // 默认不许外泄
    // 手写第二张清单（而不是派生）会在清单演化时静默漏掉某一项
    expect(excluded.filter((field) => !visible.includes(field))).toEqual(['-phone']);
  });

  test('列表：每行只有 phoneMasked，整个响应体不含明文', async () => {
    const res = await authed('get', `/api/users?search=${stamp}&limit=50`);
    expect(res.status).toBe(200);
    const row = res.body.data.find((u) => u.username === tgName);
    expect(row).toBeTruthy();
    expectMaskedShape(row, '列表行', { plain: TARGET_PHONE, masked: MASK_TARGET });
    expect(JSON.stringify(res.body)).not.toContain(TARGET_PHONE);
  });

  test('详情：与列表同口径（只修列表等于给按 ID 的读路径留旁路）', async () => {
    const res = await authed('get', `/api/users/${target._id}`);
    expect(res.status).toBe(200);
    expectMaskedShape(res.body.data, '详情', { plain: TARGET_PHONE, masked: MASK_TARGET });
  });

  test('建号回显：提交进去的明文不会原样回到响应里，写入仍接受明文', async () => {
    const res = await authed('post', '/api/users').send({
      username: newName,
      email: `${newName}@example.com`,
      password: `Aa1!${stamp}New`,
      realName: '新建对象',
      phone: NEW_PHONE,
      department: '',
    });
    expect(res.status).toBe(201);
    expectMaskedShape(res.body.data, '建号回显', { plain: NEW_PHONE, masked: MASK_NEW });
    const stored = await User.collection.findOne({ username: newName });
    expect(String(stored.phone)).toMatch(/^enc\./);
  });

  test('改号与角色分配回显：另外两条出口同样只给脱敏值', async () => {
    const put = await authed('put', `/api/users/${target._id}`).send({ phone: NEW_PHONE });
    expect(put.status).toBe(200);
    expectMaskedShape(put.body.data, '改号回显', { plain: NEW_PHONE, masked: MASK_NEW });

    const roles = await authed('put', `/api/users/${target._id}/roles`).send({
      roles: [lowRoleId],
    });
    expect(roles.status).toBe(200);
    expectMaskedShape(roles.body.data, '角色回显', { plain: NEW_PHONE, masked: MASK_NEW });
    // 按 _id 比对：Role.code 有入库前大写化的 setter，比字符串容易看错口径
    expect(roles.body.data.roles.map((r) => String(r._id))).toEqual([lowRoleId]);
  });

  test('边界自证：省略 phone 不等于清空，提交脱敏串一定被拒且不落库', async () => {
    // 前端"脏字段才提交"的全部理由压在这两条判据上：
    // 省略键 = 保持原值；把列表里的展示值当可写值提交 = 被路由正则拒掉。
    const untouched = await authed('put', `/api/users/${target._id}`).send({
      realName: '被管对象乙',
    });
    expect(untouched.status).toBe(200);
    expect((await User.findById(target._id)).phone).toBe(NEW_PHONE); // 上一用例写入的值还在

    const masked = await authed('put', `/api/users/${target._id}`).send({ phone: MASK_TARGET });
    expect(masked.status).toBe(400);
    // 400 必须发生在写入之前：否则"拒掉"与"写坏再报错"在响应上看不出区别
    expect((await User.findById(target._id)).phone).toBe(NEW_PHONE);
  });

  test('合规通道仍然可用：本人 + 口令复检拿得到明文（收窄没有关掉出口）', async () => {
    const res = await authed('post', '/api/security/view-sensitive').send({
      dataType: 'phone',
      currentPassword: password,
    });
    expect(res.status).toBe(200);
    expect([res.body.data.type, res.body.data.masked, res.body.data.full]).toEqual([
      'phone',
      MASK_OP,
      OP_PHONE,
    ]);
  });

  test('边界自证：/auth/me 是本人资料回填，明文保留是刻意的例外', async () => {
    // 这一条不是"漏网"：该响应直接回填个人资料编辑表单
    // （utils/permissionHelper.js 的 user 对象注释写明：给它脱敏值会写坏库或卡死保存）。
    // 把它钉成"必须含明文"，是为了让将来任何"顺手统一口径"的改动先撞上一条红用例，
    // 而不是静默把 ProfileView 的手机号变成不可编辑的星号。
    const res = await authed('get', '/api/auth/me');
    expect(res.status).toBe(200);
    expect(res.body.data.user.phone).toBe(OP_PHONE);
  });

  test('源码文本闸：取明文的投影与脱敏函数必须成对出现', () => {
    // 判据落在源码而非只有一次运行结果：将来新增一条用户读路径、用了
    // RESPONSE_EXCLUDE_PHONE_VISIBLE 却忘记过 toMaskedAdminUser，上面所有用例
    // 都可能依旧全绿（它们各自只覆盖已知的那几条路径），这条不会。
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(
      path.join(__dirname, '..', '..', 'services', 'userService.js'),
      'utf8'
    );
    const sites = [...src.matchAll(/RESPONSE_EXCLUDE_PHONE_VISIBLE/g)];
    expect(sites.length).toBeGreaterThanOrEqual(4);
    const starts = sites.map((m) => m.index);
    const chunks = starts.map((s, i) =>
      src.slice(s, i + 1 < starts.length ? starts[i + 1] : s + 700)
    );
    expect(chunks.filter((chunk) => !chunk.includes('toMaskedAdminUser'))).toEqual([]);
    // 脱敏函数自身：明文键必须被删掉——"打了码"和"没下发"是两回事
    expect(src).toMatch(/delete obj\.phone;/);
  });
});
