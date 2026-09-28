/**
 * 被测对象：src/controllers/userController.js 的 applyProfileFields（PUT /api/users/:id 的 status 写入）
 * 守护的不变式：把账户恢复成可登录状态（status 变为 active 且原状态非 active）时，必须连
 *   **临时锁定**（lockUntil / failedLoginCount）一起清掉，与专用解锁接口
 *   services/authService 的 lockUser 同口径；反向不变式：普通编辑不得顺手重置爆破计数。
 * 可证伪性：批次 16 变异矩阵 MV1–MV6（实测于 2026-09-25，每条变异只改一处、跑完按 sha 写回）：
 *   MV1 删掉整段清零 / MV3 只清 lockUntil / MV4 只清计数 ⇒ 两个恢复用例同时红（各 2 红）；
 *   MV2 判据放宽成「status 被写过」⇒ 红「active→active 不重置计数」与
 *     「active→locked 不解除锁定」两条反向对照；MV6 判据只看新值不看旧值 ⇒ 只剩「不重置计数」红；
 *   MV5 无条件清零 ⇒ 三条反向对照全红（唯一能打死最后一个用例的变异）。
 * 既往审计边界：只覆盖 PUT 这一条写路径的 status 语义。锁定/解锁接口自身的清零由
 *   authService 既有用例覆盖；前端「被锁定账户显示成禁用」的呈现缺陷另见
 *   web-admin/src/tests/views/userView.test.js 的状态呈现一组。
 * 命名沿革：无（首版，2026-09-25）。
 */
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('用户更新接口把账户恢复回 active 时必须一并解除临时锁定', () => {
  let app;
  let User;
  let operatorToken;
  const stamp = `urs${Date.now().toString(36)}`;
  const PASSWORD = `Aa1!${stamp}Urs`;
  const ids = {};

  /** 未来 1 小时的临时锁定时间戳 */
  const lockUntilFuture = () => new Date(Date.now() + 3600 * 1000);

  const makeTarget = async (name, fields) => {
    const user = await User.create({
      username: `${stamp}${name}`,
      email: `${stamp}${name}@example.com`,
      password: PASSWORD,
      ...fields,
    });
    ids[name] = String(user._id);
    return user;
  };

  /** 读回内部安全态（这两个字段在响应投影里被排除，只能查库断言） */
  const readBack = async (name) => {
    const row = await User.findOne({ username: `${stamp}${name}` })
      .select('status lockUntil failedLoginCount')
      .lean();
    return {
      status: row.status,
      lockUntil: row.lockUntil === null || row.lockUntil === undefined ? null : row.lockUntil,
      failedLoginCount: row.failedLoginCount,
    };
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    const Role = require('../../models/Role');
    const Permission = require('../../models/Permission');

    // 按 code find-or-create（不删除）：user:lock 等是全局标准权限码，
    // 建了就删会让并发跑的其它套件瞬时拿不到权限
    const permIds = [];
    for (const code of ['user:read', 'user:update', 'user:lock']) {
      const perm = await Permission.findOneAndUpdate(
        { code },
        { $setOnInsert: { name: code, code, type: 'api', module: 'user' } },
        { upsert: true, new: true }
      );
      permIds.push(perm._id);
    }
    const role = await Role.create({
      name: `状态恢复操作者${stamp}`,
      code: `URS_OP_${stamp}`,
      // level 9 = LEVEL_ALL：数据范围取全量档，让本文件只测 status 语义、
      // 不与 assertRecordInScope 的部门/仅自己档纠缠（那一层由 zzqB_ 系列覆盖）
      level: 9,
      permissions: permIds,
    });
    const operator = await User.create({
      username: `${stamp}op`,
      email: `${stamp}op@example.com`,
      password: PASSWORD,
      roles: [role._id],
    });
    operatorToken = jwt.sign(
      { userId: String(operator._id), username: operator.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 目标账户：管理员锁定 + 尚未到期的临时锁定（先被爆破锁定、再被管理员锁定的形态）
    await makeTarget('locked', {
      status: 'locked',
      lockUntil: lockUntilFuture(),
      failedLoginCount: 5,
    });
    // 目标账户：被禁用且临时锁定仍在（禁用→启用同样要解除）
    await makeTarget('inactive', {
      status: 'inactive',
      lockUntil: lockUntilFuture(),
      failedLoginCount: 3,
    });
    // 对照账户：本来就 active，已攒了 3 次失败但还没到锁定阈值
    await makeTarget('active', { status: 'active', failedLoginCount: 3 });
    // 对照账户：active 且带临时锁定，本次写入是「锁定」而不是恢复
    await makeTarget('locking', { status: 'active', lockUntil: lockUntilFuture() });
    // 对照账户：被锁定，但本次只改备注类字段，没写 status
    await makeTarget('untouched', {
      status: 'locked',
      lockUntil: lockUntilFuture(),
      failedLoginCount: 4,
    });

    app = require('../../app').createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await require('../../models/Role')
        .deleteMany({ code: `URS_OP_${stamp}` })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  const put = (name, body) =>
    request(app)
      .put(`/api/users/${ids[name]}`)
      .set('Authorization', `Bearer ${operatorToken}`)
      .send(body);

  test('locked → active：接口 200 且临时锁定同时解除（否则"恢复了"是假话）', async () => {
    const before = await readBack('locked');
    expect(before.status).toBe('locked');
    expect(before.lockUntil).toBeTruthy();
    expect(before.failedLoginCount).toBe(5);

    const res = await put('locked', { status: 'active' });
    expect(res.status).toBe(200);

    const after = await readBack('locked');
    expect(after.status).toBe('active');
    expect(after.lockUntil).toBeNull();
    expect(after.failedLoginCount).toBe(0);
  });

  test('inactive → active：同样解除（禁用期间残留的临时锁定不能跟着账户一起复活）', async () => {
    const res = await put('inactive', { status: 'active' });
    expect(res.status).toBe(200);
    const after = await readBack('inactive');
    expect(after.status).toBe('active');
    expect(after.lockUntil).toBeNull();
    expect(after.failedLoginCount).toBe(0);
  });

  test('反向对照：active→active 的普通编辑不得重置爆破计数', async () => {
    const res = await put('active', { status: 'active', realName: '顺手改个名字' });
    expect(res.status).toBe(200);
    const after = await readBack('active');
    expect(after.failedLoginCount).toBe(3);
    expect(after.status).toBe('active');
  });

  test('反向对照：恢复方向之外的写 status（active→locked）不得解除已有临时锁定', async () => {
    const before = await readBack('locking');
    expect(before.lockUntil).toBeTruthy();

    const res = await put('locking', { status: 'locked' });
    expect(res.status).toBe(200);
    const after = await readBack('locking');
    expect(after.status).toBe('locked');
    expect(after.lockUntil).toBeTruthy();
  });

  test('反向对照：不写 status 的编辑（哪怕目标是 locked）一律不碰锁定态', async () => {
    const res = await put('untouched', { realName: '只改姓名' });
    expect(res.status).toBe(200);
    const after = await readBack('untouched');
    expect(after.status).toBe('locked');
    expect(after.lockUntil).toBeTruthy();
    expect(after.failedLoginCount).toBe(4);
  });
});
