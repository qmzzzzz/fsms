/**
 * 管理员重置口令（PUT /api/security/users/:userId/password/reset）的分闸用例。
 *
 * 既有套件只覆盖"重置成功"主干；校验失败 / 用户不存在 / 范围外 / 自身 / 同级或更高 /
 * 内置超管 / 哈希失败 / 落库异常 / 目标状态已变更 / roles 缺失 这十个分支从未被计数
 * （全量覆盖率 branches 87.71% < 门槛 91%）。这里直接驱动控制器，不发 HTTP。
 */
jest.mock('express-validator', () => {
  const state = { empty: true };
  const validationResult = () => ({
    isEmpty: () => state.empty,
    array: () => [{ msg: '重置理由不能为空', param: 'reason' }],
  });
  validationResult.__setEmpty = (v) => {
    state.empty = v;
  };
  return { validationResult };
});

const mongoose = require('mongoose');
const { validationResult } = require('express-validator');
const { resetUserPassword } = require('../../controllers/securityController/admin');
const { User } = require('../../controllers/securityController/shared');
const Role = require('../../models/Role');
const Permission = require('../../models/Permission');
const roleService = require('../../services/roleService');
const bcryptWorker = require('../../utils/bcryptWorkerPool');
const authService = require('../../services/authService');

const stamp = 'rp' + Date.now().toString(36);
const PASSWORD = 'Zq7!Wn4#Rt9$Yp2@Ks6&Lm8*Vc3^Bh5%Jf1Nx0Kd';

const mockRes = () => {
  const res = { locals: {} };
  res.set = jest.fn(() => res);
  res.status = jest.fn(() => res);
  res.json = jest.fn((body) => {
    res.body = body;
    return res;
  });
  return res;
};

const reqFor = (userId, user) => ({
  params: { userId },
  body: { reason: '账号救济' },
  user,
  ip: '127.0.0.1',
  headers: {},
  socket: { remoteAddress: '127.0.0.1' },
  get: () => undefined,
});

const operatorReq = () =>
  reqFor('', { userId: global.__rpOperatorId, username: global.__rpOperatorName });

const errorCodeOf = (res) => res.body && res.body.errors && res.body.errors.errorCode;

describe('管理员重置口令的分闸', () => {
  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
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
    let lowRole = await Role.findOne({ code: 'RP_LOW' + stamp });
    if (!lowRole) {
      lowRole = await Role.create({ name: '低层级', code: 'RP_LOW' + stamp, level: 2 });
    }
    let peerRole = await Role.findOne({ code: 'RP_PEER' + stamp });
    if (!peerRole) {
      peerRole = await Role.create({ name: '同级', code: 'RP_PEER' + stamp, level: 10 });
    }
    global.__rpOperator = await User.create({
      username: 'rpop' + stamp,
      email: 'rpop' + stamp + '@example.com',
      password: PASSWORD,
      roles: [superRole._id],
    });
    global.__rpOperatorId = String(global.__rpOperator._id);
    global.__rpOperatorName = global.__rpOperator.username;
    global.__rpLowRole = lowRole;
    global.__rpPeerRole = peerRole;
    global.__rpTarget = await User.create({
      username: 'rptarget' + stamp,
      email: 'rptarget' + stamp + '@example.com',
      password: PASSWORD,
      roles: [lowRole._id],
      createdBy: global.__rpOperator._id,
      department: '东区',
    });
    global.__rpPeer = await User.create({
      username: 'rppeer' + stamp,
      email: 'rppeer' + stamp + '@example.com',
      password: PASSWORD,
      roles: [peerRole._id],
      createdBy: global.__rpOperator._id,
    });
    global.__rpOther = await User.create({
      username: 'rpother' + stamp,
      email: 'rpother' + stamp + '@example.com',
      password: PASSWORD,
      createdBy: global.__rpOperator._id,
    });
  });

  afterAll(() => {
    delete global.__rpOperator;
    delete global.__rpOperatorId;
    delete global.__rpOperatorName;
    delete global.__rpLowRole;
    delete global.__rpPeerRole;
    delete global.__rpTarget;
    delete global.__rpPeer;
    delete global.__rpOther;
  });

  afterEach(() => {
    validationResult.__setEmpty(true);
    jest.restoreAllMocks();
  });

  test('校验失败：理由缺失回 VALIDATION_FAILED', async () => {
    validationResult.__setEmpty(false);
    const res = mockRes();
    await resetUserPassword(operatorReq(), res);
    expect(errorCodeOf(res)).toBe('VALIDATION_FAILED');
  });

  test('用户不存在：USER_NOT_FOUND', async () => {
    const res = mockRes();
    await resetUserPassword(reqFor(String(new mongoose.Types.ObjectId()), operatorReq().user), res);
    expect(errorCodeOf(res)).toBe('USER_NOT_FOUND');
  });

  test('范围外（操作者无数据范围）：USER_SCOPE_FORBIDDEN', async () => {
    const lowOp = await User.create({
      username: 'rplowop' + stamp,
      email: 'rplowop' + stamp + '@example.com',
      password: PASSWORD,
      roles: [global.__rpLowRole._id],
    });
    const res = mockRes();
    await resetUserPassword(
      reqFor(String(global.__rpTarget._id), {
        userId: String(lowOp._id),
        username: lowOp.username,
      }),
      res
    );
    expect(errorCodeOf(res)).toBe('USER_SCOPE_FORBIDDEN');
  });

  test('不能重置自己的口令', async () => {
    const res = mockRes();
    await resetUserPassword(reqFor(global.__rpOperatorId, operatorReq().user), res);
    expect(errorCodeOf(res)).toBe('CANNOT_RESET_OWN_PASSWORD_VIA_ADMIN');
  });

  test('同级或更高层级目标被拒', async () => {
    const res = mockRes();
    await resetUserPassword(reqFor(String(global.__rpPeer._id), operatorReq().user), res);
    expect(errorCodeOf(res)).toBe('PASSWORD_RESET_PEER_OR_HIGHER_FORBIDDEN');
  });

  test('内置超管目标被拒（层级闸放行后的第二道闸）', async () => {
    const spy = jest
      .spyOn(roleService, 'findRolesByIds')
      .mockResolvedValueOnce([
        { level: 2, code: 'SUPER_ADMIN', isBuiltIn: true, name: '超级管理员' },
      ]);
    const res = mockRes();
    await resetUserPassword(reqFor(String(global.__rpTarget._id), operatorReq().user), res);
    expect(spy).toHaveBeenCalled();
    expect(errorCodeOf(res)).toBe('CANNOT_RESET_PASSWORD_SUPER_ADMIN');
  });

  test('临时口令哈希失败：PASSWORD_RESET_FAILED，目标口令不变', async () => {
    const hashSpy = jest
      .spyOn(bcryptWorker, 'hash')
      .mockRejectedValueOnce(new Error('哈希线程崩溃'));
    const before = await User.findById(global.__rpTarget._id)
      .select('password tokenVersion')
      .lean();
    const res = mockRes();
    await resetUserPassword(reqFor(String(global.__rpTarget._id), operatorReq().user), res);
    expect(hashSpy).toHaveBeenCalled();
    expect(errorCodeOf(res)).toBe('PASSWORD_RESET_FAILED');
    const after = await User.findById(global.__rpTarget._id).select('password tokenVersion').lean();
    expect(String(after.password)).toBe(String(before.password));
    expect(after.tokenVersion).toBe(before.tokenVersion);
  });

  test('落库异常：PASSWORD_RESET_FAILED', async () => {
    jest.spyOn(User, 'findOneAndUpdate').mockRejectedValueOnce(new Error('落库超时'));
    const res = mockRes();
    await resetUserPassword(reqFor(String(global.__rpTarget._id), operatorReq().user), res);
    expect(errorCodeOf(res)).toBe('PASSWORD_RESET_FAILED');
  });

  test('条件更新未命中（目标状态已变更）：USER_STATE_CONFLICT，不产生新口令', async () => {
    jest.spyOn(User, 'findOneAndUpdate').mockResolvedValueOnce(null);
    const res = mockRes();
    await resetUserPassword(reqFor(String(global.__rpTarget._id), operatorReq().user), res);
    expect(errorCodeOf(res)).toBe('USER_STATE_CONFLICT');
  });

  test('roles 缺失（null）的目标仍可重置：空集层级放行，条件更新按空数组匹配', async () => {
    const noRoles = await User.create({
      username: 'rpnoroles' + stamp,
      email: 'rpnoroles' + stamp + '@example.com',
      password: PASSWORD,
      roles: [],
      createdBy: global.__rpOperator._id,
    });
    const realFindById = User.findById.bind(User);
    // 控制器链是 `User.findById(...).select('+password')`（审计二-2 要读旧口令摘要）⇒
    // mock 必须交出 **Query 形态**：直接 return document 会在 .select 处 TypeError。
    // 这里保留真 Query（投影照常生效），只把解析结果里的 roles 改成 null。
    const findByIdSpy = jest.spyOn(User, 'findById').mockImplementationOnce((id, ...rest) => {
      const query = realFindById(id, ...rest);
      const thenBound = query.then.bind(query);
      query.then = (onFulfilled, onRejected) =>
        thenBound((doc) => {
          if (doc) doc.roles = null;
          return onFulfilled ? onFulfilled(doc) : doc;
        }, onRejected);
      return query;
    });
    const res = mockRes();
    await resetUserPassword(reqFor(String(noRoles._id), operatorReq().user), res);
    expect(findByIdSpy).toHaveBeenCalled();
    expect(res.body.success).toBe(true);
    expect(res.body.data.temporaryPassword).toBeTruthy();
    const after = await User.findById(noRoles._id).select('mustChangePassword tokenVersion').lean();
    expect(after.mustChangePassword).toBe(true);
    expect(after.tokenVersion).toBe(1);
  });

  /**
   * 审计二-2 的落库侧：被替换掉的那一代口令必须以 bcrypt 摘要形态留在 passwordRetiredHash。
   * 判据取自**读回的真实文档**（不是 mock 断言）：摘要是旧口令的可校验副本，
   * 改密路径靠它挡住「重置后又把口令改回重置前那条」。
   */
  test('重置把被替换掉的口令写成退役摘要：读回后能校验旧口令、且不含新口径', async () => {
    const target = await User.create({
      username: 'rpretired' + stamp,
      email: 'rpretired' + stamp + '@example.com',
      password: PASSWORD,
      roles: [global.__rpLowRole._id],
      createdBy: global.__rpOperator._id,
      department: '东区',
    });
    const res = mockRes();
    await resetUserPassword(reqFor(String(target._id), operatorReq().user), res);
    expect(res.body.success).toBe(true);
    const temporaryPassword = res.body.data.temporaryPassword;
    expect(typeof temporaryPassword).toBe('string');

    const after = await User.findById(target._id)
      .select('+password +passwordRetiredHash +passwordHistory')
      .lean();
    // select:false 字段：不显式取就恒 undefined（接线漏了这条，退役摘要会静默失效）
    expect(after.passwordRetiredHash).toMatch(/^\$2[aby]\$/);
    expect(await bcryptWorker.compare(PASSWORD, after.passwordRetiredHash)).toBe(true);
    // 退役摘要记的是**旧**口令；新签发的临时口令不得落进去
    expect(await bcryptWorker.compare(temporaryPassword, after.passwordRetiredHash)).toBe(false);
    // 复用历史（HMAC 摘要集）在这条路径上保持原样：重置不掌握旧口令明文，写不进历史
    expect(after.passwordHistory).toEqual([]);
  }, 60000);

  /**
   * 审计二-2 的闭环：重置后用**重置前那条口令**改密必须被拒（否则已泄露的旧口令会被
   * 用户自己改回来），换一条全新口令则通过，且退役摘要不因这次成功改密而消失。
   */
  test('重置后不能把口令改回重置前那条（PASSWORD_REUSED），全新口令放行', async () => {
    const target = await User.create({
      username: 'rpreuse' + stamp,
      email: 'rpreuse' + stamp + '@example.com',
      password: PASSWORD,
      roles: [global.__rpLowRole._id],
      createdBy: global.__rpOperator._id,
      department: '东区',
    });
    const res = mockRes();
    await resetUserPassword(reqFor(String(target._id), operatorReq().user), res);
    expect(res.body.success).toBe(true);
    const temporaryPassword = res.body.data.temporaryPassword;
    const change = (currentPassword, newPassword) =>
      authService.changeUserPassword(
        String(target._id),
        { currentPassword, newPassword, confirmPassword: newPassword },
        { username: target.username }
      );

    const revert = await change(temporaryPassword, PASSWORD);
    expect(revert.outcome).toBe('PASSWORD_REUSED');

    const freshPassword = 'N3w-' + PASSWORD;
    const fresh = await change(temporaryPassword, freshPassword);
    expect(fresh.outcome).toBe('OK');
    // 强制改密标记：本次是「管理员重置后的首改」
    expect(fresh.forced).toBe(true);

    const after = await User.findById(target._id)
      .select('+passwordRetiredHash +passwordHistory')
      .lean();
    expect(await bcryptWorker.compare(PASSWORD, after.passwordRetiredHash)).toBe(true);
    expect(after.passwordHistory.length).toBeGreaterThanOrEqual(1);

    // 第二次仍不得改回重置前那条：退役摘要不随一次成功改密被清掉
    const again = await change(freshPassword, PASSWORD);
    expect(again.outcome).toBe('PASSWORD_REUSED');
  }, 120000);

  /**
   * 审计二-2 的边界：**连续两次重置**（用户还没用上第一份临时口令就再重置一次，运维上很常见——
   * 临时口令没送达 / 过期）。第二次重置替换掉的只是管理员签发的临时口令，若把退役摘要换成它，
   * 真正要防的那一代（用户自选口令）就重新变得可设回，且本项的保护会**静默**失效。
   */
  test('连续重置：未被消费的临时口令那一代不覆盖退役摘要，最初口令仍被拒', async () => {
    const target = await User.create({
      username: 'rpagain' + stamp,
      email: 'rpagain' + stamp + '@example.com',
      password: PASSWORD,
      roles: [global.__rpLowRole._id],
      createdBy: global.__rpOperator._id,
      department: '东区',
    });
    const first = mockRes();
    await resetUserPassword(reqFor(String(target._id), operatorReq().user), first);
    const firstTemporary = first.body.data.temporaryPassword;
    const second = mockRes();
    await resetUserPassword(reqFor(String(target._id), operatorReq().user), second);
    const secondTemporary = second.body.data.temporaryPassword;
    expect(secondTemporary).not.toBe(firstTemporary);

    const after = await User.findById(target._id).select('+passwordRetiredHash').lean();
    // 退役摘要仍是用户自选的那一代（第一次重置写的），没有被临时口令顶掉
    expect(await bcryptWorker.compare(PASSWORD, after.passwordRetiredHash)).toBe(true);
    expect(await bcryptWorker.compare(firstTemporary, after.passwordRetiredHash)).toBe(false);

    const revert = await authService.changeUserPassword(
      String(target._id),
      { currentPassword: secondTemporary, newPassword: PASSWORD, confirmPassword: PASSWORD },
      { username: target.username }
    );
    expect(revert.outcome).toBe('PASSWORD_REUSED');
  }, 120000);

  /**
   * 已声明的残留（ADR-016 备选方案 D）：覆盖范围只有**一代**。本条不是「期望的安全行为」，
   * 而是把边界钉死——用户成功改密后 mustChangePassword 被清掉，再重置一次时退役摘要就被
   * 新一代顶掉，最初那代不再被拦。没有这条判据，上面三条只证明了「保护在」，
   * 谁也无法从测试里读出「保护到哪为止」，残留在文档里会慢慢被当成「已经全覆盖」。
   */
  test('已声明残留：改密后再重置会顶掉上一代摘要（覆盖只有一代，不是全覆盖）', async () => {
    const target = await User.create({
      username: 'rpgeneration' + stamp,
      email: 'rpgeneration' + stamp + '@example.com',
      password: PASSWORD,
      roles: [global.__rpLowRole._id],
      createdBy: global.__rpOperator._id,
      department: '东区',
    });
    const first = mockRes();
    await resetUserPassword(reqFor(String(target._id), operatorReq().user), first);
    const firstTemporary = first.body.data.temporaryPassword;
    const chosen = 'N3w-' + PASSWORD;
    const change = (currentPassword, newPassword) =>
      authService.changeUserPassword(
        String(target._id),
        { currentPassword, newPassword, confirmPassword: newPassword },
        { username: target.username }
      );
    expect((await change(firstTemporary, chosen)).outcome).toBe('OK');

    // 改密已清掉 mustChangePassword ⇒ 第二次重置把「用户自选的那一代」从最初口令换成 chosen
    const second = mockRes();
    await resetUserPassword(reqFor(String(target._id), operatorReq().user), second);
    const secondTemporary = second.body.data.temporaryPassword;
    const after = await User.findById(target._id).select('+passwordRetiredHash').lean();
    expect(await bcryptWorker.compare(chosen, after.passwordRetiredHash)).toBe(true);
    expect(await bcryptWorker.compare(PASSWORD, after.passwordRetiredHash)).toBe(false);
    // 残留坐实：最初那代（PASSWORD）不再被拦，因为它已不在覆盖窗口内
    expect((await change(secondTemporary, PASSWORD)).outcome).toBe('OK');
  }, 120000);
});

// 套件级收尾：本文件连了 mongoose，必须在最后一条 root 级 afterAll 里关掉
// （判据见 src/tests/ci/mongooseTeardownLedger.test.js；关在非最后一段里会被判违规）。
afterAll(async () => {
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
