/**
 * 临时权限授予（C-08）与双人复核（C-09）行为测试
 *
 * 钉住四条不变量：到期即失效（读侧判据）、高敏授予需两名不同审批人、
 * 申请人不得自审、审批人须自行持有拟授予的权限。
 * 权限码一律小写：Permission.code 有 lowercase 归一化，夹具写大写在库里查不到。
 *
 * 2026-10-30（A1/A2/A3 修复批次）追加的判据一律写成「旧实现必红」的形态，
 * 每条都能在修复前的代码上复现出红：
 *  · A1 并发签批用 Promise.all 真打服务层。旧实现是「findById → 内存副本上 push →
 *    save()」，判定值取自陈旧副本：同一审批人并发 6 次会有多条签批落库、两人各签一次
 *    后状态仍停在 pending（已批准的权限静默不生效）；
 *  · A2 保留通配 `*:*` 可经本通道申请，且 `moduleOf('*:*')==='*'` 取不到模块 ⇒ 判成非高敏、
 *    只需 1 名审批人（比 user:read 的双人复核更宽）；
 *  · A3 授予到期后缓存命中不再判 expiresAt ⇒ TTL（30 秒）内仍放行。
 */

const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

// 低敏业务模块（目录已登记）：A2 起「未登记的模块前缀」一律按高敏，普通码必须落在已登记模块里
const CODE_NORMAL = 'report:zzpriv_probe';
const CODE_HIGH = 'user:update';
const CODE_GRANT = 'privilege:grant';
const CODE_APPROVE = 'privilege:approve';

describe('临时权限授予流程', () => {
  let User;
  let Permission;
  let Role;
  let PrivilegeGrant;
  let grantService;
  let permissionService;
  let reviewService;
  let requester;
  let approverA;
  let approverB;
  let weakApprover;
  let target;

  const operator = (user) => ({ userId: String(user._id), username: user.username });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    Permission = require('../../models/Permission');
    Role = require('../../models/Role');
    PrivilegeGrant = require('../../models/PrivilegeGrant');
    require('../../models/UserSession');
    grantService = require('../../services/privilegeGrantService');
    permissionService = require('../../services/userPermissionService');
    reviewService = require('../../services/accessReviewService');

    const [permNormal, permHigh, permGrant, permApprove] = await Permission.create([
      { name: '临时只读', code: CODE_NORMAL, type: 'api', module: 'report' },
      { name: '改用户', code: CODE_HIGH, type: 'api', module: 'user' },
      { name: '授予临时权限', code: CODE_GRANT, type: 'api', module: 'privilege' },
      { name: '审批临时权限', code: CODE_APPROVE, type: 'api', module: 'privilege' },
    ]);

    const requesterRole = await Role.create({
      name: 'ZZPRIV 申请者',
      code: 'ZZPRIV_REQUESTER',
      permissions: [permGrant._id, permNormal._id, permHigh._id],
    });
    const approverRole = await Role.create({
      name: 'ZZPRIV 审批者',
      code: 'ZZPRIV_APPROVER',
      permissions: [permApprove._id, permNormal._id, permHigh._id],
    });
    const plainRole = await Role.create({
      name: 'ZZPRIV 无权限',
      code: 'ZZPRIV_PLAIN',
      permissions: [],
    });
    const weakRole = await Role.create({
      name: 'ZZPRIV 仅审批权',
      code: 'ZZPRIV_WEAK',
      permissions: [permApprove._id],
    });

    const make = (username, role) =>
      User.create({
        username,
        email: username + '@zzpriv.test',
        password: 'Zzpriv#2026Aa1',
        realName: username,
        department: 'ZZPRIV',
        roles: [role._id],
      });

    requester = await make('zzpriv_requester', requesterRole);
    approverA = await make('zzpriv_approver_a', approverRole);
    approverB = await make('zzpriv_approver_b', approverRole);
    weakApprover = await make('zzpriv_weak', weakRole);
    target = await make('zzpriv_target', plainRole);
  });

  afterAll(async () => {
    await Promise.all([
      PrivilegeGrant.deleteMany({}),
      User.deleteMany({ username: /^zzpriv_/ }),
      Role.deleteMany({ code: /^ZZPRIV_/ }),
      Permission.deleteMany({ code: { $in: [CODE_NORMAL, CODE_HIGH, CODE_GRANT, CODE_APPROVE] } }),
    ]);
    // 与其它套件共用同一个内存 Mongo：只有本套件建立的连接才关。不关会留下 2 个
    // hasRef()===true 的 Socket，jest-worker 在最后一个文件后强杀 worker 并吞掉输出。
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  /**
   * 每个用例自带前置（不是给用例排序）：PrivilegeGrant 在共享内存库里是同一集合，
   * 进程内权限缓存又按用户常驻 30 秒。--randomize 打乱文件内顺序后，前序用例留下的
   * active 授予/缓存条目会被下一条读到（seed=1..4 实测 :123 收到 report:zzpriv_probe，:223/:401/:554 同因）。
   */
  beforeEach(async () => {
    // 只清本套件的夹具（target 用户名前缀），不用 deleteMany({})：并行跑时同库其它套件的授予不是本套件的数据
    await PrivilegeGrant.deleteMany({ username: /^zzpriv_/ });
    for (const user of [requester, approverA, approverB, weakApprover, target]) {
      if (user) permissionService.invalidatePermissionCache(String(user._id));
    }
  });

  test('普通权限单审即生效，到期后读侧立即失效', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '季度报表支持',
      durationHours: 2,
      operator: operator(requester),
    });
    expect(grant.status).toBe('pending');
    expect(grant.requiredApprovals).toBe(1);
    expect(grant.expiresAt).toBeNull();

    const pendingCodes = await grantService.activeCodesForUsers([String(target._id)]);
    expect(pendingCodes.get(String(target._id))).toEqual([]);

    const approved = await grantService.approveGrant({
      grantId: grant._id,
      operator: operator(approverA),
    });
    expect(approved.status).toBe('active');
    expect(approved.expiresAt).toBeInstanceOf(Date);

    const activeCodes = await grantService.activeCodesForUsers([String(target._id)]);
    expect(activeCodes.get(String(target._id))).toContain(CODE_NORMAL);

    const merged = await permissionService.getPermissions(String(target._id));
    expect(merged).toContain(CODE_NORMAL);

    const expiredCount = await grantService.expireDue(new Date(Date.now() + 3 * 3600 * 1000));
    expect(expiredCount).toBeGreaterThanOrEqual(1);

    const afterExpiry = await grantService.activeCodesForUsers([String(target._id)]);
    expect(afterExpiry.get(String(target._id))).not.toContain(CODE_NORMAL);
    expect((await PrivilegeGrant.findById(grant._id)).status).toBe('expired');
  });

  test('高敏权限需两名不同审批人，一人签批仍处于待审批', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_HIGH],
      reason: '账号信息纠错',
      durationHours: 4,
      operator: operator(requester),
    });
    expect(grant.highRisk).toBe(true);
    expect(grant.requiredApprovals).toBe(2);

    const first = await grantService.approveGrant({
      grantId: grant._id,
      operator: operator(approverA),
    });
    expect(first.status).toBe('pending');
    expect(first.approvals).toHaveLength(1);

    await expect(
      grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_PENDING' });

    const second = await grantService.approveGrant({
      grantId: grant._id,
      operator: operator(approverB),
    });
    expect(second.status).toBe('active');
    expect(second.approvals).toHaveLength(2);
  });

  test('申请人不得审批自己的申请', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '自审阻断验证',
      durationHours: 1,
      operator: operator(requester),
    });
    await expect(
      grantService.approveGrant({ grantId: grant._id, operator: operator(requester) })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_SELF_APPROVAL_FORBIDDEN' });
  });

  test('审批人未持有拟授予的权限时被拒绝', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_HIGH],
      reason: '审批人权限不足验证',
      durationHours: 1,
      operator: operator(requester),
    });
    await expect(
      grantService.approveGrant({ grantId: grant._id, operator: operator(weakApprover) })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_APPROVAL_FORBIDDEN' });
  });

  test('撤销生效中的授予后权限码立即不再出现', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '撤销流程验证',
      durationHours: 8,
      operator: operator(requester),
    });
    await grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) });
    expect(
      (await grantService.activeCodesForUsers([String(target._id)])).get(String(target._id))
    ).toContain(CODE_NORMAL);

    const revoked = await grantService.revokeGrant({
      grantId: grant._id,
      operator: operator(requester),
      reason: '任务提前结束',
    });
    expect(revoked.status).toBe('revoked');
    expect(
      (await grantService.activeCodesForUsers([String(target._id)])).get(String(target._id))
    ).not.toContain(CODE_NORMAL);
    expect(await permissionService.getPermissions(String(target._id))).not.toContain(CODE_NORMAL);
  });

  test('有效期越界与目录外的权限码一律拒绝', async () => {
    await expect(
      grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '越界有效期',
        durationHours: 999,
        operator: operator(requester),
      })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_DURATION_INVALID' });

    await expect(
      grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: ['zzpriv:not-in-catalog'],
        reason: '目录外权限码',
        durationHours: 2,
        operator: operator(requester),
      })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_CODE_INVALID' });
  });

  test('复核汇总统计生效、即将到期与超期未复核', async () => {
    const summary = await reviewService.reviewSummary({});
    expect(summary.active).toBeGreaterThanOrEqual(0);
    expect(summary.overdue).toBeGreaterThanOrEqual(0);
    expect(summary.asOf).toBeInstanceOf(Date);

    const overdueWithZeroWindow = await reviewService.reviewSummary({ overdueDays: 0 });
    expect(overdueWithZeroWindow.overdue).toBeGreaterThanOrEqual(summary.overdue);
  });

  test('A1 并发签批：同一审批人并发 6 次只留 1 条签批记录', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_HIGH],
      reason: '并发重复签批簿记验证',
      durationHours: 2,
      operator: operator(requester),
    });
    expect(grant.requiredApprovals).toBe(2);

    const results = await Promise.allSettled(
      Array.from({ length: 6 }, () =>
        grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
      )
    );

    const stored = await PrivilegeGrant.findById(grant._id).lean();
    // 职责分离的取数基础：approvals 里同一审批人只能有一条，长度才等于「批过的人数」
    expect(
      stored.approvals.filter((item) => String(item.by) === String(approverA._id))
    ).toHaveLength(1);
    expect(stored.approvals).toHaveLength(1);
    expect(stored.status).toBe('pending');
    // 另外 5 次必须被拒（旧实现 6 次全部返回成功，库里留下 6 条同人签批）
    expect(results.filter((item) => item.status === 'fulfilled')).toHaveLength(1);
    expect(
      results.filter((item) => item.status === 'rejected').map((item) => item.reason.code)
    ).toEqual(Array(5).fill('PRIVILEGE_GRANT_NOT_PENDING'));
  });

  test('A1 并发签批：两名审批人达阈值后必定推进 active 并写入 expiresAt', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_HIGH],
      reason: '并发达阈值推进验证',
      durationHours: 2,
      operator: operator(requester),
    });

    const results = await Promise.allSettled([
      grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) }),
      grantService.approveGrant({ grantId: grant._id, operator: operator(approverB) }),
    ]);

    const stored = await PrivilegeGrant.findById(grant._id).lean();
    expect(stored.status).toBe('active');
    expect(stored.expiresAt).toBeInstanceOf(Date);
    expect(stored.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(stored.approvals).toHaveLength(2);
    expect(new Set(stored.approvals.map((item) => String(item.by))).size).toBe(2);
    // 「接口成功但授予没生效」的反面：库内已生效 ⇒ 权限集合里立刻出现该码
    const effective = (await grantService.activeCodesForUsers([String(target._id)])).get(
      String(target._id)
    );
    expect(effective).toContain(CODE_HIGH);
    // 阈值已满的那一方必须看到 active，不允许两边都报 pending 而库内也没推进
    expect(
      results.some((item) => item.status === 'fulfilled' && item.value.status === 'active')
    ).toBe(true);
  });

  test('A2 保留通配不可申请，且未被识别的模块前缀一律按高敏', async () => {
    const { RESERVED_WILDCARD_PERMISSION } = require('../../utils/superAdmin');
    const { approvalPolicyOf, KNOWN_MODULES } = require('../../constants/privilegeGrant');

    // 目录里本来就登记着这条权限（initData 的「全部权限」）：拒绝必须来自「保留」规则本身，
    // 而不是「目录里查不到」。upsert 而非 create：别的套件可能已建过（同一内存 Mongo 共用库）。
    await Permission.updateOne(
      { code: RESERVED_WILDCARD_PERMISSION },
      {
        $setOnInsert: {
          name: '全部权限',
          code: RESERVED_WILDCARD_PERMISSION,
          type: 'api',
          module: 'system',
          status: 'active',
        },
      },
      { upsert: true }
    );

    await expect(
      grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [RESERVED_WILDCARD_PERMISSION],
        reason: '通配权限申请阻断验证',
        durationHours: 2,
        operator: operator(requester),
      })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_CODE_INVALID' });

    // 判定侧 fail-closed：通配（moduleOf 取到 '*'）与未登记模块都算高敏，
    // 只有目录登记过的低敏模块才是单人签批
    expect(approvalPolicyOf([RESERVED_WILDCARD_PERMISSION])).toEqual({
      highRisk: true,
      requiredApprovals: 2,
    });
    expect(approvalPolicyOf(['zzunregistered:read'])).toEqual({
      highRisk: true,
      requiredApprovals: 2,
    });
    expect(approvalPolicyOf(['zzunregistered'])).toEqual({ highRisk: true, requiredApprovals: 2 });
    expect(approvalPolicyOf([CODE_NORMAL])).toEqual({ highRisk: false, requiredApprovals: 1 });
    expect(approvalPolicyOf([CODE_HIGH])).toEqual({ highRisk: true, requiredApprovals: 2 });

    // 已知模块清单必须覆盖播种目录里的每一个模块：新增模块不同批登记 ⇒ 此处红
    const { defaultPermissions } = require('../../services/initData/permissions');
    const catalogModules = [...new Set(defaultPermissions.map((item) => item.module))];
    expect(catalogModules.filter((mod) => !KNOWN_MODULES.includes(mod))).toEqual([]);
  });

  test('A3 授予到期后权限码 0ms 内不再出现：缓存 TTL 收敛到最近到期时刻', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '缓存窗口收敛验证',
      durationHours: 1,
      operator: operator(requester),
    });
    await grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) });

    const t0 = Date.now();
    // 只把到期时刻改到 60 秒后，好把窗口压进用例时长（不改任何业务字段，也不改状态）
    await PrivilegeGrant.updateOne(
      { _id: grant._id },
      { $set: { expiresAt: new Date(t0 + 60 * 1000) } }
    );
    permissionService.invalidatePermissionCacheLocal();

    const permsAt = async (offsetMs) => {
      const spy = jest.spyOn(Date, 'now').mockReturnValue(t0 + offsetMs);
      try {
        return await permissionService.getPermissions(String(target._id));
      } finally {
        spy.mockRestore();
      }
    };

    expect(await permsAt(0)).toContain(CODE_NORMAL);
    // 到期前 1 秒仍生效（这条也钉住「不能为了收敛而把还在生效期的授予提前掐掉」）
    expect(await permsAt(59 * 1000)).toContain(CODE_NORMAL);
    // 到期后 1 毫秒：读侧立刻不可见。旧实现此处命中 30 秒缓存条目，仍返回该码
    expect(await permsAt(60 * 1000 + 1)).not.toContain(CODE_NORMAL);
    // 直读库同拍为证：不是读侧把还在生效的授予丢了，而是它确实已过期
    const dbCodes = await grantService.activeCodesForUsers(
      [String(target._id)],
      new Date(t0 + 60 * 1000 + 1)
    );
    expect(dbCodes.get(String(target._id))).not.toContain(CODE_NORMAL);

    permissionService.invalidatePermissionCacheLocal();
  });

  test('A1 条件更新未命中时不得回成功：断言都通过也必须抛错（旧实现按内存副本计数，报成功但库里没签批）', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '回退分支 fail-open 验证',
      durationHours: 2,
      operator: operator(requester),
    });
    expect(grant.requiredApprovals).toBe(1);

    // 复现「条件更新没命中」：库里仍是 pending、申请人与签批人都合法，但本次 $push 一行都没写进去
    const spy = jest.spyOn(PrivilegeGrant, 'findOneAndUpdate').mockResolvedValueOnce(null);
    try {
      await expect(
        grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
      ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_PENDING', statusCode: 409 });
    } finally {
      spy.mockRestore();
    }

    const stored = await PrivilegeGrant.findById(grant._id).lean();
    expect(stored.approvals).toHaveLength(0);
    expect(stored.status).toBe('pending');
  });

  test('A1 存量同人重复签批不得凑阈值：条件更新拒绝命中并显式报 409，记录保持 pending', async () => {
    const at = new Date();
    const legacy = await PrivilegeGrant.create({
      userId: target._id,
      username: target.username,
      permissionCodes: [CODE_HIGH],
      reason: '修复前残留：同一审批人两条签批',
      requestedBy: requester._id,
      requestedByName: requester.username,
      requestedAt: at,
      requiredApprovals: 2,
      highRisk: true,
      durationHours: 2,
      status: 'pending',
      approvals: [
        { by: approverA._id, name: approverA.username, at },
        { by: approverA._id, name: approverA.username, at },
      ],
    });

    await expect(
      grantService.approveGrant({ grantId: legacy._id, operator: operator(approverB) })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_PENDING', statusCode: 409 });

    const stored = await PrivilegeGrant.findById(legacy._id).lean();
    expect(stored.status).toBe('pending');
    // 没有被追加第三条签批，也没有被推进 active
    expect(stored.approvals).toHaveLength(2);
    expect(new Set(stored.approvals.map((item) => String(item.by))).size).toBe(1);
  });

  test('A1 激活判据按 by 去重：库内只有同人两条时，第二名审批人不得把授予推进 active', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_HIGH],
      reason: '激活判据去重验证',
      durationHours: 2,
      operator: operator(requester),
    });
    await grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) });
    expect((await PrivilegeGrant.findById(grant._id).lean()).status).toBe('pending');

    const at = new Date();
    const real = PrivilegeGrant.findOneAndUpdate.bind(PrivilegeGrant);
    let calls = 0;
    const spy = jest
      .spyOn(PrivilegeGrant, 'findOneAndUpdate')
      .mockImplementation(async (...args) => {
        calls += 1;
        const out = await real(...args);
        if (calls === 1 && out) {
          // 签批已落库、激活判据即将按库内现值求值：此时把 approvals 换成同一人的两条
          // （等价于修复前残留数据 / 外部进程在快照之后写入的脏形态）
          await PrivilegeGrant.updateOne(
            { _id: grant._id },
            {
              $set: {
                approvals: [
                  { by: approverA._id, name: approverA.username, at },
                  { by: approverA._id, name: approverA.username, at },
                ],
              },
            }
          );
        }
        return out;
      });

    try {
      const result = await grantService.approveGrant({
        grantId: grant._id,
        operator: operator(approverB),
      });
      // 去重后只有 1 人签批，阈值 2 未达：不得因为「条数=2」而报 active
      expect(result.status).toBe('pending');
    } finally {
      spy.mockRestore();
    }

    const stored = await PrivilegeGrant.findById(grant._id).lean();
    expect(stored.status).toBe('pending');
  });

  test('A3 到期回收不在本进程失效缓存：调用方是独立进程，进程内缓存/钩子不跨进程共享', async () => {
    const invalidated = [];
    grantService.setPermissionCacheInvalidator((id) => invalidated.push(String(id)));
    try {
      const grant = await grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '过期回收缓存腿验证',
        durationHours: 1,
        operator: operator(requester),
      });
      const approved = await grantService.approveGrant({
        grantId: grant._id,
        operator: operator(approverA),
      });
      expect(approved.status).toBe('active');
      invalidated.length = 0; // 只观察 expireDue 自身是否调用失效钩子

      const expired = await grantService.expireDue(new Date(Date.now() + 3 * 3600 * 1000));
      expect(expired).toBeGreaterThanOrEqual(1);
      // 旧实现会在这里逐个用户调用失效钩子（跨进程时命中未注册的钩子＝空转）：本条即红
      expect(invalidated).toEqual([]);
    } finally {
      grantService.setPermissionCacheInvalidator(permissionService.invalidatePermissionCache);
    }

    const stored = await PrivilegeGrant.findOne({
      permissionCodes: CODE_NORMAL,
      status: 'expired',
    }).lean();
    expect(stored).not.toBeNull();
    // 到期即失效的唯一保证在读侧：回收之后读路径必须立刻看不到该码（不依赖任何缓存失效）
    expect(
      (await grantService.activeCodesForUsers([String(target._id)])).get(String(target._id))
    ).not.toContain(CODE_NORMAL);
    permissionService.invalidatePermissionCacheLocal();
  });

  test('C-08 接线：巡检脚本 --review 才登记复核（reviewedAt 落库、超期清单收缩；默认只读）', async () => {
    // markReviewed 此前零调用 ⇒ reviewedAt 永远为空 ⇒ 超期清单只增不减。本用例真跑 CLI
    // 子进程（接线在 scripts/access-review.js），并断言「不带参数时对数据零副作用」。
    const { spawnSync } = require('child_process');
    const path = require('path');
    const ROOT = path.resolve(__dirname, '../../..'); // src/tests/services → 仓库根
    const CLI = path.join(ROOT, 'scripts/access-review.js');
    const runCli = (args) =>
      spawnSync(process.execPath, [CLI, ...args], {
        cwd: ROOT,
        encoding: 'utf8',
        timeout: 60000,
        env: { ...process.env },
      });
    const parseReport = (stdout) => {
      // stdout 里既有 logger 行也有 JSON 报告：报告是最后一段顶格 JSON
      const start = stdout.lastIndexOf('\n{');
      expect(start).toBeGreaterThanOrEqual(0);
      return JSON.parse(stdout.slice(start));
    };
    const overdueIds = async () =>
      (await reviewService.listOverdueGrants({ limit: 200 })).map((g) => String(g._id));

    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '复核接线端到端',
      durationHours: 4,
      operator: operator(requester),
    });
    await grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) });
    // 推进到超期窗口：90 天前授予、尚未到期、且未复核
    await PrivilegeGrant.updateOne(
      { _id: grant._id },
      { $set: { grantedAt: new Date(Date.now() - 100 * 24 * 3600 * 1000) } }
    );
    expect(await overdueIds()).toContain(String(grant._id));

    // ① 默认只读：不带参数跑一遍，不得写任何 reviewedAt
    // 断言带上 stderr：子进程失败时只看到「状态码不是 0」会完全不知道原因
    // （此前在整仓串跑下出现过 status=1，孤立跑不复现——诊断信息必须先落地）
    const readOnly = runCli([]);
    // jest 的 expect 只收一个实参（不能像 vitest 那样带消息），所以失败原因走 throw
    if (readOnly.status !== 0) {
      throw new Error(
        `CLI 只读跑失败（status=${readOnly.status}）：${readOnly.stderr || readOnly.stdout}`
      );
    }
    expect(readOnly.status).toBe(0);
    expect((await PrivilegeGrant.findById(grant._id).lean()).reviewedAt).toBeNull();

    // ② 参数不全必须拒绝（不做「参数没生效但看起来生效」的静默回退）
    const noReviewer = runCli(['--review', String(grant._id)]);
    expect(noReviewer.status).toBe(2);
    expect((await PrivilegeGrant.findById(grant._id).lean()).reviewedAt).toBeNull();

    // ③ 显式复核：reviewedAt/reviewedBy 落库，超期清单收缩
    const reviewed = runCli(['--review', String(grant._id), '--reviewer', 'zzpriv_approver_b']);
    expect(reviewed.status).toBe(0);
    const report = parseReport(reviewed.stdout);
    expect(report.reviewed.id).toBe(String(grant._id));
    expect(report.reviewed.reviewedBy).toBe(String(approverB._id));

    const stored = await PrivilegeGrant.findById(grant._id).lean();
    expect(stored.reviewedAt).toBeInstanceOf(Date);
    expect(String(stored.reviewedBy)).toBe(String(approverB._id));
    expect(await overdueIds()).not.toContain(String(grant._id));
  });

  test('驳回链路：驳回写决策留痕；驳回后审批与撤销都不再成立（状态机单向）', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '驳回链路验证',
      durationHours: 2,
      operator: operator(requester),
    });

    const rejected = await grantService.rejectGrant({
      grantId: grant._id,
      operator: operator(approverA),
      reason: '  业务窗口已关闭  ',
    });
    expect(rejected.status).toBe('rejected');
    expect(rejected.decisionReason).toBe('业务窗口已关闭');

    // 驳回后不得再被审批：条件更新的 filter 要求库里仍是 pending，此处走「未命中→回库内现值」腿
    await expect(
      grantService.approveGrant({ grantId: grant._id, operator: operator(approverB) })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_PENDING', statusCode: 409 });

    // 也不可撤销：rejected 不是可撤销态，撤销只对 pending/active 成立
    await expect(
      grantService.revokeGrant({ grantId: grant._id, operator: operator(requester) })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_ACTIVE', statusCode: 409 });
  });

  test('复核登记 markReviewed：生效期内留痕；非生效态（驳回/已撤销）一律 409', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '复核登记生效态验证',
      durationHours: 2,
      operator: operator(requester),
    });
    await grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) });

    const reviewed = await reviewService.markReviewed({
      grantId: grant._id,
      operator: operator(approverB),
    });
    expect(reviewed.reviewedAt).toBeInstanceOf(Date);
    expect(String(reviewed.reviewedBy)).toBe(String(approverB._id));

    const rejectedGrant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '非生效态复核登记验证',
      durationHours: 2,
      operator: operator(requester),
    });
    await grantService.rejectGrant({
      grantId: rejectedGrant._id,
      operator: operator(approverA),
      reason: '业务上不必要',
    });
    await expect(
      reviewService.markReviewed({ grantId: rejectedGrant._id, operator: operator(approverB) })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_ACTIVE', statusCode: 409 });
  });

  test('服务层入参兜底：空列表、超 20 项、空白理由一律 400（不能只靠路由层校验）', async () => {
    const base = {
      targetUserId: target._id,
      reason: '服务层入参兜底',
      durationHours: 2,
      operator: operator(requester),
    };
    await expect(grantService.requestGrant({ ...base, permissionCodes: [] })).rejects.toMatchObject(
      { code: 'PRIVILEGE_GRANT_INVALID', statusCode: 400 }
    );
    await expect(
      grantService.requestGrant({
        ...base,
        permissionCodes: Array.from({ length: 21 }, (_, i) => 'report:zzpriv_over_' + i),
      })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_INVALID', statusCode: 400 });
    await expect(
      grantService.requestGrant({ ...base, permissionCodes: [CODE_NORMAL], reason: '   ' })
    ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_INVALID', statusCode: 400 });
  });

  test('被授权账户不可用时拒绝授予（inactive 用户不得拿到临时权限）', async () => {
    const inactive = await User.create({
      username: 'zzpriv_inactive_target',
      email: 'zzpriv_inactive_target@zzpriv.test',
      password: 'Zzpriv#2026Aa1',
      department: 'ZZPRIV',
      status: 'inactive',
      roles: [],
    });
    await expect(
      grantService.requestGrant({
        targetUserId: inactive._id,
        permissionCodes: [CODE_NORMAL],
        reason: '不可用账户授予验证',
        durationHours: 2,
        operator: operator(requester),
      })
    ).rejects.toMatchObject({ statusCode: 400 });
  });

  test('钩子未注册必须 fail-closed：权限判定缺失时审批报错，缓存失效缺失时不得静默报告成功', async () => {
    // 判定钩子缺失：审批人是否持有拟授予的权限无法确认 ⇒ 直接拒绝（不允许"查不到就放行"）
    grantService.setPermissionChecker(null);
    try {
      const grant = await grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '判定钩子缺失验证',
        durationHours: 2,
        operator: operator(requester),
      });
      await expect(
        grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
      ).rejects.toThrow(/权限判定钩子未注册/);
    } finally {
      grantService.setPermissionChecker((userId, code) =>
        permissionService.hasPermission(userId, code)
      );
    }

    // 失效钩子缺失：签批已落库但缓存不失效 ⇒ 拒绝报告成功，把不一致暴露给调用方
    grantService.setPermissionCacheInvalidator(null);
    try {
      const grant = await grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '失效钩子缺失验证',
        durationHours: 2,
        operator: operator(requester),
      });
      await expect(
        grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
      ).rejects.toThrow(/缓存失效钩子未注册/);
    } finally {
      grantService.setPermissionCacheInvalidator(permissionService.invalidatePermissionCache);
    }
  });

  /** 让「另一路写者」精确落在指定阶段之后：按 update 形态显式定位（$push.approvals=签批落库，其余=状态推进），
   *  不再假设「第一次 findOneAndUpdate 一定是签批」——并发/热加载下该假设会把插桩挪到别的阶段。 */
  const injectAfterConditionalStage = async (grantId, patch, expectedStage) => {
    const real = PrivilegeGrant.findOneAndUpdate.bind(PrivilegeGrant);
    let injected = false;
    const seen = [];
    const spy = jest
      .spyOn(PrivilegeGrant, 'findOneAndUpdate')
      .mockImplementation(async (...args) => {
        const [, update = {}] = args;
        const stage = update.$push && update.$push.approvals ? 'pushApprovals' : 'advanceStatus';
        seen.push(stage);
        const result = await real(...args);
        if (!injected && stage === expectedStage) {
          injected = true;
          await PrivilegeGrant.updateOne({ _id: grantId, status: 'pending' }, { $set: patch });
        }
        return result;
      });
    return {
      spy,
      seen,
      restore: () => spy.mockRestore(),
      assertInjected: () => {
        if (!injected) {
          throw new Error(
            '插桩未命中「' +
              expectedStage +
              '」阶段：实际阶段序列=' +
              JSON.stringify(seen) +
              '（前置没建立成时必须显式失败，不能让空断言放行）'
          );
        }
      },
    };
  };

  const withRecordedInvalidator = async (fn) => {
    const calls = [];
    grantService.setPermissionCacheInvalidator((id) => calls.push(String(id)));
    try {
      const value = await fn();
      return { value, calls };
    } finally {
      grantService.setPermissionCacheInvalidator(permissionService.invalidatePermissionCache);
    }
  };

  /** 竞态插桩：在本路「写库之前」让另一路把同一条推成 active（与真实 approve 落库同义），并把生效权限种进读缓存；
   *  save 与条件更新两条写路径都能命中，保证同一条用例在旧快照实现上必红、在当前实现上必绿。 */
  const race = { arm: null };

  const armRace = (grantId, targetUserId) => {
    const state = { grantId: String(grantId), targetUserId: String(targetUserId), fired: false };
    race.arm = state;
    return {
      state,
      disarm: () => {
        if (race.arm === state) race.arm = null;
      },
    };
  };

  const runRaceInjection = async (rawId, toStatus) => {
    const armed = race.arm;
    if (!armed || armed.fired || String(rawId) !== armed.grantId) return;
    if (toStatus && toStatus !== 'revoked' && toStatus !== 'rejected') return;
    armed.fired = true;
    await PrivilegeGrant.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(armed.grantId) },
      {
        $set: {
          status: 'active',
          grantedAt: new Date(),
          expiresAt: new Date(Date.now() + 3600 * 1000),
        },
      }
    );
    await permissionService.getPermissions(armed.targetUserId); // 读请求把 active 的权限码种进缓存
  };

  /** 两条写路径的插桩：旧快照实现是 doc.save()，当前实现是 findOneAndUpdate；都必须在真实写库之前跑注入 */
  const installRaceSpies = () => {
    const realFindOneAndUpdate = PrivilegeGrant.findOneAndUpdate.bind(PrivilegeGrant);
    const realSave = PrivilegeGrant.prototype.save;
    const findOneAndUpdate = jest
      .spyOn(PrivilegeGrant, 'findOneAndUpdate')
      .mockImplementation(async (...args) => {
        const [filter = {}, update = {}] = args;
        await runRaceInjection(filter._id, update.$set && update.$set.status);
        return realFindOneAndUpdate(...args);
      });
    const save = jest.spyOn(PrivilegeGrant.prototype, 'save').mockImplementation(async function (
      ...args
    ) {
      await runRaceInjection(this._id);
      return realSave.apply(this, args);
    });
    return () => {
      findOneAndUpdate.mockRestore();
      save.mockRestore();
    };
  };

  const assertRaceInjected = (armed) => {
    if (!armed.state.fired) {
      throw new Error('插桩未命中：本路写库之前另一路没有被推成 active，本用例不成立');
    }
  };

  /** 记录失效调用并真实转调本地失效：既断言「谁被失效」，也断言读路径确实不再放行 */
  const withLiveInvalidator = async (fn) => {
    const calls = [];
    grantService.setPermissionCacheInvalidator((id) => {
      calls.push(String(id));
      permissionService.invalidatePermissionCache(String(id));
    });
    try {
      return { value: await fn(), calls };
    } finally {
      grantService.setPermissionCacheInvalidator(permissionService.invalidatePermissionCache);
    }
  };

  test('R3-1 驳回插在「签批落库」与「激活」之间 ⇒ 签批方必须 409，不得按 200 报告成功', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '竞态：驳回插在签批与激活之间',
      durationHours: 2,
      operator: operator(requester),
    });
    expect(grant.requiredApprovals).toBe(1);
    const { restore, assertInjected } = await injectAfterConditionalStage(
      grant._id,
      { status: 'rejected' },
      'pushApprovals'
    );
    const invalidations = [];
    grantService.setPermissionCacheInvalidator((id) => invalidations.push(String(id)));
    try {
      // 修复前：这一路会 resolve 出「库内现值 = rejected」，控制器按 200 返回 ⇒ 审批方以为签批生效
      await expect(
        grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
      ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_PENDING', statusCode: 409 });
    } finally {
      restore();
      grantService.setPermissionCacheInvalidator(permissionService.invalidatePermissionCache);
    }
    assertInjected();
    const stored = await PrivilegeGrant.findById(grant._id).lean();
    expect(stored.status).toBe('rejected');
    expect(stored.grantedAt).toBeFalsy();
    // 授予从未生效过 ⇒ 不得产生失效调用（失效点只在「落库为 active」与「撤销 active」）
    expect(invalidations).toEqual([]);
  });

  test('R3-2 撤销插在「签批落库」与「激活」之间 ⇒ 同样必须 409（撤销可以吃掉 pending，但不能被读成签批成功）', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '竞态：撤销插在签批与激活之间',
      durationHours: 2,
      operator: operator(requester),
    });
    const { restore, assertInjected } = await injectAfterConditionalStage(
      grant._id,
      { status: 'revoked' },
      'pushApprovals'
    );
    try {
      await expect(
        grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
      ).rejects.toMatchObject({ code: 'PRIVILEGE_GRANT_NOT_PENDING', statusCode: 409 });
    } finally {
      restore();
    }
    assertInjected();
    const stored = await PrivilegeGrant.findById(grant._id).lean();
    expect(stored.status).toBe('revoked');
    expect(stored.grantedAt).toBeFalsy();
    const afterRevoke = await grantService.activeCodesForUsers([String(target._id)]);
    // F3：钉住读侧结果——Map 恒真，toBeTruthy 钉不住「放行/未放行」；撤销后的授予不得产生任何生效码
    expect(afterRevoke.get(String(target._id))).toEqual([]);
  });

  test('R3-3 反向对照：另一路抢先推进成 active ⇒ 签批方拿到库内 active（幂等成功），不得被 409 误伤', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '竞态：另一路抢先激活',
      durationHours: 2,
      operator: operator(requester),
    });
    const { restore, assertInjected } = await injectAfterConditionalStage(
      grant._id,
      { status: 'active', grantedAt: new Date(), expiresAt: new Date(Date.now() + 3600 * 1000) },
      'pushApprovals'
    );
    try {
      const { value, calls } = await withRecordedInvalidator(() =>
        grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) })
      );
      assertInjected();
      expect(value.status).toBe('active');
      // 库内已经生效 ⇒ 必须失效缓存，否则这一路的旧快照（无该码）最长 30 秒仍在放行
      expect(calls).toEqual([String(target._id)]);
    } finally {
      restore();
    }
  });
  test('A4 失效时点：只有「落库为 active」「撤销一条 active」两处失效，pending 侧一律不失效', async () => {
    const makeGrant = () =>
      grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '失效时点判定',
        durationHours: 2,
        operator: operator(requester),
      });

    const activated = await makeGrant();
    const { calls: onActivate } = await withRecordedInvalidator(() =>
      grantService.approveGrant({ grantId: activated._id, operator: operator(approverA) })
    );
    expect(onActivate).toEqual([String(target._id)]);

    const revocable = await makeGrant();
    await grantService.approveGrant({ grantId: revocable._id, operator: operator(approverA) });
    const { calls: onRevokeActive } = await withRecordedInvalidator(() =>
      grantService.revokeGrant({
        grantId: revocable._id,
        operator: operator(requester),
        reason: '提前结束',
      })
    );
    expect(onRevokeActive).toEqual([String(target._id)]);

    // 端到端（独立用户 + **真实**失效钩子）：缓存里先种上该码 ⇒ 撤销后必须立刻读不到。
    // 用独立用户是因为同套件其它用例会给 target 留下仍然 active 的授予，那个码不该消失，会污染这条判据。
    const cacheTarget = await User.create({
      username: 'zzpriv_cache_target',
      email: 'zzpriv_cache_target@zzpriv.test',
      password: 'Zzpriv#2026Aa1',
      department: 'ZZPRIV',
      roles: [],
    });
    const forCache = await grantService.requestGrant({
      targetUserId: cacheTarget._id,
      permissionCodes: [CODE_NORMAL],
      reason: '缓存窗口判定',
      durationHours: 2,
      operator: operator(requester),
    });
    await grantService.approveGrant({ grantId: forCache._id, operator: operator(approverA) });
    const codesOf = async (id) =>
      (await permissionService.getPermissions(String(id))).map((p) => p.code || p);
    expect(await codesOf(cacheTarget._id)).toContain(CODE_NORMAL); // 前提：缓存里此刻确实有该码
    await grantService.revokeGrant({
      grantId: forCache._id,
      operator: operator(requester),
      reason: '提前结束',
    });
    expect(await codesOf(cacheTarget._id)).not.toContain(CODE_NORMAL);

    const pendingReject = await makeGrant();
    const { calls: onRejectPending } = await withRecordedInvalidator(() =>
      grantService.rejectGrant({
        grantId: pendingReject._id,
        operator: operator(approverB),
        reason: '材料不全',
      })
    );
    expect(onRejectPending).toEqual([]);

    const pendingRevoke = await makeGrant();
    const { calls: onRevokePending } = await withRecordedInvalidator(() =>
      grantService.revokeGrant({
        grantId: pendingRevoke._id,
        operator: operator(requester),
        reason: '申请作废',
      })
    );
    expect(onRevokePending).toEqual([]);
  });

  test('R3-4 撤销竞态：本路写库前另一路把同一条推成 active ⇒ 必须按返回文档判定并失效缓存（读路径不再放行）', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '竞态：撤销写前被激活',
      durationHours: 2,
      operator: operator(requester),
    });
    const armed = armRace(grant._id, target._id);
    const restore = installRaceSpies();
    let outcome;
    try {
      outcome = await withLiveInvalidator(() =>
        grantService.revokeGrant({
          grantId: grant._id,
          operator: operator(requester),
          reason: '竞态撤销',
        })
      );
    } finally {
      restore();
      armed.disarm();
    }
    assertRaceInjected(armed);
    expect(outcome.value.status).toBe('revoked');
    // 条件更新返回的更新前文档 status=active ⇒ 必须失效；旧实现按调用前快照算 wasActive=false，这里会是 []
    expect(outcome.calls).toEqual([String(target._id)]);
    const codes = (await permissionService.getPermissions(String(target._id))).map(
      (p) => p.code || p
    );
    expect(codes).not.toContain(CODE_NORMAL);
  });

  test('R3-5 驳回竞态：本路写库前另一路把同一条推成 active ⇒ 409，且不得把已生效的授予覆写成 rejected', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '竞态：驳回写前被激活',
      durationHours: 2,
      operator: operator(requester),
    });
    const armed = armRace(grant._id, target._id);
    const restore = installRaceSpies();
    let error = null;
    try {
      await grantService.rejectGrant({
        grantId: grant._id,
        operator: operator(approverB),
        reason: '竞态驳回',
      });
    } catch (e) {
      error = e;
    } finally {
      restore();
      armed.disarm();
    }
    assertRaceInjected(armed);
    expect(error && error.code).toBe('PRIVILEGE_GRANT_NOT_PENDING');
    expect(error && error.statusCode).toBe(409);
    expect((await PrivilegeGrant.findById(grant._id).lean()).status).toBe('active');
  });

  test('F1 撤销不得覆写批准留痕：decidedBy/decidedAt/decisionReason 原样保留，撤销另写 revokedBy/revokedAt/revokeReason', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '留痕保留验证',
      durationHours: 2,
      operator: operator(requester),
    });
    const approved = await grantService.approveGrant({
      grantId: grant._id,
      operator: operator(approverA),
    });
    expect(approved.status).toBe('active');
    const approvedAt = approved.decidedAt;
    expect(String(approved.decidedBy)).toBe(String(approverA._id));

    const revoked = await grantService.revokeGrant({
      grantId: grant._id,
      operator: operator(requester),
      reason: '  任务提前结束  ',
    });
    expect(revoked.status).toBe('revoked');

    const stored = await PrivilegeGrant.findById(grant._id).lean();
    // 批准轨迹必须原样保留（撤销者不得成为 decidedBy）
    expect(String(stored.decidedBy)).toBe(String(approverA._id));
    expect(stored.decidedByName).toBe(approverA.username);
    expect(new Date(stored.decidedAt).getTime()).toBe(new Date(approvedAt).getTime());
    expect(stored.decisionReason).toBe('');
    // 撤销轨迹独立字段
    expect(String(stored.revokedBy)).toBe(String(requester._id));
    expect(stored.revokedByName).toBe(requester.username);
    expect(stored.revokedAt).toBeInstanceOf(Date);
    expect(stored.revokeReason).toBe('任务提前结束');
  });

  test('F2 驳回/撤销日志必须带前态与后态：reject 记 from=pending→to=rejected，revoke 记 from=pending|active→to=revoked 且 wasActive 如实', async () => {
    const logger = require('../../utils/logger');
    const infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
    try {
      const toReject = await grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '日志前态验证',
        durationHours: 2,
        operator: operator(requester),
      });
      await grantService.rejectGrant({
        grantId: toReject._id,
        operator: operator(approverA),
        reason: '材料不全',
      });
      const rejectCall = infoSpy.mock.calls.find((c) => c[0] === '临时权限授予已驳回');
      expect(rejectCall).toBeTruthy();
      expect(rejectCall[1]).toMatchObject({ from: 'pending', to: 'rejected' });
      expect(String(rejectCall[1].grantId)).toBe(String(toReject._id));

      const toRevokePending = await grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '日志前态验证（pending 撤销）',
        durationHours: 2,
        operator: operator(requester),
      });
      await grantService.revokeGrant({
        grantId: toRevokePending._id,
        operator: operator(requester),
        reason: '申请作废',
      });
      const revokePendingCall = infoSpy.mock.calls
        .filter((c) => c[0] === '临时权限授予已撤销')
        .pop();
      expect(revokePendingCall[1]).toMatchObject({
        from: 'pending',
        to: 'revoked',
        wasActive: false,
      });

      const toRevokeActive = await grantService.requestGrant({
        targetUserId: target._id,
        permissionCodes: [CODE_NORMAL],
        reason: '日志前态验证（active 撤销）',
        durationHours: 2,
        operator: operator(requester),
      });
      await grantService.approveGrant({
        grantId: toRevokeActive._id,
        operator: operator(approverA),
      });
      await grantService.revokeGrant({
        grantId: toRevokeActive._id,
        operator: operator(requester),
        reason: '提前结束',
      });
      const revokeActiveCall = infoSpy.mock.calls
        .filter((c) => c[0] === '临时权限授予已撤销')
        .pop();
      expect(revokeActiveCall[1]).toMatchObject({ from: 'active', to: 'revoked', wasActive: true });
    } finally {
      infoSpy.mockRestore();
    }
  });

  test('契约：PRIVILEGE_GRANT_NOT_ACTIVE 的每个后端发出点都必须把状态塞进 errors（新增点漏参会红）', () => {
    const root = path.join(__dirname, '../../..');
    const files = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
        if (entry.name === 'node_modules' || entry.name === 'tests') continue;
        const rel = dir + '/' + entry.name;
        if (entry.isDirectory()) walk(rel);
        else if (entry.name.endsWith('.js')) files.push(rel);
      }
    };
    walk('src');
    // 括号配平取出每个 grantError(...) / new ApiError(...) 的整段实参，只留发本码的那些
    const sites = [];
    for (const rel of files) {
      const text = fs.readFileSync(path.join(root, rel), 'utf8');
      const callRe = /\b(?:grantError|new\s+ApiError)\s*\(/g;
      let m;
      while ((m = callRe.exec(text)) !== null) {
        const open = text.indexOf('(', m.index);
        let depth = 0;
        let args = '';
        for (let i = open; i < text.length; i += 1) {
          if (text[i] === '(') depth += 1;
          else if (text[i] === ')') {
            depth -= 1;
            if (depth === 0) {
              args = text.slice(open + 1, i);
              break;
            }
          }
        }
        if (args.includes('PRIVILEGE_GRANT_NOT_ACTIVE')) {
          sites.push({ file: rel, hasStatus: /currentStatus/.test(args) });
        }
      }
    }
    // 逐个断言：每个发出点都要带 currentStatus（前端 resolveErrorMessage 用它插值）；
    // 清单同时是封闭的：新增发出点必须一并带上状态并在此登记（漏参/漏登都红，红字里直接列出全部站点）
    expect(sites.map((s) => s.file + ' currentStatus=' + s.hasStatus).sort()).toEqual([
      'src/services/accessReviewService.js currentStatus=true',
      'src/services/privilegeGrantService.js currentStatus=true',
    ]);
  });

  test('契约：该码的 i18n key 在两个 locale 都带 {currentStatus} 占位（否则状态无处落地）', () => {
    const root = path.join(__dirname, '../../..');
    for (const rel of [
      'web-admin/src/i18n/locales/zh-CN.js',
      'web-admin/src/i18n/locales/en-US.js',
    ]) {
      const text = fs.readFileSync(path.join(root, rel), 'utf8');
      const m = text.match(/privilegeGrantNotActive:\s*'([^']*)'/);
      expect([rel, m ? m[1] : null]).toEqual([rel, expect.stringContaining('{currentStatus}')]);
    }
  });

  test('R10-1 到期回收不得覆写批准留痕：decidedAt/decidedBy/decidedByName/decisionReason 原样保留，另写 expiredAt', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '到期留痕保护验证',
      durationHours: 2,
      operator: operator(requester),
    });
    const approved = await grantService.approveGrant({
      grantId: grant._id,
      operator: operator(approverA),
    });
    expect(approved.status).toBe('active');
    // 把 expiresAt 拨到过去：到期事实由 expiresAt 表达（读侧与巡检同一判据）
    await PrivilegeGrant.updateOne(
      { _id: grant._id },
      { $set: { expiresAt: new Date(Date.now() - 60 * 1000) } }
    );
    const before = await PrivilegeGrant.findById(grant._id).lean();
    expect(before.decidedBy).toBeTruthy();
    expect(before.decidedAt).toBeInstanceOf(Date);

    const now = new Date();
    expect(await grantService.expireDue(now)).toBeGreaterThanOrEqual(1);

    const stored = await PrivilegeGrant.findById(grant._id).lean();
    expect(stored.status).toBe('expired');
    // 到期是另一件事：批准留下的 decided* 是既成事实，巡检不得把它改写成自己的时间戳
    expect(new Date(stored.decidedAt).getTime()).toBe(new Date(before.decidedAt).getTime());
    expect(String(stored.decidedBy)).toBe(String(before.decidedBy));
    expect(stored.decidedByName).toBe(before.decidedByName);
    expect(stored.decisionReason).toBe(before.decisionReason);
    // 自己的回收时刻单独落字段，不复用 decidedAt
    expect(stored.expiredAt).toBeInstanceOf(Date);
    expect(stored.expiredAt.getTime()).toBe(now.getTime());
  });

  test('契约：GRANT_LIST_FIELDS 每项都必须真实存在于 schema（写错的键不报错，只会永远不下发）', () => {
    const { GRANT_LIST_FIELDS } = require('../../constants/privilegeGrant');
    // 前提自证：`.select()` 对不存在的键静默忽略 ⇒ 白名单写错一个键的后果是「该字段永远不下发」，
    // 不会红在任何行为用例上；本用例把「每项都是真字段」钉死在结构上
    expect(GRANT_LIST_FIELDS.filter((field) => !PrivilegeGrant.schema.paths[field])).toEqual([]);
    // 同一键重复登记同样是白名单写错（重复键会让「19 键」的名义数字与实际不符）
    expect(new Set(GRANT_LIST_FIELDS).size).toBe(GRANT_LIST_FIELDS.length);
  });

  test('R10-2 到期回收幂等：二次 expireDue 不改写 expiredAt，decided*/expiresAt 全部原样', async () => {
    const grant = await grantService.requestGrant({
      targetUserId: target._id,
      permissionCodes: [CODE_NORMAL],
      reason: '回收幂等验证',
      durationHours: 2,
      operator: operator(requester),
    });
    await grantService.approveGrant({ grantId: grant._id, operator: operator(approverA) });
    await PrivilegeGrant.updateOne(
      { _id: grant._id },
      { $set: { expiresAt: new Date(Date.now() - 60 * 1000) } }
    );
    const before = await PrivilegeGrant.findById(grant._id).lean();

    const first = new Date();
    expect(await grantService.expireDue(first)).toBeGreaterThanOrEqual(1);
    const afterFirst = await PrivilegeGrant.findById(grant._id).lean();
    expect(afterFirst.status).toBe('expired');
    expect(afterFirst.expiredAt).toBeInstanceOf(Date);
    expect(afterFirst.expiredAt.getTime()).toBe(first.getTime());

    // 二次巡检：已回收的不再命中 filter（幂等），且不得顺手改写任何留痕/时刻
    expect(await grantService.expireDue(new Date())).toBe(0);
    const afterSecond = await PrivilegeGrant.findById(grant._id).lean();
    expect(new Date(afterSecond.expiredAt).getTime()).toBe(first.getTime());
    expect(new Date(afterSecond.decidedAt).getTime()).toBe(new Date(before.decidedAt).getTime());
    expect(String(afterSecond.decidedBy)).toBe(String(before.decidedBy));
    expect(afterSecond.decidedByName).toBe(before.decidedByName);
    expect(afterSecond.decisionReason).toBe(before.decisionReason);
    expect(new Date(afterSecond.expiresAt).getTime()).toBe(new Date(before.expiresAt).getTime());
  });
});
