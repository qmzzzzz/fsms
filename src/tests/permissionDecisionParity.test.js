'use strict';

/**
 * 授权判定同口径：同一用户 + 同一权限码，四条路径必须给出同一个答案
 *
 * 仓内"用户是否拥有权限 X"这件事有四个入口，各自独立实现：
 *   1) `utils/permissionHelper.hasPermission`（走自己的 getUserPermissions 聚合）
 *   2) `services/userPermissionService.hasPermission`（走带 TTL 缓存的 getPermissions）
 *   3) `models/User.hasPermission` 静态方法（2 的转发）
 *   4) `utils/permissionHelper.matchesPermissionCodes(codes, X)`（数组级判据，
 *      角色/用户控制器用它校验"能不能授予自己没有的权限"）
 * 今天四条语义一致（精确码 / `*:*` / `模块:*`；且两侧都只认 status=active 的角色与权限项）。
 * 但它们是**两份聚合 + 两份通配判定**分散在三个文件里——本仓已经为"两份实现漂移"
 * 付过一次学费（E-05：auditQuery 的本地副本让查询与导出在同一天差 8 小时）。
 * 授权判定漂移的后果不是数据错，而是越权或误拒，所以先把等价性钉住：
 * 任何人以后只改其中一条路径，这里会红。
 *
 * 夹具特意包含**停用角色**与**停用权限项**：状态过滤是这四条路径最容易走偏的一格
 * （停用即失权是注释里承诺的语义），只测活跃数据等于没测。
 */

const mongoose = require('mongoose');

describe('授权判定四路径同口径', () => {
  let User;
  let Role;
  let Permission;
  let helper;
  let userPermService;

  const stamp = `zzpd${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const createdPermIds = []; // 只清理自己建的文档：同码权限可能由 initData 播种，别的套件正在用
  let pListId; // 按 _id 改状态：同码权限可能别处也有，按码更新会打偏
  let activeUser; // 持 生效角色(含停用权限项) + 停用角色
  let superUser; // 持 *:*
  let ghostUser; // 角色列表为空

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../models/User');
    Role = require('../models/Role');
    Permission = require('../models/Permission');
    helper = require('../utils/permissionHelper');
    userPermService = require('../services/userPermissionService');

    const mk = async (code, status = 'active') => {
      const created = await Permission.create({
        name: `zzpd-${code}-${stamp}`,
        code,
        type: 'api',
        module: code.split(':')[0],
        status,
      });
      createdPermIds.push(created._id);
      return created;
    };
    const pList = await mk('zzpd:list');
    pListId = pList._id;
    const pStopped = await mk('zzpd:stopped', 'inactive'); // 停用权限项
    const pModWild = await mk('zzpdmod:*');
    const pStar = await mk('*:*');

    const roleActive = await Role.create({
      name: `pd-active-${stamp}`,
      code: `PD_ACTIVE_${stamp}`.toUpperCase(),
      level: 5,
      status: 'active',
      permissions: [pList._id, pStopped._id, pModWild._id],
    });
    const roleStopped = await Role.create({
      name: `pd-stopped-${stamp}`,
      code: `PD_STOPPED_${stamp}`.toUpperCase(),
      level: 5,
      status: 'inactive',
      permissions: [pStar._id],
    });
    const mkUser = async (name, roles) =>
      User.create({
        username: name,
        email: `${name}@example.com`,
        password: 'Aa1!aaaaaaaaaaaaaaaa',
        status: 'active',
        roles,
      });
    activeUser = await mkUser(`zzpd_${stamp}`, [roleActive._id, roleStopped._id]);
    superUser = await mkUser(`zzpd_${stamp}s`, [roleStopped._id]);
    ghostUser = await mkUser(`zzpd_${stamp}g`, []);
  });

  afterAll(async () => {
    await User.deleteMany({ username: new RegExp(`^zzpd_${stamp}`) });
    await Role.deleteMany({ code: new RegExp(`^PD_.*_${stamp}$`) });
    if (createdPermIds.length) await Permission.deleteMany({ _id: { $in: createdPermIds } });
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  /** 四条路径各自的判定 */
  const fourPaths = async (userId, code) => {
    const a = await helper.hasPermission(userId, code);
    const b = await userPermService.hasPermission(userId, code);
    const c = await User.hasPermission(userId, code);
    const codes = await userPermService.getPermissions(userId);
    const d = helper.matchesPermissionCodes(codes, code);
    return { helper: a, service: b, userModel: c, arrayJudge: d };
  };

  // 语义锚点：true/false 都是**人算过的期望**，不是"四路径互相一致"的自我循环
  const MATRIX = [
    { user: () => activeUser, code: 'zzpd:list', want: true, why: '生效角色里的精确码' },
    { user: () => activeUser, code: 'zzpd:read', want: false, why: '未持有' },
    { user: () => activeUser, code: 'zzpdmod:whatever', want: true, why: 'zzpdmod:* 模块通配' },
    { user: () => activeUser, code: 'zzpd:stopped', want: false, why: '权限项已停用 ⇒ 失权' },
    { user: () => activeUser, code: '*:*', want: false, why: '唯一带 *:* 的角色已停用' },
    {
      user: () => activeUser,
      code: 'zzpdother:delete',
      want: false,
      why: '模块不同，通配不跨模块',
    },
    { user: () => superUser, code: 'zzpdstar:goes', want: false, why: '停用角色里的 *:* 不得生效' },
    {
      user: () => ghostUser,
      code: 'zzpd:list',
      want: false,
      why: '无角色 ⇒ 无权限（空集不等于全权）',
    },
  ];

  test.each(MATRIX)(
    '$code ⇒ $want（$why）：四条路径必须给出同一个答案',
    async ({ user, code, want }) => {
      const uid = user()._id;
      expect(await fourPaths(uid, code)).toEqual({
        helper: want,
        service: want,
        userModel: want,
        arrayJudge: want,
      });
    }
  );

  test('前提自证：矩阵里 true 与 false 都出现过（防"四路径恒 false"式全绿）', async () => {
    const trues = MATRIX.filter((m) => m.want).length;
    const falses = MATRIX.filter((m) => !m.want).length;
    expect(trues).toBeGreaterThan(0);
    expect(falses).toBeGreaterThan(0);
  });

  test('缓存路径与直查路径在权限变更后同口径（失效广播不许漏）', async () => {
    const uid = activeUser._id;
    // 先让缓存里存一份
    expect(await userPermService.hasPermission(uid, 'zzpd:list')).toBe(true);
    // 停用那条权限项 ⇒ 全局失效后四条路径都必须改口
    // 按 _id 定位：同码权限可能别处也有，按 code 更新会打偏甚至误伤别人的夹具
    await Permission.updateOne({ _id: pListId }, { $set: { status: 'inactive' } });
    userPermService.invalidatePermissionCache();
    expect(await fourPaths(uid, 'zzpd:list')).toEqual({
      helper: false,
      service: false,
      userModel: false,
      arrayJudge: false,
    });
    await Permission.updateOne({ _id: pListId }, { $set: { status: 'active' } });
    userPermService.invalidatePermissionCache();
  });

  test('用户级失效只影响该用户的判定', async () => {
    const u1 = activeUser._id;
    const u2 = superUser._id;
    expect(await userPermService.hasPermission(u1, 'zzpd:list')).toBe(true);
    expect(await userPermService.hasPermission(u2, 'zzpd:list')).toBe(false);
    userPermService.invalidatePermissionCacheLocal(String(u1));
    // 失效 u1 后，u2 的判定结果不变（此处只断言结果等价——实现走的是"清空"还是"逐条删"
    // 属实现细节，钉死它会让合理的容量策略变更变成红灯）
    expect(await userPermService.hasPermission(u1, 'zzpd:list')).toBe(true);
    expect(await userPermService.hasPermission(u2, 'zzpd:list')).toBe(false);
  });
});
