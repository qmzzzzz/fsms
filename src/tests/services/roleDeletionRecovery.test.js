/**
 * 角色删除的中断恢复（P3）
 *
 * 缺陷形状：删除流程是「置 inactive → 统计持有者 → 删除/恢复」。进程在
 * 统计之后、恢复之前退出（或恢复写失败）时，角色会永久停在 inactive，
 * 持有该角色的用户下一次登录就失去全部权限，且界面没有任何入口改回来。
 *
 * 修复后：置 inactive 的同一次更新把原状态原子抄进 deletionPreviousStatus；
 * 启动对账据此还原。本文件锁三件事：
 *   ① 正常「使用中」路径会把状态恢复成原值并清掉标记；
 *   ② 启动对账能还原被中断的 inactive 角色；
 *   ③ 已被并发改回 active 的角色不被对账改坏，只清理残留标记。
 */
const mongoose = require('mongoose');

describe('角色删除中断恢复', () => {
  let Role;
  let User;
  let roleService;
  const stamp = `rdr${Date.now().toString(36)}`;
  const createdRoleIds = [];
  const createdUserIds = [];

  const makeRole = async (label, status = 'active') => {
    const role = await Role.create({
      name: `${stamp}_${label}`,
      code: `${stamp}_${label}`.toUpperCase(),
      status,
    });
    createdRoleIds.push(role._id);
    return role;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    Role = require('../../models/Role');
    User = require('../../models/User');
    roleService = require('../../services/roleService');
  });

  afterAll(async () => {
    await User.deleteMany({ _id: { $in: createdUserIds } }).catch(() => {});
    await Role.deleteMany({ _id: { $in: createdRoleIds } }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('使用中回滚：状态恢复原值且删除标记被清理', async () => {
    const role = await makeRole('inuse');
    const user = await User.create({
      username: `rdr_${stamp}_inuse`,
      email: `rdr_${stamp}_inuse@example.com`,
      password: 'Rdr-Strong-Pass-123!',
      roles: [role._id],
    });
    createdUserIds.push(user._id);

    const outcome = await roleService.deleteRoleIfUnused(role._id);
    expect(outcome.status).toBe('in_use');
    expect(outcome.userCount).toBe(1);

    const fresh = await Role.findById(role._id).select(
      '+deletionPreviousStatus +deletionStartedAt'
    );
    expect(fresh.status).toBe('active');
    expect(fresh.deletionPreviousStatus).toBeUndefined();
    expect(fresh.deletionStartedAt).toBeUndefined();
  });

  test('启动对账还原被中断的删除（进程崩溃/恢复写失败）', async () => {
    const role = await makeRole('crashed');
    // 直接模拟中断现场：已停用、标记记录了原状态、删除未完成
    await Role.updateOne(
      { _id: role._id },
      {
        $set: {
          status: 'inactive',
          deletionPreviousStatus: 'active',
          deletionStartedAt: new Date(),
        },
      }
    );

    const count = await roleService.reconcileInterruptedRoleDeletions();
    expect(count).toBeGreaterThanOrEqual(1);

    const fresh = await Role.findById(role._id).select(
      '+deletionPreviousStatus +deletionStartedAt'
    );
    expect(fresh.status).toBe('active');
    expect(fresh.deletionPreviousStatus).toBeUndefined();
    expect(fresh.deletionStartedAt).toBeUndefined();
  });

  test('对账不把已被并发改回 active 的角色改坏，只清理残留标记', async () => {
    const role = await makeRole('reactivated');
    await Role.updateOne(
      { _id: role._id },
      {
        $set: {
          status: 'active',
          deletionPreviousStatus: 'inactive',
          deletionStartedAt: new Date(),
        },
      }
    );

    await roleService.reconcileInterruptedRoleDeletions();

    const fresh = await Role.findById(role._id).select(
      '+deletionPreviousStatus +deletionStartedAt'
    );
    expect(fresh.status).toBe('active');
    expect(fresh.deletionPreviousStatus).toBeUndefined();
    expect(fresh.deletionStartedAt).toBeUndefined();
  });

  test('无持有者时正常删除', async () => {
    const role = await makeRole('deletable');
    const outcome = await roleService.deleteRoleIfUnused(role._id);
    expect(outcome.status).toBe('deleted');
    expect(await Role.findById(role._id)).toBeNull();
  });
});
