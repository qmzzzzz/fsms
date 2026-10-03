/**
 * 角色业务服务层：集中角色、权限引用和相关用户统计的数据访问，
 * 控制器保留 HTTP 编排、提权规则与事件通知，避免继续直接操作 Model。
 */

const Role = require('../models/Role');
const Permission = require('../models/Permission');
const User = require('../models/User');
const userPermissionService = require('./userPermissionService');
const { withListBudget, listCountOptions } = require('../utils/queryBudget');

const ROLE_PERMISSION_POPULATE = { path: 'permissions', select: 'name code type module' };
const ROLE_DETAIL_POPULATE = {
  path: 'permissions',
  select: 'name code type module path method parent',
  populate: { path: 'parent', select: 'name code' },
};

class RoleService {
  async listRoles(query, page, limit) {
    const [roles, count] = await Promise.all([
      withListBudget(Role.find(query))
        .populate(ROLE_PERMISSION_POPULATE)
        .sort({ level: 1, createdAt: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      Role.countDocuments(query, listCountOptions()),
    ]);

    const roleIds = roles.map((role) => role._id);
    // L-23：$match 前置到 $unwind 之前。
    //
    // 原顺序（$unwind → $match）会先把**每个用户**的 roles 数组整体展开成多行
    // （N 用户 × 平均角色数），再逐行过滤出目标角色。前置的 $match 在数组层
    // 先做粗筛，把不相关用户整条剔除，$unwind 的输入行数随之下降。
    //
    // 实测（2 万用户 × 200 角色、每用户 1~8 角色、目标角色 10 个）：
    //   原顺序 中位 133.57ms → 新顺序 中位 81.53ms（1.64x），结果一致（n=4500）。
    // 注意 explain 阶段序列两者相同——优化器本就会把数组层粗筛下推，
    // 收益来自 $unwind 展开行数减少，而非查询计划差异。
    // 明细见 deliverables/性能实测基线-2026-09-16.json。
    const userCounts = await User.aggregate([
      { $match: { roles: { $in: roleIds } } },
      { $unwind: '$roles' },
      { $match: { roles: { $in: roleIds } } },
      { $group: { _id: '$roles', count: { $sum: 1 } } },
    ]);

    const countMap = new Map(userCounts.map((item) => [item._id.toString(), item.count]));
    return {
      roles: roles.map((role) => ({
        ...role.toObject(),
        userCount: countMap.get(role._id.toString()) || 0,
      })),
      count,
    };
  }

  listAllRoles(query = {}) {
    return Role.find({ status: 'active', ...query })
      .select('name code description')
      .sort({ level: 1 });
  }

  async getRoleDetail(id) {
    const role = await Role.findById(id).populate(ROLE_DETAIL_POPULATE);
    if (!role) return null;
    const [userCount, validPermissions] = await Promise.all([
      User.countDocuments({ roles: role._id }),
      role.permissions.filter((perm) => perm._id && /^[0-9a-fA-F]{24}$/.test(perm._id.toString())),
    ]);
    return { ...role.toObject(), permissions: validPermissions, userCount };
  }

  findRoleByCode(code) {
    return Role.findOne({ code });
  }

  findRoleForUpdate(id) {
    return Role.findById(id);
  }

  getOperatorPermissions(userId) {
    return userPermissionService.getPermissions(userId);
  }

  findPermissionsByIds(ids, select = 'code') {
    return Permission.find({ _id: { $in: ids } }).select(select);
  }

  createRole(fields) {
    return Role.create(fields);
  }

  saveRole(role) {
    return role.save();
  }

  findPopulatedRole(id) {
    return Role.findById(id).populate(ROLE_PERMISSION_POPULATE);
  }

  listActivePermissionTree() {
    return Permission.find({ status: 'active' })
      .populate({ path: 'parent', select: 'name code module' })
      .sort({ module: 1, sort: 1 });
  }

  findUserForUpdate(id) {
    return User.findById(id);
  }

  findRolesByIds(ids, select = 'level code isBuiltIn') {
    return Role.find({ _id: { $in: ids } }).select(select);
  }

  updateUserRoles(userId, roleIds) {
    return User.findByIdAndUpdate(userId, { $set: { roles: roleIds } });
  }

  listUsersWithRole(roleId) {
    return User.find({ roles: roleId }).select('_id').lean();
  }

  countUsersWithRole(roleId) {
    return User.countDocuments({ roles: roleId });
  }

  deleteRole(id) {
    return Role.findByIdAndDelete(id);
  }
}

module.exports = new RoleService();
