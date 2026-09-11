/**
 * 角色业务服务层：集中角色、权限引用和相关用户统计的数据访问，
 * 控制器保留 HTTP 编排、提权规则与事件通知，避免继续直接操作 Model。
 */

const Role = require('../models/Role');
const Permission = require('../models/Permission');
const User = require('../models/User');
const userPermissionService = require('./userPermissionService');

const ROLE_PERMISSION_POPULATE = { path: 'permissions', select: 'name code type module' };
const ROLE_DETAIL_POPULATE = {
  path: 'permissions',
  select: 'name code type module path method parent',
  populate: { path: 'parent', select: 'name code' },
};

class RoleService {
  async listRoles(query, page, limit) {
    const [roles, count] = await Promise.all([
      Role.find(query)
        .populate(ROLE_PERMISSION_POPULATE)
        .sort({ level: 1, createdAt: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      Role.countDocuments(query),
    ]);

    const roleIds = roles.map((role) => role._id);
    const userCounts = await User.aggregate([
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
