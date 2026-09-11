/**
 * 用户业务服务层：集中用户 CRUD、角色引用查询和统计聚合的数据访问。
 * 控制器保留数据范围判断、业务校验与响应编排。
 */

const User = require('../models/User');
const Role = require('../models/Role');
const userPermissionService = require('./userPermissionService');
const { applyDataScopeToQuery } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { escapeRegExp } = require('../utils/helpers');

const SIMPLE_ROLE_POPULATE = { path: 'roles', select: 'name code' };
const DETAIL_ROLE_POPULATE = {
  path: 'roles',
  select: 'name code description permissions',
  populate: { path: 'permissions', select: 'name code' },
};

class UserService {
  async buildListQuery(filters, dataScope) {
    const query = {};

    if (filters.search) {
      const escapedSearch = escapeRegExp(filters.search.trim());
      query.$or = [
        { username: new RegExp(escapedSearch, 'i') },
        { email: new RegExp(escapedSearch, 'i') },
        { realName: new RegExp(escapedSearch, 'i') },
      ];
    }

    const VALID_USER_STATUS = ['active', 'inactive', 'locked'];
    if (typeof filters.status === 'string' && VALID_USER_STATUS.includes(filters.status)) {
      query.status = filters.status;
    }

    if (typeof filters.department === 'string' && filters.department !== '') {
      query.department = filters.department;
    }

    if (filters.role) {
      const roleDoc = await this.findRoleByCode(filters.role);
      if (!roleDoc) return { roleFound: false, scopeAllowed: false, query: null };
      query.roles = roleDoc._id;
    }

    const scopeAllowed = applyDataScopeToQuery(query, dataScope, DATA_SCOPE_FIELDS.user);
    return { roleFound: true, scopeAllowed, query };
  }

  async listUsers(query, sort, page, limit) {
    const [users, count] = await Promise.all([
      User.find(query)
        .populate(SIMPLE_ROLE_POPULATE)
        .select(User.RESPONSE_EXCLUDE)
        .sort(sort)
        .limit(limit)
        .skip((page - 1) * limit),
      User.countDocuments(query),
    ]);
    return { users, count };
  }

  async getUserDetail(id) {
    return User.findById(id).populate(DETAIL_ROLE_POPULATE).select(User.RESPONSE_EXCLUDE);
  }

  async getCreatedUser(id) {
    return User.findById(id).populate(SIMPLE_ROLE_POPULATE).select(User.RESPONSE_EXCLUDE);
  }

  async getUpdatedUser(id) {
    return User.findById(id).populate(SIMPLE_ROLE_POPULATE).select(User.RESPONSE_EXCLUDE);
  }

  findUserForUpdate(id) {
    return User.findById(id);
  }

  findDuplicateUsername(username) {
    return User.findByUsername(username).select('_id').lean();
  }

  findOneUser(filter) {
    return User.findOne(filter);
  }

  createUser(fields) {
    return User.create(fields);
  }

  saveUser(user) {
    return user.save();
  }

  updateRoles(userId, roles) {
    return User.findByIdAndUpdate(userId, { $set: { roles } });
  }

  getPermissions(userId) {
    return userPermissionService.getPermissions(userId);
  }

  findRoleByCode(code) {
    return Role.findOne({ code });
  }

  findRolesByIds(ids, select = 'level code isBuiltIn', options = {}) {
    let query = Role.find({ _id: { $in: ids } }).select(select);
    if (options.populate) query = query.populate(options.populate);
    if (options.lean) query = query.lean();
    return query;
  }

  findRolePermissionDocs(roleIds) {
    return this.findRolesByIds(roleIds, 'permissions', {
      populate: { path: 'permissions', select: 'code' },
      lean: true,
    });
  }

  findBatchUsers(ids) {
    return User.find({ _id: { $in: ids } })
      .populate('roles', 'level code isBuiltIn')
      .lean();
  }

  deleteById(id) {
    return User.findByIdAndDelete(id);
  }

  deleteMany(filter) {
    return User.deleteMany(filter);
  }

  aggregateStats(pipeline) {
    return User.aggregate(pipeline);
  }
}

module.exports = new UserService();
