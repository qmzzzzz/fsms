/**
 * 用户管理控制器（门面）
 * 处理用户的 CRUD 操作
 */
const { getUsers, getUserById, getUserStats } = require('./read');
const { createUser } = require('./create');
const { updateUser } = require('./update');
const { assignRoles } = require('./roles');
const { deleteUser, batchDeleteUsers } = require('./delete');

module.exports = {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  assignRoles,
  deleteUser,
  batchDeleteUsers,
  getUserStats,
};
