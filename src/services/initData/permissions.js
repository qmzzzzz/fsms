/**
 * 系统初始化数据服务 · 权限目录合并（保持原数组元素顺序）
 */

const { systemPermissions } = require('./permissionsSystem');
const { businessPermissions } = require('./permissionsBusiness');

const defaultPermissions = [...systemPermissions, ...businessPermissions];

module.exports = { defaultPermissions };
