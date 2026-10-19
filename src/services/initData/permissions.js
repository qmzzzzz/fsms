/**
 * 系统初始化数据服务 · 权限目录合并（保持原数组元素顺序）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const { systemPermissions } = require('./permissionsSystem');
const { businessPermissions } = require('./permissionsBusiness');

const defaultPermissions = [...systemPermissions, ...businessPermissions];

module.exports = { defaultPermissions };
