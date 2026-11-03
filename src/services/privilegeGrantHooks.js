/** 临时权限授予的两个外部钩子（C-08）：权限缓存失效与权限判定。由 userPermissionService 加载时注册，**未注册即抛**——授予落库后缓存没失效、或审批人持权无法确认时，宁可报错也不静默放行（fail-closed）。 */

'use strict';

let permissionCacheInvalidator = null;

const setPermissionCacheInvalidator = (fn) => {
  permissionCacheInvalidator = fn;
};

const invalidatePermissionCache = (userId) => {
  if (typeof permissionCacheInvalidator !== 'function') {
    throw new Error('权限缓存失效钩子未注册：临时授予已落库但缓存未失效，拒绝静默放行');
  }
  permissionCacheInvalidator(String(userId));
};

let permissionChecker = null;

const setPermissionChecker = (fn) => {
  permissionChecker = fn;
};

const hasPermission = async (userId, code, options) => {
  if (typeof permissionChecker !== 'function') {
    throw new Error('权限判定钩子未注册：无法确认审批人是否持有拟授予的权限');
  }
  return permissionChecker(String(userId), code, options);
};

module.exports = {
  setPermissionCacheInvalidator,
  setPermissionChecker,
  invalidatePermissionCache,
  hasPermission,
};
