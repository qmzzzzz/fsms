// 头像控制器：上传 / 删除 / 读取。读取授权在控制器内完成：本人直通，
// 他人需 user:read + 数据范围（与 GET /api/users/:id 同一把尺）。
const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');
const { asyncHandler } = require('../middleware/errorHandler');
const { assertRecordInScope } = require('../middleware/rbac');
const { safeFieldErrors } = require('../utils/validationRules');
const { AvatarImageError } = require('../utils/avatarImage');
const avatarService = require('../services/avatarService');
const userPermissionService = require('../services/userPermissionService');
const { matchesPermissionCodes } = require('../utils/permissionHelper');
const { USER_OWNER_FIELD, USER_DEPT_FIELD } = require('./userController/shared');

const rejectValidation = (req, res) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) return false;
  ApiResponse.codeError(res, 'VALIDATION_FAILED', { fieldErrors: safeFieldErrors(errors) });
  return true;
};

/** PUT /api/auth/avatar —— 本人上传/替换头像 */
const uploadAvatar = asyncHandler(async (req, res) => {
  if (rejectValidation(req, res)) return;
  try {
    const result = await avatarService.uploadAvatar(req.user.userId, req.body.image);
    if (result.outcome === 'USER_NOT_FOUND') {
      return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
    }
    return ApiResponse.success(
      res,
      {
        avatar: result.avatar,
        width: result.width,
        height: result.height,
        size: result.size,
      },
      '头像更新成功'
    );
  } catch (error) {
    // 只把图片形态类错误回给客户端；其余（DB/加密）照常上抛给全局错误处理
    if (error instanceof AvatarImageError) {
      return ApiResponse.codeError(res, 'AVATAR_INVALID', { message: error.message });
    }
    throw error;
  }
});

/** DELETE /api/auth/avatar —— 本人移除头像（幂等） */
const removeAvatar = asyncHandler(async (req, res) => {
  await avatarService.removeAvatar(req.user.userId);
  return ApiResponse.success(res, null, '头像已移除');
});

/** GET /api/avatars/:userId —— 本人或具备 user:read + 数据范围的他人 */
const getAvatar = asyncHandler(async (req, res) => {
  if (rejectValidation(req, res)) return;
  const targetId = String(req.params.userId);
  const isSelf = String(req.user.userId) === targetId;

  if (!isSelf) {
    const permissions = await userPermissionService.getPermissions(req.user.userId);
    // 通配口径同 checkPermission：*:* 与 user:* 都必须放行
    if (!matchesPermissionCodes(permissions, 'user:read')) {
      return ApiResponse.codeError(res, 'PERMISSION_DENIED');
    }
    const target = await avatarService.loadScopeTarget(targetId);
    if (!target) {
      return ApiResponse.codeError(res, 'USER_NOT_FOUND', { statusCode: 404 });
    }
    const { allowed } = await assertRecordInScope(req, target, USER_OWNER_FIELD, USER_DEPT_FIELD);
    if (!allowed) {
      // 与 GET /api/users/:id 同码：同一语义在两个读接口上不能有两个状态码
      return ApiResponse.codeError(res, 'USER_VIEW_FORBIDDEN');
    }
  }

  const result = await avatarService.getAvatar(targetId, req.headers['if-none-match']);
  if (result.outcome === 'NOT_FOUND') {
    return ApiResponse.codeError(res, 'AVATAR_NOT_FOUND', { statusCode: 404 });
  }

  // 头必须先于 304 分支设置：条件请求命中时浏览器要靠 ETag/Cache-Control 刷新过期时间
  res.set('ETag', result.etag);
  res.set('Cache-Control', 'private, no-cache');
  res.set('Vary', 'Cookie');
  // 头像是唯一直接回吐用户可控字节的响应：显式 nosniff + CSP sandbox 把"直接导航
  // 到该 URL"钉成不可执行、无同源权限的文档；即使未来全局 nosniff 被误删，
  // 也不会因 polyglot 图片把响应渲染成 HTML/脚本。
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Content-Security-Policy', "default-src 'none'; sandbox");
  if (result.outcome === 'NOT_MODIFIED') {
    return res.status(304).end();
  }

  res.set('Content-Type', result.mime);
  res.set('Content-Disposition', 'inline');
  res.set('Content-Length', String(result.buffer.length));
  return res.status(200).send(result.buffer);
});

module.exports = { uploadAvatar, removeAvatar, getAvatar };
