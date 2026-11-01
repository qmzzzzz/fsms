/** 临时权限授予的入参校验与错误构造（C-08）：grantError 是全部 PRIVILEGE_* 码的**唯一**出口（服务与控制器都从这里取），有效期/权限码归一口径在下方三个函数。 */

'use strict';

const Permission = require('../models/Permission');
const ApiError = require('../utils/ApiError'); // 业务码只认 utils/errorCodes.js 那份注册表
const { RESERVED_WILDCARD_PERMISSION } = require('../utils/superAdmin'); // 保留码只认权威常量，不在这里再写一遍字面量
const {
  MIN_GRANT_HOURS,
  MAX_GRANT_HOURS,
  MAX_GRANT_CODES,
} = require('../constants/privilegeGrant');

const grantError = (message, statusCode, code, errors = undefined) =>
  new ApiError(message, statusCode, errors, code);

const clampDurationHours = (raw) => {
  const hours = Number(raw);
  if (!Number.isFinite(hours) || hours < MIN_GRANT_HOURS || hours > MAX_GRANT_HOURS) {
    const range = MIN_GRANT_HOURS + '-' + MAX_GRANT_HOURS;
    throw grantError('有效期需为 ' + range + ' 小时之间的整数', 400, 'PRIVILEGE_DURATION_INVALID');
  }
  return Math.round(hours);
};

const normalizeCodes = (codes) => {
  const list = (Array.isArray(codes) ? codes : []) // 归一：去重、去空白、条数上限
    .map((code) => String(code || '').trim())
    .filter(Boolean);
  const unique = [...new Set(list)];
  if (unique.length === 0 || unique.length > MAX_GRANT_CODES) {
    throw grantError('权限码数量应为 1-' + MAX_GRANT_CODES + ' 项', 400, 'PRIVILEGE_GRANT_INVALID');
  }
  return unique;
};

async function assertCodesGrantable(codes) {
  const reserved = codes.filter((code) => code === RESERVED_WILDCARD_PERMISSION); // 可授予性：保留通配不可授（其余三条授予路径也都拒绝它）
  if (reserved.length > 0) {
    const detail = '保留权限码不可经临时授权通道申请：' + reserved.join(', ');
    throw grantError(detail, 400, 'PRIVILEGE_CODE_INVALID');
  }
  const active = await Permission.find({ code: { $in: codes }, status: 'active' })
    .select('code')
    .lean();
  const found = new Set(active.map((p) => p.code));
  const missing = codes.filter((code) => !found.has(code));
  if (missing.length === 0) return;
  throw grantError('权限码不存在或已停用：' + missing.join(', '), 400, 'PRIVILEGE_CODE_INVALID');
}

module.exports = { grantError, clampDurationHours, normalizeCodes, assertCodesGrantable };
