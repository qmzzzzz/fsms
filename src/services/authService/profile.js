/**
 * 用户资料更新与账号锁定/解锁
 *
 * 自 authService.js 拆出。锁定态是资料写入的一部分（setUserLockStatus 落库时
 * 会带出资料字段），两者共享同一份用户文档写入口，拆开反而要来回传文档。
 */

const User = require('../../models/User');
const Role = require('../../models/Role');
const logger = require('../../utils/logger');
const { isValidAvatar } = require('../../utils/helpers');
const AuditLog = require('../../models/AuditLog');
// P0-5 后手写审计写入是这些操作的唯一留痕，静默吞错＝审计库零痕迹（且无可观测信号）
const { onAuditWriteFailure } = require('../../utils/auditWriteFailure');
const { normalizeEmailKey } = require('../../utils/emailKey');
// A3：email 已 at-rest 加密，查重不能再比对明文列（随机 IV 下相等性不成立），
// 统一走 HMAC 检索键 emailKey。piiSearchKey 的归一化口径（trim+lowercase）与
// normalizeEmailKey 一致，两者在同一个查询里可互换——但语义不同，见 utils/emailKey.js。
const { piiSearchKey } = require('../../utils/piiCrypto');
// O-2 下沉引入：管理员锁定/解锁的层级与内置超管校验（纯工具模块，无循环依赖）
const { getOperatorMaxLevel, maxRoleLevel } = require('../../utils/permissionHelper');
const { isSuperAdminRole } = require('../../utils/superAdmin');

/**
 * 更新个人资料（业务层）
 *
 * 【H-01 修复】department 刻意不在自助可改字段内：
 * 它是数据范围的唯一来源（middleware/rbac.js:215 以 user.department 构造
 * department 型 dataScope，再经 constants/dataScopeFields.js 映射为各业务
 * 资源的过滤字段）。若允许用户自助修改，持有 level>=7 角色的账户只需一次
 * PUT /api/auth/profile 即可把 dataScope 指向任意部门，绕过部门隔离读取并
 * 导出该部门的设备/报警/巡检/用户数据。
 *
 * 反向证据：管理员改他人部门（PUT /api/users/:id）是有层级校验的，
 * 而自助入口原先无任何关卡——这一不对称说明原实现是疏漏而非设计。
 *
 * 部门变更应经管理员接口（userController），不自助。
 *
 * @returns {Promise<{outcome:'NOT_FOUND'|'INVALID_PHONE'|'INVALID_EMAIL'|'EMAIL_TAKEN'|'INVALID_AVATAR'|'OK'}>}
 *   OK 时附 { profile }
 */
/** 资料入参的手机号/邮箱形态（原为函数内联字面量，取值与顺序不变） */
const PROFILE_PHONE_RE = /^1[3-9]\d{9}$/;
const PROFILE_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * 资料入参格式校验（手机号 → 邮箱 → 头像，顺序即原实现顺序）。
 *
 * @returns {string|null} 拒绝时的 outcome，通过时 null
 */
function validateProfileInput({ email, phone, avatar }) {
  // 验证手机号格式（如果提供）
  if (phone && !PROFILE_PHONE_RE.test(phone)) return 'INVALID_PHONE';
  // 验证邮箱格式（如果提供）
  if (email && !PROFILE_EMAIL_RE.test(email)) return 'INVALID_EMAIL';
  // 头像白名单校验：仅允许 http(s) URL、相对图片路径或 data:image 数据 URI（不含 svg，防存储型脚本注入）
  if (avatar !== undefined && avatar !== '' && !isValidAvatar(avatar)) return 'INVALID_AVATAR';
  return null;
}

/**
 * 邮箱是否已被**其他**用户占用。
 *
 * ① `normalizedEmail !== normalizeEmailKey(user.email)` 是**普通 JS 比对**（无 setter）：
 *    用户提交"自己邮箱的大写形态"时若不归一化就会判成"被他人占用"（实测过）。
 * ② 查重改走 **emailKey**（A3）：email 列已加密，明文相等性在随机 IV 的密文列上
 *    不成立。局部变量刻意叫 `normalizedEmail` 而**不叫** `emailKey`——后者现在是
 *    schema 上的 HMAC 字段名，同名不同义极易写出 `user.emailKey = <小写明文>`
 *    这种把明文写进检索键列的 bug（旧代码正是这个名字）。
 */
async function isEmailTakenByAnother(user, normalizedEmail) {
  if (!normalizedEmail || normalizedEmail === normalizeEmailKey(user.email)) return false;
  const existingUser = await User.findOne({ emailKey: piiSearchKey(normalizedEmail) });
  return Boolean(existingUser);
}

/**
 * 更新允许的字段（白名单，非黑名单）。
 * department 不在其列——见 updateUserProfile 函数头的 H-01 说明；
 * 它是授权范围来源，只能由管理员改。
 */
function assignProfileFields(user, { realName, email, phone, avatar }, normalizedEmail) {
  if (realName !== undefined) user.realName = realName;
  // 赋归一化后的明文（不是 emailKey）：写侧钩子负责加密并同步 HMAC 键与 n-gram，
  // 落库的 email 是密文。这里若赋原样串，钩子也会再归一化一次——赋值取规范形态
  // 只是让"内存里的值"与"落库明文"始终一致，便于紧邻的比对判据阅读。
  if (email !== undefined) user.email = normalizedEmail;
  if (phone !== undefined) user.phone = phone;
  if (avatar !== undefined) user.avatar = avatar;
}

async function updateUserProfile(userId, body) {
  // 注意：不解构 department——即使请求体携带该字段也会被静默忽略（不报错，
  // 避免向调用方暴露"该字段不可改"的实现细节）
  const { realName, email, phone, avatar } = body;

  // 排除投影不可省：这里后面是 user.save()，不写投影时 Mongoose 会把未加载的
  // 凭证列按 schema 默认值写回 $set（机理见 models/User.js 的 unselectedCredentialProjection）
  const user = await User.findById(userId).select(User.unselectedCredentialProjection());
  if (!user) {
    return { outcome: 'NOT_FOUND' };
  }

  const invalid = validateProfileInput({ email, phone, avatar });
  if (invalid) {
    return { outcome: invalid };
  }

  const normalizedEmail = normalizeEmailKey(email);
  if (await isEmailTakenByAnother(user, normalizedEmail)) {
    return { outcome: 'EMAIL_TAKEN' };
  }

  assignProfileFields(user, { realName, email, phone, avatar }, normalizedEmail);

  await user.save();

  logger.info('用户更新了个人资料', { username: user.username });

  return {
    outcome: 'OK',
    profile: {
      userId: user._id,
      username: user.username,
      realName: user.realName,
      email: user.email,
      phone: user.phone,
      department: user.department,
      avatar: user.avatar,
    },
  };
}

/**
 * 管理员锁定/解锁用户账户（O-2 自 securityController.toggleUserLock 下沉）
 *
 * 业务规则原样迁移：层级校验（同级及以上拦截，含 isSelf 豁免）、内置超管
 * 锁定拒绝、inactive 双向状态机保护（禁用账户不可借解锁复活、亦不可重复
 * 锁定）、成功后缓存失效与专用审计落库。控制器只保留参数校验与
 * outcome → HTTP 响应映射，行为口径与迁移前逐项一致
 * （controllers/securityControllerOutcomeAndGuards.test.js 的 toggleUserLock 分支为安全网）。
 *
 * @param {string} userId 目标用户 ID
 * @param {object} params { locked: boolean, reason?: string }
 * @param {object} ctx { operatorId, operatorUsername, ip, userAgent }
 * @returns {Promise<{outcome:'NOT_FOUND'|'FORBIDDEN_SAME_LEVEL'|'CANNOT_LOCK_SUPER_ADMIN'|'INACTIVE_UNLOCK'|'INACTIVE_LOCK'|'NOT_LOCKED'|'OK', ...}>}
 */
/**
 * 锁定/解锁的三类拒绝判据（层级 → 内置超管 → inactive 双向状态机），顺序即原实现顺序。
 *
 * @returns {string|null} 拒绝时的 outcome，通过时 null
 */
function checkLockTransitionAllowed(
  user,
  { locked, targetUserRoles, targetMaxLevel, operatorMaxLevel, operatorId }
) {
  // 禁止操作同级或更高级别的用户（isSelf 例外）
  if (targetMaxLevel >= operatorMaxLevel && String(user._id) !== String(operatorId)) {
    return 'FORBIDDEN_SAME_LEVEL';
  }

  // 禁止锁定超级管理员（无 isSelf 例外：锁定后层级校验会拦下所有解锁尝试）
  if (locked && targetUserRoles.some(isSuperAdminRole)) {
    return 'CANNOT_LOCK_SUPER_ADMIN';
  }

  // 仅当账户当前确实处于锁定态时才允许解锁并恢复为 active；
  // 管理员禁用（inactive）的账户不允许借“解锁”复活，需先由管理员通过用户更新接口恢复启用
  if (!locked && user.status === 'inactive') return 'INACTIVE_UNLOCK';
  if (!locked && user.status !== 'locked') return 'NOT_LOCKED';
  // 锁定方向同样拒绝已禁用账户：若允许 inactive → locked，
  // 后续“锁定→解锁”链路会把禁用账户洗回 active，变相复活被禁用账户
  if (locked && user.status === 'inactive') return 'INACTIVE_LOCK';
  return null;
}

/**
 * 状态与 lockUntil 的**写入计划**（纯函数，可单测）。
 *
 * 解锁必须连**临时锁定**一起清掉。两套锁定是分开的：管理员锁定改 status，
 * 暴力破解阈值只写 lockUntil。而 authenticate（middleware/auth.js:297，经
 * assertAccountUsable）与 loginUser（:350）都只看 lockUntil 就拒绝登录。
 * 因此"先被爆破锁定、再被管理员锁定"的账户，此前解锁只改回 status ⇒
 * 接口 200「用户已解锁」+ 审计 success:true，用户依然登不进来（且活令牌全部 403），
 * 运维只会去怀疑密码。与"改密假成功"同一类：**报告了没做到的事**。
 */
function planLockStateChange({ locked, reason }) {
  const plan = {
    status: locked ? 'locked' : 'active',
    clearTemporaryLock: !locked,
  };
  if (locked && reason) plan.remark = reason;
  return plan;
}

/** 把写入计划落到文档上（只碰计划里明确列出的字段，未列出的保持原值） */
function applyLockStatePlan(user, plan) {
  user.status = plan.status;
  if (plan.clearTemporaryLock) {
    user.lockUntil = null;
    user.failedLoginCount = 0;
  }
  if (plan.remark !== undefined) user.remark = plan.remark;
}

async function setUserLockStatus(userId, { locked, reason }, ctx) {
  const { operatorId, operatorUsername, ip, userAgent } = ctx;

  // 同 updateUserProfile：本函数末尾是 user.save()，载入端必须排除凭证列，
  // 否则锁定/解锁一次就把 MFA 配置与口令历史写回默认值
  const user = await User.findById(userId).select(User.unselectedCredentialProjection());
  if (!user) {
    return { outcome: 'NOT_FOUND' };
  }

  // 层级校验：禁止锁定/解锁等于或高于自身层级的用户
  // select 必须包含 isBuiltIn，否则下方内置超管保护判断恒为 false（死代码）
  const targetUserRoles = await Role.find({ _id: { $in: user.roles } }).select(
    'level code isBuiltIn'
  );
  const targetMaxLevel = maxRoleLevel(targetUserRoles);

  // 按操作者 ID 重新查询角色层级（req.user.roles 存的是角色编码字符串，
  // 直接用于 _id: {$in: ...} 会触发 CastError，导致整个接口 500）
  const operatorMaxLevel = await getOperatorMaxLevel(operatorId);

  const denial = checkLockTransitionAllowed(user, {
    locked,
    targetUserRoles,
    targetMaxLevel,
    operatorMaxLevel,
    operatorId,
  });
  if (denial) {
    return { outcome: denial };
  }

  applyLockStatePlan(user, planLockStateChange({ locked, reason }));

  await user.save();

  // 失效用户缓存（与原实现一致：惰性 require，规避 middleware ↔ service 潜在循环）
  const { invalidateUserCache } = require('../../middleware/auth');
  invalidateUserCache(user._id);
  // 锁定/解锁影响用户统计，目标用户与操作者（统计视角）的统计缓存均需失效
  const statsCache = require('../statsCache');
  statsCache.invalidateByUserId(user._id);
  statsCache.invalidateByUserId(operatorId);

  // 注意：不将用户级锁定关联到 IP 黑名单，避免误封 NAT 出口（原样保留）

  // 记录审计日志
  await AuditLog.create({
    action: locked ? 'user_locked' : 'user_unlocked',
    category: 'user',
    userId: operatorId,
    username: operatorUsername,
    targetUserId: user._id,
    targetUsername: user.username,
    reason,
    ip,
    userAgent,
    success: true,
    riskLevel: 'high',
    // 本函数没有 req（只有 ctx），按 onAuditWriteFailure 的取用形态传入操作者
  }).catch(onAuditWriteFailure('user_lock_status', { user: { username: operatorUsername } }));

  logger.info('用户锁定状态变更', { username: user.username, locked, operator: operatorUsername });

  return {
    outcome: 'OK',
    userId: user._id,
    username: user.username,
    status: user.status,
    locked,
  };
}

module.exports = {
  updateUserProfile,
  setUserLockStatus,
};
