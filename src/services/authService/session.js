/**
 * 注册与登录会话/令牌签发
 *
 * 自 authService.js 拆出。issueRevocableTokenPair 是「注册成功即建会话」与
 * 「登录成功即签发令牌对」两条路径共用的那一段，故与注册放在一起，不与
 * refresh 侧的轮换逻辑混在一处——后者是另一个生命周期（见 token.js）。
 */

const crypto = require('crypto');
const User = require('../../models/User');
const Role = require('../../models/Role');
const logger = require('../../utils/logger');
const { validatePasswordStrength } = require('../../utils/helpers');
const { checkUnusualTime } = require('../securityAlert');
const canaryWatch = require('../canaryWatch');
const AuditLog = require('../../models/AuditLog');
// P0-5 后手写审计写入是这些操作的唯一留痕，静默吞错＝审计库零痕迹（且无可观测信号）
const { onAuditWriteFailure } = require('../../utils/auditWriteFailure');
const captchaService = require('../captchaService');
const { decryptLoginCredential } = require('../../utils/loginCipher');
// A3：email 已 at-rest 加密，查重不能再比对明文列（随机 IV 下相等性不成立），
// 统一走 HMAC 检索键 emailKey。piiSearchKey 的归一化口径（trim+lowercase）与
// normalizeEmailKey 一致，两者在同一个查询里可互换——但语义不同，见 utils/emailKey.js。
const { piiSearchKey } = require('../../utils/piiCrypto');
const sessionService = require('../sessionService');
const { generateToken, generateRefreshToken } = require('../tokenService');

/**
 * 用户注册（业务层）
 * @param {object} body 请求体
 * @param {object} [ctx] `{ req }`：注册成功即建立会话，UserSession 的 ip / UA / 设备指纹
 *   都只能从真实请求对象取（见 sessionService.createSession），没有 req 时按既有降级口径
 *   签发不可吊销的令牌
 * @returns {Promise<{outcome:'CAPTCHA_INVALID'|'ENC_INVALID'|'WEAK'|'DUPLICATE'|'OK'}>}
 *   OK 时附 { userId, username, email, token, refreshToken }
 */
async function registerUser(body, ctx = {}) {
  // 前置人机校验：注册接口强制图形验证码（后台可动态开关，默认开启）
  // 验证码错误/过期时直接拒绝，不进入用户名/邮箱查重与用户创建，
  // 也不计入后续统计——验证码层已挡住自动化批量注册
  const { captchaId, captchaText } = body;
  // 开关读取统一走 SystemConfig.captchaSwitch：DB 故障时降级为静态默认（fail-open）
  // 并留可告警信号。原先这里自带一份 try/catch，同一个降级动作在 3 个调用点各写一遍、
  // 且全都没有信号（见 models/SystemConfig.js 的 signalCaptchaSwitchFallback 说明）。
  const { SystemConfig: SysConfig } = require('../../models');
  const registerCaptchaEnabled = await SysConfig.captchaSwitch('register');
  if (registerCaptchaEnabled && !(await captchaService.verify(captchaId, captchaText))) {
    return { outcome: 'CAPTCHA_INVALID' };
  }

  const { username, email, realName, phone, department } = body;

  // 哨兵用户名（canary）闸：系统保留名不经注册进入用户集合——幽灵名的价值
  // 完全建立在"不可能是真账号"上，注册通过即把哨兵变成普通用户（启动期
  // 遮蔽对账会把这种状态告警，但不该先把库写脏）。对外与重名同口径
  // （模糊拒绝防枚举，且不新增 outcome，credentials 层 switch 不动）；
  // 探测方的尝试会在登录路径被 canaryWatch 记录与告警。
  if (canaryWatch.matchCanaryName(username)) {
    logger.warn('注册被拒 - 用户名为安全哨兵保留名', { username });
    return { outcome: 'DUPLICATE' };
  }

  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  let password;
  if (typeof body.encPassword === 'string' && body.encPassword) {
    try {
      password = await decryptLoginCredential(body.encPassword, 'REGISTER');
    } catch (err) {
      logger.warn('注册拒绝 - 口令密文无效', { username, code: err.code });
      return { outcome: 'ENC_INVALID' };
    }
    // 密文轨的强度校验在解密后补做（校验层只见密文，无法评估强度）
    const encStrengthError = validatePasswordStrength(password);
    if (encStrengthError) {
      return { outcome: 'WEAK', message: encStrengthError };
    }
  } else {
    password = body.password; // 明文兼容轨（强度已由校验层把关）
  }

  // 检查用户名是否已存在（统一返回模糊提示，防止枚举探测有效用户名/邮箱）
  // P3-30：拆成两次查询而非 $or 单查——username 判重必须带 collation（大小写不敏感），
  // 而带 collation 的查询无法命中默认 collation 的索引，合并写会让另一分支退化。
  // A3（2026-10-16）：邮箱分支改查 **emailKey**（HMAC 检索键）。原先查的是明文
  // `email_1` 索引，而 email 列已加密（随机 IV）——明文相等性在密文列上不再成立，
  // 继续查明文列会**恒不命中**，表现为「注册时重名邮箱能通过判重」。
  // 归一化由 piiSearchKey 内部完成（trim + lowercase），与落库键同口径。
  const [existingByName, existingByEmail] = await Promise.all([
    User.findByUsername(username).select('_id').lean(),
    User.findOne({ emailKey: piiSearchKey(email) })
      .select('_id')
      .lean(),
  ]);
  if (existingByName || existingByEmail) {
    return { outcome: 'DUPLICATE' };
  }

  // 安全修复：先查默认角色，在 create 时一次性写入 roles，避免两步写入产生孤儿用户
  const defaultRole = await Role.findOne({ code: 'GUEST' }).select('_id code').lean();
  const roleIds = defaultRole ? [defaultRole._id] : [];

  // 创建用户（一次性写入角色，避免 create 后 save 失败导致无角色用户）
  const user = await User.create({
    username,
    email,
    password,
    realName,
    phone,
    department,
    roles: roleIds,
  });

  // 注册成功即建立会话：注册后立即登录无需再次输密码。
  // 「建立会话」得真的建立——与登录走同一段 sid + UserSession 落库（判据与降级方向
  // 见 issueRevocableTokenPair）：只签令牌而不落库，这条登录态在「登录会话」界面里
  // 不存在、踢不掉，且不带 sid 的 refresh 轮换会一路自我续期而永不过期。
  const regRoles = defaultRole ? [defaultRole.code] : [];
  const { token, refreshToken, sid, sessionRegistered } = await issueRevocableTokenPair({
    user,
    roles: regRoles,
    req: ctx.req,
  });

  logger.info('新用户注册', { username });

  return {
    outcome: 'OK',
    userId: user._id,
    username: user.username,
    email: user.email,
    token,
    refreshToken,
    // 调用方（控制器）不消费这两个键，但降级必须可判定：sid 为 null 就是"这次注册
    // 没有可吊销会话"，测试与后续治理据此区分正常路径与落库失败路径
    sid,
    sessionRegistered,
  };
}
/**
 * 签发「与一条 UserSession 记录绑定」的令牌对（登录与注册共用同一段实现）
 *
 * 为什么必须共用：`sid` 的语义是"跨 refresh 轮换保持不变 ⇒ 踢掉某台设备后那台设备
 * 刷新令牌也无法复活"，而"落库失败就退回不带 sid 的令牌"是这条语义的唯一兜底。
 * 两处 mint 各抄一份时，注册路径正是漏抄的那一份（F-175）：它既不建 UserSession，
 * 签出的 refresh 令牌却能一路自续下去——`refreshSession` 里的 `if (rotateSid)`
 * 对无 sid 的令牌整段跳过，于是每次轮换再签一对新的无 sid 7 天令牌。结果是这条
 * 血统不出现在「登录会话」界面、点不掉，也只有改密码（tokenVersion）才能终止，
 * 而 auth.js 对无 sid 令牌的承诺是"最长在 refresh 有效期后自然消亡"——被无限轮换
 * 续下去的令牌不消亡。共用之后，新增的登录态一律可吊销；降级只保留给真正的
 * 落库失败（那一条仍属无上限血统，见交接的待拍板项）。
 *
 * 降级方向是"少给一份可吊销性"而不是"拒绝这次登录/注册"，理由见
 * issueLoginSession 的 JSDoc；`sid` 返回 null 让调用方能看得见降级发生了。
 *
 * @returns {Promise<{token:string, refreshToken:string, sessionId:string, sid:string|null, sessionRegistered:boolean}>}
 */
async function issueRevocableTokenPair({ user, roles, req }) {
  // 同一个 UUID 同时作为审计用的 sessionId 与会话表的 sid：两者语义一致（都标识本次
  // 登录），分开生成只会让审计日志的 sessionId 与 UserSession.sid 无法对应，事后追溯断链。
  const sessionId = crypto.randomUUID();
  const tokenVersion = user.tokenVersion ?? 0;
  let sessionRegistered = false;
  try {
    await sessionService.createSession({ userId: user._id, req, sid: sessionId });
    sessionRegistered = true;
  } catch (e) {
    logger.error(`会话注册失败（本次签发降级为无设备级吊销能力）：${e.message}`, {
      userId: String(user._id),
    });
  }
  const sid = sessionRegistered ? sessionId : null;
  return {
    token: generateToken(
      user._id,
      user.username,
      user.email,
      roles,
      user.realName,
      tokenVersion,
      sessionId,
      sid
    ),
    refreshToken: generateRefreshToken(user._id, tokenVersion, sid),
    sessionId,
    sid,
    sessionRegistered,
  };
}

/**
 * 登录成功后的收尾（E-01 自 loginUser 拆出）：非常规时间审计、登录信息更新、
 * 角色权限读取、令牌签发、设备会话注册与成功审计。
 *
 * 会话注册表落库失败不阻断登录，但要降级为「令牌不含可吊销会话」：若此处失败
 * 仍下发带 sid 的令牌，authenticate 会因查不到会话而拒绝该令牌，用户登录成功
 * 却立刻无法访问任何接口——比「本次登录不支持设备级吊销」严重得多。
 */
async function issueLoginSession(user, ctx, username) {
  const { ip, userAgent, fingerprint } = ctx;

  // 检查非常规时间登录
  const { isUnusual, hour } = checkUnusualTime();
  if (isUnusual) {
    logger.info('非常规时间登录', { username, hour });
    // 记录非常规时间访问日志
    await AuditLog.create({
      action: 'login_unusual_time',
      category: 'auth',
      userId: user._id,
      username,
      ip,
      userAgent,
      riskLevel: 'medium',
      riskFactors: ['unusual_time_access'],
      body: { loginHour: hour },
    }).catch(onAuditWriteFailure('login_unusual_time'));
  }

  // 更新登录信息（使用 findByIdAndUpdate 避免触发完整 pre-save 钩子）
  await User.findByIdAndUpdate(user._id, {
    lastLoginAt: new Date(),
    lastLoginIp: ip,
    failedLoginCount: 0,
    lockUntil: null,
  });

  // 获取用户角色和权限（仅生效角色/权限项：登录响应即客户端权限快照，
  // 若含停用角色，前端会渲染出服务端必然 403 的控件）
  const populatedUser = await User.findById(user._id).populate({
    path: 'roles',
    select: 'name code',
    match: { status: 'active' },
    populate: { path: 'permissions', select: 'code', match: { status: 'active' } },
  });
  // 安全修复：populate 后可能存在 null（指向已删除角色的 ObjectId），需过滤
  const roles = populatedUser.roles.map((r) => r?.code).filter(Boolean);
  const permissions = [
    ...new Set(populatedUser.roles.flatMap((r) => r?.permissions?.map((p) => p.code) || [])),
  ];

  // 令牌签发 + 设备会话注册：与注册路径共用同一段实现（见 issueRevocableTokenPair），
  // 免得"sid 语义"与"落库失败怎么降级"这两条判据各抄一份后各自漂移。
  const {
    token: issuedToken,
    refreshToken: issuedRefreshToken,
    sessionId,
  } = await issueRevocableTokenPair({ user, roles, req: ctx.req });

  logger.info('用户登录成功', { username });

  // 操作溯源：记录登录成功
  AuditLog.recordLogin(user._id, username, ip, true, userAgent, { sessionId, fingerprint }).catch(
    onAuditWriteFailure('login_success_audit', { user: { username } })
  );

  return {
    outcome: 'OK',
    token: issuedToken,
    refreshToken: issuedRefreshToken,
    user: {
      userId: user._id,
      username: user.username,
      email: user.email,
      realName: user.realName,
      roles,
      permissions,
    },
  };
}

module.exports = {
  registerUser,
  issueLoginSession,
};
