/**
 * 登录/MFA 失败计数口径 + 二段校验（MFA TOTP 与恢复码）
 *
 * 自 authService.js 拆出。失败阈值、锁定时长与「计数读不到即按已达阈值处理」
 * 的 fail-closed 解析规则是**一处口径**：口令主路径（login.js）与 MFA/恢复码
 * 累计路径（本文件）共用同一份常量与同一个解析函数，两边各写一遍必然漂移——
 * 漂移的后果是其中一条路径的防线阈值被悄悄抬高。
 * 本文件因此对内不引用 login.js，避免与登录主流程形成循环依赖。
 */

const User = require('../../models/User');
const logger = require('../../utils/logger');
const AuditLog = require('../../models/AuditLog');
const { verifyTotpDetailed } = require('../../utils/totp');
const { decryptMfaSecret } = require('../../utils/mfaSecret');
const {
  isMfaLocked,
  recordMfaFailure,
  resetMfaFailures,
  hashRecoveryCode,
} = require('../mfaService');

// 登录失败计数阈值与锁定时长（原为 loginUser 内的局部常量，现提到
// 模块级，供 verifyPasswordOrTrackFailure / incrementFailedLoginCount 共用）
const MAX_FAILED_LOGINS = 10;
const LOCK_DURATION_MS = 10 * 60 * 1000;

/**
 * 失败计数的解析规则（口令错误主路径与 MFA/恢复码累计路径共用同一判据）
 *
 * 计数写不进库时按「已达阈值」处理（fail-closed），与 mfaService.recordMfaFailure 同口径。
 * 旧实现的两处兜底方向都反了：一处 `?? 1`（读不到计数 = 第一次失败），
 * 一处「用请求早先读到的陈旧快照 +1」（写路径持续失败时那个快照永不变，等效卡在 1）。
 * 后果同形：Mongo 可读不可写（主从切换 / 写关注失败）的窗口里，攻击者对已知用户名
 * 连续试错，计数永远落不了库 ⇒ 阈值永远到不了 ⇒ 账户临时锁定与自动封禁两道防线
 * 同时静默消失，只剩 IP 限流。观测不到防线时要收紧，不能假定防线还在。
 *
 * 代价如实写明：DB 写故障期间的正当用户会被锁 10 分钟。这与 MFA 侧已作出的取舍一致。
 */
const resolveFailedLoginCount = (updated) =>
  typeof updated?.failedLoginCount === 'number' ? updated.failedLoginCount : MAX_FAILED_LOGINS;
/**
 * MFA 二期验证（自 loginUser 拆出）：TOTP 动态口令或备用恢复码二选一。
 *
 * 独立防爆破：6 位码空间小，除 failedLoginCount 外另有 MFA 专用阈值（见
 * mfaService），锁定期间直接拒绝，攻击者持正确密码也无法对 6 位码无限尝试。
 * 支持 6 位 TOTP 或备用恢复码（XXXX-XXXX）二选一：手机丢失/换机时的恢复途径。
 *
 * @returns {Promise<{outcome:'MFA_REQUIRED'|'MFA_ATTEMPTS_EXCEEDED'|'MFA_CODE_INVALID'|'OK'}>}
 */
async function verifyMfaChallenge(user, { mfaCodeRaw, username, ctx }) {
  const { ip, userAgent, fingerprint } = ctx;
  const mfaCode = typeof mfaCodeRaw === 'string' ? mfaCodeRaw.trim() : '';
  if (!mfaCode) {
    await AuditLog.record({
      action: 'mfa_challenge',
      category: 'auth',
      userId: user._id,
      username,
      ip,
      userAgent,
      fingerprint,
      success: true,
      reason: '密码已验证，等待两步验证码',
    }).catch(() => {});
    return { outcome: 'MFA_REQUIRED' };
  }
  // MFA 验证码独立防爆破：锁定期内直接拒绝（与 failedLoginCount 双轨，
  // 攻击者持正确密码时也无法对 6 位码无限尝试）
  if (await isMfaLocked(user._id)) {
    logger.warn('登录拒绝 - MFA 验证通道锁定中', { username });
    await AuditLog.record({
      action: 'mfa_verify_failed',
      category: 'auth',
      userId: user._id,
      username,
      ip,
      userAgent,
      fingerprint,
      success: false,
      riskLevel: 'high',
      riskFactors: ['mfa_bruteforce'],
      reason: 'MFA 验证通道锁定期间尝试登录',
    }).catch(() => {});
    return { outcome: 'MFA_ATTEMPTS_EXCEEDED' };
  }

  // L5：重放防护——验证码命中的时间窗必须晚于最近一次成功使用的窗口；
  // 失败与密码错误同口径计入 failedLoginCount，连续失败触发账户锁定。
  // 支持 6 位 TOTP 或备用恢复码（XXXX-XXXX）二选一：手机丢失/换机时的恢复途径
  const mfaUser = await User.findById(user._id).select(
    '+mfaSecret +mfaLastCounter +mfaRecoveryCodes'
  );

  const result = /^\d{6}$/.test(mfaCode)
    ? await verifyTotpChallenge(user, { mfaCode, mfaUser, username, ctx })
    : await verifyRecoveryCodeChallenge(user, { mfaCode, username, ctx });
  if (result.outcome !== 'OK') return result;

  await resetMfaFailures(user._id);

  // mfaLastCounter 已在上方的原子条件更新中推进，此处无需再写
  // （原实现在此无条件覆写，正是 TOTP 双花的成因之一）
  return { outcome: 'OK' };
}

/**
 * TOTP 动态口令校验（二级拆分，控制圈复杂度）
 *
 * 重放防护必须原子。原实现「读 mfaLastCounter → 比较 → 事后无条件覆写」
 * 三步分离，两个携带同一有效验证码的并发请求都会读到旧 counter、都判定通过，
 * 造成 TOTP 双花（同一 6 位码换取两个会话）。现改为条件更新：以
 * `mfaLastCounter < counter` 为过滤条件推进，只有第一个请求能命中（DB 保证），
 * 其余落入重放分支；与恢复码的原子消费（$pull 条件过滤）口径一致。
 */
async function verifyTotpChallenge(user, { mfaCode, mfaUser, username, ctx }) {
  const { ip, userAgent, fingerprint } = ctx;
  const totpResult = verifyTotpDetailed(decryptMfaSecret(mfaUser?.mfaSecret), mfaCode);
  // 修复：重放防护必须原子。原实现「读 mfaLastCounter → 比较 → 事后无条件覆写」
  // 三步分离，两个携带同一有效验证码的并发请求都会读到旧 counter、都判定通过，
  // 造成 TOTP 双花（同一 6 位码换取两个会话）。
  // 现改为条件更新：以 `mfaLastCounter < counter` 为过滤条件推进，
  // 只有第一个请求能命中（DB 保证），其余落入重放分支。
  // 与恢复码的原子消费（下方 $pull 条件过滤）口径一致。
  let claimedCounter = false;
  if (totpResult.valid) {
    const advanced = await User.findOneAndUpdate(
      {
        _id: user._id,
        $or: [
          { mfaLastCounter: { $lt: totpResult.counter } },
          { mfaLastCounter: { $exists: false } },
          { mfaLastCounter: null },
        ],
      },
      { $set: { mfaLastCounter: totpResult.counter } },
      { new: true }
    ).catch(() => null);
    claimedCounter = !!advanced;
  }

  const replayed = totpResult.valid && !claimedCounter;
  if (!totpResult.valid || replayed) {
    logger.warn(`登录失败 - 两步验证码${replayed ? '重放' : '错误'}`, { username });
    // 原子递增 + 阈值锁定（与口令失败路径同口径；抽为共用 helper）
    await incrementFailedLoginCount(user, { username, lockReason: 'MFA 失败累计' });
    // 独立防爆破计数（6 位码空间小，必须有独立阈值）
    await recordMfaFailure(user);
    await AuditLog.record({
      action: 'mfa_verify_failed',
      category: 'auth',
      userId: user._id,
      username,
      ip,
      userAgent,
      fingerprint,
      success: false,
      riskLevel: replayed ? 'high' : 'medium',
      riskFactors: [replayed ? 'mfa_code_replay' : 'mfa_code_invalid'],
      reason: replayed ? '两步验证码重放' : '两步验证码错误',
    }).catch(() => {});
    return { outcome: 'MFA_CODE_INVALID' };
  }
  return { outcome: 'OK' };
}

/**
 * 备用恢复码校验（二级拆分，控制圈复杂度）：格式 XXXX-XXXX，命中即消费。
 *
 * 原子消费：以「数组中仍含该摘要」为过滤条件执行 $pull 并要求命中——消除
 * check 与 pull 分离导致的并发双花窗口；未命中即视为无效。
 *
 * 必须用 findOneAndUpdate 而非 findByIdAndUpdate（Critical 修复）：
 * findByIdAndUpdate 只从第一参取 _id，其余键被**静默丢弃**——实测传
 * { _id, mfaRecoveryCodes: '不存在的摘要' } 依然返回文档，于是任意「格式合法」的
 * 恢复码都能通过校验并签发会话，等同于对所有已开启 MFA 的账户完全绕过两步验证。
 */
async function verifyRecoveryCodeChallenge(user, { mfaCode, username, ctx }) {
  const { ip, userAgent, fingerprint } = ctx;
  // 备用恢复码路径：格式 XXXX-XXXX，命中即消费（一次性）
  const normalized = mfaCode.toUpperCase().replace(/\s/g, '');
  // 辅助函数：恢复码失败时统一记录（增量 failedLoginCount + MFA 独立计数），
  // 与上方 6 位 TOTP 错误路径保持口径一致，消除"恢复码爆破不触发账户锁定"的逻辑漏洞
  // 恢复码失败统一记录（增量 failedLoginCount + MFA 独立计数 + 审计），
  // 与 6 位 TOTP 错误路径保持口径一致，消除「恢复码爆破不触发账户锁定」的漏洞
  const handleRecoveryFailure = (riskFactors, reason) =>
    recordRecoveryFailure(user, { username, ip, userAgent, fingerprint }, riskFactors, reason);
  if (!/^[A-HJ-KM-NP-Z2-9]{4}-[A-HJ-KM-NP-Z2-9]{4}$/.test(normalized)) {
    await handleRecoveryFailure(['recovery_code_invalid'], '恢复码格式无效');
    return { outcome: 'MFA_CODE_INVALID' };
  }
  const codeHash = hashRecoveryCode(normalized);
  // 原子消费：以「数组中仍含该摘要」为过滤条件执行 $pull 并要求命中——
  // 消除 check 与 pull 分离导致的并发双花窗口；未命中即视为无效。
  //
  // 必须用 findOneAndUpdate 而非 findByIdAndUpdate（Critical 修复）：
  // findByIdAndUpdate 只从第一参取 _id，其余键被**静默丢弃**——
  // 实测传 { _id, mfaRecoveryCodes: '不存在的摘要' } 依然返回文档，
  // 于是任意「格式合法」的恢复码都能通过校验并签发会话，
  // 等同于对所有已开启 MFA 的账户完全绕过两步验证。
  const consumed = await User.findOneAndUpdate(
    { _id: user._id, mfaRecoveryCodes: codeHash },
    { $pull: { mfaRecoveryCodes: codeHash } },
    { new: true, select: '+mfaRecoveryCodes' }
  ).catch(() => null);
  if (!consumed) {
    logger.warn('登录失败 - 备用恢复码无效', { username });
    await handleRecoveryFailure(['recovery_code_invalid'], '备用恢复码不匹配');
    return { outcome: 'MFA_CODE_INVALID' };
  }

  const remaining = Array.isArray(consumed.mfaRecoveryCodes) ? consumed.mfaRecoveryCodes.length : 0;
  if (remaining <= 3) {
    logger.warn('备用恢复码余量不足', { username, remaining });
  }
  await AuditLog.record({
    action: 'login_recovery_code',
    category: 'auth',
    userId: user._id,
    username,
    ip,
    userAgent,
    fingerprint,
    success: true,
    riskLevel: 'medium',
    riskFactors: ['recovery_code_used'],
    reason: `使用备用恢复码登录（剩余 ${remaining} 个）`,
  }).catch(() => {});
  return { outcome: 'OK' };
}

/**
 * 恢复码失败统一记录（自 loginUser 内的局部闭包提到模块级）
 *
 * 与 TOTP 错误路径同口径：增量 failedLoginCount + MFA 独立计数 + 审计。
 * riskFactors/reason 由调用方区分「格式无效」与「不匹配」两种情况。
 */
async function recordRecoveryFailure(
  user,
  { username, ip, userAgent, fingerprint },
  riskFactors,
  reason
) {
  await incrementFailedLoginCount(user, { username, lockReason: '恢复码验证失败累计' });
  await recordMfaFailure(user);
  await AuditLog.record({
    action: 'mfa_verify_failed',
    category: 'auth',
    userId: user._id,
    username,
    ip,
    userAgent,
    fingerprint,
    success: false,
    riskLevel: 'high',
    riskFactors,
    reason,
  }).catch(() => {});
}

/**
 * 登录失败计数原子递增 + 阈值锁定（抽出，MFA 两条失败路径共用）
 *
 * $inc 由 DB 保证无丢失更新：读-算-写竞态会让并发请求基于陈旧计数互相覆盖，
 * 丢失更新导致锁定阈值被推迟，利于爆破。阈值判定可能并发重复触发，但
 * lockUntil 覆写幂等，审计重复仅产生冗余日志，可接受。
 *
 * 补 lockExpired 重置，与口令路径
 * （verifyPasswordOrTrackFailure 内 :403-410）对齐。MFA 两条失败路径
 * 此前只做纯 $inc：此前 10 分钟锁定刚过期时，旧计数会继续累计——
 * 解锁后仅剩 1 次试错即再次锁定，对正常用户表现为「输错一次就锁」。
 * 已过期的 lockUntil 视为新一轮：重置计数从 1 起算并清空过期时间戳。
 * 走到本函数时 lockUntil 必为空或已过期（loginUser ③ 已在锁定期间提前返回），
 * 故该判断不会误伤「锁定仍生效」的场景。
 *
 * @returns {Promise<number>} 递增后的失败计数
 */
async function incrementFailedLoginCount(user, { username, lockReason }) {
  const lockExpired = user.lockUntil && user.lockUntil <= new Date();
  const updated = await User.findByIdAndUpdate(
    user._id,
    lockExpired
      ? { $set: { failedLoginCount: 1, lockUntil: null } }
      : { $inc: { failedLoginCount: 1 } },
    { new: true }
  ).catch(() => null);
  const newCount = resolveFailedLoginCount(updated);
  if (newCount >= MAX_FAILED_LOGINS) {
    // 与上面 checkBruteForce 里的同一条修法（本函数是它的第二条登录失败路径）：
    // 锁定写不进库时不得照常写下「账户临时锁定」——读日志的人会以为防线还在。
    let lockApplied = true;
    await User.findByIdAndUpdate(user._id, {
      lockUntil: new Date(Date.now() + LOCK_DURATION_MS),
    }).catch((err) => {
      lockApplied = false;
      logger.error(`账户临时锁定写入失败（防爆破防线未生效）：${err.message}`, { username });
    });
    logger.warn(`账户临时锁定（${lockReason}）`, {
      username,
      failedCount: newCount,
      lockApplied,
    });
  }
  return newCount;
}

module.exports = {
  MAX_FAILED_LOGINS,
  LOCK_DURATION_MS,
  resolveFailedLoginCount,
  incrementFailedLoginCount,
  verifyMfaChallenge,
};
