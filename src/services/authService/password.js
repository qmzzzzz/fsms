/**
 * 口令变更
 *
 * 自 authService.js 拆出。改密的三段判据（密文解密、口令策略与历史、口令轮换后的会话吊销）此前与登录流程同处一个文件，实测互相之间零引用。
 */

const User = require('../../models/User');
const logger = require('../../utils/logger');
const { validatePasswordStrength } = require('../../utils/helpers');
const { matchesHistory, withPrevious, HISTORY_DEPTH } = require('../../utils/passwordHistory');
const { invalidateUserTokens } = require('../../middleware/tokenBlacklist');
const bcryptWorker = require('../../utils/bcryptWorkerPool');
const config = require('../../config');
const { decryptLoginCredential } = require('../../utils/loginCipher');
const sessionService = require('../sessionService');
const initialPasswordFile = require('../initialPasswordFile');

/**
 * 解出一段口令：密文轨优先，回落到明文轨。
 *
 * 双轨并存期（LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）两条轨解出的值同权，后续的非空/强度/复用校验对二者一视同仁——所以这里只负责"拿到明文"，不在这里判空（`MISSING` 要等两段都解完再判，否则"密文轨失败"会被误报成"没填"）。
 *
 * @param {unknown} encValue 密文轨字段值
 * @param {unknown} plainValue 明文轨字段值
 * @param {'PASSWORD_CURRENT'|'PASSWORD_NEW'} purpose 解密用途（参与 AAD，两段不可互换）
 * @param {string} label 日志里的人话标签（"当前口令" / "新口令"）
 * @param {{username: string}} ctx
 * @returns {Promise<{ok: true, value: unknown}|{ok: false, outcome: 'ENC_INVALID'}>}
 */
async function resolveCredentialTrack(encValue, plainValue, purpose, label, ctx) {
  if (typeof encValue !== 'string' || !encValue) {
    return { ok: true, value: plainValue };
  }
  try {
    return { ok: true, value: await decryptLoginCredential(encValue, purpose) };
  } catch (err) {
    logger.warn(`改密拒绝 - ${label}密文无效`, { username: ctx.username, code: err.code });
    return { ok: false, outcome: 'ENC_INVALID' };
  }
}

/**
 * 入参层校验：非空 → 确认一致性 → 强度策略。
 *
 * 顺序即优先级，且"确认密码"必须在**解密之后**才判：密文轨下明文只有解完才知道（评价报告 #15 收敛点：原 securityController 内联比对，密文轨下永远比的是密文）。客户端未携带 confirmPassword 时不强制——/api/auth/password 一直如此。
 *
 * @param {object} body 原始请求体
 * @param {unknown} currentPassword 已解出的当前口令
 * @param {unknown} newPassword 已解出的新口令
 * @returns {{outcome: string, message?: string}|null} 拒绝时返回 outcome 对象，放行返回 null
 */
function validatePasswordChangeInput(body, currentPassword, newPassword) {
  if (!currentPassword || !newPassword) {
    return { outcome: 'MISSING' };
  }
  if (
    typeof body.confirmPassword === 'string' &&
    body.confirmPassword &&
    body.confirmPassword !== newPassword
  ) {
    return { outcome: 'CONFIRM_MISMATCH' };
  }
  // 统一企业级密码强度策略
  const strengthError = validatePasswordStrength(newPassword);
  if (strengthError) {
    return { outcome: 'WEAK', message: strengthError };
  }
  return null;
}

/**
 * 账户层校验：存在 → 当前口令正确 → 与当前不同 → 不命中复用历史（HMAC 摘要集）→ 不是上一次管理员重置换掉的那一代口令。「与当前相同」（SAME_PASSWORD）与「与更早的相同」（PASSWORD_REUSED）是两件事，错误码必须分开：合并成一个码会让用户以为自己只是没改够。A→B→A 这种两步复用上面那条 SAME_PASSWORD 挡不住（当前口令是 B），只能靠查历史。
 * @param {object|null} user 已 select +password +passwordHistory 的文档
 * @param {unknown} currentPassword
 * @param {unknown} newPassword
 * @param {{username: string}} ctx
 * @returns {Promise<{outcome: string, historyDepth?: number}|null>}
 */
async function assertPasswordRotatable(user, currentPassword, newPassword, ctx) {
  if (!user) {
    return { outcome: 'USER_NOT_FOUND' };
  }
  const isMatch = await user.comparePassword(currentPassword);
  if (!isMatch) {
    return { outcome: 'CURRENT_WRONG' };
  }
  // 检查新密码是否与旧密码相同
  if (await user.comparePassword(newPassword)) {
    return { outcome: 'SAME_PASSWORD' };
  }
  if (matchesHistory(user.passwordHistory, newPassword)) {
    logger.warn(`改密拒绝 - 新口令命中复用历史（最近 ${HISTORY_DEPTH} 条）`, {
      username: ctx.username,
    });
    return { outcome: 'PASSWORD_REUSED', historyDepth: HISTORY_DEPTH };
  }
  if (await matchesRetiredPassword(user.passwordRetiredHash, newPassword)) {
    // 与 PASSWORD_REUSED 合并成一个 outcome：用户要做的动作完全相同（换一条没被重置掉的口令），
    // 拆码只会多一份前端文案；服务端日志里两个来源区分得开（ADR-016 记了这条取舍）。
    logger.warn('改密拒绝 - 新口令是管理员重置前的那一代口令（退役摘要命中）', {
      username: ctx.username,
    });
    return { outcome: 'PASSWORD_REUSED', historyDepth: HISTORY_DEPTH };
  }
  return null;
}

/**
 * 退役摘要比对（审计二-2）：管理员重置时被替换掉的那一代口令的 bcrypt 摘要留在
 * passwordRetiredHash，改密时对候选口令比对一次，命中即拒。必须用 bcrypt 而非复用历史的
 * HMAC：重置路径没有旧口令**明文**（口令一落库就是 bcrypt 摘要），算不出 HMAC。只留最近
 * 一条 ⇒ 成本上限一次比对（~250ms），且只出现在「曾被管理员重置过口令」的账户上。
 * 判不了（形态不对 / 比对抛错）按**放行**处理并留 error 日志：它是加强层，主防线是
 * 当前口令 + HMAC 历史，不能让一次数据形态异常把改密端点变成 DoS 面。
 */
async function matchesRetiredPassword(retiredHash, candidatePassword) {
  if (typeof retiredHash !== 'string' || !/^\$2[aby]\$/.test(retiredHash)) return false;
  if (typeof candidatePassword !== 'string' || !candidatePassword) return false;
  try {
    return await bcryptWorker.compare(candidatePassword, retiredHash);
  } catch (err) {
    logger.error(`退役摘要比对失败，本条按放行处理：${err.message}`);
    return false;
  }
}

/**
 * 改密后的会话收口：吊销全部会话（tokenVersion 递增 + 缓存失效）→ 收敛会话表 → 审计。 fail-closed：密码已落库，吊销失败绝不能静默吞掉——旧会话是否仍有效处于未知态，返回 REVOKE_FAILED 让控制器如实告知「已改但未吊销」，而不是用 500 掩盖部分成功。而会话表收敛用 Safe 版本：收敛失败只是「显示不准」，不能让改密请求整体失败。
 * @param {object} user 已落库的文档
 * @returns {Promise<{outcome: string, username: string}>}
 */
async function revokeSessionsAfterPasswordChange(user) {
  try {
    await invalidateUserTokens(user._id);
  } catch (revokeErr) {
    logger.error(`改密成功但会话吊销失败：${revokeErr.message}`, { username: user.username });
    return { outcome: 'REVOKE_FAILED', username: user.username };
  }
  // 会话表须与 tokenVersion 同步收敛：tokenVersion 递增已让所有令牌失效，
  // 但会话记录若仍是 active，「登录会话」界面会列出一批实际已掉线的设备，
  // 用户按列表判断「账号是否被别人登录着」就会得到错误结论
  await sessionService.revokeAllSessionsSafe(user._id, 'password_changed');
  logger.info('用户修改密码', { username: user.username });
  return { outcome: 'OK', username: user.username };
}

/**
 * 修改密码（业务层）
 * @param {string} userId
 * @param {object} body 原始请求体（含明文轨与密文轨字段）
 * @param {object} ctx { username } 供审计/日志使用
 * @returns {Promise<{outcome:'ENC_INVALID'|'MISSING'|'CONFIRM_MISMATCH'|'WEAK'|'USER_NOT_FOUND'|'CURRENT_WRONG'|'SAME_PASSWORD'|'PASSWORD_REUSED'|'REVOKE_FAILED'|'OK'}>}
 *   OK / REVOKE_FAILED 时附 { username, forced }（forced=true 表示本次是强制改密完成；
 *   REVOKE_FAILED 表示密码已改但会话吊销失败）
 *   PASSWORD_REUSED 时附 { historyDepth }（供控制器回显可用范围）
 */
async function changeUserPassword(userId, body, ctx) {
  // ===== 口令密文轨（与明文轨双轨并存，LOGIN_ENCRYPT_STRICT=true 后明文轨由校验层关闭）=====
  // 密文轨解密后走原有校验流程（非空/强度检查对双轨同样生效）
  const current = await resolveCredentialTrack(
    body.encCurrentPassword,
    body.currentPassword,
    'PASSWORD_CURRENT',
    '当前口令',
    ctx
  );
  if (!current.ok) {
    return { outcome: current.outcome };
  }

  const next = await resolveCredentialTrack(
    body.encNewPassword,
    body.newPassword,
    'PASSWORD_NEW',
    '新口令',
    ctx
  );
  if (!next.ok) {
    return { outcome: next.outcome };
  }

  const inputRejection = validatePasswordChangeInput(body, current.value, next.value);
  if (inputRejection) {
    return inputRejection;
  }

  const user = await User.findById(userId).select(
    '+password +passwordHistory +passwordRetiredHash'
  );
  const subjectRejection = await assertPasswordRotatable(user, current.value, next.value, ctx);
  if (subjectRejection) {
    return subjectRejection;
  }

  // 落库留在本函数体内，**不抽成 applyPasswordChange**：passwordHistory.test.js 的接线不变量
  // 直接按「changeUserPassword 起点之后的文本」找 `user.passwordHistory = withPrevious(`，
  // 抽走之后那条判据会红——而它守的正是「历史真的被写进去了」，不是一次代码整理可以豁免的。
  // P1-2：本次改密是否是"首次登录/管理员重置后的强制改密"决定审计动作
  // （password_force_changed 与普通 password_changed 分开，审计页才分得清
  // "用户自己定期换"和"临时口令完成首改"）。
  const wasForced = user.mustChangePassword === true;

  // 先算新摘要，再用「旧摘要仍一致」作为条件做原子更新。
  // 无条件 save() 会在并发时造成 lost update：管理员重置写入临时口令后，
  // 用户侧这条 save 把管理员的处置覆盖回自己已知的新口令（重置被静默抵消）；
  // 同一旧口令的双击重试也会后写覆盖先写，而两次都记成功审计。
  // 条件里带旧摘要：期间的任何一方改过口令，本次更新就落空，由下方统一判冲突。
  const newPasswordHash = await bcryptWorker.hash(next.value, config.bcryptRounds);
  // 记的是**刚被替换掉的旧口令**：本次比较发生在写入之前，检查对象是
  // 「候选新口令 vs 既往口令」。当前口令由上面的 SAME_PASSWORD 单独判。
  user.passwordHistory = withPrevious(user.passwordHistory, current.value);
  const now = new Date();
  const updated = await User.findOneAndUpdate(
    { _id: user._id, password: user.password },
    {
      $set: {
        password: newPasswordHash,
        passwordChangedAt: now,
        passwordSetAt: now,
        mustChangePassword: false,
        passwordHistory: user.passwordHistory,
      },
    },
    { new: true }
  );
  if (!updated) {
    // 条件落空 = 读取之后有人改过口令（管理员重置 / 并发改密）。
    // 不回 OK：本次提交的新口令并未生效；也不能回 500，这是可预期的并发结果。
    const fresh = await User.findById(userId).select('_id').lean();
    logger.warn('改密中止 - 口令在读取后被并发变更', { username: ctx.username });
    return { outcome: fresh ? 'CURRENT_WRONG' : 'USER_NOT_FOUND' };
  }

  // 口令已变 ⇒ 初始口令作废；即使随后的会话吊销失败也必须销毁该文件
  initialPasswordFile.consume(user.username, '修改密码');

  const revoked = await revokeSessionsAfterPasswordChange(user);
  return { ...revoked, forced: wasForced && revoked.outcome === 'OK' };
}

module.exports = {
  changeUserPassword,
};
