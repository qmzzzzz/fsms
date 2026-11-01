/**
 * 关闭 MFA 的领域判定与条件写（自 mfaService 拆出，控制单文件体积）
 *
 * 依赖方向单向：本模块 → mfaService（摘要、失败计数、TOTP 验签）， mfaService 不反向依赖，避免循环引用。
 */

const User = require('../models/User');
const logger = require('../utils/logger');
const { hashRecoveryCode, recordMfaFailure, verifyTotpFactor } = require('./mfaService');

/**
 * 原子消费一个备用恢复码（关闭 MFA 的第二因子之一）。
 *
 * 过滤条件同时包含 `_id` 与摘要，`$pull` 未命中即视为无效——与登录侧 verifyRecoveryCodeChallenge 同一形状，消除"先查后删"的并发双花窗口。必须用 findOneAndUpdate 而非 findByIdAndUpdate：后者只取第一参的 _id，其余过滤键会被静默丢弃（登录侧曾因此让任意格式合法恢复码通过）。写库异常按无效处理（fail-closed），并留痕。
 */
const consumeRecoveryCodeForDisable = async (userId, normalizedCode) => {
  const codeHash = hashRecoveryCode(normalizedCode);
  return User.findOneAndUpdate(
    { _id: userId, mfaRecoveryCodes: codeHash },
    { $pull: { mfaRecoveryCodes: codeHash } },
    { new: true }
  ).catch((err) => {
    logger.error(`关闭 MFA 时恢复码消费失败（按无效处理）：${err.message}`, {
      userId: String(userId),
    });
    return null;
  });
};

/**
 * 用恢复码关闭 MFA：消费恢复码与清空 MFA 状态必须是**同一条文档写**。
 *
 * 原实现先 `$pull` 恢复码、再发一条独立的 `findOneAndUpdate` 清 MFA。第二步失败（并发重新登记导致条件 miss、或写库异常）时恢复码已经没了、MFA 仍在—— 用户手里少一张码，却什么都没关掉；只剩最后一张码时直接锁死在登录第二步。两者作用在同一个 User 文档上，没有理由拆成两步：过滤条件同时要求「码在组里」和「密钥仍是本次验证的那份」，一次 `$set` 同时完成消费与关闭。
 *
 * @returns {Promise<{outcome:'OK'|'VERIFY_FAILED'|'STATE_CONFLICT'|'NOT_ENABLED', user?: object}>}
 */
const disableWithRecoveryCode = async (user, normalizedCode) => {
  const codeHash = hashRecoveryCode(normalizedCode);
  let disabled = null;
  try {
    disabled = await User.findOneAndUpdate(
      {
        _id: user._id,
        mfaEnabled: true,
        mfaSecret: user.mfaSecret,
        mfaRecoveryCodes: codeHash,
      },
      {
        $set: {
          mfaEnabled: false,
          mfaSecret: '',
          mfaRecoveryCodes: [],
          mfaFailCount: 0,
          mfaLockUntil: null,
        },
      },
      { new: true }
    );
  } catch (err) {
    // 写结果未知：不在这里断言失败，交给下面的回读判定
    logger.error(`关闭 MFA 的原子写失败（恢复码与开关均未确认变更）：${err.message}`, {
      userId: String(user._id),
    });
  }
  if (disabled) return { outcome: 'OK', user: disabled };

  const current = await User.findById(user._id)
    .select('mfaEnabled mfaSecret')
    .catch(() => null);
  if (!current || !current.mfaEnabled) return { outcome: 'NOT_ENABLED' };
  // 码本身可能有效，但登记已换：本次验证不再针对当前密钥，码不清、开关不动
  if (current.mfaSecret !== user.mfaSecret) return { outcome: 'STATE_CONFLICT' };

  await recordMfaFailure(user);
  return { outcome: 'VERIFY_FAILED' };
};

/**
 * 关闭 MFA 的第二因子验证：TOTP 优先，其次恢复码（"二选一"，不是叠加）。
 *
 * 两条路径统一受防爆破约束：不能借恢复码路径绕过 TOTP 的尝试限额。放在 service 而不是 controller——"什么算验证通过"是领域判定， controller 只该决定"通过后写什么、失败时回什么码"。
 * @returns {Promise<{verified: boolean, method: string}>}
 */
const verifyDisableFactor = async (user, { mfaCode, normalizedCode, codePath }) => {
  if (codePath) return verifyTotpFactor(user, mfaCode);
  const consumed = await consumeRecoveryCodeForDisable(user._id, normalizedCode);
  if (!consumed) await recordMfaFailure(user);
  return { verified: !!consumed, method: consumed ? 'recovery_code' : 'recovery_code_invalid' };
};

/**
 * 关闭 MFA 的统一入口：先验第二因子，再用**条件写**清理状态。
 *
 * 两条路径的共同约束：验证是对载入时的 `user.mfaSecret` 做的，落库必须继续锁定那份密钥。否则并发 enroll/enable 换掉密钥后，本次从未证明过控制权的新登记会被一并清掉（审计还记成"用户关闭 MFA"）。恢复码路径额外要求"消费码 + 清状态"同一条写，见 disableWithRecoveryCode。
 *
 * @returns {Promise<{outcome:'OK'|'VERIFY_FAILED'|'STATE_CONFLICT'|'NOT_ENABLED', verifyMethod?: string}>}
 */
const disableWithSecondFactor = async (
  user,
  { mfaCode, normalizedCode, codePath, recoveryPath }
) => {
  if (recoveryPath) return disableWithRecoveryCode(user, normalizedCode);

  const { verified, method } = await verifyDisableFactor(user, {
    mfaCode,
    normalizedCode,
    codePath,
  });
  if (!verified) return { outcome: 'VERIFY_FAILED', verifyMethod: method };

  const disabled = await User.findOneAndUpdate(
    { _id: user._id, mfaEnabled: true, mfaSecret: user.mfaSecret },
    {
      $set: {
        mfaEnabled: false,
        mfaSecret: '',
        mfaRecoveryCodes: [],
        mfaFailCount: 0,
        mfaLockUntil: null,
        // mfaLastCounter 不在此处写：TOTP 路径已在验证时由 verifyTotpFactor 原子认领
        // （原实现等到这里才 $max，中间那段就是"同一码可被并发登录双花"的窗口；
        // 且 $max 从不拒绝请求，等于水位的码照样能通过——认领把这两半一起补上了）
      },
    }
  );
  if (disabled) return { outcome: 'OK', verifyMethod: method };

  // 并发关闭：状态已是目标态，但这次写没发生 ⇒ 不记"成功关闭"的审计。
  // 用户已被删除时同样回 MFA_NOT_ENABLED（对调用方就是"没有 MFA 可关"）。
  const current = await User.findById(user._id).select('mfaEnabled');
  if (!current || !current.mfaEnabled) return { outcome: 'NOT_ENABLED', verifyMethod: method };
  return { outcome: 'STATE_CONFLICT', verifyMethod: method };
};

module.exports = {
  consumeRecoveryCodeForDisable,
  disableWithRecoveryCode,
  verifyDisableFactor,
  disableWithSecondFactor,
};
