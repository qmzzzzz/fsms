/**
 * 登录失败计数的共享原子写（P1-1）：口令路径与 MFA 路径必须共用同一份并发判据。
 * User 由调用方传入（两处均已持有模型引用，避免新增顶层依赖边）。
 */
async function applyLoginFailureCountAtomic(User, user) {
  const now = new Date();
  const lockExpired = user.lockUntil && user.lockUntil <= now;
  let updated = null;
  if (lockExpired) {
    updated = await User.findOneAndUpdate(
      { _id: user._id, lockUntil: { $lte: now } },
      { $set: { failedLoginCount: 1, lockUntil: null } },
      { new: true }
    ).catch(() => null);
  }
  if (!updated) {
    updated = await User.findByIdAndUpdate(
      user._id,
      { $inc: { failedLoginCount: 1 } },
      { new: true }
    ).catch(() => null);
  }
  return updated;
}

module.exports = { applyLoginFailureCountAtomic };
