/**
 * MFA 两步验证基础服务（D-1 自 authController 拆出）
 *
 * 恢复码生成/摘要与 MFA 独立防爆破的原语层，供登录 MFA 步骤、
 * MFA 管理端点（controllers/mfaController.js）与管理员重置
 * （securityController.resetUserMfa）共用，避免多处各自实现。
 */

const crypto = require('crypto');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

// MFA 验证码连续失败阈值与锁定时长（独立于 failedLoginCount：
// 覆盖登录 MFA 步骤、关闭 MFA、重新生成恢复码等所有验证码校验路径）
const MFA_MAX_FAILS = 5;
const MFA_LOCK_MS = 10 * 60 * 1000;

/** 恢复码摘要：HMAC-SHA256（以服务端 HMAC 密钥为 pepper）。
 * 恢复码是低熵认证因子：熵 = log2(31^8) = 39.6 bit（原注释写「~38.6 bit」，
 * 差了近一倍空间，数字本身也是无人验证的手写常量）。这个量级下无盐快哈希一旦
 * 库泄露即可 GPU 穷举（2^39.6 次 HMAC-SHA256 在单卡上以秒计），因此真正的防线是
 * pepper：离线枚举需先拿到 HMAC_SECRET，在线枚举则受 MFA_MAX_FAILS 锁定窗口约束。
 * 未配置密钥时退化为普通 sha256（开发/测试）——生产侧不会走到：
 * config/validate.js 的 requiresProductionSemantics 把「未识别的 NODE_ENV」一律按
 * 生产处理，并强制 HMAC_SECRET 达到强随机长度。 */
const getRecoveryPepper = () => {
  try {
    return require('../config').hmacSecret || '';
  } catch {
    return process.env.HMAC_SECRET || '';
  }
};

const hashRecoveryCode = (code) => {
  const pepper = getRecoveryPepper();
  if (pepper) {
    return crypto.createHmac('sha256', pepper).update(code, 'utf8').digest('hex');
  }
  return crypto.createHash('sha256').update(code, 'utf8').digest('hex');
};

/**
 * 备用恢复码字母表——「什么字符算合法恢复码」这条谓词的**单一来源**。
 * 31 字符：26 个大写字母剔除易混的 I/L/O，10 个数字剔除易混的 0/1。
 *
 * 这条谓词在本仓库有三份手写拷贝：本文件的字母表（生成侧，权威——只有它决定
 * 用户实际拿到什么码），以及两份校验侧的等价正则
 * `[A-HJ-KM-NP-Z2-9]{4}-[A-HJ-KM-NP-Z2-9]{4}`（services/authService.js 登录、
 * routes/authRoutes.js 入参）。三份今天等价却互不引用：任一处改动都会静默分叉成
 * 「发出去的码被校验侧判为格式非法」，且只在被改字符恰好落在某一位时复现——
 * 是极难定位的一类登录故障。故导出 isRecoveryCodeFormat / RECOVERY_CODE_PATTERN
 * 供校验侧收敛，并由 tests/services/recoveryCodeFormatSingleSource.test.js
 * 以「逐字符行为等价 + 绝对值」双门禁盯住两份手写正则是否漂移。
 */
const RECOVERY_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
/** 格式 XXXX-XXXX：连字符两侧各这么多位 */
const RECOVERY_CODE_HALF = 4;

// 字符类逐字符拼装、不做区间压缩——压缩写法（[A-HJ-KM-NP-Z2-9]）正是三份拷贝
// 无法机械互推的根源。转义元字符是为今后往字母表里加 '-' / ']' 时字符类不崩。
const toClassChar = (c) => (/[-[\]^]/.test(c) ? `\\${c}` : c);
const RECOVERY_CODE_CHAR_CLASS = `[${[...RECOVERY_CODE_ALPHABET].map(toClassChar).join('')}]`;
const RECOVERY_CODE_PATTERN = new RegExp(
  `^${RECOVERY_CODE_CHAR_CLASS}{${RECOVERY_CODE_HALF}}-${RECOVERY_CODE_CHAR_CLASS}{${RECOVERY_CODE_HALF}}$`
);

/**
 * 恢复码格式判定。大小写敏感：调用方须先 `.toUpperCase()` 规范化
 * （登录侧 authService 已做，入参侧 authRoutes 用 /i 放行小写再交给登录侧规范化）。
 * @param {unknown} code
 * @returns {boolean}
 */
const isRecoveryCodeFormat = (code) => typeof code === 'string' && RECOVERY_CODE_PATTERN.test(code);

/**
 * 生成备用恢复码（默认 10 个，格式 XXXX-XXXX）
 *
 * 取字符用 crypto.randomInt(31) 而非 bytes[j] % 31：后者是**模偏差**——
 * 256 % 31 = 8，字母表前 8 个字符（A–H）各由 9 个字节值映射而来、其余 23 个各由
 * 8 个映射而来，于是 A–H 出现概率高 12.5%（枚举 0..255 即可复现，见测试前提行）。
 * 恢复码是低熵认证因子，任何让取值分布不均的偏差都在给「先猜高频」的离线枚举让利，
 * 而 randomInt 内部已做拒绝采样，去掉偏差零成本。
 */
const generateRecoveryCodes = (count = 10) => {
  const total = RECOVERY_CODE_HALF * 2;
  const codes = [];
  for (let i = 0; i < count; i++) {
    let raw = '';
    for (let j = 0; j < total; j++) {
      raw += RECOVERY_CODE_ALPHABET[crypto.randomInt(RECOVERY_CODE_ALPHABET.length)];
    }
    codes.push(`${raw.slice(0, RECOVERY_CODE_HALF)}-${raw.slice(RECOVERY_CODE_HALF)}`);
  }
  return codes;
};

/** MFA 验证是否处于锁定窗口（连续失败达阈值后触发）。
 * 锁定自然到期时惰性清零失败计数：否则计数停留在阈值上，
 * 合法用户到期后手滑一次即立即再锁，等效"每 10 分钟仅一次试错"。 */
const isMfaLocked = async (userId) => {
  const u = await User.findById(userId).select('mfaLockUntil');
  if (!u || !u.mfaLockUntil) return false;
  if (u.mfaLockUntil > new Date()) return true;
  // 已过期：惰性重置，解除放大效应。
  // 清零写不进库时必须留痕：静默失败会让计数停留在阈值上，用户到期后手滑
  // 一次即立即再锁（正是本函数想避免的"每 10 分钟仅一次试错"），而运维从
  // 日志上看不到防线为什么在反复锁人——只有一遍遍的 warn，没有根因。
  await User.findByIdAndUpdate(userId, { mfaFailCount: 0, mfaLockUntil: null }).catch((err) => {
    logger.error(`MFA 过期锁定的惰性清零失败（下次误一次即立即再锁）：${err.message}`, {
      userId: String(userId),
    });
  });
  return false;
};

/** 记录一次 MFA 验证失败：原子递增，达阈值即锁定并审计 */
const recordMfaFailure = async (user) => {
  let recordFailed = false;
  const updated = await User.findByIdAndUpdate(
    user._id,
    { $inc: { mfaFailCount: 1 } },
    { new: true }
  )
    .select('mfaFailCount')
    .catch((err) => {
      recordFailed = true;
      logger.error(`MFA 失败计数写入失败（按已达阈值处理）：${err.message}`, {
        username: user.username,
      });
      return null;
    });

  // 计数写不进去时必须按"已达阈值"处理，而不是当作第 1 次失败。
  // 原实现 `updated?.mfaFailCount ?? 1` 让 DB 故障期间第 5 次、第 50 次失败
  // 都不触发锁定；而 isMfaLocked 读的正是同一个库 ⇒ 故障持续 = 锁定能力持续消失
  // = 6 位动态口令（10^6 空间）退化成可无限在线尝试。
  // 判据与 blacklistToken 的 P2-26 同一条：访问控制类防线观测不到时要收紧，
  // 不能"记不上就算没记过"。
  if (!recordFailed && updated === null) return; // 用户文档已不存在：无锁定对象

  if (recordFailed || updated.mfaFailCount >= MFA_MAX_FAILS) {
    // 锁定这条更新本身也可能写不进库。静默吞掉它比计数器失败更糟：下面那行
    // logger.warn 会照常写下「MFA 验证触发临时锁定」，于是日志宣称了一道
    // 并不存在的防线，而 6 位动态口令在故障窗口内仍可被无限次在线尝试。
    // 口径与上面的计数写失败一致——不静默，且不谎报观测结果。
    let lockApplied = true;
    await User.findByIdAndUpdate(user._id, {
      mfaLockUntil: new Date(Date.now() + MFA_LOCK_MS),
    }).catch((err) => {
      lockApplied = false;
      logger.error(`MFA 临时锁定写入失败（防爆破防线未生效）：${err.message}`, {
        username: user.username,
      });
    });
    logger.warn('MFA 验证触发临时锁定', {
      username: user.username,
      // 记不上计数时不谎报次数：审计载荷里宁可缺字段也不要写一个没发生过的数字
      ...(recordFailed ? {} : { failedCount: updated.mfaFailCount }),
      reason: recordFailed ? 'counter_unavailable' : 'threshold_reached',
      lockMinutes: 10,
      // 锁到底有没有落库：读日志的人据此判断防线是否还在，而不是信一句断言
      lockApplied,
    });
    AuditLog.record({
      action: 'mfa_attempt_locked',
      category: 'auth',
      userId: user._id,
      username: user.username,
      success: false,
      riskLevel: 'high',
      riskFactors: [recordFailed ? 'mfa_counter_unavailable' : 'mfa_bruteforce'],
      reason: recordFailed
        ? 'MFA 失败计数无法落库，按已达阈值处理并临时锁定验证通道 10 分钟'
        : `MFA 验证连续失败 ${updated.mfaFailCount} 次，验证通道临时锁定 10 分钟`,
    }).catch(() => {});
  }
};

/** MFA 验证成功后清零失败计数并解除锁定
 *
 * 清零失败不阻断主流程（验证已经成功，不能因为记不上就判用户失败），
 * 但必须留痕：计数停留在阈值上时，用户下次手滑一次就会被立即锁 10 分钟，
 * 而排查「为什么他总被锁」的人需要在日志里看到这一次失败的写入。
 */
const resetMfaFailures = (userId) => {
  return User.findByIdAndUpdate(userId, { mfaFailCount: 0, mfaLockUntil: null }).catch((err) => {
    logger.error(`MFA 验证成功后的计数清零失败（下次误一次即立即再锁）：${err.message}`, {
      userId: String(userId),
    });
  });
};

/**
 * 原子「认领」一个 TOTP 时间窗，返回 false 即该窗口已被消费过（重放）
 *
 * 判据与登录侧 authService.verifyTotpChallenge / 步进侧 middleware/security 同一形状：
 * 以 `mfaLastCounter < counter` 为过滤条件的更新只有第一个请求能命中，互斥由 DB 保证。
 * 两条额外 $or 兜底是给历史脏文档（字段缺失或为 null）用的。
 * `.catch(() => null)` 是 fail-closed：写不进水位就当认领失败，不给重放留空隙。
 *
 * 为什么不能用 $max：$max 只保证"不把水位拉回"，从不拒绝任何请求
 * ⇒ "等于水位的窗口"——也就是登录刚刚原子消费掉的那个码——在生命周期端点上
 * 依然有效。verifyTotp 带 ±1 窗口（≈90 秒）：AiTM 代理把受害者实时口令转发给真实登录
 * （水位推进到 W、代理方拿到会话）后，同一个码还能在代理方会话上冒关 MFA + 铸 10 张
 * 恢复码。恢复码不依赖口令，换密码也带不走 ⇒ 持久化据点。
 */
const claimTotpWindow = async (userId, counter) => {
  const claimed = await User.findOneAndUpdate(
    {
      _id: userId,
      $or: [
        { mfaLastCounter: { $lt: counter } },
        { mfaLastCounter: { $exists: false } },
        { mfaLastCounter: null },
      ],
    },
    { $set: { mfaLastCounter: counter } },
    { new: true }
  ).catch(() => null);
  return Boolean(claimed);
};

/**
 * 本次请求走哪条身份路径。动态口令优先：给了 6 位码就按码验，
 * 只有在没有可用码时才考虑登录密码（两者是"二选一"，不是叠加）。
 */
const resolveMfaFactorPaths = (mfaCode, currentPassword) => {
  const codePath = typeof mfaCode === 'string' && /^\d{6}$/.test(mfaCode.trim());
  return {
    codePath,
    passwordPath: !codePath && typeof currentPassword === 'string' && currentPassword,
  };
};

/**
 * 动态口令因子验证：验证通过还必须原子认领它所属的时间窗，认领失败即重放——
 * 登录时消费过的码不得用来冒关 MFA（认领提前到验证处，补掉"验证通过到写库之间
 * 同一码可被并发双花"那段窗口）。失败计数只有 recordMfaFailure 一个落点，
 * 重放与口令错误同口径：翻倍计数会把正当用户提前锁在门外。
 * @returns {Promise<{verified: boolean, method: string}>}
 */
const verifyTotpFactor = async (user, mfaCode) => {
  const { verifyTotpDetailed } = require('../utils/totp');
  const { decryptMfaSecret } = require('../utils/mfaSecret');
  const totpResult = verifyTotpDetailed(decryptMfaSecret(user.mfaSecret), mfaCode.trim());
  let verified = totpResult.valid;
  let method = 'mfa_code';
  if (verified && !(await claimTotpWindow(user._id, totpResult.counter))) {
    verified = false;
    method = 'mfa_code_replayed';
  }
  if (!verified) await recordMfaFailure(user);
  return { verified, method };
};

module.exports = {
  MFA_MAX_FAILS,
  MFA_LOCK_MS,
  getRecoveryPepper,
  hashRecoveryCode,
  RECOVERY_CODE_ALPHABET,
  RECOVERY_CODE_PATTERN,
  isRecoveryCodeFormat,
  generateRecoveryCodes,
  isMfaLocked,
  recordMfaFailure,
  resetMfaFailures,
  claimTotpWindow,
  resolveMfaFactorPaths,
  verifyTotpFactor,
};
