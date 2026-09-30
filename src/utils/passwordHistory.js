/**
 * 口令复用历史（OWASP ASVS V2 密码策略的"禁止复用近期口令"一条）
 *
 * 存在理由：`helpers.validatePasswordStrength` 只管**强度**（长度/复杂度/泄露库），
 * 全仓没有任何一处检查"新口令是不是最近用过的"。而 `changeUserPassword` 里已有的
 * `SAME_PASSWORD` 检查只挡**与当前口令相同**——把口令改成 A→B→A 这种两步复用完全放行。
 * 复用是真实攻击路径：口令泄露后施压要求"改回你原来的口令"，或在多个系统间轮换
 * 同一弱口令，复用历史是唯一能自动挡掉它的机制。
 *
 * ============================ 为什么摘要而不是 bcrypt ============================
 * 口令历史的用途是**等值比较**（"这个新口令之前用过吗"），而比较时明文就在手里。
 * bcrypt 的"慢"是为**离线爆破**服务的（库里只有摘要、没有明文），这里完全不适用，
 * 而且代价很实在：逐条 bcrypt.compare 在 rounds=12 下每条约 250~300ms，
 * 保留 5 条就是 1.5 秒、10 条 3 秒，且全部挂在改密端点上——
 * `passwordChangeLimiter` 只按 user+ip 限到 5 次/15 分钟，**没有全局护栏**，
 * 于是 N 个账号就能把 CPU 打满。这是一条自己造出来的放大面。
 *
 * 所以沿用**本仓已有的同类先例** `services/mfaService.hashRecoveryCode`：
 * HMAC-SHA256，以服务端 HMAC 密钥为 pepper；未配置密钥时退化为普通 sha256。
 * 两者的威胁模型其实不同，必须说清差别：
 *   - MFA 恢复码是**低熵**认证因子（熵 ≈ 39.6 bit），无盐快哈希在库泄露后
 *     单卡秒级可枚举 ⇒ pepper 是真防线；
 *   - 口令有强度策略兜底（12 位 + 四类字符），且**同一份文档里已经躺着一条
 *     rounds≥10 的 bcrypt 摘要**——攻击者拿到的第一目标是那条，快哈希带来的
 *     边际收益很小。而 pepper 让"库泄露"本身不足以离线枚举口令历史。
 *
 * 换句话说：**这条防线防的是"复用"这个行为，不是"库泄露后破解历史口令"。**
 * 后者由 `password` 字段自身的 bcrypt 承担。
 *
 * ============================ pepper 轮换的已知代价 ============================
 * 轮换 HMAC_SECRET 后既有摘要全部对不上 ⇒ 历史长度归零，用户在轮换后仍可复用
 * 前 N 条旧口令一次，之后重新积累。与审计链 HMAC 换钥是同一类问题
 * （`scripts/resign-audit-hmac.js` 那套重签工具在这里**不适用**：没有明文就无法重算）。
 * 故此处如实记录而不假装解决：轮换窗口内复用防线短暂变弱，是可接受的已知取舍。
 */
const crypto = require('crypto');
const logger = require('./logger');
const { readPositiveNumberEnv } = require('./envNumber');

/**
 * 保留条数。默认 5 取自 ASVS V2「至少最近 5 条」的下限；
 * 上限 24 是为了防止误配成 1000 之后单文档膨胀（每条 64 字符 hex ⇒ 1000 条 = 64KB/用户）。
 */
const HISTORY_DEPTH = Math.min(
  Math.max(
    readPositiveNumberEnv('PASSWORD_HISTORY_DEPTH', 5, {
      integer: true,
      onInvalid: (name, raw, d) =>
        logger.error(`${name}=${JSON.stringify(raw)} 非法（须为正整数），已按默认 ${d} 处理`),
    }),
    1
  ),
  24
);

/**
 * pepper 解析。与 mfaService.getRecoveryPepper 同形同理由：
 * 生产侧不会走到空 pepper —— config/validate.js 的 requiresProductionSemantics
 * 把未识别的 NODE_ENV 一律按生产处理，并强制 HMAC_SECRET 达到强随机长度。
 * try/catch 是为了模块加载早期 config 尚未就绪时不至于整个崩掉（退化即无 pepper）。
 */
const getPepper = () => {
  try {
    return require('../config').hmacSecret || '';
  } catch {
    return process.env.HMAC_SECRET || '';
  }
};

/** 单条口令历史摘要（64 字符 hex） */
const digestOf = (plaintext) => {
  if (typeof plaintext !== 'string' || plaintext === '') return null;
  const pepper = getPepper();
  if (pepper) {
    return crypto.createHmac('sha256', pepper).update(plaintext, 'utf8').digest('hex');
  }
  return crypto.createHash('sha256').update(plaintext, 'utf8').digest('hex');
};

/**
 * 规整历史数组：剔除非字符串（脏数据 / 手工写库）、截到深度上限。
 *
 * 读取侧也要做，不能只在写入侧封顶：历史字段可能来自备份还原或裸写库，
 * 而一条超长数组会让每次改密的比较次数不可控（那正是上面要避免的 CPU 放大面）。
 */
const sanitizeHistory = (history) => {
  if (!Array.isArray(history)) return [];
  const seen = new Set();
  const out = [];
  for (const item of history) {
    if (typeof item !== 'string' || item.length === 0) continue;
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
    if (out.length >= HISTORY_DEPTH) break;
  }
  return out;
};

/**
 * 新口令是否命中历史。
 *
 * 只算一次摘要再逐条比对，而不是每条重算——口令明文在这里是同一个值，
 * N 次 HMAC 与 1 次没有区别。
 *
 * 用 timingSafeEqual 纯粹是避免让复核者重新推一遍"这里到底需不需要定长比较"：
 * 候选明文由请求方提供，命中某条历史并不泄露新信息（他本来就知道自己提交了什么），
 * 所以严格说这不是密钥比较。但两条路径都是定长 hex，按 timingSafeEqual 的前置条件
 * 处理更省事，长度不等时按"不匹配"返回而不是抛错。
 */
const matchesHistory = (history, plaintext) => {
  const digest = digestOf(plaintext);
  if (!digest) return false;
  const probe = Buffer.from(digest, 'utf8');
  for (const item of sanitizeHistory(history)) {
    const candidate = Buffer.from(item, 'utf8');
    if (candidate.length !== probe.length) continue;
    if (crypto.timingSafeEqual(candidate, probe)) return true;
  }
  return false;
};

/**
 * 记录一条**刚被替换掉**的旧口令，返回新的历史数组（最新在前）。
 *
 * 记的是旧口令而不是新口令：比较发生在写入之前，检查对象是"候选新口令 vs 既往口令"，
 * 而当前口令由 `changeUserPassword` 里的 `SAME_PASSWORD` 单独判（错误码不同、语义不同）。
 * 两条路径互补：SAME_PASSWORD 挡"与当前相同"，历史挡"与更早的相同"。
 */
const withPrevious = (history, previousPlaintext) => {
  const digest = digestOf(previousPlaintext);
  if (!digest) return sanitizeHistory(history);
  // 新条目在前；已有条目里若已存在同一条（正常不该发生）由 sanitizeHistory 去重
  return sanitizeHistory([digest, ...sanitizeHistory(history)]);
};

module.exports = {
  HISTORY_DEPTH,
  digestOf,
  sanitizeHistory,
  matchesHistory,
  withPrevious,
};
