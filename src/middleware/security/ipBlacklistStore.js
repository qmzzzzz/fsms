/**
 * IP 黑名单写入原语（自 ipBlacklist.js 抽出）
 *
 * 抽出的原因：自动封禁的三条臂（暴力破解 / 权限滥用 / 限流升级）只需要
 * `addToBlacklist`，此前却经 `middleware/security` 门面取用；门面反向拉入
 * ipBlacklist → securityAlert → 三条臂，构成惰性环。本模块只碰 IPBlacklist 模型，
 * 不引用任何告警/中间件门面，是叶子节点。
 */

const logger = require('../../utils/logger');
const { normalizeIP } = require('../../utils/ipUtils');

/**
 * 动态添加 IP 到黑名单（持久化到 MongoDB）
 * 入库前归一化 IP：Node 在 IPv6 栈下 req.ip 形如 ::ffff:1.2.3.4，
 * 若原样入库会与管理员手动录入的 1.2.3.4 产生两条指向同一地址的记录
 * （复合唯一索引 { ip, type } 按文本判重，无法拦截），导致解封时漏删。
 * @param {string} ip - 要封禁的 IP
 * @param {number} durationMs - 封禁时长（毫秒），默认 1 小时
 * @param {string} reason - 封禁原因
 * @param {string} source - 封禁来源（manual/auto）
 * @returns {Promise<{banned: boolean, reason?: string, normalizedIp?: string}>}
 *   本函数**从不抛错**（内部自己 catch 掉持久化失败），所以"await 正常返回"绝不等于"封禁生效"。
 *   成功与否只能靠这个返回值判断，调用方不得按"没抛异常"记成功：
 *   - `{banned:true, normalizedIp}`：黑名单已落库；
 *   - `{banned:false, reason}`：一条记录都没写，reason ∈ unparsable_ip / whitelisted / persist_failed。
 */
const addToBlacklist = async (
  ip,
  durationMs = 3600000,
  reason = 'security_policy',
  source = 'manual'
) => {
  try {
    const IPBlacklist = require('../../models/IPBlacklist');

    const normalizedIp = normalizeIP(ip);
    if (!normalizedIp) {
      logger.warn(`IP 黑名单添加跳过：无法解析的地址 ${ip}`);
      return { banned: false, reason: 'unparsable_ip' };
    }

    // 白名单优先：信任 IP 不做自动封禁（如内网监控探针等可信来源的高频请求）
    const whitelisted = await IPBlacklist.isWhitelisted(normalizedIp).catch(() => false);
    if (whitelisted) {
      logger.info(`IP ${normalizedIp} 在白名单中，跳过自动封禁`);
      return { banned: false, reason: 'whitelisted' };
    }

    await IPBlacklist.blockIP(normalizedIp, { reason, durationMs, source });
    logger.warn(
      `IP 已加入黑名单：${normalizedIp}, 封禁时长：${durationMs / 1000}秒, 原因：${reason}`
    );
    return { banned: true, normalizedIp };
  } catch (err) {
    logger.error(`IP 黑名单添加失败：${ip}, 错误：${err.message}`);
    return { banned: false, reason: 'persist_failed' };
  }
};

module.exports = { addToBlacklist };
