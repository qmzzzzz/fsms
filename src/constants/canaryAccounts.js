/**
 * 安全哨兵用户名（canary username）名单：默认值与 env 解析
 *
 * 名单里的每个名字都必须是**幽灵**——合法用户不可能持有、也不应该尝试。
 * 凭证失败命中名单（且该用户名查无此人）即确定性探测信号；检测与处置见
 * services/canaryWatch.js，本文件只回答「名单是什么」这一件事。
 *
 * 默认名单（10 个）：administrator / root / user / test / guest / system /
 * oracle / postgres / backup / demo——都是攻击者字典里的高频词，而正常
 * 业务系统不会把这些词用作真实账号名（若确有，见下方「遮蔽」提示）。
 *
 * 【为什么默认名单里没有 admin】
 * admin 是本仓默认超管用户名（utils/superAdmin.getSuperAdminUsername 默认
 * 'admin'）。幽灵语义的构造性保证是「真实存在的账号永远不会走进 canary
 * 判定分支」（只在整个登录流程的"用户名查无此人"分支触发），所以 admin
 * 在名单里也不会误报；但正因为它**默认一直真实存在**，放进默认名单等于
 * 默认名单里有一个固定失效项，徒增启动期遮蔽对账噪音。超管改名后若想把
 * admin 纳入监控，用 CANARY_USERNAMES 显式加入即可。
 *
 * 【CANARY_USERNAMES 语义（env 解析与 config/trustedProxies.js 同一条纪律）】
 *   - 未配置（undefined/空白）→ 用默认名单：安全能力默认开启，不依赖
 *     运维记得配置（哨兵是**兜底检测**，静默缺席比误报危险）；
 *   - 配置非空 → **整体覆盖**默认名单（想连默认名一起盯就在 env 里列全）。
 *     不提供 env/默认并集合并：两份来源相加会制造"env 里删了一个名字，
 *     它却因默认名单仍在生效"的静默漂移，单线程的安全配置必须只有一个答案；
 *   - 条目一律 trim + lowercase：与 User.USERNAME_COLLATION（大小写不敏感的
 *     username_ci 唯一索引，models/User.js:32/:406）同口径，'Root ' 与 'root'
 *     必须命中同一个哨兵；
 *   - 空条目忽略并记入 errors；全部无效时回退默认名单并记 errors——宁可打
 *     日志保留默认防护，也不静默把哨兵整个关掉（fail-loud）。
 */

const DEFAULT_CANARY_USERNAMES = Object.freeze([
  'administrator',
  'root',
  'user',
  'test',
  'guest',
  'system',
  'oracle',
  'postgres',
  'backup',
  'demo',
]);

/**
 * 归一化单个候选用户名：仅接受字符串；trim + lowercase 后为空视为无效。
 * @param {*} value
 * @returns {string|null} 归一化结果，或 null（非字符串/空白）
 */
const normalizeCanaryUsername = (value) => {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return normalized === '' ? null : normalized;
};

/**
 * 解析 CANARY_USERNAMES 原始值。
 * @param {*} raw env 原始字符串（通常是 process.env.CANARY_USERNAMES）
 * @returns {{names: string[], fromEnv: boolean, errors: string[]}}
 *   names 永远是可直接使用的生效名单（解析失败时是默认名单的拷贝）；
 *   fromEnv=false 但 errors 非空 ⇒ "配了但配坏了，已回退默认"，须告警。
 */
const parseCanaryUsernames = (raw) => {
  const errors = [];
  const configured = typeof raw === 'string' && raw.trim() !== '';
  if (!configured) {
    return { names: [...DEFAULT_CANARY_USERNAMES], fromEnv: false, errors };
  }

  const names = [];
  const seen = new Set();
  for (const item of String(raw).split(',')) {
    const name = normalizeCanaryUsername(item);
    if (name === null) {
      errors.push(`忽略空条目：${JSON.stringify(item)}`);
      continue;
    }
    if (seen.has(name)) continue; // 重复项去重；无害，不记为错误
    seen.add(name);
    names.push(name);
  }

  if (names.length === 0) {
    errors.push('CANARY_USERNAMES 不含任何有效用户名，已回退默认名单（不静默停用哨兵）');
    return { names: [...DEFAULT_CANARY_USERNAMES], fromEnv: false, errors };
  }
  return { names, fromEnv: true, errors };
};

/**
 * 大小写不敏感地判断 username 是否命中名单。
 * @param {*} username 待判定用户名（可为任意类型，非字符串一律不命中）
 * @param {string[]} [names] 已归一化的名单；缺省用默认名单（调用方通常传
 *   canaryWatch 的生效名单）
 * @returns {string|null} 命中的**归一化**名字（可作稳定键），或 null
 */
const findCanaryMatch = (username, names = DEFAULT_CANARY_USERNAMES) => {
  const normalized = normalizeCanaryUsername(username);
  if (normalized === null || !Array.isArray(names)) return null;
  return names.includes(normalized) ? normalized : null;
};

module.exports = {
  DEFAULT_CANARY_USERNAMES,
  normalizeCanaryUsername,
  parseCanaryUsernames,
  findCanaryMatch,
};
