const { normalizeCanaryUsername, DEFAULT_CANARY_USERNAMES } = require('./canaryAccounts'); // 与哨兵名单共用一份归一化（trim + 小写），不新造第二份大小写规则；默认诱饵名也直接派生自默认哨兵名，避免两份名单各自演化漂移
const { isBreachedPassword } = require('../utils/helpers'); // 诱饵口令判据复用弱口令词干表，不新造第二张词表
const { getSuperAdminUsername } = require('../utils/superAdmin'); // 超管名判据（该模块零 require，不成环）

const HONEYPOT_ENABLED_ENV = 'HONEYPOT_ENABLED'; // 物化与接客总开关：未设置或非真值即关闭（默认关闭，任何部署不会被动多出一个可疑账户）
const HONEYPOT_USERNAMES_ENV = 'HONEYPOT_USERNAMES'; // 诱饵名单环境变量：整份覆盖默认值（与 CANARY_USERNAMES 同口径：空项报错、全无效回退默认）
const ENABLED_VALUES = Object.freeze(['true', '1', 'yes', 'on']); // 真值词表（大小写与首尾空白不敏感）

const DEFAULT_HONEYPOT_USERNAMES = Object.freeze([
  'sysadmin',
  ...DEFAULT_CANARY_USERNAMES,
  'admin',
]); // 默认诱饵名 = sysadmin + 全部默认哨兵名 + admin：把「猜名字」的幽灵哨兵升级为「猜对口令就进得来」的蜜罐（逐条接管登记与判据见 tests/ci/honeypotNameOverlapLedger）；admin 默认恒被超管名判据剔除，超管改名后自动生效
const HONEYPOT_EXCLUDED_FILTER = Object.freeze({ isHoneypot: { $ne: true } }); // 枚举面排除蜜罐账户的唯一判据：$ne true 同时放行「字段缺失」的历史行（迁移期/裸写进库的行）

const normalizeHoneypotUsername = (value) => normalizeCanaryUsername(value); // 单一实现：诱饵名与哨兵名必须按同一套规则归一，否则同一个名字会算成两笔账

const isHoneypotEnabled = (raw = process.env[HONEYPOT_ENABLED_ENV]) =>
  ENABLED_VALUES.includes(
    String(raw ?? '')
      .trim()
      .toLowerCase()
  );

const isReservedHoneypotName = (normalized) =>
  normalized !== null && normalized === normalizeHoneypotUsername(getSuperAdminUsername()); // 超管名判据（安全不变量，先于运维意图）：生效名单永不含当前超管名——占用它等于把最高权限账户变成陷阱（其口令会被当诱饵判据、且在枚举面隐藏）

function parseHoneypotUsernames(raw = process.env[HONEYPOT_USERNAMES_ENV]) {
  const source = typeof raw === 'string' ? raw : ''; // 解析入口：默认名单、env 整份覆盖、空项记 errors、全无效回退默认，一律先过超管名判据
  const fromEnv = source.trim() !== '';
  const errors = [];
  const dropped = []; // 因占用超管名被剔除的条目：单独回传而不记 errors——默认名单里的 admin 是有意登记的未来意图，不是配置错误，启动期按 info 播报即可
  const names = [];
  const seen = new Set();
  const collect = (items) => {
    for (const item of items) {
      const normalized = normalizeHoneypotUsername(item);
      if (!normalized) {
        errors.push('忽略空条目：' + JSON.stringify(item));
        continue;
      }
      if (isReservedHoneypotName(normalized)) {
        dropped.push(normalized); // 超管名：一律剔除，env 显式写入也剔——安全不变量优先于运维意图
        continue;
      }
      if (seen.has(normalized)) continue; // 去重含大小写差异：Root 与 root 是同一个诱饵名
      seen.add(normalized);
      names.push(normalized);
    }
  };
  collect(fromEnv ? source.split(',') : DEFAULT_HONEYPOT_USERNAMES);
  if (names.length === 0) {
    errors.push('HONEYPOT_USERNAMES 无有效条目，已回退默认名单（不静默停用诱饵账户）');
    collect(DEFAULT_HONEYPOT_USERNAMES); // 回退路径同样过判据：否则「env 只写 admin」会绕开超管名剔除
    return { names: Object.freeze(names), fromEnv: false, errors, dropped };
  }
  return { names: Object.freeze(names), fromEnv, errors, dropped };
}

const matchHoneypotName = (username, names = parseHoneypotUsernames().names) => {
  const normalized = normalizeHoneypotUsername(username);
  if (!normalized) return null; // 空/非字符串不是名单名（调用方热路径的绝大多数）
  return names.includes(normalized) ? normalized : null;
};

const withHoneypotExcluded = (filter = {}) => ({ ...filter, ...HONEYPOT_EXCLUDED_FILTER }); // 调用方过滤器在前、排除判据在后：调用方不得覆盖掉排除项

const isLurePassword = (password) => isBreachedPassword(password) === true; // 诱饵口令判据：命中弱口令词干即视为「攻击者猜对了」，不看账户里那份真随机口令

const findNameOverlap = (names, otherNames) => names.filter((name) => otherNames.includes(name)); // 登记名单交集：非空 ⇒ 该哨兵改由蜜罐账户接管，启动期必须显式告知而不是静默

module.exports = {
  DEFAULT_HONEYPOT_USERNAMES,
  HONEYPOT_EXCLUDED_FILTER,
  HONEYPOT_ENABLED_ENV,
  HONEYPOT_USERNAMES_ENV,
  findNameOverlap,
  isHoneypotEnabled,
  isReservedHoneypotName,
  isLurePassword,
  matchHoneypotName,
  normalizeHoneypotUsername,
  parseHoneypotUsernames,
  withHoneypotExcluded,
};
