/**
 * immutable 档位配置的启动期告警（2026-09-30）
 *
 * 【这个模块解决什么】
 * 仓库里有一类配置项不属于「配错就起不来」的致命项，而属于「改了之后**存量数据**
 * 对不上」——配置本身语法合法、服务照常启动、日志一行不打，失效只体现在
 * **业务语义**上（防线变弱、数据解不开、合规口径与实际不符）。这类配置在本文
 * 统一称为 immutable 档位（改档即需要配套的数据迁移）。
 *
 * 现状是：只有审计留存期（`AUDIT_RETENTION_DAYS`）有这一层，且它的判据落在
 * `scripts/compliance-check.js`——**只在 CI / 手动跑该脚本时执行**。应用启动路径
 * （`config/validate.js` 的 collectProductionWarnings）完全看不到它。于是运维改了
 * 配置、直接重启服务，启动日志里没有任何提示；唯一的信号要等到下一次合规检查
 * （可能是几天后的 CI），或者根本不出现（该脚本不进部署流水线）。
 *
 * 【与 legacyCbcGuard 的同构关系】
 * 本模块的形态与 `config/legacyCbcGuard.js` 完全一致，理由是同一组：
 *   ① config/validate.js 的净代码行贴着 max-lines 棘轮上限（实测 299/300），
 *      该文件自己的注释就写着「新增校验须放在独立文件」；
 *   ② 这里的取舍（为什么只告警不阻断）值得有名字与独立文档。
 * 判据集合是开放的——新增「改配置需要迁移」的项时，把断言加进 collectInvariantWarnings，
 * **不要**去动 validate.js（那里已经没有行数余量）。
 *
 * 【为什么是"告警 + 计数"而不是"拒绝启动"】
 * 与 ALLOW_LEGACY_CBC_DECRYPT 同理：这些配置的合法值区间本身就包含"已知代价"
 * 的那一档（如 PASSWORD_HISTORY_DEPTH 调小、AUDIT_RETENTION_DAYS 调小都是
 * 运维有权做的选择）。启动阻断会把「合法的取舍」与「误配」一起拒掉，而真正要
 * 拦截的是**静默**——运维不知道自己的改动带来了什么后果。故收口为
 * "可见 + 提醒"：启动日志告警 + incSecurityAlert 计数（监控面能看见）。
 *
 * 这与 ALLOWED_HOSTS 那类"未配置就不可用"的致命项有本质区别——后者阻断是安全的，
 * 因为修复它不需要服务先跑起来。
 */

/**
 * 需要同时计入安全告警面的项。
 *
 * 为什么不是所有项都计数：指标 `alerts` 是给告警规则用的，只有"属于安全防线削弱"
 * 的项才该进（口令复用防线归零、遗留 CBC 解密面重开）。纯运维口径类（审计留存期）
 * 走 compliance-check 的既有通道即可——在那里它已是"不通过"，信号强度更高，
 * 再计一次安全告警只会污染告警面。
 */
const SECURITY_RELEVANT = new Set([
  'password_history_pepper_rotation',
  'pii_rotation_old_key_lingering',
]);

/**
 * 轮换用的旧主密钥变量名。
 *
 * 为什么这个变量需要启动期守卫：它是 `scripts/migrate-pii-encryption.js --rotate`
 * 的**输入参数**（临时用旧钥解密存量密文），语义上是"轮换过程的中间态"，
 * 轮换完成后必须从生产环境移除。但没有任何机制保证它被移除——
 * 而它一旦驻留，**轮换这件事就等于白做**：轮换的全部意义是"假定旧钥已泄露"，
 * 而旧钥 + 轮换前的备份归档仍能解出当时全部 PII。把已泄露的东西
 * 在生产环境变量里再挂一个可读副本，等于把窗口从"轮换那一刻"延长到"永远"。
 *
 * 与其它项的差别：前两项（pepper 轮换、CBC 开关）是"配置组合本身有代价"，
 * 这一项是"过程残留物没清"——性质更像遗留垃圾，而不是一个取舍。之所以
 * 仍走"告警不阻断"，是因为它同样可恢复（unset 后重启即可），
 * 而阻断会让一次疏忽直接变成停机事故。
 */
const PII_OLD_KEY_NAME = 'PII_ROTATION_OLD_AES_KEY';

/** 旧主密钥残留的告警文案（拆出来便于测试逐字断言） */
const piiOldKeyLingeringMessage = () =>
  `${PII_OLD_KEY_NAME} 仍存在于进程环境：这是 PII 密钥轮换（migrate-pii-encryption.js ` +
  '--rotate）的**输入参数**，不是运行时配置，轮换完成后必须从生产环境移除。' +
  '它一旦驻留，轮换即失效——旧密钥 + 轮换前的备份归档仍可解出当时全部 PII。' +
  '处置：unset 该变量后重启，并确认启动日志不再出现本告警；' +
  '见 deployment/secret-rotation.md 的收尾检查清单。';

/**
 * 是否检测到轮换旧钥驻留。
 *
 * 只看"存在且非空"：空串是 unset 的常见等价物（`.env` 里写了 `KEY=`、
 * docker compose 里传了空值），把它判成残留会造成恒真误报。
 */
const hasPiiOldKeyLingering = () =>
  typeof process.env[PII_OLD_KEY_NAME] === 'string' && process.env[PII_OLD_KEY_NAME].trim() !== '';

/** 口令复用历史在 pepper 轮换后的告警文案（拆出来便于测试逐字断言） */
const passwordHistoryRotationMessage = () =>
  'HMAC_SECRET 轮换后口令复用历史全部失配：utils/passwordHistory 的摘要以 HMAC_SECRET 为 pepper' +
  '（见该文件「pepper 轮换的已知代价」一节），换钥后既有摘要一条都对不上 ⇒ 历史长度归零，' +
  '用户可复用前 N 条旧口令一次（N = PASSWORD_HISTORY_DEPTH）。' +
  '与审计链 hmac 不同，这里**没有配套重签工具**——没有明文就无法重算摘要。' +
  '若本次确为轮换，请知悉该窗口并按 deployment/secret-rotation.md 记录；' +
  '若非有意轮换，说明存在未同步的密钥副本，需立即排查。';

/**
 * 是否存在「已配置 pepper 且历史深度 > 0」的组合。
 *
 * 只有这个组合下"轮换导致历史归零"才是一条真实削弱：若 PASSWORD_HISTORY_DEPTH=0
 * （或该模块加载失败），本就没有历史可归零，告警会是纯噪声。
 *
 * 为什么可以 require passwordHistory：该模块自身是惰性取 config（getPepper 用
 * try/catch 包着 require('../config')），且 validate.js 调用本函数的时刻
 * config 已就绪。仍包 try/catch，理由同 legacyCbcGuard——本函数是导出 API，
 * 测试可能单独调用它。
 */
const hasPasswordHistoryToInvalidate = () => {
  try {
    return require('../utils/passwordHistory').HISTORY_DEPTH > 0;
  } catch (_) {
    return false;
  }
};

/**
 * 收集 immutable 档位相关告警。
 *
 * 当前两项：
 *   ① 口令复用历史的 pepper 轮换——"是否能检测到"本身有歧义的一类：应用**无法
 *      自行判断** HMAC_SECRET 是否刚被轮换过（没有任何持久化的密钥版本记录可比对）。
 *      因此做法是：只要配置组合满足"轮换会削弱防线"这一前提，就在每次启动时提醒一次，
 *      把判断交给读到日志的运维。
 *   ② PII 轮换旧钥残留——这一项**可以**确定性检测（变量在不在是客观事实），
 *      但它只在生产环境判：开发机保留旧钥做演练是正常操作（见下）。
 *
 * 这是刻意的保守取向：宁可每次启动多一行日志（内容恒定、可 grep、可屏蔽），
 * 也不要让一次真实轮换完全静默——静默的代价是运维以为轮换是无害操作，
 * 而实际上防线在那一刻归零了。
 *
 * @returns {string[]} 告警消息列表（便于测试断言）
 */
function collectInvariantWarnings() {
  const warnings = [];

  if (hasPasswordHistoryToInvalidate()) {
    if (SECURITY_RELEVANT.has('password_history_pepper_rotation')) {
      try {
        require('../utils/metrics').incSecurityAlert('password_history_pepper_rotation', 'medium');
      } catch (_) {
        /* 指标端不可用：调用方推的 warning 文案仍是唯一留痕（同 legacyCbcGuard） */
      }
    }
    warnings.push(passwordHistoryRotationMessage());
  }

  // 只在生产环境判：开发机/CI 保留 PII_ROTATION_OLD_AES_KEY 做演练是正常的
  // （validate.js 的 collectProductionWarnings 正是生产专属路径，但本函数是导出
  // API，测试与其他调用方可能直接调它，故这里**自己判一次**而不依赖调用方）。
  if (process.env.NODE_ENV === 'production' && hasPiiOldKeyLingering()) {
    if (SECURITY_RELEVANT.has('pii_rotation_old_key_lingering')) {
      try {
        require('../utils/metrics').incSecurityAlert('pii_rotation_old_key_lingering', 'medium');
      } catch (_) {
        /* 同上：指标端不可用时文案仍是唯一留痕 */
      }
    }
    warnings.push(piiOldKeyLingeringMessage());
  }

  return warnings;
}

module.exports = {
  collectInvariantWarnings,
  passwordHistoryRotationMessage,
  hasPasswordHistoryToInvalidate,
  piiOldKeyLingeringMessage,
  hasPiiOldKeyLingering,
  PII_OLD_KEY_NAME,
};
