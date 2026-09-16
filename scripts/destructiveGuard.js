/**
 * 破坏性脚本护栏（M-08）
 *
 * 【背景】仓库内多个脚本会批量改写或删除数据，但护栏口径原先不一致：
 *   - run-rollback-drill.js：需 `--apply-source` + `--yes` 双标志，且有库名白名单
 *   - resign-audit-hmac.js / fix-token-blacklist-index.js / migrate-mfa-secret.js：
 *     只需单个 `--apply` 即可执行，且默认回退到本地库 URI，无库名白名单
 *
 * 后果有两个方向：
 *   ① 在生产 shell 中误敲 `--apply` 时，不会因"库名不在白名单"而中止；
 *   ② 破坏性最强（清空 4 个集合）的脚本护栏最严，而**批量改写审计链 HMAC**
 *      这类"重写完整性证据"的操作护栏反而最松——强度与危害不匹配。
 *
 * 另外 run-rollback-drill.js 的白名单本身是 fail-open 的：
 *   `if (allowList.length > 0 && !allowList.includes(dbName))`
 * 未设置 ALLOWED_SOURCE_DB 时条件恒假，等于**白名单不存在**。
 *
 * 本模块把护栏收敛为单一声明，供各脚本复用，避免"每个脚本各写一套"再次漂移。
 */

/** 各脚本在未配置 MONGODB_URI 时回退的本地库（与 .env.example 一致） */
const LOCAL_FALLBACK_URI = 'mongodb://127.0.0.1:27017/fire_safety_db';

/**
 * 从连接串解析库名。
 * 处理 mongodb://host:port/db?opts 与 mongodb+srv://... 两种形态。
 * @returns {string} 库名；无法解析时返回空串
 */
function dbNameFromUri(uri) {
  if (typeof uri !== 'string' || !uri) return '';
  try {
    // 去掉 query 与 hash 后再取路径末段
    const withoutQuery = uri.split('?')[0].split('#')[0];
    const afterScheme = withoutQuery.replace(/^mongodb(\+srv)?:\/\//, '');
    const slash = afterScheme.indexOf('/');
    if (slash === -1) return '';
    const name = afterScheme.slice(slash + 1).replace(/\/+$/, '');
    return name;
  } catch (_) {
    return '';
  }
}

/**
 * 解析本次要操作的 MongoDB URI，并在回退到本地库时显式告警。
 *
 * 回退本身不算错误（本地开发即如此），但**静默回退**会让"以为在演练、
 * 实际打到了本地库"或反之的情况无法察觉。此处统一打印来源。
 *
 * @param {{scriptName: string}} opts
 * @returns {{uri: string, dbName: string, isFallback: boolean}}
 */
function resolveMongoUri({ scriptName }) {
  const fromEnv = (process.env.MONGODB_URI || '').trim();
  const isFallback = !fromEnv;
  const uri = fromEnv || LOCAL_FALLBACK_URI;
  const dbName = dbNameFromUri(uri);

  if (isFallback) {
    console.warn(`[${scriptName}] 未设置 MONGODB_URI，回退到本地默认库：${LOCAL_FALLBACK_URI}`);
    console.warn(`[${scriptName}] 若目标是其他环境，请先 export MONGODB_URI=<目标连接串> 再执行。`);
  }
  return { uri, dbName, isFallback };
}

/**
 * fail-closed 白名单校验：破坏性操作（--apply 类）必须显式声明目标库。
 *
 * 规则（与 run-rollback-drill.js 的原意图一致，但把失败方向改为拒绝）：
 *   - 未设置 ALLOWED_SOURCE_DB → **拒绝执行**（原先静默放行，等于无白名单）
 *   - 目标库不在白名单内       → 拒绝执行
 *   - 演练模式（apply=false）  → 不拦截，正常输出报告
 *
 * @param {{scriptName: string, dbName: string, apply: boolean}} opts
 * @returns {boolean} true=放行；false=已拒绝（调用方应 return / exit）
 */
function assertApplyAllowed({ scriptName, dbName, apply }) {
  if (!apply) return true;

  const allowList = (process.env.ALLOWED_SOURCE_DB || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (allowList.length === 0) {
    console.error(
      `\n[${scriptName}] 拒绝执行：--apply 类操作必须显式设置 ALLOWED_SOURCE_DB 白名单。\n` +
        `  目的：防止误把演练/迁移指向非预期库（尤其生产库）。\n` +
        `  用法：ALLOWED_SOURCE_DB=${dbName || '<库名>'} node scripts/${scriptName} --apply ...\n` +
        `  多个库用英文逗号分隔。\n`
    );
    process.exitCode = 2;
    return false;
  }

  if (!dbName || !allowList.includes(dbName)) {
    console.error(
      `\n[${scriptName}] 拒绝执行：目标库「${dbName || '(未解析出库名)'}」不在 ALLOWED_SOURCE_DB 白名单中。\n` +
        `  当前白名单：${allowList.join(', ')}\n` +
        `  如确需操作该库，请设置 ALLOWED_SOURCE_DB 后重试。\n`
    );
    process.exitCode = 2;
    return false;
  }

  return true;
}

module.exports = {
  LOCAL_FALLBACK_URI,
  dbNameFromUri,
  resolveMongoUri,
  assertApplyAllowed,
};
