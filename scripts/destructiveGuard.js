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
 * 解析连接串的 `host:port` 段（小写；无端口则只有 host）。
 * 用于 `ALLOWED_SOURCE_DB=host:port/db` 这一收紧形态——**只比库名挡不住同名库**：
 * 本地回退串与生产库同名（`docker-compose.yml` 的 `MONGO_INITDB_DATABASE` 与
 * `.env.example` 的 `ALLOWED_SOURCE_DB` 都是 `fire_safety_db`），而运维用
 * `ssh -L 27017:mongo:27017 <prod>` 把生产库打到本机时，主机段变了、库名没变。
 * @returns {string} 如 `127.0.0.1:27017`；解析不出时返回空串
 */
function hostFromUri(uri) {
  if (typeof uri !== 'string' || !uri) return '';
  const afterScheme = uri.replace(/^mongodb(\+srv)?:\/\//, '');
  const at = afterScheme.lastIndexOf('@'); // 去掉凭据段（user:pw@host）
  const rest = at === -1 ? afterScheme : afterScheme.slice(at + 1);
  const slash = rest.indexOf('/');
  return (slash === -1 ? rest : rest.slice(0, slash)).toLowerCase();
}

/**
 * 解析本次要操作的 MongoDB URI，并在回退到本地库时显式告警。
 *
 * 回退本身不算错误（本地开发即如此），但**静默回退**会让"以为在演练、
 * 实际打到了本地库"或反之的情况无法察觉。此处统一打印来源。
 *
 * @param {{scriptName: string}} opts
 * @returns {{uri: string, dbName: string, host: string, isFallback: boolean}}
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
  return { uri, dbName, host: hostFromUri(uri), isFallback };
}

/**
 * fail-closed 白名单校验：破坏性操作（--apply 类）必须显式声明目标库。
 *
 * 规则（与 run-rollback-drill.js 的原意图一致，但把失败方向改为拒绝）：
 *   - 未设置 ALLOWED_SOURCE_DB → **拒绝执行**（原先静默放行，等于无白名单）
 *   - 目标库不在白名单内       → 拒绝执行
 *   - 演练模式（apply=false）  → 不拦截，正常输出报告
 *
 * 两条后置收紧（都朝"拒绝"方向，不新增放行面）：
 *   - `isFallback: true` 且 `apply: true` → **拒绝**：回退出来的库不允许做破坏性写。
 *     这是"只比库名"唯一的实际漏洞形态——回退串与生产库同名，运维少 export 一次
 *     `MONGODB_URI`（且本机恰好隧道着生产端口）就会把 `dropIndex` / `deleteMany`
 *     打到生产库，而白名单全程没比较过主机段。
 *   - 白名单条目写成 `host:port/db` 时按**全限定名**比对：想只放行某台机器上的某个库，
 *     现在能表达。裸库名条目保持原语义（向后兼容 `.env.example` 的写法）。
 *
 * @param {{scriptName: string, dbName: string, apply: boolean, host?: string, isFallback?: boolean}} opts
 * @returns {boolean} true=放行；false=已拒绝（调用方应 return / exit）
 */
function assertApplyAllowed({ scriptName, dbName, apply, host = '', isFallback = false }) {
  if (!apply) return true;

  if (isFallback) {
    console.error(
      `\n[${scriptName}] 拒绝执行：--apply 类操作不得作用于"未设置 MONGODB_URI 时回退出来的库"。\n` +
        `  原因：回退库与生产库**同名**（都是 ${dbNameFromUri(LOCAL_FALLBACK_URI)}），` +
        `只比库名的白名单分不开"本机开发库"与"隧道到本地的生产库"。\n` +
        `  用法：export MONGODB_URI=<目标连接串> 后重试；确需在本地做破坏性演练，` +
        `请显式连到一个改名后的库（如 .../fire_safety_drill）。\n`
    );
    process.exitCode = 2;
    return false;
  }

  const allowList = (process.env.ALLOWED_SOURCE_DB || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (allowList.length === 0) {
    console.error(
      `\n[${scriptName}] 拒绝执行：--apply 类操作必须显式设置 ALLOWED_SOURCE_DB 白名单。\n` +
        `  目的：防止误把演练/迁移指向非预期库（尤其生产库）。\n` +
        `  用法：ALLOWED_SOURCE_DB=${dbName || '<库名>'} node scripts/${scriptName} --apply ...\n` +
        `  多个库用英文逗号分隔；写全限定名（如 127.0.0.1:27017/${dbName || '<库名>'}）` +
        `可把放行面收紧到指定主机。\n`
    );
    process.exitCode = 2;
    return false;
  }

  const qualifiedHost = (host || '').toLowerCase();
  // 条目含 `/` ⇒ 全限定名 `host:port/db`：主机段大小写不敏感（DNS 语义），
  // 库名段大小写敏感（Mongo 库名本身敏感）。
  // 已知限制：副本集串的主机段是逗号分隔整串，而本白名单用逗号分隔条目，
  // 因此该形态**表达不出来 → 只会误拒不会误放**（fail 方向仍朝拒绝）。
  const matched = allowList.some((entry) => {
    const slash = entry.indexOf('/');
    if (slash === -1) return entry === dbName;
    return (
      entry.slice(0, slash).trim().toLowerCase() === qualifiedHost &&
      entry.slice(slash + 1).trim() === dbName
    );
  });

  if (!dbName || !matched) {
    console.error(
      `\n[${scriptName}] 拒绝执行：目标库「${dbName || '(未解析出库名)'}」不在 ALLOWED_SOURCE_DB 白名单中。\n` +
        `  当前白名单：${allowList.join(', ')}\n` +
        `  如白名单写的是 host:port/db 形态，还需脚本向护栏提供 host（本次 host=${host || '(未提供)'}）。\n` +
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
  hostFromUri,
  resolveMongoUri,
  assertApplyAllowed,
};
