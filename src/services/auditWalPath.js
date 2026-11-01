/**
 * 审计 WAL 的默认路径派生（自 services/auditBufferWal.js 拆出，O-3 体积棘轮）
 *
 * 路径解析时机（auditBufferGap 抖动修复）：历史上是模块加载期 const—— Jest 并行 worker 里先 require 本模块的测试文件会锁死路径，后设 AUDIT_WAL_PATH 的套件被静默忽略，指向已清理目录或共享默认文件，
 * 造成跨套件 WAL 串写与断言抖动。现由 start() 时重读 env（与 AUDIT_WAL_MAX_BYTES 的运行期读法同语义）：每次启动都可重指向，生产环境一次启动一个路径不受影响；测试套件按 worker 独立 mkdtemp。
 */

const path = require('path');

/**
 * 默认 WAL 路径：**按目标库名派生**，避免多进程共享同一份 WAL（L-28，2026-09-16）。
 *
 * 原默认值是固定的 `logs/audit-buffer.wal`：两个进程 cwd 相同（dev 实例 + 脚本 + 测试）就往同一文件追加。后果不是「互相覆盖」而是更隐蔽的**交叉重放**——A 崩溃重启会把 B 尚未
 * 落库的行也读进自己的缓冲并落库，而 B 仍在运行、稍后也会落库同一批 ⇒ 审计记录**重复插入**，哈希链分叉，verify-audit-chain 报 chain_break。派生规则（后者覆盖前者）：① 显式
 * AUDIT_WAL_PATH 完全照运维指定；② 有 MONGODB_URI ⇒ logs/audit-buffer.<dbName>.wal； ③ 都没有 ⇒ 历史默认值 logs/audit-buffer.wal。用库名而不是 pid，是因为 WAL 的用途是
 * **跨重启**恢复：pid 文件在进程死后就无人认领，而库名是「同一份审计数据」的天然标识。
 *
 * 【D9 前提，别读成「多实例天然隔离」】派生只认库名 ⇒ **同库多实例共用同一个默认 WAL 文件**，谁后写谁赢：并行跑两个实例（或实例 + 维护脚本）时，它们的行仍会落进同一文件，上面那套交叉重放只是被**收窄到同库**、没有消失。隔离粒度到库为止；要按实例隔离只能显式
 * 设 AUDIT_WAL_PATH（带 pid / 实例名）。该粒度不只写在注释里：见 resolveWalPath().scope。
 */
/** 派生结果：path + 依据（dbName）+ 隔离粒度；`shared-fallback` = 没有库名可用的历史默认值。 */
function resolveWalPath() {
  const uri = process.env.MONGODB_URI;
  let dbName = '';
  if (uri) {
    try {
      // 取 URI path 段的库名：mongodb://host:port/<db>?opts
      // 不用 URL 解析：mongodb:// 不是标准 scheme，URL 会误判 user:pass 部分
      const m = String(uri).match(/^[a-z+]+:\/\/[^/]*\/([^?/]+)/i);
      if (m && m[1]) dbName = dbNameToFileSegment(decodeURIComponent(m[1]));
    } catch {
      /* 解析失败回退到历史默认值，不因路径问题阻断启动 */
    }
  }
  const base = path.join(__dirname, '../../logs/audit-buffer');
  return {
    path: dbName ? `${base}.${dbName}.wal` : `${base}.wal`,
    dbName: dbName || null,
    scope: dbName ? 'per-database' : 'shared-fallback',
  };
}

/** 兼容入口：只返回路径字符串（与拆分前逐字一致，调用方无需感知）。 */
const deriveDefaultWalPath = () => resolveWalPath().path;
/** D9 自证入口：把「隔离粒度到库为止」暴露成可断言的返回值（纯函数，无 env 之外的输入）。 */
const deriveDefaultWalPathInfo = () => resolveWalPath();

/**
 * 库名 → 文件名安全片段（L-30）。
 *
 * 缺陷（本函数抽出的原因）：库名直接拼进文件名，而 URI 里的库名要经 decodeURIComponent 还原（`%2F` 就是 `/`）。于是 `mongodb://h/db%2F..%2Fevil`
 * 会让 WAL 落到 `logs/audit-buffer.db/../../evil.wal`——实测更深一级的 `db%2F..%2F..%2Fevil` 直接逃出 `logs/` 到仓库根。**文件名可被 URI 控制 =
 * 任意相对路径写**，攻击面不需要本地权限，只要有人能影响 MONGODB_URI。
 *
 * 编码选择：用 encodeURIComponent 做**单射**转义（`%` 仍保留、大小写敏感），而不是「非法字符一律替换成下划线」——后者不单射：`db/x` 与 `db_x`、 `a b` 与 `a_b` 都会映射到同一文件，等于把 L-28 刚消除的**交叉重放**
 * 又从另一条路引回来（两个不同的库共写一份 WAL）。宁可文件名难看，不可歧义。
 *
 * 对合法库名的行为：MongoDB 库名约束里不含 `/ \ : * ? " < > |` 等字符（本文档不引用具体版本条款，只按「白名单字符恒等」这一可验证性质陈述），
 * 因此本函数对真实库名是**恒等变换**——`fire_safety_db` → `fire_safety_db`。唯一补一刀的是 `*`：encodeURIComponent 不转义它，而它在 NTFS 上是非法字符。
 *
 * @param {string} raw 已 decodeURIComponent 的库名
 * @returns {string} 可安全拼进文件名的片段；无法安全化时返回空串（回退默认路径）
 */
function dbNameToFileSegment(raw) {
  const name = String(raw);
  if (!name) return '';
  // '*' 是 encodeURIComponent 的保留字符（不转义）但为 Windows 非法文件名字符，
  // 单独补转义；其余非法字符（/ \ : ? " < > | 空格控制符）它已全部转义
  const encoded = encodeURIComponent(name).replace(/\*/g, '%2A');
  // 兜底断言：转义后仍含路径分隔符或相对路径片段 → 拒绝，回退默认路径
  // （encodeURIComponent 的正确性不该被"信任"，这是 fail-closed 的第二道闸）
  if (encoded.includes('/') || encoded.includes('\\')) return '';
  if (encoded === '.' || encoded === '..') return '';
  return encoded;
}

module.exports = { deriveDefaultWalPath, deriveDefaultWalPathInfo };
