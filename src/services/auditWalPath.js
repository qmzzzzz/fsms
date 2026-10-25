/**
 * 审计 WAL 的默认路径派生（自 services/auditBufferWal.js 拆出，O-3 体积棘轮）
 *
 * 路径解析时机（auditBufferGap 抖动修复）：历史上是模块加载期 const——
 * Jest 并行 worker 里先 require 本模块的测试文件会锁死路径，后设
 * AUDIT_WAL_PATH 的套件被静默忽略，指向已清理目录或共享默认文件，
 * 造成跨套件 WAL 串写与断言抖动。现由 start() 时重读 env（与
 * AUDIT_WAL_MAX_BYTES 的运行期读法同语义）：每次启动都可重指向，
 * 生产环境一次启动一个路径不受影响；测试套件按 worker 独立 mkdtemp。
 */

const path = require('path');

/**
 * 默认 WAL 路径：**按目标库名派生**，避免多进程共享同一份 WAL。
 *
 * L-28 修复（2026-09-16）：原默认值为固定的 `logs/audit-buffer.wal`，
 * 只要两个进程 cwd 相同（典型场景：同一台机上跑 dev 实例 + 脚本 + 测试),
 * 就会往同一个文件里追加各自的行。后果不是「互相覆盖」而是更隐蔽的
 * **交叉重放**：A 进程崩溃后重启，会把 B 进程尚未落库的行也读进自己的
 * 缓冲并落库——而 B 进程仍在运行、稍后也会落库同一批 → 审计记录**重复插入**，
 * 哈希链随之出现分叉，verify-audit-chain 报 chain_break。
 *
 * 派生规则（三层，后者覆盖前者）：
 *   1. 显式 AUDIT_WAL_PATH → 完全按运维指定（最高优先级，保持向后兼容）
 *   2. 有 MONGODB_URI → logs/audit-buffer.<dbName>.wal（各库各一份，天然隔离）
 *   3. 都没有 → logs/audit-buffer.wal（历史默认值，单实例场景行为不变）
 *
 * 为什么用库名而不是 pid：WAL 的唯一用途是**跨重启**崩溃恢复，
 * pid 命名的文件在进程死掉后就再也无人认领，等于放弃了 WAL 的全部价值。
 * 库名是「同一份审计数据」的天然标识，重启前后保持不变。
 */
function deriveDefaultWalPath() {
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
  return dbName ? `${base}.${dbName}.wal` : `${base}.wal`;
}

/**
 * 库名 → 文件名安全片段（L-30）。
 *
 * 缺陷（本函数抽出的原因）：库名直接拼进文件名，而 URI 里的库名要经
 * decodeURIComponent 还原（`%2F` 就是 `/`）。于是 `mongodb://h/db%2F..%2Fevil`
 * 会让 WAL 落到 `logs/audit-buffer.db/../../evil.wal`——实测更深一级的
 * `db%2F..%2F..%2Fevil` 直接逃出 `logs/` 到仓库根。**文件名可被 URI 控制 =
 * 任意相对路径写**，攻击面不需要本地权限，只要有人能影响 MONGODB_URI。
 *
 * 编码选择：用 encodeURIComponent 做**单射**转义（`%` 仍保留、大小写敏感），
 * 而不是「非法字符一律替换成下划线」——后者不单射：`db/x` 与 `db_x`、
 * `a b` 与 `a_b` 都会映射到同一文件，等于把 L-28 刚消除的**交叉重放**
 * 又从另一条路引回来（两个不同的库共写一份 WAL）。宁可文件名难看，不可歧义。
 *
 * 对合法库名的行为：MongoDB 库名约束里不含 `/ \ : * ? " < > |` 等字符
 * （本文档不引用具体版本条款，只按「白名单字符恒等」这一可验证性质陈述），
 * 因此本函数对真实库名是**恒等变换**——`fire_safety_db` → `fire_safety_db`。
 * 唯一补一刀的是 `*`：encodeURIComponent 不转义它，而它在 NTFS 上是非法字符。
 *
 * @param {string} raw 已 decodeURIComponent 的库名
 * @returns {string} 可安全拼进文件名的片段；无法安全化时返回空串（回退默认路径）
 */
function dbNameToFileSegment(raw) {
  const name = String(raw);
  if (!name) return '';
  // '*' 是 encodeURIComponent 的保留字符（不转义）但为 Windows 非法文件名字符，
  // 单独补转义；其余非法字符（/ \ : ? " < > | 空格 控制符）它已全部转义
  const encoded = encodeURIComponent(name).replace(/\*/g, '%2A');
  // 兜底断言：转义后仍含路径分隔符或相对路径片段 → 拒绝，回退默认路径
  // （encodeURIComponent 的正确性不该被"信任"，这是 fail-closed 的第二道闸）
  if (encoded.includes('/') || encoded.includes('\\')) return '';
  if (encoded === '.' || encoded === '..') return '';
  return encoded;
}

module.exports = { deriveDefaultWalPath };
