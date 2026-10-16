/**
 * 备份产物完整性判据（A8，2026-10-16）—— **纯函数**，无 fs / 无子进程 / 无副作用
 *
 * 为什么单独成模块：巡检（scripts/backup-integrity-patrol.js）需要判据可被用例直接驱动，
 * 而不是"造一堆临时文件再跑一次脚本看输出"。判据与 IO 分离后，每条规则的**反例**
 * （缺 sidecar / 摘要对不上 / 0 字节 / 孤儿 sidecar / 备份过旧）都能在内存里构造。
 *
 * ===== 格式契约（与 shell 侧同源，改动必须两侧一起）=====
 * 备份侧 `scripts/backupCrypto.sh:83-86` 写 sidecar 的方式是
 *   `sha256sum "$file" > "$file.sha256"`
 * ⇒ sidecar 内容形如 `<64位hex>  <备份宿主机上的路径>`（分隔符是两空格）。
 * 校验侧 `scripts/restore-mongo.sh:94-95` **不用 `sha256sum --check`**，而是
 *   `grep -oE '[0-9a-f]{64}'` 取第一段 64 位十六进制再与本地重算值比对。
 * 理由是实测过的：`--check` 认的是 sidecar 里那串**备份宿主机路径**，异地取回后
 * 文件名/路径必然对不上，`--check` 会直接报 "no such file"——那等于逼操作者跳过校验。
 * 本模块逐字沿用同一判据（`SIDECAR_DIGEST_RE`），因此它是 restore 的**孪生**而不是
 * 第三套口径：三处（写、恢复校验、巡检）认的是同一个正则。
 *
 * 判据本身不在这里：本模块只说"什么样的产物算完整"，不做任何 IO。
 */

/** 归档文件名形态：`fire-safety-backup-<时间戳>.gz` 或加密后的 `.gz.gpg` */
const ARCHIVE_RE = /^fire-safety-backup-.+\.gz(\.gpg)?$/;
/** 校验和 sidecar 后缀（backup-mongo.sh 对**每个**产物都写一份） */
const SIDECAR_SUFFIX = '.sha256';
/** 与 restore-mongo.sh:94 同一条正则：从 sidecar 文本里取第一段 64 位十六进制 */
const SIDECAR_DIGEST_RE = /[0-9a-f]{64}/;

/** 是否是一个备份归档文件名 */
const isArchiveName = (name) => ARCHIVE_RE.test(String(name || ''));
/** 是否是一个校验和 sidecar 文件名 */
const isSidecarName = (name) => String(name || '').endsWith(SIDECAR_SUFFIX);
/** 由归档名推出其配对的 sidecar 名 */
const sidecarNameFor = (archiveName) => `${archiveName}${SIDECAR_SUFFIX}`;
/** 由 sidecar 名推出其配对的归档名；不是 sidecar 时返回 null */
const archiveNameFor = (sidecarName) =>
  isSidecarName(sidecarName) ? sidecarName.slice(0, -SIDECAR_SUFFIX.length) : null;

/**
 * 从 sidecar 文本里解析期望摘要。
 * @param {string} text sidecar 内容
 * @returns {string|null} 64 位小写 hex；解析不出时 null（调用方必须当成**错误**，不是"跳过"）
 */
const parseSidecarDigest = (text) => {
  const m = SIDECAR_DIGEST_RE.exec(String(text == null ? '' : text));
  return m ? m[0] : null;
};

/** 最小合理归档字节数：比这还小说明是半成品（mongodump 写出空文件后进程被杀） */
const MIN_ARCHIVE_BYTES = 1024;

/**
 * 单个归档的完整性判据。返回 true 表示"已判死，不必再往下判"
 * （缺证据时再去比摘要没有意义，而且会掩盖"缺 sidecar"这个更根本的问题）。
 *
 * @param {{name: string, size: number, expectedDigest: string|null, actualDigest: string|null}} a
 * @param {(level: string, code: string, message: string) => void} add
 */
const classifyArchive = (a, add) => {
  // 元信息读不到（stat 失败）与"文件确实是 0 字节"是两件事，必须分开报：
  // 前者是"没读到证据"，后者是"证据表明产物是空壳"。混成一句会让运维
  // 去查"为什么备份是空的"，而真相是权限/挂载/路径写错。
  if (!Number.isFinite(a.size)) {
    add('error', 'unreadable_archive', `读不到归档元信息（stat 失败或不可读）：${a.name}`);
    return true;
  }
  if (a.size <= 0) {
    add('error', 'zero_bytes', `归档为空文件：${a.name}`);
  } else if (a.size < MIN_ARCHIVE_BYTES) {
    add(
      'error',
      'suspiciously_small',
      `归档仅 ${a.size} 字节（< ${MIN_ARCHIVE_BYTES}），疑为半成品：${a.name}`
    );
  }
  if (!a.expectedDigest) {
    add(
      'error',
      'missing_sidecar',
      `归档缺少可解析的 .sha256（缺的是证据，不是"可跳过"）：${a.name}`
    );
    return true;
  }
  if (!a.actualDigest) {
    add('error', 'unreadable_archive', `归档不可读，无法重算摘要：${a.name}`);
    return true;
  }
  if (a.expectedDigest !== a.actualDigest) {
    add(
      'error',
      'digest_mismatch',
      `摘要对不上（这是**反证**，不是缺证据）：${a.name} 期望 ${a.expectedDigest} 实际 ${a.actualDigest}`
    );
  }
  return false;
};

/**
 * 孤儿 sidecar：归档被清理/搬走但校验和留下。它本身不是数据风险，
 * 但会让"归档数 vs 校验和数"的对账永远不平，掩盖真正的缺件。
 */
const findOrphanSidecars = (sidecarNames, archiveNames, add) => {
  for (const s of sidecarNames) {
    const archive = archiveNameFor(s);
    if (archive && !archiveNames.has(archive)) {
      add('warn', 'orphan_sidecar', `校验和没有对应的归档（对账不平）：${s}`);
    }
  }
};

/**
 * 评估一批备份产物的完整性。
 *
 * @param {object} input
 * @param {Array<{name: string, size: number, mtimeMs: number,
 *   expectedDigest?: string|null, actualDigest?: string|null}>} input.archives
 *   目录里所有**归档**产物；`expectedDigest` 为 null 表示 sidecar 缺失/解析不出，
 *   `actualDigest` 为 null 表示文件不可读。
 * @param {string[]} [input.sidecarNames] 目录里所有 sidecar 文件名（用于查孤儿）
 * @param {number} [input.now] 当前时刻（毫秒），注入以便用例可控
 * @param {number} [input.rpoHours] RPO 目标（小时）。给定时，最新归档的年龄超过它即报错
 * @returns {{ok: boolean, findings: Array<{level: 'error'|'warn', code: string, message: string}>, newestAgeHours: number|null}}
 */
const evaluateBackupArtifacts = ({
  archives = [],
  sidecarNames = [],
  now = Date.now(),
  rpoHours = null,
} = {}) => {
  const findings = [];
  const add = (level, code, message) => findings.push({ level, code, message });

  if (archives.length === 0) {
    add('error', 'no_archives', '目录里没有任何备份归档（fire-safety-backup-*.gz[.gpg]）');
  }
  for (const a of archives) classifyArchive(a, add);
  findOrphanSidecars(sidecarNames, new Set(archives.map((a) => a.name)), add);

  let newestAgeHours = null;
  if (archives.length > 0) {
    newestAgeHours = (now - Math.max(...archives.map((a) => a.mtimeMs || 0))) / 3600000;
    if (Number.isFinite(rpoHours) && rpoHours > 0 && newestAgeHours > rpoHours) {
      add(
        'error',
        'stale_backup',
        `最新归档已 ${newestAgeHours.toFixed(1)} 小时未更新，超过 RPO 目标 ${rpoHours} 小时`
      );
    }
  }

  return { ok: findings.every((f) => f.level !== 'error'), findings, newestAgeHours };
};

/**
 * 异地副本可达性判据（A8：单机副本在"机器没了"面前等于没有备份）。
 * 判据只有一条：异地目录**可读**且**含最新归档**（或至少含任一归档）。
 * 不含最新归档 ≠ 不可达，但它是 RPO 意义上的缺口，故分级为 error：
 * 异地存在的全部意义就是"本机没了还能恢复"，落后一个周期的副本救不了当前的 RPO。
 *
 * @param {{reachable: boolean, names?: string[], newestLocalName?: string|null}} input
 */
const evaluateOffsiteReplica = ({ reachable, names = [], newestLocalName = null } = {}) => {
  if (!reachable) {
    return {
      ok: false,
      findings: [{ level: 'error', code: 'offsite_unreachable', message: '异地副本目录不可达' }],
    };
  }
  const archives = names.filter(isArchiveName);
  if (archives.length === 0) {
    return {
      ok: false,
      findings: [
        { level: 'error', code: 'offsite_empty', message: '异地副本目录可达，但里面没有任何归档' },
      ],
    };
  }
  if (newestLocalName && !archives.includes(newestLocalName)) {
    return {
      ok: false,
      findings: [
        {
          level: 'error',
          code: 'offsite_lagging',
          message: `异地副本不含最新归档 ${newestLocalName}（落后一个周期的副本救不了当前的 RPO）`,
        },
      ],
    };
  }
  return { ok: true, findings: [] };
};

module.exports = {
  ARCHIVE_RE,
  SIDECAR_SUFFIX,
  SIDECAR_DIGEST_RE,
  MIN_ARCHIVE_BYTES,
  isArchiveName,
  isSidecarName,
  sidecarNameFor,
  archiveNameFor,
  parseSidecarDigest,
  classifyArchive,
  findOrphanSidecars,
  evaluateBackupArtifacts,
  evaluateOffsiteReplica,
};
