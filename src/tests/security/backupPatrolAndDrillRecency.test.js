/**
 * 备份与恢复就绪度（A8，2026-10-16）
 *
 * 需求对应：安全需求加固清单 A8 ——
 *   ① 恢复演练**定时化**（结果自动留档）；
 *   ② runbook 写明 **RPO / RTO 目标值**并与备份频率对齐；
 *   ③ 备份**完整性巡检**自动化（校验和巡检 + 异地副本可达性探针）。
 *
 * 本文件钉住三层的判据，且**全部用内存夹具驱动**（不造临时文件、不起进程）：
 *   - `scripts/backupIntegrityPolicy.js`：产物完整性的纯判据；
 *   - `src/constants/backupObjectives.js`：目标值解析与"RPO 是否优于备份频率"的对齐判定；
 *   - `scripts/backup-integrity-patrol.js`：巡检汇总（IO 注入）+ 演练留档时效解析；
 *   - `scripts/record-rollback-drill.js`：留档渲染与锚点定位。
 *
 * 可证伪性：每条 error 级判据都配一条"只差一个字段"的对照夹具（healthy 夹具翻红），
 * 避免写出"永远 ok"的空断言。文档引用（cron 行、留档锚点、恢复侧正则）也逐条回源断言——
 * 这些常量是**承重假设**：文档改了而常量没改，判据就变成一句假话。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const readRoot = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const {
  isArchiveName,
  isSidecarName,
  sidecarNameFor,
  archiveNameFor,
  parseSidecarDigest,
  evaluateBackupArtifacts,
  evaluateOffsiteReplica,
  MIN_ARCHIVE_BYTES,
} = require('../../../scripts/backupIntegrityPolicy');

const {
  BACKUP_SCHEDULE,
  resolveBackupObjective,
  evaluateRpoAlignment,
  evaluateDeclaredBound,
  parseObjectiveHours,
  describeBackupObjective,
  describeAllBackupObjectives,
} = require('../../constants/backupObjectives');

const {
  parseArgs,
  runPatrol,
  DRILL_INTERVAL_DAYS,
  DEFAULT_DRILL_RECORD,
} = require('../../../scripts/backup-integrity-patrol');

const { collectArtifacts } = require('../../../scripts/backupArtifactScan');

const {
  parseDrillRecordDates,
  evaluateDrillRecency,
} = require('../../../scripts/drReadinessPolicy');

const {
  RECORD_ANCHOR,
  maxDrillNumber,
  validateManifest,
  renderDrillRecord,
  appendDrillRecord,
} = require('../../../scripts/record-rollback-drill');

const HOUR_MS = 3600000;
const NOW = Date.parse('2026-10-16T04:00:00Z');
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

// ============================ 内存夹具 ============================
/**
 * 极简虚拟文件系统。只实现巡检真正用到的五种操作，避免用例依赖真实磁盘。
 * `files` 的键是绝对/相对路径（与 path.join 一致），值形如
 * `{ size, mtimeMs, content?, sha256? }`。
 */
function makeIo({ dirs = [], files = {} } = {}) {
  const dirSet = new Set(dirs);
  const fileMap = new Map(Object.entries(files));
  const childNames = (dir) => {
    const prefix = dir.endsWith(path.sep) ? dir : `${dir}${path.sep}`;
    const names = new Set();
    for (const key of fileMap.keys()) {
      if (!key.startsWith(prefix)) continue;
      const rest = key.slice(prefix.length);
      if (!rest.includes(path.sep)) names.add(rest);
    }
    for (const d of dirSet) {
      if (!d.startsWith(prefix)) continue;
      const rest = d.slice(prefix.length);
      if (rest && !rest.includes(path.sep)) names.add(rest);
    }
    return [...names];
  };
  return {
    async isDir(p) {
      return dirSet.has(p);
    },
    async listNames(p) {
      return childNames(p);
    },
    async statFile(p) {
      const f = fileMap.get(p);
      if (!f) throw new Error('ENOENT');
      return { size: f.size, mtimeMs: f.mtimeMs };
    },
    async readText(p) {
      const f = fileMap.get(p);
      if (!f || f.content === undefined) throw new Error('ENOENT');
      return f.content;
    },
    async sha256(p) {
      const f = fileMap.get(p);
      if (!f || f.sha256 === undefined) throw new Error('ENOENT');
      return f.sha256;
    },
  };
}

const BACKUP_DIR = path.join('backups');
const ARCHIVE = 'fire-safety-backup-2026-10-16-0200.gz.gpg';
const ARCHIVE_PATH = path.join(BACKUP_DIR, ARCHIVE);

/** 一份"完全健康"的夹具：唯一归档 + 配对 sidecar + 摘要一致 + 1 小时前 */
const healthyTree = () => ({
  dirs: [BACKUP_DIR],
  files: {
    [ARCHIVE_PATH]: { size: 5 * 1024 * 1024, mtimeMs: NOW - HOUR_MS, sha256: DIGEST_A },
    [`${ARCHIVE_PATH}.sha256`]: { content: `${DIGEST_A}  /opt/xf/backups/${ARCHIVE}\n` },
  },
});

// ============================ 1. 产物完整性判据 ============================
describe('备份产物完整性判据（A8 动作 3）', () => {
  test('sidecar 命名契约：归档 ↔ sidecar 一一对应，且与备份侧写出的后缀一致', () => {
    expect(isArchiveName(ARCHIVE)).toBe(true);
    expect(isArchiveName('fire-safety-backup-2026-10-16-0200.gz')).toBe(true);
    expect(isArchiveName(`${ARCHIVE}.sha256`)).toBe(false);
    expect(isArchiveName('deliverables-2026-09-28')).toBe(false);

    expect(sidecarNameFor(ARCHIVE)).toBe(`${ARCHIVE}.sha256`);
    expect(isSidecarName(`${ARCHIVE}.sha256`)).toBe(true);
    expect(archiveNameFor(`${ARCHIVE}.sha256`)).toBe(ARCHIVE);
    expect(archiveNameFor(ARCHIVE)).toBe(null);
  });

  test('摘要解析与 restore 侧同一条正则：只取第一段 64 位十六进制', () => {
    // 与 restore-mongo.sh 同源（写侧 backupCrypto.sh 用 `sha256sum >`，分隔符两空格；
    // 异地带回后路径不同，所以两侧都不能用 `sha256sum --check`）。回源断言见下一组。
    expect(parseSidecarDigest(`${DIGEST_A}  /some/other/path/file.gz.gpg\n`)).toBe(DIGEST_A);
    expect(parseSidecarDigest(`${DIGEST_A} *file.gz.gpg\n`)).toBe(DIGEST_A);
    // 解析不出必须返回 null（调用方当成"缺证据"），而不是返回空串或抛错
    expect(parseSidecarDigest('not a checksum')).toBe(null);
    expect(parseSidecarDigest('')).toBe(null);
    expect(parseSidecarDigest(null)).toBe(null);
  });

  test('健康夹具零发现（前提自证：判据不是恒红）', () => {
    const r = evaluateBackupArtifacts({
      archives: [
        {
          name: ARCHIVE,
          size: 5e6,
          mtimeMs: NOW - HOUR_MS,
          expectedDigest: DIGEST_A,
          actualDigest: DIGEST_A,
        },
      ],
      sidecarNames: [`${ARCHIVE}.sha256`],
      now: NOW,
      rpoHours: 24,
    });
    expect(r).toEqual({ ok: true, findings: [], newestAgeHours: 1 });
  });

  test('八类判据逐条可触发（每条只改一个字段）', () => {
    const base = {
      name: ARCHIVE,
      size: 5e6,
      mtimeMs: NOW - HOUR_MS,
      expectedDigest: DIGEST_A,
      actualDigest: DIGEST_A,
    };
    const codesOf = (input) => evaluateBackupArtifacts(input).findings.map((f) => f.code);

    // ① 没有任何归档
    expect(codesOf({ archives: [], now: NOW })).toContain('no_archives');
    // ② 空文件
    expect(codesOf({ archives: [{ ...base, size: 0 }], now: NOW })).toContain('zero_bytes');
    // ③ 半成品（< 1KB）
    expect(codesOf({ archives: [{ ...base, size: MIN_ARCHIVE_BYTES - 1 }], now: NOW })).toContain(
      'suspiciously_small'
    );
    // ④ 元信息读不到：必须报 unreadable_archive，而**不是** zero_bytes
    //    （把"没读到证据"说成"证据表明是空壳"会把排查引向错误方向）
    const nan = codesOf({ archives: [{ ...base, size: NaN }], now: NOW });
    expect(nan).toContain('unreadable_archive');
    expect(nan).not.toContain('zero_bytes');
    // ⑤ 缺 sidecar
    expect(codesOf({ archives: [{ ...base, expectedDigest: null }], now: NOW })).toContain(
      'missing_sidecar'
    );
    // ⑥ 摘要对不上
    expect(codesOf({ archives: [{ ...base, actualDigest: DIGEST_B }], now: NOW })).toContain(
      'digest_mismatch'
    );
    // ⑦ 孤儿 sidecar（归档被搬走、校验和留下）
    expect(codesOf({ archives: [], sidecarNames: [`${ARCHIVE}.sha256`], now: NOW })).toContain(
      'orphan_sidecar'
    );
    // ⑧ 备份过旧（超过 RPO）
    const stale = evaluateBackupArtifacts({
      archives: [{ ...base, mtimeMs: NOW - 30 * HOUR_MS }],
      now: NOW,
      rpoHours: 24,
    });
    expect(stale.findings.map((f) => f.code)).toContain('stale_backup');
    expect(stale.newestAgeHours).toBeCloseTo(30, 6);
    // 不给 rpoHours 时**不做**过期判定（口径未定就不许发明阈值）
    expect(
      codesOf({ archives: [{ ...base, mtimeMs: NOW - 30 * HOUR_MS }], now: NOW, rpoHours: null })
    ).not.toContain('stale_backup');
  });

  test('可证伪：healthy → 只把摘要换成另一个值即翻红（判据不是常量 ok）', () => {
    const healthy = evaluateBackupArtifacts({
      archives: [
        {
          name: ARCHIVE,
          size: 5e6,
          mtimeMs: NOW,
          expectedDigest: DIGEST_A,
          actualDigest: DIGEST_A,
        },
      ],
      now: NOW,
    });
    const mutated = evaluateBackupArtifacts({
      archives: [
        {
          name: ARCHIVE,
          size: 5e6,
          mtimeMs: NOW,
          expectedDigest: DIGEST_A,
          actualDigest: DIGEST_B,
        },
      ],
      now: NOW,
    });
    expect(healthy.ok).toBe(true);
    expect(mutated.ok).toBe(false);
    expect(mutated.findings.map((f) => f.code)).toEqual(['digest_mismatch']);
  });

  test('异地副本判据：不可达 / 空 / 落后一个周期 / 正常', () => {
    expect(evaluateOffsiteReplica({ reachable: false }).findings[0].code).toBe(
      'offsite_unreachable'
    );
    expect(evaluateOffsiteReplica({ reachable: true, names: [] }).findings[0].code).toBe(
      'offsite_empty'
    );
    // 只有非归档文件也算"空"
    expect(
      evaluateOffsiteReplica({ reachable: true, names: ['readme.txt'] }).findings[0].code
    ).toBe('offsite_empty');
    // 有归档但不含最新那一份：落后一个周期救不了当前的 RPO
    expect(
      evaluateOffsiteReplica({
        reachable: true,
        names: ['fire-safety-backup-2026-10-15-0200.gz.gpg'],
        newestLocalName: ARCHIVE,
      }).findings[0].code
    ).toBe('offsite_lagging');
    expect(
      evaluateOffsiteReplica({ reachable: true, names: [ARCHIVE], newestLocalName: ARCHIVE })
    ).toEqual({ ok: true, findings: [] });
  });
});

// ============================ 2. 文档回源（承重假设） ============================
describe('A8 判据的承重假设必须回源（文档改了常量就是假话）', () => {
  test('BACKUP_SCHEDULE 的 cron 与来源文件逐字一致', () => {
    const doc = readRoot('deployment/backup-encryption.md');
    expect(doc).toContain(BACKUP_SCHEDULE.cron);
    expect(BACKUP_SCHEDULE.source).toBe('deployment/backup-encryption.md:39-43');
    expect(doc).toContain('每日全量');
    expect(BACKUP_SCHEDULE.intervalHours).toBe(24);
  });

  test('写侧确实产出 <file>.sha256（backupCrypto.sh）', () => {
    expect(readRoot('scripts/backupCrypto.sh')).toContain(
      'sha256sum "$_crypto_file" > "$_crypto_file.sha256"'
    );
  });

  test('恢复侧确实用 grep 取 64 位十六进制而非 sha256sum --check（孪生判据同源）', () => {
    const restore = readRoot('scripts/restore-mongo.sh');
    expect(restore).toContain("grep -oE '[0-9a-f]{64}'");
    expect(restore).toContain('RESTORE_SKIP_CHECKSUM');
  });

  test('留档锚点真实存在（否则 record-rollback-drill.js 一运行即拒绝）', () => {
    expect(readRoot('deployment/rollback-drill-record.md')).toContain(RECORD_ANCHOR);
  });

  test('CI 定时工作流真实调用巡检脚本（"定时化"要有执行者）', () => {
    const wf = readRoot('.github/workflows/dr-readiness.yml');
    expect(wf).toContain('node scripts/backup-integrity-patrol.js --drill-only');
    expect(wf).toMatch(/schedule:/);
    expect(wf).toMatch(/permissions:\s*\n\s*contents:\s*read/);
  });

  test('runbook 写明 RPO/RTO 目标值，且点明依据不是等保条文（F-08 已定值）', () => {
    const doc = readRoot('deployment/rollback-drill.md');
    expect(doc).toContain('RPO');
    expect(doc).toContain('RTO');
    expect(doc).toContain('BACKUP_RPO_HOURS');
    // 2026-10-17 业务方拍板后已定值：文档不得再写"待业务确认"
    expect(doc).not.toContain('☐ 待业务确认');
    // 但依据必须诚实：等保三级没有规定 RPO/RTO 小时数，别把内部决策说成标准条文
    expect(doc).toContain('不是等保规定的小时数');
    expect(doc).toContain('业务决策值');
    // 反向判据（生效值宽于声明）也必须在手册里写明，否则只有一半
    expect(doc).toContain('rpo_looser_than_declared');
  });
});

// ============================ 3. RPO / RTO 声明与对齐 ============================
describe('RPO / RTO 声明与备份频率对齐（A8 动作 2）', () => {
  const saved = {};
  beforeEach(() => {
    saved.rpo = process.env.BACKUP_RPO_HOURS;
    saved.rto = process.env.BACKUP_RTO_HOURS;
    delete process.env.BACKUP_RPO_HOURS;
    delete process.env.BACKUP_RTO_HOURS;
  });
  afterEach(() => {
    if (saved.rpo === undefined) delete process.env.BACKUP_RPO_HOURS;
    else process.env.BACKUP_RPO_HOURS = saved.rpo;
    if (saved.rto === undefined) delete process.env.BACKUP_RTO_HOURS;
    else process.env.BACKUP_RTO_HOURS = saved.rto;
  });

  test('声明值已定（RPO 24h / RTO 4h），未配置生效值时 set=false 且说明里点出"未设定"', () => {
    const rpo = resolveBackupObjective('rpo');
    expect(rpo.set).toBe(false);
    expect(rpo.effectiveHours).toBe(null);
    // F-08：声明值由业务方拍板填值，与"是否已在部署侧生效"是两件事
    expect(rpo.declaredHours).toBe(24);
    expect(resolveBackupObjective('rto').declaredHours).toBe(4);
    expect(describeBackupObjective('rpo')).toContain('未设定');
    expect(describeBackupObjective('rpo')).toContain('声明 24h');
    expect(describeAllBackupObjectives()).toHaveLength(2);
  });

  test('生效值宽于声明值 ⇒ 判红（对外承诺 24h 而配 48h = 承诺没兑现）', () => {
    process.env.BACKUP_RPO_HOURS = '48';
    const rpo = resolveBackupObjective('rpo');
    expect(rpo.exceedsDeclared).toBe(true);
    const verdict = evaluateDeclaredBound('rpo');
    expect(verdict.ok).toBe(false);
    expect(verdict.code).toBe('rpo_looser_than_declared');
    expect(verdict.message).toContain('宽于');

    // 等于声明值 ⇒ 可兑现，判绿
    process.env.BACKUP_RPO_HOURS = '24';
    expect(resolveBackupObjective('rpo').exceedsDeclared).toBe(false);
    expect(evaluateDeclaredBound('rpo').ok).toBe(true);

    // 严于声明值（12h）不由本条拦——它由 evaluateRpoAlignment 拦（比备份频率还严）
    process.env.BACKUP_RPO_HOURS = '12';
    expect(resolveBackupObjective('rpo').exceedsDeclared).toBe(false);
    expect(evaluateDeclaredBound('rpo').ok).toBe(true);
  });

  test('parseObjectiveHours 是纯函数（发布路径注入 env，不读进程环境）', () => {
    // 与进程环境无关：即使 process.env 里配了别的值，传入什么就解析什么
    process.env.BACKUP_RPO_HOURS = '1';
    expect(parseObjectiveHours('24').effectiveHours).toBe(24);
    expect(parseObjectiveHours(undefined).set).toBe(false);
    expect(parseObjectiveHours('').set).toBe(false);
    expect(parseObjectiveHours('48x').set).toBe(false);
    expect(parseObjectiveHours('99999').effectiveHours).toBe(720);
    expect(parseObjectiveHours('99999').wasAdjusted).toBe(true);
  });

  test('严格解析：`24x` / `1e3` / 空串都不得被静默吃掉（parseInt 会放过前两个）', () => {
    process.env.BACKUP_RPO_HOURS = '24x';
    expect(resolveBackupObjective('rpo').set).toBe(false);
    expect(describeBackupObjective('rpo')).toContain('无法解析为数值');

    process.env.BACKUP_RPO_HOURS = '';
    expect(resolveBackupObjective('rpo').set).toBe(false);
    // 空串是"未配置"，不是"配了个非法值"——两种文案必须分开
    expect(describeBackupObjective('rpo')).toContain('未配置');

    // Number('2e1') === 20（合法数值，非 parseInt 的 2）⇒ 落在区间内原样生效
    process.env.BACKUP_RPO_HOURS = '2e1';
    expect(resolveBackupObjective('rpo').effectiveHours).toBe(20);
  });

  test('越界钳制并置 wasAdjusted（对外声明与实际生效不一致必须可见）', () => {
    process.env.BACKUP_RTO_HOURS = '99999';
    const rto = resolveBackupObjective('rto');
    expect(rto.wasAdjusted).toBe(true);
    expect(rto.effectiveHours).toBe(720);
    expect(describeBackupObjective('rto')).toContain('超出允许区间');
  });

  test('对齐判据：未声明 → 不阻断但说明下限；等于间隔 → 可兑现；优于间隔 → error', () => {
    const unset = evaluateRpoAlignment({ declaredRpoHours: null });
    expect(unset.ok).toBe(true);
    expect(unset.floorHours).toBe(24);

    expect(evaluateRpoAlignment({ declaredRpoHours: 24 }).ok).toBe(true);
    expect(evaluateRpoAlignment({ declaredRpoHours: 48 }).ok).toBe(true);

    // 核心判据：备份每 24h 一次 ⇒ 声明 1h 是不可能兑现的承诺
    const bad = evaluateRpoAlignment({ declaredRpoHours: 1 });
    expect(bad.ok).toBe(false);
    expect(bad.code).toBe('rpo_better_than_frequency');
    expect(bad.message).toContain('不可能兑现');
  });
});

// ============================ 4. 巡检汇总（IO 注入） ============================
describe('巡检脚本：参数严格性与汇总（A8 动作 3）', () => {
  const saved = {};
  beforeEach(() => {
    saved.rpo = process.env.BACKUP_RPO_HOURS;
    delete process.env.BACKUP_RPO_HOURS;
  });
  afterEach(() => {
    if (saved.rpo === undefined) delete process.env.BACKUP_RPO_HOURS;
    else process.env.BACKUP_RPO_HOURS = saved.rpo;
  });

  test('参数解析：缺值 / 未知开关一律拒绝，不猜', () => {
    expect(parseArgs([]).errors).toEqual([]);
    expect(parseArgs(['--backup-dir', '--offsite-dir']).errors).toContain('--backup-dir 缺少参数');
    expect(parseArgs(['--bogus']).errors[0]).toContain('未知参数');
    expect(parseArgs(['--now', 'not-a-date']).errors[0]).toContain('不是合法时间');
    const ok = parseArgs(['--backup-dir', '/x', '--offsite-dir', '/y', '--drill-only', '--json']);
    expect(ok).toMatchObject({ backupDir: '/x', offsiteDir: '/y', drillOnly: true, json: true });
  });

  test('collectArtifacts：三种"读不到"分别落成不同取值（本层只取证不判断）', async () => {
    const io = makeIo({
      dirs: [BACKUP_DIR],
      files: {
        // 正常一件
        [ARCHIVE_PATH]: { size: 2048, mtimeMs: NOW, sha256: DIGEST_A },
        [`${ARCHIVE_PATH}.sha256`]: { content: `${DIGEST_A}  x\n` },
        // 缺 sidecar
        [path.join(BACKUP_DIR, 'fire-safety-backup-2026-10-15-0200.gz.gpg')]: {
          size: 4096,
          mtimeMs: NOW,
          sha256: DIGEST_B,
        },
        // 孤儿 sidecar
        [path.join(BACKUP_DIR, 'fire-safety-backup-2026-10-14-0200.gz.gpg.sha256')]: {
          content: `${DIGEST_B}  y\n`,
        },
        // 非归档文件必须被忽略
        [path.join(BACKUP_DIR, 'README.md')]: { size: 10, mtimeMs: NOW, content: 'x' },
      },
    });
    const { archives, sidecarNames } = await collectArtifacts({ dir: BACKUP_DIR, io });
    expect(archives.map((a) => a.name).sort()).toEqual(
      [ARCHIVE, 'fire-safety-backup-2026-10-15-0200.gz.gpg'].sort()
    );
    expect(sidecarNames.sort()).toEqual(
      [`${ARCHIVE}.sha256`, 'fire-safety-backup-2026-10-14-0200.gz.gpg.sha256'].sort()
    );
    expect(archives.find((a) => a.name === ARCHIVE)).toMatchObject({
      expectedDigest: DIGEST_A,
      actualDigest: DIGEST_A,
    });
    expect(archives.find((a) => a.name !== ARCHIVE).expectedDigest).toBe(null);
  });

  test('健康夹具：只出 warn（RPO/RTO 未声明 + 未配异地），ok 为真', async () => {
    const report = await runPatrol({ backupDir: BACKUP_DIR, now: NOW, io: makeIo(healthyTree()) });
    expect(report.fatal).toBe(null);
    expect(report.ok).toBe(true);
    expect(report.findings.map((f) => f.code).sort()).toEqual([
      'offsite_unconfigured',
      'rpo_undeclared',
      'rto_undeclared',
    ]);
    expect(report.findings.every((f) => f.level === 'warn')).toBe(true);
    expect(report.summary).toMatchObject({ archiveCount: 1, newestArchive: ARCHIVE });
    expect(report.summary.newestAgeHours).toBeCloseTo(1, 6);
  });

  test('备份目录不存在 ⇒ fatal（未做判定不能报成就绪）', async () => {
    const report = await runPatrol({ backupDir: 'no-such-dir', now: NOW, io: makeIo() });
    expect(report.ok).toBe(false);
    expect(report.fatal).toContain('不存在');
    expect(report.summary).toBe(null);
  });

  test('异地副本配了但目录不可达 ⇒ error；可达但落后 ⇒ error', async () => {
    const tree = healthyTree();
    // 目录名一律经 path.join 构造：Windows 下 `path.join('/mnt/x','f')` 会变成 `\mnt\x\f`，
    // 与字面量 '/mnt/x' 拼前缀对不上（夹具自身踩过一次，故在此写明）。
    const OFFSITE_DIR = path.join('offsite-mirror');
    const unreachable = await runPatrol({
      backupDir: BACKUP_DIR,
      offsiteDir: OFFSITE_DIR,
      now: NOW,
      io: makeIo(tree),
    });
    expect(unreachable.ok).toBe(false);
    expect(unreachable.findings.map((f) => f.code)).toContain('offsite_unreachable');

    const lagging = await runPatrol({
      backupDir: BACKUP_DIR,
      offsiteDir: OFFSITE_DIR,
      now: NOW,
      io: makeIo({
        ...tree,
        dirs: [BACKUP_DIR, OFFSITE_DIR],
        files: {
          ...tree.files,
          [path.join(OFFSITE_DIR, 'fire-safety-backup-2026-10-15-0200.gz.gpg')]: {
            size: 2048,
            mtimeMs: NOW,
            sha256: DIGEST_B,
          },
        },
      }),
    });
    expect(lagging.ok).toBe(false);
    expect(lagging.findings.map((f) => f.code)).toContain('offsite_lagging');
  });

  test('声明 RPO=1h ⇒ 巡检判红（承诺优于备份频率，兑现不了）', async () => {
    process.env.BACKUP_RPO_HOURS = '1';
    const report = await runPatrol({ backupDir: BACKUP_DIR, now: NOW, io: makeIo(healthyTree()) });
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain('rpo_better_than_frequency');
  });

  test('--drill-only 模式：不碰备份目录，即使它不存在也不 fatal', async () => {
    const report = await runPatrol({
      backupDir: 'no-such-dir',
      drillRecord: DEFAULT_DRILL_RECORD,
      drillOnly: true,
      now: NOW,
      io: makeIo(),
    });
    expect(report.fatal).toBe(null);
    expect(report.summary.backupDir).toBe(null);
  });
});

// ============================ 5. 演练时效 ============================
describe('恢复演练时效判定（A8 动作 1 的可执行形态）', () => {
  const TEMPLATE_WITH_PLACEHOLDERS = [
    '# 回滚演练记录',
    '',
    '## 一、演练记录模板（复制本节登记新记录）',
    '',
    '```markdown',
    '### 演练 #<序号>（<YYYY-MM-DD>）',
    '',
    '| 项目     | 内容 |',
    '| -------- | ---- |',
    '| 演练日期 | YYYY-MM-DD HH:mm ~ HH:mm |',
    '```',
    '',
    '## 二、示例记录（模板填充演示）',
    '',
    '### 演练 #0（示例，待实际执行补录）',
    '',
    '| 演练日期 | 20XX-XX-XX 14:00 ~ 14:35 |',
    '',
    '## 三、实际演练记录',
    '',
    '### 演练 #1（2026-08-31，开发环境·迁移回滚专项）',
    '',
    '### 演练 #2（2026-09-10，开发环境·数据级快照回滚专项）',
    '',
  ].join('\n');

  test('只认 `### 演练 #N（YYYY-MM-DD…）`：模板占位与示例假日期一律不得入选', () => {
    // 这是本判据最容易写错的地方：全文抓日期会把 `YYYY-MM-DD` / `20XX-XX-XX` 当演练记录，
    // 于是"从来没练过"的环境会因为模板本身而永远显示"刚练过"。
    expect(parseDrillRecordDates(TEMPLATE_WITH_PLACEHOLDERS)).toEqual(['2026-08-31', '2026-09-10']);
    expect(parseDrillRecordDates('')).toEqual([]);
    expect(parseDrillRecordDates('### 演练 #<序号>（<YYYY-MM-DD>）')).toEqual([]);
  });

  test('真实留档文件可解析且形态正确（前提自证：不是空表）', () => {
    const dates = parseDrillRecordDates(readRoot(DEFAULT_DRILL_RECORD));
    expect(dates.length).toBeGreaterThanOrEqual(2);
    for (const d of dates) expect(d).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(dates).toEqual([...dates].sort());
  });

  test('时效判据三态：无记录 / 逾期 / 在周期内', () => {
    const never = evaluateDrillRecency({ dates: [], now: NOW });
    expect(never.ok).toBe(false);
    expect(never.code).toBe('drill_never_recorded');
    expect(never.message).toContain('没有执行者');

    const overdue = evaluateDrillRecency({ dates: ['2026-06-01'], now: NOW });
    expect(overdue.ok).toBe(false);
    expect(overdue.code).toBe('drill_overdue');
    expect(overdue.ageDays).toBeGreaterThan(DRILL_INTERVAL_DAYS);

    const fresh = evaluateDrillRecency({ dates: ['2026-09-10'], now: NOW });
    expect(fresh.ok).toBe(true);
    expect(fresh.lastDrillDate).toBe('2026-09-10');
    expect(fresh.ageDays).toBeLessThan(DRILL_INTERVAL_DAYS);
  });

  test('可证伪：把唯一日期往前挪 100 天，ok 从真翻假', () => {
    expect(evaluateDrillRecency({ dates: ['2026-09-10'], now: NOW }).ok).toBe(true);
    expect(evaluateDrillRecency({ dates: ['2026-05-01'], now: NOW }).ok).toBe(false);
  });

  test('留档不可读 ⇒ error（读不到不等于没逾期）', async () => {
    const report = await runPatrol({
      backupDir: BACKUP_DIR,
      drillRecord: 'no-such-record.md',
      now: NOW,
      io: makeIo(healthyTree()),
    });
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain('drill_record_unreadable');
  });
});

// ============================ 6. 演练结果自动留档 ============================
describe('演练结果自动留档（A8 动作 1）', () => {
  const manifest = {
    uri: 'fsms_e2e_drill',
    timestamp: '2026-10-16T03:00:00.000Z',
    collections: {
      users: { file: 'users-x.ndjson.gz', documents: 12, restored: 12 },
      roles: { file: 'roles-x.ndjson.gz', documents: 4, restored: 4 },
    },
    applySource: true,
    restoreVerified: true,
    totalSnapshotDocuments: 16,
  };

  test('manifest 校验：只做快照 / 缺 restoreVerified 一律拒绝登记', () => {
    expect(validateManifest(manifest)).toEqual({ ok: true });
    // 只做快照、没清空回灌 ⇒ 不构成"回滚能力"证明
    const snapshotOnly = validateManifest({ ...manifest, applySource: false });
    expect(snapshotOnly.ok).toBe(false);
    expect(snapshotOnly.reason).toContain('applySource');
    // 缺 restoreVerified ⇒ 无法证明回灌与快照一致
    const { restoreVerified: _dropped, ...withoutVerdict } = manifest;
    expect(withoutVerdict).not.toHaveProperty('restoreVerified');
    expect(validateManifest(withoutVerdict).ok).toBe(false);
    expect(validateManifest(null).ok).toBe(false);
    expect(validateManifest({}).ok).toBe(false);
  });

  test('序号取既有最大值 + 1（模板里的 `#<序号>` 不算）', () => {
    expect(maxDrillNumber('### 演练 #1（2026-08-31）\n### 演练 #2（2026-09-10）')).toBe(2);
    expect(maxDrillNumber('### 演练 #<序号>（<YYYY-MM-DD>）')).toBe(0);
    expect(maxDrillNumber('')).toBe(0);
  });

  test('渲染含逐集合对账与结论；不一致时必须显式标红', () => {
    const okText = renderDrillRecord({ manifest, sequence: 3, operator: '运维A' });
    expect(okText).toContain('### 演练 #3（2026-10-16，自动登记）');
    expect(okText).toContain('| users | 12 | 12 | ☑ 一致 |');
    expect(okText).toContain('restoreVerified=true');
    expect(okText).toContain('总快照 16 条');
    expect(okText).toContain('☑ 数据级恢复');

    const bad = renderDrillRecord({
      manifest: {
        ...manifest,
        collections: { users: { documents: 12, restored: 11 } },
        restoreVerified: false,
      },
      sequence: 4,
      operator: '运维B',
    });
    expect(bad).toContain('**不一致**');
    expect(bad).toContain('本次演练不合格');
  });

  test('锚点缺失即拒绝写入（不猜位置，避免把记录塞进错误段落）', () => {
    const section = renderDrillRecord({ manifest, sequence: 3, operator: 'x' });
    expect(appendDrillRecord('# 没有锚点的文件\n', section)).toEqual({
      ok: false,
      reason: `留档文件里找不到锚点「${RECORD_ANCHOR}」`,
    });
    const appended = appendDrillRecord(
      `# 头\n\n${RECORD_ANCHOR}\n\n### 演练 #2（2026-09-10）\n`,
      section
    );
    expect(appended.ok).toBe(true);
    expect(appended.text).toContain(RECORD_ANCHOR);
    // 新小节整体追加在末尾（逐集合对账行与结论都在）
    expect(appended.text).toContain('| roles | 4 | 4 | ☑ 一致 |');
    expect(appended.text.trimEnd().endsWith('总快照 16 条。')).toBe(true);
    // 追加不破坏已有内容
    expect(appended.text).toContain('### 演练 #2（2026-09-10）');
    // 追加后仍可解析出演练日期（留档 → 时效判据这条链是闭合的）
    expect(parseDrillRecordDates(appended.text)).toEqual(['2026-09-10', '2026-10-16']);
  });
});
