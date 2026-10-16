#!/usr/bin/env node
/**
 * 备份与恢复就绪度巡检（A8，2026-10-16）
 *
 * 缺口（deliverables/安全需求加固清单-2026-10-16.md A8 动作 3）：
 * 「备份完整性巡检自动化（校验和巡检 + 异地副本可达性探针）」此前**完全不存在**。
 * 备份脚本自己会验一次（`backup-mongo.sh` 的产物有效性闸 + `.sha256`），
 * 但那验的是"刚写出来的那一份"。它回答不了下面任何一个问题：
 *   - 三天前那份归档，今天还能解开吗？（位翻转 / 存储层静默损坏 / 被别的进程截断）
 *   - 目录里有没有缺 sidecar 的归档？（缺 sidecar 的归档在恢复时会被
 *     `restore-mongo.sh` 硬失败挡下——也就是说"有备份"是错觉）
 *   - 异地副本还在更新吗？（`BACKUP_OFFSITE_CMD` 失败过一次之后没人发现，
 *     异地副本就永久停在上个周期——而它存在的全部意义就是"本机没了还能恢复"）
 *   - 最新一份备份是多久以前的？（备份流水线静默停摆是这类系统最典型的失效模式：
 *     cron 里那行改了路径、密钥文件挪了位、磁盘满了——失败只进 stderr，没人读）
 *   - 恢复演练上次是什么时候做的？（A8 动作 1 的"定时化"必须有个执行者）
 *
 * 本文件只做**编排**：判据与取证都不在这里——
 *   - 产物完整性判据：`scripts/backupIntegrityPolicy.js`（纯函数）
 *   - 目录取证：`scripts/backupArtifactScan.js`（IO 适配层，可注入）
 *   - 演练时效判据：`scripts/drReadinessPolicy.js`（纯函数）
 *   - 目标值声明：`src/constants/backupObjectives.js`
 * 与 `run-rollback-drill.js` 同一条纪律：判据与副作用分离，纯函数可被用例直接驱动。
 *
 * 用法:
 *   node scripts/backup-integrity-patrol.js [选项]
 *
 * 选项:
 *   --backup-dir <dir>    本地备份目录（默认 env BACKUP_DIR，再默认 ./backups）
 *   --offsite-dir <dir>   异地副本目录（默认 env BACKUP_OFFSITE_DIR；未给则跳过探针并如实标注）
 *   --drill-record <file> 回滚演练留档（默认 deployment/rollback-drill-record.md）
 *   --no-drill            跳过演练时效判定（只做备份侧巡检）
 *   --drill-only          **只**做演练时效判定（CI 用：CI 里没有生产备份目录，
 *                         但"本季度做过演练没有"是可以、也应该在 CI 里被判的）
 *   --now <ISO8601>       注入"当前时刻"，便于复现与用例（默认系统时间）
 *   --json                只输出 JSON（cron / CI 用；默认也输出 JSON + 人读摘要）
 *
 * 环境变量:
 *   BACKUP_DIR / BACKUP_OFFSITE_DIR       目录（选项优先）
 *   BACKUP_RPO_HOURS / BACKUP_RTO_HOURS   恢复目标（见 src/constants/backupObjectives.js）
 *
 * 退出码:
 *   0 = 无 error 级发现（warn 不阻断：例如"RPO 未声明""异地副本未配置"属如实告知）
 *   1 = 存在 error 级发现（产物损坏 / 缺证据 / 备份过旧 / 异地副本落后 / 演练逾期）
 *   2 = 参数或目录不可用（**未做任何判定**，不能报成"就绪"）
 */

const path = require('path');

const { evaluateBackupArtifacts, evaluateOffsiteReplica } = require('./backupIntegrityPolicy');
const { defaultIo, collectArtifacts } = require('./backupArtifactScan');
const {
  DRILL_INTERVAL_DAYS,
  DEFAULT_DRILL_RECORD,
  parseDrillRecordDates,
  evaluateDrillRecency,
} = require('./drReadinessPolicy');
const {
  resolveBackupObjective,
  evaluateRpoAlignment,
  describeBackupObjective,
  BACKUP_SCHEDULE,
} = require('../src/constants/backupObjectives');

/** 取值的选项：`--flag <value>` ⇒ args 字段 */
const VALUE_FLAGS = {
  '--backup-dir': 'backupDir',
  '--offsite-dir': 'offsiteDir',
  '--drill-record': 'drillRecord',
};
/** 开关型选项：`--flag` ⇒ [args 字段, 值] */
const BOOL_FLAGS = {
  '--no-drill': ['checkDrill', false],
  '--drill-only': ['drillOnly', true],
  '--json': ['json', true],
};

// ============================ 参数解析 ============================
/**
 * 与 run-rollback-drill.js 的 parseArgs 同一严格度：值缺失或以 `--` 开头一律按
 * "未提供"处理并报错，绝不猜——把开关当值吃掉会同时造成"设置没生效"和"意外执行"。
 * 值槽被开关形态的 token 占掉之后，后面的 token 边界已不可信：停止解析、不猜。
 */
function parseArgs(argv) {
  const args = {
    backupDir: process.env.BACKUP_DIR || path.join('backups'),
    offsiteDir: process.env.BACKUP_OFFSITE_DIR || null,
    drillRecord: DEFAULT_DRILL_RECORD,
    checkDrill: true,
    drillOnly: false,
    now: null,
    json: false,
    errors: [],
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (VALUE_FLAGS[token]) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        args.errors.push(`${token} 缺少参数`);
        break;
      }
      args[VALUE_FLAGS[token]] = value;
      i += 1;
    } else if (BOOL_FLAGS[token]) {
      args[BOOL_FLAGS[token][0]] = BOOL_FLAGS[token][1];
    } else if (token === '--now') {
      const ts = Date.parse(argv[i + 1] || '');
      if (!Number.isFinite(ts)) {
        args.errors.push(`--now 缺少参数或不是合法时间：${argv[i + 1] || '(缺值)'}`);
        break;
      }
      args.now = ts;
      i += 1;
    } else {
      args.errors.push(
        `未知参数：「${token}」（只接受 --backup-dir / --offsite-dir / --drill-record / --no-drill / --drill-only / --now / --json）`
      );
    }
  }
  return args;
}

// ============================ 逐项判定 ============================
/** RPO/RTO 声明与"声明是否优于备份频率"（判据在 src/constants/backupObjectives.js） */
const resolveObjectives = () => {
  const rpo = resolveBackupObjective('rpo');
  const rto = resolveBackupObjective('rto');
  return {
    rpo,
    rto,
    alignment: evaluateRpoAlignment({
      declaredRpoHours: rpo.set ? rpo.effectiveHours : null,
      intervalHours: BACKUP_SCHEDULE.intervalHours,
    }),
  };
};

/** 目标值这一档：声明优于频率 ⇒ error；未声明 ⇒ warn（如实告知，不阻断） */
const checkObjectives = (objectives, add) => {
  if (!objectives.alignment.ok)
    add('error', objectives.alignment.code, objectives.alignment.message);
  if (!objectives.rpo.set) add('warn', 'rpo_undeclared', describeBackupObjective('rpo'));
  if (!objectives.rto.set) add('warn', 'rto_undeclared', describeBackupObjective('rto'));
};

/**
 * 异地副本探针。
 *
 * `BACKUP_OFFSITE_CMD` 本身是可选的（backup-encryption.md:15 未配置时只警告），
 * 但"没配异地"必须**被说出来**：单机副本在"机器没了"面前等于没有备份。
 */
const checkOffsite = async ({ offsiteDir, newestLocalName, io, add }) => {
  if (!offsiteDir) {
    add(
      'warn',
      'offsite_unconfigured',
      '未配置异地副本目录（--offsite-dir / BACKUP_OFFSITE_DIR）：异地可达性**未探测**。' +
        '注意单机副本不构成异地备份。'
    );
    return;
  }
  if (!(await io.isDir(offsiteDir))) {
    add('error', 'offsite_unreachable', `异地副本目录不可达或不是目录：${offsiteDir}`);
    return;
  }
  const verdict = evaluateOffsiteReplica({
    reachable: true,
    names: await io.listNames(offsiteDir),
    newestLocalName,
  });
  for (const f of verdict.findings) add(f.level, f.code, f.message);
};

/** 演练时效：读不到留档也报 error（读不到 ≠ 没逾期） */
const checkDrill = async ({ drillRecord, now, io, add, summary }) => {
  if (!drillRecord) return;
  let text = '';
  try {
    text = await io.readText(drillRecord);
  } catch (err) {
    add('error', 'drill_record_unreadable', `读不到演练留档 ${drillRecord}：${err.message}`);
    return;
  }
  const drill = evaluateDrillRecency({ dates: parseDrillRecordDates(text), now });
  summary.drill = {
    lastDrillDate: drill.lastDrillDate,
    ageDays: drill.ageDays,
    intervalDays: drill.intervalDays,
  };
  if (!drill.ok) add('error', drill.code, drill.message);
};

// ============================ 汇总 ============================
/**
 * 跑完整巡检。所有 IO 与"当前时刻"都从参数进，函数本身不做时间/文件系统访问。
 *
 * @param {object} input
 * @param {string} input.backupDir
 * @param {string|null} input.offsiteDir
 * @param {string|null} input.drillRecord 留档路径；null = 跳过演练判定
 * @param {number} input.now
 * @param {boolean} [input.drillOnly] 只判演练时效（CI 用；不碰备份目录）
 * @param {object} [input.io]
 */
async function runPatrol({
  backupDir,
  offsiteDir = null,
  drillRecord = null,
  now = Date.now(),
  drillOnly = false,
  io = defaultIo,
} = {}) {
  const findings = [];
  const add = (level, code, message) => findings.push({ level, code, message });
  const objectives = resolveObjectives();
  const summary = {
    backupDir: drillOnly ? null : backupDir,
    offsiteDir: drillOnly ? null : offsiteDir,
    archiveCount: null,
    newestArchive: null,
    newestAgeHours: null,
    rpo: {
      set: objectives.rpo.set,
      effectiveHours: objectives.rpo.effectiveHours,
      envKey: objectives.rpo.envKey,
    },
    rto: {
      set: objectives.rto.set,
      effectiveHours: objectives.rto.effectiveHours,
      envKey: objectives.rto.envKey,
    },
    rpoAlignment: {
      ok: objectives.alignment.ok,
      floorHours: objectives.alignment.floorHours,
      message: objectives.alignment.message,
    },
    drill: null,
  };

  if (!drillOnly) {
    // 目录不存在**不是**"没有发现"——它意味着本次巡检什么都没验。
    // 报成 fatal 并由主流程以退出码 2 结束（未做判定 ≠ 就绪）。
    if (!(await io.isDir(backupDir))) {
      return {
        ok: false,
        fatal: `备份目录不存在或不是目录：${backupDir}`,
        findings: [],
        summary: null,
      };
    }
    const { archives, sidecarNames } = await collectArtifacts({ dir: backupDir, io });
    checkObjectives(objectives, add);

    const artifacts = evaluateBackupArtifacts({
      archives,
      sidecarNames,
      now,
      rpoHours: objectives.rpo.set ? objectives.rpo.effectiveHours : null,
    });
    for (const f of artifacts.findings) add(f.level, f.code, f.message);

    const newestArchive =
      archives.length > 0
        ? archives.reduce((a, b) => ((b.mtimeMs || 0) > (a.mtimeMs || 0) ? b : a)).name
        : null;
    Object.assign(summary, {
      archiveCount: archives.length,
      newestArchive,
      newestAgeHours: artifacts.newestAgeHours,
    });
    await checkOffsite({ offsiteDir, newestLocalName: newestArchive, io, add });
  }

  await checkDrill({ drillRecord, now, io, add, summary });
  return { ok: findings.every((f) => f.level !== 'error'), fatal: null, findings, summary };
}

// ============================ 人读摘要 ============================
const printHumanSummary = (report) => {
  console.log('\n========== 备份与恢复就绪度摘要 ==========');
  const s = report.summary;
  if (s && s.archiveCount !== null) {
    console.log(`备份目录：${s.backupDir}（${s.archiveCount} 个归档）`);
    console.log(
      s.newestAgeHours === null
        ? '最新归档：无'
        : `最新归档：${s.newestArchive}（${s.newestAgeHours.toFixed(1)} 小时前）`
    );
    console.log(`异地副本：${s.offsiteDir || '未配置'}`);
    console.log(`RPO/RTO 对齐：${s.rpoAlignment.message}`);
  }
  if (s) {
    const drill = s.drill
      ? `上次 ${s.drill.lastDrillDate}（${s.drill.ageDays.toFixed(0)} 天前）`
      : '未判定';
    console.log(`演练时效：${drill}`);
  }
  for (const f of report.findings) {
    console.log(`${f.level === 'error' ? '❌' : '⚠️ '} [${f.code}] ${f.message}`);
  }
  console.log(`\n总体: ${report.ok ? '就绪' : '存在缺失'}`);
};

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.errors.length > 0) {
    console.error('参数不合法，拒绝执行（未做任何判定）：');
    for (const e of args.errors) console.error(`  ✗ ${e}`);
    process.exit(2);
  }

  const now = args.now === null ? Date.now() : args.now;
  const report = await runPatrol({
    backupDir: args.backupDir,
    offsiteDir: args.offsiteDir,
    drillRecord: args.drillOnly || args.checkDrill ? args.drillRecord : null,
    now,
    drillOnly: args.drillOnly,
  });
  const out = { timestamp: new Date(now).toISOString(), ...report };
  console.log(args.json ? JSON.stringify(out) : JSON.stringify(out, null, 2));

  if (report.fatal) {
    console.error(`\n巡检无法执行：${report.fatal}`);
    process.exit(2);
  }
  if (!args.json) printHumanSummary(report);
  process.exit(report.ok ? 0 : 1);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`巡检异常：${err.message}`);
    process.exit(2);
  });
}

// 纯函数与编排导出供单测驱动（不触发主流程）。
module.exports = { parseArgs, runPatrol, DRILL_INTERVAL_DAYS, DEFAULT_DRILL_RECORD };
