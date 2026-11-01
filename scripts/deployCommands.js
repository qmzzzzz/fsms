/**
 * 部署命令拼装（O-5，2026-10-20）
 *
 * 审计事实：`deploy.js` 的命令拼装原先内联在执行函数里，验证只能靠
 * 「输出里出现过 migrate-mongo」这类文本断言——看不到 argv 的边界。
 * 例如把 `--no-deps` 挪到 `app` 之后，字符串里仍然"包含"它，断言照绿。
 *
 * 抽成纯函数后：
 *   · 每条外发命令的完整 argv 可被逐项断言（顺序、位置、元素个数）；
 *   · `deploy.js` 只负责执行与呈现，不再自带命令行字面量；
 *   · `--dry-run` 打印的是**真实 argv**（不是步骤描述），演练输出可留档核对。
 *
 * 约束（与 deployPolicy.js 同风格）：
 *   - 零副作用：不读 process.env、不碰文件系统、不执行命令、不打印；
 *   - 只返回 argv 数组，绝不拼 shell 字符串——调用方用 execFileSync 直接执行，
 *     因此路径里的空格/分号/换行不会获得任何解释权；
 *   - 密钥与镜像引用一律走环境变量，**不得**进入 argv（/proc/<pid>/cmdline 可读）。
 */

'use strict';

const path = require('path');

const DEFAULT_COMPOSE_FILE = path.resolve(__dirname, '..', 'docker-compose.yml');
const DEFAULT_BACKUP_SCRIPT = path.resolve(__dirname, 'backup-mongo.sh');
const DEFAULT_BACKUP_DIR = path.resolve(__dirname, '..', 'backups');
const DEFAULT_HOT_UPGRADE_SCRIPT = path.resolve(__dirname, 'hotUpgrade.js');
const DEFAULT_IMPORT_BUNDLE_SCRIPT = path.resolve(__dirname, 'importOfflineBundle.js');

/** compose 公共前缀：显式指定文件，避免命令受 cwd 影响（cwd 决定项目名）。 */
function composeArgs(composeFile = DEFAULT_COMPOSE_FILE) {
  return ['compose', '-f', composeFile];
}

function buildPullInvocation({ composeFile = DEFAULT_COMPOSE_FILE } = {}) {
  return { file: 'docker', args: [...composeArgs(composeFile), 'pull', 'app'] };
}

/**
 * `migrate-mongo` 的 status / up 共用同一段前缀——两处分别手写时，
 * 一侧加了 `--rm` 另一侧没加，会留下"残留一次性容器"这种只在真机可见的差异。
 */
function buildMigrateInvocation(subcommand, { composeFile = DEFAULT_COMPOSE_FILE } = {}) {
  return {
    file: 'docker',
    args: [
      ...composeArgs(composeFile),
      'run',
      '--rm',
      '--no-deps',
      'app',
      'node',
      'node_modules/.bin/migrate-mongo',
      subcommand,
    ],
  };
}

/** 滚动切换（以及回滚时的同一动作）：--no-build 保证发布的是已拉取的镜像。 */
function buildUpInvocation({ composeFile = DEFAULT_COMPOSE_FILE } = {}) {
  return {
    file: 'docker',
    args: [...composeArgs(composeFile), 'up', '-d', '--no-build', 'app'],
  };
}

/** 健康门禁探针：/readyz（带 Mongo ping），不是永远 200 的 /health。 */
function buildProbeInvocation(probeUrl) {
  return {
    file: 'curl',
    args: [
      '--silent',
      '--output',
      '/dev/null',
      '--write-out',
      '%{http_code}',
      '--max-time',
      '5',
      probeUrl,
    ],
  };
}

/** 备份：连接串由调用方放进 env（MONGODB_URI），不进 argv。 */
function buildBackupInvocation({
  scriptFile = DEFAULT_BACKUP_SCRIPT,
  backupDir = DEFAULT_BACKUP_DIR,
} = {}) {
  return { file: 'bash', args: [scriptFile, backupDir] };
}

/**
 * 升级（蓝绿）：宿主代理与人工发布共用同一条命令。
 *
 * 镜像引用走 `HOT_UPGRADE_IMAGE` 环境变量而不是 `--image`：与本模块的
 * 既有约束一致（镜像/密钥不进 argv，/proc/<pid>/cmdline 同机可读）。
 * `--status-file` 让应用的进度弹窗能看到每一步；缺省时不传。
 * `offline: true` 追加 `--offline`：换装前断言本地 docker 已有该 digest（离线包已导入），
 * 且脚本执行期间不接受联网拉取——只由离线请求（request.mode=offline）触发。
 */
function buildHotUpgradeInvocation({
  nginxConf,
  statusFile = '',
  dryRun = false,
  offline = false,
  scriptFile = DEFAULT_HOT_UPGRADE_SCRIPT,
} = {}) {
  if (!nginxConf) throw new Error('升级必须显式给出 nginxConf');
  const args = [scriptFile, '--nginx-conf', nginxConf];
  if (statusFile) args.push('--status-file', statusFile);
  if (offline) args.push('--offline');
  args.push(dryRun ? '--dry-run' : '--apply');
  return { file: process.execPath, args };
}

/**
 * 离线包导入（离线请求的第一段，先于换装执行）：
 * 固定脚本 + 固定参数，包目录与白名单都来自代理配置/扫描结果，绝不来自请求内容——
 * 请求只声明目标 digest，导入哪个目录由代理在 bundles 根目录内定位。
 * `--bundle-root` 把包钉在代理管理的 bundles 目录之内：请求被伪造时，最坏也只是
 * 「导入一个 root 放进来的合法包」，指向包外的路径在导入器就被拒绝。
 * allowlist 为空时不传该参数：导入器按「空白名单 = 全拒」自己拒绝，与在线路径同口径。
 */
function buildImportBundleInvocation({
  bundleDir,
  bundleRoot,
  allowlist = [],
  scriptFile = DEFAULT_IMPORT_BUNDLE_SCRIPT,
} = {}) {
  if (!bundleDir) throw new Error('离线包导入必须显式给出 bundleDir');
  if (!bundleRoot) throw new Error('离线包导入必须显式给出 bundleRoot（把包钉在受管目录之内）');
  const args = [scriptFile, '--bundle', bundleDir, '--bundle-root', bundleRoot];
  if (Array.isArray(allowlist) && allowlist.length > 0) {
    args.push('--allowlist', allowlist.join(','));
  }
  args.push('--apply');
  return { file: process.execPath, args };
}

/**
 * 本次发布的**完整外部命令序列**（顺序即执行顺序；条件分支见 deploy.js）：
 * 备份 → 拉取 → 查看迁移 → 应用迁移 → 切换 → 健康探针。
 * 回滚命令与被跳过的步骤不在此列（它们由运行时条件决定）。
 *
 * @returns {Array<{id: string, file: string, args: string[]}>}
 */
function buildCommandPlan(options = {}) {
  return [
    { id: 'backup', ...buildBackupInvocation(options) },
    { id: 'pull', ...buildPullInvocation(options) },
    { id: 'migrate-status', ...buildMigrateInvocation('status', options) },
    { id: 'migrate-up', ...buildMigrateInvocation('up', options) },
    { id: 'up', ...buildUpInvocation(options) },
    { id: 'health', ...buildProbeInvocation(options.probeUrl) },
  ];
}

/** 供 `--dry-run` 与日志使用：`file arg arg …`（不做 shell 引用，仅便于人读）。 */
const formatInvocation = (invocation) => [invocation.file, ...invocation.args].join(' ');

module.exports = {
  DEFAULT_COMPOSE_FILE,
  DEFAULT_BACKUP_SCRIPT,
  DEFAULT_BACKUP_DIR,
  DEFAULT_HOT_UPGRADE_SCRIPT,
  DEFAULT_IMPORT_BUNDLE_SCRIPT,
  composeArgs,
  buildPullInvocation,
  buildMigrateInvocation,
  buildUpInvocation,
  buildProbeInvocation,
  buildBackupInvocation,
  buildHotUpgradeInvocation,
  buildImportBundleInvocation,
  buildCommandPlan,
  formatInvocation,
};
