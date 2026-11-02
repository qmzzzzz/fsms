/**
 * 离线包落位的子进程调用（tar 与导入器）
 *
 * 收在独立文件里的理由：本仓对「外部命令」的纪律是「argv 逐项构造、绝不拼 shell 字符串、
 * 动态值不进选项位」。把这两处调用与状态机分开放，评审时能一眼看完整个命令面，
 * 不必在几百行编排逻辑里找 execFileSync。
 *
 * 形态（与 scripts/provision-mongod.js 的 tar 调用同族）：
 *   · file 一律是字面量（'tar'）或 process.execPath；
 *   · argv 是数组字面量，变量按位置插入；成员名排在 `--` 之后（tar 的选项终止符）。
 * 调用方负责：所有路径先过 offlineBundleIntakePolicy.resolveWithinRoot
 * （非空、不以 `-` 开头、在允许的根之内）——本模块不重复实现那套判据。
 */

'use strict';

const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

/** 单次调用的超时与输出上限（畸形归档不能把落位变成一次超长读） */
const SUBPROCESS_TIMEOUT_MS = 30 * 60 * 1000;
const SUBPROCESS_MAX_BUFFER = 4 * 1024 * 1024;

/**
 * 路径形态适配：Windows 上交给 GNU tar 的路径必须转成 POSIX 形态。
 *
 * 踩过的坑（实测，2026-11-02）：MSYS2/Git Bash 自带的 GNU tar 1.35 会把 `C:\dir\a.tar.gz`
 * 与 `C:/dir/a.tar.gz` 都解析成**远程归档**（`host:path` 是 tar 的古老语法），报
 * `Cannot connect to C: resolve failed`。生产（Linux）不受影响，但开发机与 Windows 上
 * 的测试会成片红，且报错形态指向「归档坏了」而不是「路径形态不对」。
 *
 * 只做形态转换，不做存在性判断——路径的合法性判据在 offlineBundleIntakePolicy，这里
 * 只管「交给 tar 的那个字符串长什么样」。非 Windows 与已是 POSIX 形态的输入原样返回。
 */
function toTarPath(filePath) {
  const text = String(filePath);
  if (process.platform !== 'win32') return text;
  if (!/^[a-zA-Z]:[\\/]/.test(text) && !text.startsWith('\\\\')) return text;
  // C:\a\b 与 C:/a/b → /c/a/b（MSYS 的挂载形态）；UNC 无法可靠转换，直接拒绝
  if (text.startsWith('\\\\')) {
    throw new Error(`UNC 路径无法交给 tar（拒绝继续）：${text}`);
  }
  const drive = text[0].toLowerCase();
  const rest = text.slice(2).replace(/\\/g, '/');
  return `/${drive}${rest.startsWith('/') ? '' : '/'}${rest}`;
}

/**
 * 列归档条目（只读头，不解压）。
 *
 * **用 `-v`（verbose）而不是裸 `-t`**：实测（GNU tar 1.35）裸 `-tzf` 对软链条目
 * **只打印名字**（`evil`），` -> ` 只在 verbose 形态出现；靠裸清单判「是不是链接」
 * 是一道空防线（实测钉住，见 ADR-020 踩过的坑）。verbose 形态每行形如：
 *
 *   -rw-r--r-- 0/0  2 1970-01-01 08:00 manifest.json
 *   lrw-r--r-- 0/0  0 1970-01-01 08:00 evil -> /etc
 *   drwxr-xr-x 0/0  0 1970-01-01 08:00 payload/
 *
 * 首字符即类型位（`-` 普通文件 / `d` 目录 / `l` 符号链接 / `h` 硬链接），
 * 由判据层的 parseArchiveListing 逐个判定——**链接类型在解包之前就被拒绝**。
 *
 * @param {string} archive 已过 resolveWithinRoot 的归档绝对路径
 */
function listArchiveEntries(archive) {
  return execFileSync('tar', ['-tvzf', toTarPath(archive)], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: SUBPROCESS_TIMEOUT_MS,
    maxBuffer: SUBPROCESS_MAX_BUFFER,
  });
}

/**
 * 把**指定的条目**解到目标目录。
 *
 * 成员名排在 `--` 之后：GNU tar 在选项终止符之后一律当文件名（判据层已拒 `-` 开头，
 * 这里是第二道）。空成员列表直接拒绝——那会退化成「整包全解」，正是本链路不要的形态。
 *
 * @param {string} archive 已过 resolveWithinRoot
 * @param {string} destDir 已过 resolveWithinRoot
 * @param {string[]} members 已逐个过 resolveWithinRoot
 */
function extractArchiveMembers(archive, destDir, members) {
  if (!Array.isArray(members) || members.length === 0) {
    throw new Error('解包必须显式给出成员名：空列表会退化成整包全解（拒绝）');
  }
  return execFileSync(
    'tar',
    ['-xzf', toTarPath(archive), '-C', toTarPath(destDir), '--', ...members],
    {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: SUBPROCESS_TIMEOUT_MS,
      maxBuffer: SUBPROCESS_MAX_BUFFER,
    }
  );
}

/**
 * 跑既有导入器（演练模式：校验通过 exit 0，绝不碰 docker）。
 * 参数由 deployCommands.buildImportBundleInvocation 拼装（那个函数的既有约束是
 * 「只返回 argv 数组、密钥与镜像引用不进 argv」）。
 */
function runImporter(args) {
  return execFileSync(process.execPath, args, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: SUBPROCESS_TIMEOUT_MS,
    maxBuffer: SUBPROCESS_MAX_BUFFER,
  });
}

module.exports = {
  ROOT,
  SUBPROCESS_TIMEOUT_MS,
  SUBPROCESS_MAX_BUFFER,
  toTarPath,
  listArchiveEntries,
  extractArchiveMembers,
  runImporter,
};
