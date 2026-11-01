'use strict';

/**
 * 测试进程的 POSIX shell 解析（跨平台）
 *
 * 为什么要它：`src/tests/deploy/**`、`src/tests/config/**` 等门禁用**真实进程**跑
 * `scripts/*.sh`（桩掉 mongodump / mongorestore / gpg / docker 等外部命令），依赖 PATH 上的
 * `bash`。Windows 上 PATH 里那个 `bash` 通常是 `C:\Windows\system32\bash.exe`——它只是 WSL
 * 启动桩：没装发行版时它**退出码非 0 且什么也不执行**。于是整族 shell 门禁在本机成片红，
 * 根因与被测代码无关，每轮迭代都要把这些红重新定性一遍，真红的信噪比被拖垮。
 *
 * 本模块只做一件事：**行为验证**出可用的 POSIX shell（跑得起来、`-c` 语义成立、标记能原样
 * 带回来），把它插到 PATH 最前面并记为 `FSMS_TEST_SHELL`，让既有用例里的
 * `spawnSync('bash')` 命中它；找不到就把「一片红」换成一条带根因的告警，不伪造成功。
 *
 * 三条纪律：
 *  1. 显式指定优先且**不静默回退**：`FSMS_TEST_SHELL` 指错就抛错（免得「以为在真跑」）。
 *  2. 候选一律行为验证，不看文件存在性——`bash.exe` 存在 ≠ 可用（WSL 桩就是反例）。
 *  3. 本机 shell ≠ Linux 权威：来源记进 `FSMS_TEST_SHELL_SOURCE`，Windows 上的绿是
 *     「MSYS 语义下的绿」，Linux 结论仍以 CI 为准（见 CONTRIBUTING $6）。
 */

const { spawnSync } = require('child_process');
const path = require('path');

/** 显式指定 shell 的环境变量（优先级最高，且失败即报错） */
const SHELL_OVERRIDE_ENV = 'FSMS_TEST_SHELL';
/** 解析来源的环境变量：override | git-bash | path | posix */
const SHELL_SOURCE_ENV = 'FSMS_TEST_SHELL_SOURCE';

const PROBE_MARKER = 'FSMS_POSIX_SHELL_OK';
// 探针只用 POSIX 基线语法：任何「真 shell」都能跑，非 shell 的可执行文件跑不出这个标记
const PROBE_SCRIPT = `printf '%s' ${PROBE_MARKER}`;
const PROBE_TIMEOUT_MS = 10000;

const probeCache = new Map();
const resolveCache = new Map();

/**
 * 行为验证：候选能不能执行 POSIX `-c` 脚本，并把标记原样写在 stdout 上。
 * 这是本模块唯一的「可用性」判据——退出码 0 但输出里没有标记的（WSL 桩、`node -e`）不算数。
 */
function probeShell(cmd, extraArgs = []) {
  const key = `${cmd}\u0000${extraArgs.join(' ')}`;
  if (probeCache.has(key)) return probeCache.get(key);
  let ok = false;
  try {
    const r = spawnSync(cmd, [...extraArgs, '-c', PROBE_SCRIPT], {
      encoding: 'utf8',
      timeout: PROBE_TIMEOUT_MS,
      windowsHide: true,
    });
    // 严格相等而不是 includes：MSYS 的 `echo.exe` 会把参数原样回显（`-c printf …` 整串都打出来），
    // includes 于是在一个**根本不是 shell** 的可执行文件上判真 —— 探针就退化成「能起进程就算可用」，
    // 正是本模块要防的那类假阳性。标记必须**独占** stdout（前导/尾随空白也算不合格）。
    ok = !r.error && r.status === 0 && String(r.stdout || '') === PROBE_MARKER;
  } catch {
    ok = false;
  }
  probeCache.set(key, ok);
  return ok;
}

/** cmd 带路径分隔符时取其目录（PATH 前置用）；裸命令名（走 PATH 找）返回 null */
function dirOf(cmd) {
  return cmd.includes('/') || cmd.includes('\\') ? path.dirname(cmd) : null;
}

/** Windows 上 Git for Windows 的常见安装位（环境变量缺失时仍要能命中默认位置） */
function windowsGitBashCandidates() {
  const roots = [
    process.env.ProgramFiles,
    process.env['ProgramFiles(x86)'],
    process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs'),
  ].filter(Boolean);
  const out = [];
  const seen = new Set();
  for (const root of [...roots, 'C:\\Program Files']) {
    const p = path.join(root, 'Git', 'bin', 'bash.exe');
    if (!seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  return out;
}

function candidateList() {
  if (process.platform === 'win32') {
    return [
      ...windowsGitBashCandidates().map((cmd) => ({ cmd, args: [], source: 'git-bash' })),
      // PATH 上的 bash 可能是真 Git Bash，也可能是 WSL 桩——统一交给行为验证兜底
      { cmd: 'bash', args: [], source: 'path' },
      { cmd: 'sh', args: [], source: 'path' },
    ];
  }
  return [
    { cmd: '/bin/bash', args: [], source: 'posix' },
    { cmd: 'bash', args: [], source: 'path' },
    { cmd: '/bin/sh', args: [], source: 'posix' },
    { cmd: 'sh', args: [], source: 'path' },
  ];
}

/**
 * 解析出可用的 POSIX shell。
 * @returns {{cmd: string, dir: string|null, source: string}|null} 找不到可用 shell 时返回 null
 * @throws {Error} 仅当 `FSMS_TEST_SHELL` 显式指定却不可用时（fail-closed，不静默回退）
 */
function resolveShell(env = process.env) {
  const override = env[SHELL_OVERRIDE_ENV];
  const cacheKey = override ? `override:${override}` : 'auto';
  if (resolveCache.has(cacheKey)) return resolveCache.get(cacheKey);

  let result = null;
  if (override) {
    if (!probeShell(override)) {
      throw new Error(
        `${SHELL_OVERRIDE_ENV} 指定的 shell 不可用（跑不通 -c 探针）：${override}。` +
          '它必须是真的 POSIX shell（Windows 上如 C:\\Program Files\\Git\\bin\\bash.exe）；' +
          '清空该变量则回落到自动探测。'
      );
    }
    result = { cmd: override, dir: dirOf(override), source: 'override' };
  } else {
    for (const cand of candidateList()) {
      if (probeShell(cand.cmd, cand.args)) {
        result = { cmd: cand.cmd, dir: dirOf(cand.cmd), source: cand.source };
        break;
      }
    }
  }
  resolveCache.set(cacheKey, result);
  return result;
}

/** Windows 的 PATH 变量名大小写不固定（PATH / Path），只改真实存在的那个键 */
function pathKeyOf(env) {
  if ('PATH' in env) return 'PATH';
  if ('Path' in env) return 'Path';
  return process.platform === 'win32' ? 'Path' : 'PATH';
}

/** 把 dir 幂等地插到 PATH 最前面（重复调用不会堆积重复项） */
function prependToPath(dir, env) {
  const key = pathKeyOf(env);
  const parts = String(env[key] || '').split(path.delimiter);
  if (parts[0] === dir) return env[key];
  const next = [dir, ...parts.filter((p) => p && p !== dir)].join(path.delimiter);
  env[key] = next;
  return next;
}

/**
 * 解析 shell 并把它接进 PATH（供 `src/tests/setup.js` 调用一次）。
 * @returns {{cmd: string, dir: string|null, source: string}|null}
 */
function ensureShellOnPath(env = process.env) {
  const resolved = resolveShell(env);
  if (!resolved) return null;
  if (resolved.dir) prependToPath(resolved.dir, env);
  env[SHELL_OVERRIDE_ENV] = resolved.cmd;
  env[SHELL_SOURCE_ENV] = resolved.source;
  return resolved;
}

module.exports = {
  SHELL_OVERRIDE_ENV,
  SHELL_SOURCE_ENV,
  PROBE_MARKER,
  PROBE_SCRIPT,
  probeShell,
  resolveShell,
  ensureShellOnPath,
};
