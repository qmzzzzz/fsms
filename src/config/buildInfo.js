/**
 * 构建元数据（版本 / 构建标识 / 构建时间）
 *
 * 为什么需要它：蓝绿升级后「线上跑的是哪个 commit」必须能被回答。没有这个标识，
 * 升级完成与否只能靠人肉比对镜像 tag，前端也无法判断「我加载的壳子是否已过期」——
 * 后者正是 PWA 场景下「升级了但用户看到的还是旧界面」的根因。
 *
 * 取值优先级（前者优先，全部缺失时为 unknown；**任何情况下不得抛错**，
 * 版本信息缺失不该阻止服务启动）：
 *   1. 环境变量 APP_BUILD_ID / APP_BUILD_TIME —— CI 构建期注入，生产唯一可靠来源
 *      （容器内没有 .git，也读不到宿主机仓库）
 *   2. 开发态 git rev-parse —— 仅当仓库根存在 .git 时尝试，且只取短 sha
 *   3. 'unknown'
 *
 * 安全边界：本模块的产物会经 GET /api/version **匿名**返回，所以只放与
 * 「识别版本」直接相关的最小字段。**不放** node 版本、依赖清单、git remote、
 * 主机名、环境变量快照——这些是攻击者做指纹与 CVE 映射的原料，而识别版本
 * 只需要 version + buildId。镜像 digest 同理不进响应，改由启动日志留档
 * （见 src/index.js），运维侧仍可查，匿名端拿不到。
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

/** 仓库根（src/config → ../..） */
const ROOT = path.resolve(__dirname, '../..');

/** package.json 的 version 是唯一事实来源；读不到就退到 0.0.0-unknown，不抛 */
function readPackageVersion() {
  try {
    return require(path.join(ROOT, 'package.json')).version || '0.0.0-unknown';
  } catch (_) {
    return '0.0.0-unknown';
  }
}

/**
 * 开发态回退：读 git 短 sha。
 *
 * 只在存在 .git 时尝试——容器镜像里没有 .git，因此生产走不到这条路径，
 * 也就不会在启动时拉起一个 git 子进程。超时 1s 且吞掉所有异常：
 * 这是一条「有更好、没有也能跑」的旁路，不允许它影响启动。
 */
function readGitSha() {
  if (!fs.existsSync(path.join(ROOT, '.git'))) return '';
  try {
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], {
      cwd: ROOT,
      timeout: 1000,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch (_) {
    return '';
  }
}

/** 时间戳归一：只接受能被 Date 解析的值，否则返回 null（不编造时间） */
function normalizeTime(value) {
  if (!value) return null;
  const t = new Date(value);
  return Number.isNaN(t.getTime()) ? null : t.toISOString();
}

/**
 * 纯函数：由「环境变量 + git 读取器」解析出构建信息。
 *
 * 依赖注入只为可测：测试直接传假 env 与假 gitSha，不必真的去改进程环境或
 * 真的跑 git——否则用例会随「仓库是否有 .git」「HEAD 是否变化」而飘。
 *
 * @param {object} [deps]
 * @param {Record<string,string|undefined>} [deps.env] 环境变量来源
 * @param {() => string} [deps.gitSha] git 短 sha 读取器（返回空串表示不可用）
 * @param {string} [deps.version] package.json 版本
 * @param {number} [deps.now] 当前时间戳（ms），仅供测试注入
 * @param {number} [deps.uptimeSec] 进程已运行秒数，仅供测试注入
 */
function resolveBuildInfo(deps = {}) {
  const env = deps.env || process.env;
  const gitSha = deps.gitSha || readGitSha;
  const version = deps.version || readPackageVersion();
  const now = deps.now === undefined ? Date.now() : deps.now;
  const uptimeSec = deps.uptimeSec === undefined ? process.uptime() : deps.uptimeSec;

  // 环境变量优先；trim 后为空串视为未设置（CI 里 `APP_BUILD_ID=` 这种空赋值
  // 很常见，若当成有效值，所有实例的 buildId 会一起变成 ''，前端比对退化成恒等）
  const envId = typeof env.APP_BUILD_ID === 'string' ? env.APP_BUILD_ID.trim() : '';
  const buildId = envId || (typeof gitSha === 'function' ? gitSha() || '' : '') || 'unknown';

  return {
    version,
    buildId,
    buildTime: normalizeTime(env.APP_BUILD_TIME),
    // 进程启动时刻：蓝绿切换后可用它判断「这个实例是不是刚起来的那个」
    startedAt: new Date(now - uptimeSec * 1000).toISOString(),
    uptimeSec: Math.max(0, Math.floor(uptimeSec)),
  };
}

let cached = null;

/** 进程内只解析一次：git 子进程与文件读取都不该在每次请求里重跑 */
function getBuildInfo() {
  if (!cached) cached = Object.freeze(resolveBuildInfo());
  return cached;
}

/** 仅供测试：清掉记忆化结果 */
function resetBuildInfoCache() {
  cached = null;
}

module.exports = { getBuildInfo, resolveBuildInfo, resetBuildInfoCache };
