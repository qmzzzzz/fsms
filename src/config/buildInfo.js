/**
 * 构建元数据（version / buildId / buildTime）——回答「线上跑的是哪个 commit」：APP_BUILD_ID / APP_BUILD_TIME（CI 注入）→ 开发态 git 短 sha
 * → 'unknown'；缺失不得阻止启动。安全边界：GET /api/version 匿名返回，只放识别版本所需最小字段；node 版本 / 依赖清单 / git remote / 主机名 /
 * env 快照 / 镜像 digest 一律不放（指纹与 CVE 映射的原料）。 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../..');

/** package.json 的 version 是唯一事实来源；读不到就退到 0.0.0-unknown，不抛 */
function readPackageVersion() {
  try {
    return require(path.join(ROOT, 'package.json')).version || '0.0.0-unknown';
  } catch (_) {
    return '0.0.0-unknown';
  }
}

/** 开发态回退：读 git 短 sha。只在有 .git 时尝试（容器内不会拉起子进程），超时 1s 且吞异常。 */
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

/** 纯函数：由「env + git 读取器」解析构建信息；deps 注入（env/gitSha/version/now/uptimeSec）只为可测，否则用例会随「仓库有没有 .git」而飘。 */
function resolveBuildInfo(deps = {}) {
  const env = deps.env || process.env;
  const gitSha = deps.gitSha || readGitSha;
  const version = deps.version || readPackageVersion();
  const now = deps.now === undefined ? Date.now() : deps.now;
  const uptimeSec = deps.uptimeSec === undefined ? process.uptime() : deps.uptimeSec;

  // trim 后为空串视为未设置：`APP_BUILD_ID=` 这种空赋值很常见，当成有效值会让 buildId 全变 ''，前端比对退化成恒等
  const envId = typeof env.APP_BUILD_ID === 'string' ? env.APP_BUILD_ID.trim() : '';
  const buildId = envId || (typeof gitSha === 'function' ? gitSha() || '' : '') || 'unknown';

  return {
    version,
    buildId,
    buildTime: normalizeTime(env.APP_BUILD_TIME),
    startedAt: new Date(now - uptimeSec * 1000).toISOString(),
    uptimeSec: Math.max(0, Math.floor(uptimeSec)),
  };
}

let cached = null;

/** 进程内只解析一次：git 子进程与文件读取都不该在每次请求里重跑；resetBuildInfoCache 仅供测试重置 */
function getBuildInfo() {
  if (!cached) cached = Object.freeze(resolveBuildInfo());
  return cached;
}

function resetBuildInfoCache() {
  cached = null;
}

module.exports = { getBuildInfo, resolveBuildInfo, resetBuildInfoCache };
