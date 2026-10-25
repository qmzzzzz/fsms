/**
 * 预置 mongod 二进制（CI 专用）：把「安装脚本下载并执行二进制」替换为
 * 「仓库内 SHA-256 锚定 → 校验 → 预置 → MONGOMS_SYSTEM_BINARY」。
 *
 * 为什么需要它：mongodb-memory-server 的 postinstall 会从 fastdl.mongodb.org
 * 下载 mongod 并解压执行；其 MD5 校验来自**同一个 host**，不构成独立信任锚，
 * 而本仓 globalSetup 为了兼容镜像源又把 checkMD5 显式关掉了。CI 因此等于
 * 「上游/中间人给什么就执行什么」。本脚本用版本库里的 sha256 作为独立锚：
 *   - 下载流式哈希，与 deployment/mongod-artifacts.json 逐字比对，不一致即删除并退出；
 *   - 校验通过才解压，然后打印二进制绝对路径；
 *   - CI 把它写入 MONGOMS_SYSTEM_BINARY，`npm ci --ignore-scripts` 不再触发任何下载脚本。
 *
 * 用法：
 *   MONGOMS_SYSTEM_BINARY="$(node scripts/provision-mongod.js)" npm test
 * 日志一律走 stderr，stdout 只输出路径（供命令替换消费）。
 *
 * 平台不在表中时 fail-closed（退出码 2），而不是回退到无校验下载；本地开发
 * （Windows/macOS）不受影响——它们本来就用 mongodb-memory-server 的默认路径。
 */

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TABLE = path.resolve(ROOT, 'deployment', 'mongod-artifacts.json');
const CACHE_ROOT = process.env.MONGOD_PROVISION_DIR || path.join(os.tmpdir(), 'fsms-mongod');

/** 归一化架构名：Node 的 arm64 对应 MongoDB 的 aarch64 */
function normalizeArch(arch) {
  return arch === 'arm64' ? 'aarch64' : arch;
}

/**
 * 从 os-release 文本解析发行版标识，例如 ubuntu 24.04 → ubuntu2404。
 * 只支持表里出现的 Ubuntu 形态；其他发行版返回 null（由调用方 fail-closed）。
 */
function distroFromOsRelease(text) {
  const read = (key) => {
    const m = new RegExp(`^${key}="?([^"\\n]+)"?`, 'm').exec(text || '');
    return m ? m[1].trim() : null;
  };
  const id = (read('ID') || '').toLowerCase();
  const version = read('VERSION_ID') || '';
  if (id !== 'ubuntu') return null;
  const m = /^(\d+)\.(\d+)$/.exec(version);
  if (!m) return null;
  return `ubuntu${m[1]}${m[2]}`;
}

/** @returns {{platform:string, arch:string, distro:string}|null} */
function detectTarget(platform = process.platform, arch = process.arch, osRelease = null) {
  if (platform !== 'linux') return null;
  let text = osRelease;
  if (text === null) {
    try {
      text = fs.readFileSync('/etc/os-release', 'utf8');
    } catch {
      return null;
    }
  }
  const distro = distroFromOsRelease(text);
  if (!distro) return null;
  return { platform, arch: normalizeArch(arch), distro };
}

/** 在表中查找；找不到返回 null（调用方 fail-closed） */
function findArtifact(table, target) {
  if (!target) return null;
  return (
    (table.artifacts || []).find(
      (a) => a.platform === target.platform && a.arch === target.arch && a.distro === target.distro
    ) || null
  );
}

/** 流式下载并同时算 SHA-256（跟随最多 5 次重定向） */
function download(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('重定向次数超限'));
    const req = https.get(
      url,
      { headers: { 'User-Agent': 'fsms-provision-mongod/1.0' } },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return download(new URL(res.headers.location, url).toString(), dest, redirects + 1).then(
            resolve,
            reject
          );
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode}`));
        }
        const hash = crypto.createHash('sha256');
        const out = fs.createWriteStream(dest);
        res.on('data', (chunk) => hash.update(chunk));
        res.pipe(out);
        out.on('finish', () => resolve(hash.digest('hex')));
        res.on('error', reject);
        out.on('error', reject);
      }
    );
    req.on('error', reject);
    req.setTimeout(120000, () => req.destroy(new Error('下载超时（120s）')));
  });
}

function isCached(extractDir, binaryRel, sha256) {
  const marker = path.join(extractDir, '.sha256');
  const binary = path.join(extractDir, binaryRel);
  try {
    return fs.readFileSync(marker, 'utf8').trim() === sha256 && fs.existsSync(binary);
  } catch {
    return false;
  }
}

async function main() {
  const table = JSON.parse(fs.readFileSync(TABLE, 'utf8'));
  const target = detectTarget();
  const artifact = findArtifact(table, target);
  if (!artifact) {
    console.error(
      `[provision-mongod] 当前平台不在锚定表中（target=${JSON.stringify(target)}）。` +
        '请使用 MONGOMS_SYSTEM_BINARY 指向已核验的二进制，或在 deployment/mongod-artifacts.json 登记。'
    );
    process.exit(2);
  }
  if (!/^[0-9a-f]{64}$/.test(artifact.sha256)) {
    console.error('[provision-mongod] 锚定表里的 sha256 格式非法');
    process.exit(2);
  }

  const key = `${artifact.version}-${artifact.platform}-${artifact.arch}-${artifact.distro}`;
  const extractDir = path.join(CACHE_ROOT, key);
  const binary = path.join(extractDir, artifact.binary);
  if (isCached(extractDir, artifact.binary, artifact.sha256)) {
    console.error(`[provision-mongod] 命中缓存：${binary}`);
    process.stdout.write(`${binary}\n`);
    return;
  }

  fs.mkdirSync(CACHE_ROOT, { recursive: true });
  const archive = path.join(CACHE_ROOT, `${key}.tgz.part`);
  console.error(`[provision-mongod] 下载 ${artifact.url}`);
  const actual = await download(artifact.url, archive);
  if (actual !== artifact.sha256) {
    fs.rmSync(archive, { force: true });
    console.error(
      `[provision-mongod] SHA-256 不匹配（期望 ${artifact.sha256}，实际 ${actual}）——拒绝执行`
    );
    process.exit(1);
  }
  console.error('[provision-mongod] SHA-256 校验通过，解压中');

  fs.rmSync(extractDir, { recursive: true, force: true });
  fs.mkdirSync(extractDir, { recursive: true });
  try {
    execFileSync('tar', ['-xzf', archive, '-C', extractDir], { stdio: 'inherit' });
  } finally {
    fs.rmSync(archive, { force: true });
  }
  if (!fs.existsSync(binary)) {
    console.error(`[provision-mongod] 解压后未找到 ${binary}`);
    process.exit(1);
  }
  fs.chmodSync(binary, 0o755);
  fs.writeFileSync(path.join(extractDir, '.sha256'), `${artifact.sha256}\n`);
  console.error(`[provision-mongod] 就绪：${binary}`);
  process.stdout.write(`${binary}\n`);
}

if (require.main === module) {
  main().catch((e) => {
    console.error(`[provision-mongod] 失败：${e.message}`);
    process.exit(1);
  });
}

module.exports = { detectTarget, distroFromOsRelease, findArtifact, normalizeArch };
