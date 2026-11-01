/**
 * 离线包扫描（宿主代理侧，供心跳公布「目标机上有哪些包」）
 *
 * 与导入器（scripts/importOfflineBundle.js）的分工必须分清：
 *   · 本模块只回答「这个目录**自称**是什么、形态与白名单过不过」——读 manifest.json、
 *     跑纯判据，**绝不读 payload、绝不算 sha256**。包动辄上 GB，心跳每 15s 一轮，
 *     把全量校验放这里等于让代理永远在算哈希；
 *   · 全量校验只在执行时发生（离线请求触发 importOfflineBundle.js --apply，逐字节比对
 *     + 验签 + load 后 RepoDigests 复核）。因此心跳里的 available 是**候选**，不是「已证明
 *     可安装」——应用侧不得把它当成任何形式的完整性背书。
 *
 * fail-soft 边界：扫描结果只进心跳（展示与下拉候选），任何异常都不许炸掉代理这一轮，
 * 也不许让代理自检变红——离线通道坏了，在线升级仍必须可用。bundlesDir 不存在（ENOENT）
 * 不是异常：那是「本机没启用离线通道」的正常形态。
 *
 * 心跳是 0644 全局可读文件，因此这里的每条输出都按「能被读走」设计：只含包目录名、
 * 镜像 ref/version 这些本来就要展示给有 security:config 权限者的字段，逐字段截断，
 * 数量封顶——一个塞满畸形包的 bundles 目录不能把心跳文件撑成 DoS 载体。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const policy = require('./offlineBundlePolicy');

/** available / invalid 各自的心跳条数上限 */
const MAX_AVAILABLE = 10;
const MAX_INVALID = 10;
/** 扫描条目上限：正常部署 bundles 下只有个位数的包；超出视为目录被滥用，丢弃并报原因 */
const MAX_SCAN_ENTRIES = 100;

const clip = (value, max) => (typeof value === 'string' ? value.slice(0, max) : '');

/**
 * 单个包目录 → 心跳摘要。任何判据不过都 throw（message 可读、不含宿主绝对路径——
 * 判据层 offlineBundlePolicy 的报错只引用 manifest 内的相对路径与字段名）。
 */
function summarizeBundle(bundleDir, dirName, allowlist) {
  const manifestPath = path.join(bundleDir, 'manifest.json');
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    throw new Error(
      err.code === 'ENOENT'
        ? '包里没有 manifest.json'
        : `manifest.json 不是合法 JSON（${err.message.slice(0, 120)}）`
    );
  }
  const manifest = policy.parseBundleManifest(raw);
  for (const img of manifest.images) {
    policy.assertBundleImageAllowed(img, allowlist);
  }
  const app = manifest.images.find((img) => img.role === 'app') || manifest.images[0];
  return {
    dirName: clip(dirName, 128),
    ref: clip(app.ref, 512),
    digest: clip(app.digest, 71),
    repository: clip(app.repository, 256),
    version: clip(manifest.version, 64),
    buildId: clip(manifest.buildId, 128),
    createdAt: clip(manifest.createdAt, 32),
  };
}

/**
 * 扫描 bundles 目录。永远 resolve、绝不 throw；错误一律折进 result.error（应用侧展示）。
 */
function scanBundles({ bundlesDir, allowlist }) {
  const result = { available: [], invalid: [], error: '' };
  if (!bundlesDir) return result;
  let entries;
  try {
    entries = fs.readdirSync(bundlesDir, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') return result; // 未启用离线通道的正常形态
    result.error = `离线包目录不可读（OFFLINE_BUNDLE_DIR 指向的位置）：${err.code || 'io'}`;
    return result;
  }
  const dirs = entries.filter((entry) => entry.isDirectory() && !entry.name.startsWith('.'));
  if (dirs.length > MAX_SCAN_ENTRIES) {
    result.error = `离线包目录下有 ${dirs.length} 个子目录，超过扫描上限（${MAX_SCAN_ENTRIES}）：请清理不再使用的旧包`;
    return result;
  }
  for (const entry of dirs) {
    try {
      result.available.push(
        summarizeBundle(path.join(bundlesDir, entry.name), entry.name, allowlist)
      );
    } catch (err) {
      result.invalid.push({
        dirName: clip(entry.name, 128),
        error: clip(err && err.message ? err.message : String(err), 200),
      });
    }
  }
  result.available = result.available.slice(0, MAX_AVAILABLE);
  result.invalid = result.invalid.slice(0, MAX_INVALID);
  return result;
}

module.exports = { scanBundles, summarizeBundle, MAX_AVAILABLE, MAX_INVALID, MAX_SCAN_ENTRIES };
