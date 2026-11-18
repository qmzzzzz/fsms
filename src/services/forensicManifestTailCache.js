/** 取证清单末行哈希的进程内缓存（forensicManifest 的读尾加速，体积棘轮批拆出）。
 *
 * 清单按业务日只增不减（默认 2s 一轮 flush，日终数 MB～10MB）：若每次追加都
 * readFileSync **整读**文件取末行，会在「正被攻击、捕获全开」的最重负载时段把
 * 共享事件循环阻塞在同步 IO 上。按文件路径缓存「末行 chainHash + 文件字节数」：
 * 本进程刚追加过的文件，下次追加只需 statSync 比对字节数一致即可复用，不再整读。
 *
 * 正确性边界：持锁临界区内无并发写（跨进程由 forensicManifestLock 的文件锁互斥）；
 * 字节数失配（锁被他人接管后追加、prune/reconcile 改写、人工改动）即缓存失效整读
 * 重算——绝不拿可能过期的哈希接链。进程重启后缓存为空，首个追加自然走整读，起点正确。
 */

'use strict';

const fs = require('fs');

const GENESIS = 'genesis';

/** 末行哈希缓存：键 = 清单文件绝对路径，值 = { chainHash, size } */
const lastChainHashCache = new Map();

/** 读当日清单最后一行拿 prevChainHash（文件不存在 ⇒ genesis；末行坏掉 ⇒ 报错而不是猜） */
const readLastChainHash = (filePath) => {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    if (e?.code === 'ENOENT') return GENESIS;
    throw e;
  }
  const lines = content.split('\n').filter(Boolean);
  if (lines.length === 0) return GENESIS;
  let last;
  try {
    last = JSON.parse(lines[lines.length - 1]);
  } catch {
    // 末行损坏时**不猜**：宁可让本批起链失败并留下可复核的痕迹，也不悄悄接上一个读不懂的哈希
    throw new Error(`清单末行解析不出（${filePath}），拒绝在其后继续接链`);
  }
  if (!last || typeof last.chainHash !== 'string')
    throw new Error(`清单末行缺少 chainHash（${filePath}）`);
  return last.chainHash;
};

/** 取「末行 chainHash + 文件字节数」：缓存命中免整读；未命中/失配整读并回填缓存 */
const readTailForAppend = (filePath) => {
  let size;
  try {
    size = fs.statSync(filePath).size;
  } catch (e) {
    if (e?.code === 'ENOENT') return { chainHash: GENESIS, size: 0 }; // 无文件 ⇒ 无缓存可言，genesis 起链
    throw e;
  }
  const hit = lastChainHashCache.get(filePath);
  if (hit && hit.size === size) return { chainHash: hit.chainHash, size };
  const chainHash = readLastChainHash(filePath);
  lastChainHashCache.set(filePath, { chainHash, size });
  return { chainHash, size };
};

/** 追加成功后按「新末行哈希 + 追加后字节数」推进缓存，下一批免整读。
 * appendFile 失败则不会走到这里，缓存保持旧值（下次按字节数失配整读自愈）。 */
const recordAppendedTail = (filePath, chainHash, size) => {
  lastChainHashCache.set(filePath, { chainHash, size });
};

/** 测试/重置语义：清空缓存（回到「未写过」的干净态，残留会让用例在别的清单文件上命中旧路径的错觉） */
const clearTailCache = () => lastChainHashCache.clear();

module.exports = {
  GENESIS,
  readLastChainHash,
  readTailForAppend,
  recordAppendedTail,
  clearTailCache,
};
