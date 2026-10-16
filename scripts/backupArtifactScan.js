#!/usr/bin/env node
/**
 * 备份目录**取证**（A8，2026-10-16）—— 只做 IO，不做任何判断
 *
 * 与 `scripts/backupIntegrityPolicy.js`（纯判据）的分工：
 *   - 本文件把目录里的文件名/大小/时间/摘要**读出来**；
 *   - 判据文件说"什么样的产物算完整"。
 * 分开的理由与判据文件头那段相同：判据要能被用例直接驱动，而不是"造一堆临时文件
 * 再跑一次脚本看输出"。本层的 IO 适配器可注入，于是"stat 失败""sidecar 不可读"
 * "归档不可读"这三种最难在真实磁盘上造出来的形态，在用例里是一行夹具。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  SIDECAR_SUFFIX,
  isArchiveName,
  isSidecarName,
  parseSidecarDigest,
} = require('./backupIntegrityPolicy');

/**
 * 默认 IO 实现。抽成一层是为了让用例能注入假文件系统直接驱动判据，
 * 不必"造一堆临时文件再跑一次脚本看输出"——那样写出来的用例既慢又只能测到
 * 自己造的那几种形态，而真正的边界（stat 失败、sidecar 不可读、目录不存在）
 * 恰恰是最难造出来的。
 */
const defaultIo = {
  async listNames(dir) {
    return fs.promises.readdir(dir);
  },
  async isDir(p) {
    try {
      return (await fs.promises.stat(p)).isDirectory();
    } catch {
      return false;
    }
  },
  async statFile(p) {
    const st = await fs.promises.stat(p);
    return { size: st.size, mtimeMs: st.mtimeMs };
  },
  async readText(p) {
    return fs.promises.readFile(p, 'utf8');
  },
  /** 流式 sha256：归档是**全量业务库**，几十 MB 起步，一次性 readFile 会把内存顶起来 */
  sha256(p) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(p);
      stream.on('error', reject);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  },
};

/** 读 sidecar 的期望摘要；读不到 / 解析不出一律 null（判据会当成"缺证据"报错） */
const readExpectedDigest = async (file, io) => {
  try {
    return parseSidecarDigest(await io.readText(`${file}${SIDECAR_SUFFIX}`));
  } catch {
    return null;
  }
};

/** 重算归档摘要；不可读时 null（判据报 unreadable_archive） */
const readActualDigest = async (file, size, io) => {
  if (!Number.isFinite(size)) return null;
  try {
    return await io.sha256(file);
  } catch {
    return null;
  }
};

/**
 * 扫描备份目录，把每个归档连同"期望摘要 / 实际摘要"一起收集出来。
 *
 * 三种"读不到"分别落成不同的值，交给判据去解释（本层不做判断，只做取证）：
 *   - 归档 stat 失败 ⇒ size = NaN（判据报 unreadable_archive）
 *   - sidecar 读不到 / 解析不出 ⇒ expectedDigest = null（判据报 missing_sidecar）
 *   - 归档不可读 ⇒ actualDigest = null（判据报 unreadable_archive）
 *
 * @returns {Promise<{archives: Array, sidecarNames: string[]}>}
 */
async function collectArtifacts({ dir, io = defaultIo }) {
  const names = await io.listNames(dir);
  const sidecarNames = names.filter(isSidecarName);
  const archives = [];

  for (const name of names.filter(isArchiveName)) {
    const file = path.join(dir, name);
    let size = NaN;
    let mtimeMs = 0;
    try {
      const st = await io.statFile(file);
      size = st.size;
      mtimeMs = st.mtimeMs || 0;
    } catch {
      // 保持 NaN：判据会把"读不到元信息"与"确实是空文件"分开报
    }
    archives.push({
      name,
      size,
      mtimeMs,
      expectedDigest: await readExpectedDigest(file, io),
      actualDigest: await readActualDigest(file, size, io),
    });
  }

  return { archives, sidecarNames };
}

module.exports = { defaultIo, collectArtifacts, readExpectedDigest, readActualDigest };
