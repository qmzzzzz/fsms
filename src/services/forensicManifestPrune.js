/** 取证清单的保留与归档（B-5）。 一天一个文件会一直堆下去（默认 flush 2s 一次 ⇒ 理论上限约 4.3 万行/天）。 清理动作本身是**销毁证据**，所以口径比普通日志严得多： - 只**归档**不删除：挪到 .discarded/，证据仍在盘上。 - 只认 `<YYYY-MM-DD>.jsonl` 形状：锁文件、别的日志混在同目录时一律不碰。 - 当天文件永不清理（它还在被写）。 - 归档失败不抛：清理是尽力而为，不能反过来拖垮主流程。 - 归档条数计数可见。 默认保留 60 天 = 取证保留期（30 天）的两倍：数据被 TTL 清掉之后， 清单还要能再撑一段，用来证明「那批记录当时确实存在过」。 / / */
const fs = require('fs');
const { toEpochMs } = require('../utils/helpers');
const path = require('path');

const DISCARD_DIR = '.discarded';
const DEFAULT_KEEP_DAYS = 60;
const DAY_FILE_RE = /^(\d{4})-(\d{2})-(\d{2})\.jsonl$/;

const state = { prunedFiles: 0, prunedBytes: 0, lastError: null };

/** YYYY-MM-DD 视作 UTC 零点：显式补 Z，避免本机时区把日历日挪一天 */
const dayEpoch = (dateStr) => toEpochMs(`${dateStr}T00:00:00Z`);

const dayOf = (name) => {
  const m = DAY_FILE_RE.exec(name);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
};

/** 两个 YYYY-MM-DD 相差的天数（UTC 日历，不受本机时区影响） */
const daysBetween = (a, b) => Math.round((dayEpoch(a) - dayEpoch(b)) / 86400000); // 裸 Date.parse 是 dateParamGateSingleSource 的禁形，日期口径统一走 helpers

const readKeepDays = () => {
  const v = Number.parseInt(process.env.FORENSIC_MANIFEST_KEEP_DAYS || '', 10);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_KEEP_DAYS;
};

/** @param {{dir?: string, keepDays?: number, today?: string}} opts @returns {{archived: string[], kept: number}} / */
function pruneManifest({ dir, keepDays, today } = {}) {
  const target = dir || path.join(path.resolve(__dirname, '..', '..'), 'logs', 'forensic-manifest');
  const keep = keepDays != null ? keepDays : readKeepDays();
  const now = today || new Date().toISOString().slice(0, 10);
  let names;
  try {
    names = fs.readdirSync(target);
  } catch (e) {
    state.lastError = String(e && e.message).slice(0, 200);
    return { archived: [], kept: 0 }; // 目录还不存在（很正常）⇒ 无事可做
  }
  const archived = [];
  let kept = 0;
  for (const name of names) {
    const day = dayOf(name);
    if (!day) continue;
    const age = daysBetween(now, day);
    if (age <= keep) {
      // 当天与保留期内不动；未来日期（时钟回拨）也不动 —— 宁可留着
      kept += 1;
      continue;
    }
    try {
      const from = path.join(target, name);
      const toDir = path.join(target, DISCARD_DIR);
      fs.mkdirSync(toDir, { recursive: true, mode: 0o700 });
      const size = fs.statSync(from).size;
      fs.renameSync(from, path.join(toDir, name));
      archived.push(name);
      state.prunedFiles += 1;
      state.prunedBytes += size;
    } catch (e) {
      state.lastError = String(e && e.message).slice(0, 200);
    }
  }
  return { archived, kept };
}

const getPruneStats = () => ({ ...state });
const resetPruneState = () => {
  state.prunedFiles = 0;
  state.prunedBytes = 0;
  state.lastError = null;
};

module.exports = { DISCARD_DIR, DEFAULT_KEEP_DAYS, pruneManifest, getPruneStats, resetPruneState };
