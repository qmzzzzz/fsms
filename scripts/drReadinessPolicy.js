#!/usr/bin/env node
/**
 * 恢复演练留档的**判据**（A8，2026-10-16）—— 纯函数，无 IO
 *
 * 为什么需要它：手册写了"每季度至少一次"（`deployment/backup-encryption.md:73`、
 * `deployment/rollback-drill-record.md:6`），但**没有任何东西会因为没做而变红**。
 * 一条只写在手册里的频率要求，等价于一条没有执行者的待办。
 * 本模块把"上次演练是什么时候、算不算逾期"变成可执行的判定，
 * 由 `scripts/backup-integrity-patrol.js --drill-only` 与 CI 定时工作流消费。
 */

const path = require('path');

/**
 * 演练周期上限：手册口径是"每季度至少一次"（`deployment/backup-encryption.md:73`、
 * `deployment/rollback-drill-record.md:6`），另有"每个发布周期至少一次"
 * （`deployment/rollback-drill.md:103`）的更严口径。取 92 天 = 一个季度的上界
 * （含闰年余量），留一天容差避免"季末最后一天跑"被判逾期。
 */
const DRILL_INTERVAL_DAYS = 92;

/** 默认留档文件（相对仓库根） */
const DEFAULT_DRILL_RECORD = path.join('deployment', 'rollback-drill-record.md');

/**
 * 从 `deployment/rollback-drill-record.md` 里取所有**真实**演练日期。
 *
 * 只认 `### 演练 #<数字>（YYYY-MM-DD…）` 这种标题形态，而不是"全文抓日期"：
 * 记录文件里有三类假日期，全文抓会把它们一起当演练——
 *   ① 模板段（```markdown 围栏内）的 `YYYY-MM-DD` 占位；
 *   ② 示例段 `### 演练 #0（示例…）` 里的 `20XX-XX-XX`；
 *   ③ 正文里的命令示例（如 `backups/fire-safety-backup-<时间点>.gz.gpg`）。
 * ①②被"必须是 4 位数字年"挡掉，③被"必须紧跟 `### 演练 #` 标题"挡掉。
 * 这条判据最容易写错的地方正在这里：把 `YYYY-MM-DD` 当成一次演练，
 * 会让"从来没练过"的环境因为模板本身而永远显示"刚练过"。
 *
 * @param {string} text 留档全文
 * @returns {string[]} 升序去重的 `YYYY-MM-DD` 列表
 */
function parseDrillRecordDates(text) {
  const re = /^###\s*演练\s*#\d+\s*[（(]\s*(\d{4})-(\d{2})-(\d{2})/gm;
  const found = new Set();
  let m;
  while ((m = re.exec(String(text == null ? '' : text))) !== null) {
    found.add(`${m[1]}-${m[2]}-${m[3]}`);
  }
  return [...found].sort();
}

/**
 * 演练时效判据（A8 动作 1「定时化」的可执行形态）。
 *
 * @param {{dates?: string[], now?: number, intervalDays?: number}} input
 * @returns {{ok: boolean, code: string|null, message: string,
 *   lastDrillDate: string|null, ageDays: number|null, intervalDays: number}}
 */
function evaluateDrillRecency({
  dates = [],
  now = Date.now(),
  intervalDays = DRILL_INTERVAL_DAYS,
} = {}) {
  const lastDrillDate = dates.length > 0 ? dates[dates.length - 1] : null;
  if (!lastDrillDate) {
    return {
      ok: false,
      code: 'drill_never_recorded',
      lastDrillDate: null,
      ageDays: null,
      intervalDays,
      message:
        '演练留档里没有任何真实演练记录（只有模板/示例）：' +
        '「每季度至少一次」这条要求目前**没有执行者**，恢复能力未经任何实证。',
    };
  }
  const ts = Date.parse(`${lastDrillDate}T00:00:00Z`);
  const ageDays = (now - ts) / 86400000;
  if (ageDays > intervalDays) {
    return {
      ok: false,
      code: 'drill_overdue',
      lastDrillDate,
      ageDays,
      intervalDays,
      message: `上次演练 ${lastDrillDate} 距今 ${ageDays.toFixed(0)} 天，超过周期上限 ${intervalDays} 天`,
    };
  }
  return {
    ok: true,
    code: null,
    lastDrillDate,
    ageDays,
    intervalDays,
    message: `上次演练 ${lastDrillDate} 距今 ${ageDays.toFixed(0)} 天，在 ${intervalDays} 天周期内`,
  };
}

module.exports = {
  DRILL_INTERVAL_DAYS,
  DEFAULT_DRILL_RECORD,
  parseDrillRecordDates,
  evaluateDrillRecency,
};
