#!/usr/bin/env node
/**
 * 生产主机时钟同步前置检查（P1-5，2026-10-30）
 *
 * 为什么必须查宿主而不是容器：容器共享宿主内核时钟，容器内装 NTP 客户端没有意义；
 * JWT 的 nbf/exp、TOTP 的 30 秒时间窗、审计时间戳与跨机日志对齐都锚在宿主时钟上。
 *
 * 判据（fail-closed）：
 *   - timedatectl 报 NTPSynchronized=yes 且 timesync-status 的偏移在阈值内；或
 *   - chronyc tracking 报 Leap status: Normal 且 System time 偏移在阈值内。
 *   - 两条路都拿不到结论 ⇒ 退出码 2（不是 0）："判不了"不能当"同步了"。
 *
 * 用法：
 *   node scripts/check-clock-sync.js
 *   CLOCK_MAX_OFFSET_MS=500 node scripts/check-clock-sync.js
 * 退出码：0 通过；1 未同步/偏移超限；2 无法判定（fail-closed）。
 */

'use strict';

const { execFileSync } = require('child_process');

const DEFAULT_MAX_OFFSET_MS = 1000;

/** 从 timedatectl 的 NTPSynchronized 输出解析布尔（yes/no） */
function parseNtpSynchronized(value) {
  const text = String(value || '')
    .trim()
    .toLowerCase();
  if (text === 'yes' || text === 'true' || text === '1') return true;
  if (text === 'no' || text === 'false' || text === '0') return false;
  return null;
}

/** 从 timedatectl timesync-status 的 OffsetUSec 解析毫秒绝对值 */
function parseTimesyncOffsetMs(value) {
  const text = String(value || '').trim();
  if (!/^-?\d+(?:\.\d+)?$/.test(text)) return null;
  return Math.abs(Number(text)) / 1000;
}

/**
 * 从 chronyc tracking 输出解析 {leapNormal, offsetMs}
 * 样例：`System time     : 0.000123456 seconds slow of NTP time`
 *       `Leap status    : Normal`
 */
function parseChronyTracking(text) {
  const raw = String(text || '');
  const leapMatch = /Leap status\s*:\s*(\S+)/i.exec(raw);
  const timeMatch = /System time\s*:\s*([\d.]+)\s*seconds\s+(fast|slow)/i.exec(raw);
  if (!leapMatch || !timeMatch) return null;
  return {
    leapNormal: leapMatch[1].toLowerCase() === 'normal',
    offsetMs: Number(timeMatch[1]) * 1000,
  };
}

function run(file, args) {
  try {
    return execFileSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (_) {
    return null;
  }
}

/** 返回 { ok, code, source, offsetMs, detail } */
function checkClock(maxOffsetMs = DEFAULT_MAX_OFFSET_MS) {
  const syncedRaw = run('timedatectl', ['show', '--property=NTPSynchronized', '--value']);
  const synced = parseNtpSynchronized(syncedRaw);
  if (synced === true) {
    const offsetRaw = run('timedatectl', ['timesync-status', '--property=OffsetUSec', '--value']);
    const offsetMs = parseTimesyncOffsetMs(offsetRaw);
    if (offsetMs === null) {
      return {
        ok: false,
        code: 2,
        source: 'timedatectl',
        offsetMs: null,
        detail: 'NTPSynchronized=yes 但读不到 timesync offset，无法判定偏移是否在阈值内',
      };
    }
    const ok = offsetMs <= maxOffsetMs;
    return {
      ok,
      code: ok ? 0 : 1,
      source: 'timedatectl',
      offsetMs,
      detail: ok
        ? `宿主时钟已同步，偏移 ${offsetMs.toFixed(3)}ms ≤ ${maxOffsetMs}ms`
        : `宿主时钟偏移 ${offsetMs.toFixed(3)}ms 超过阈值 ${maxOffsetMs}ms`,
    };
  }
  if (synced === false) {
    return {
      ok: false,
      code: 1,
      source: 'timedatectl',
      offsetMs: null,
      detail: 'NTPSynchronized=no：宿主时钟未同步',
    };
  }

  const chronyRaw = run('chronyc', ['-n', 'tracking']);
  const chrony = parseChronyTracking(chronyRaw);
  if (chrony) {
    const ok = chrony.leapNormal && chrony.offsetMs <= maxOffsetMs;
    return {
      ok,
      code: ok ? 0 : 1,
      source: 'chronyc',
      offsetMs: chrony.offsetMs,
      detail: ok
        ? `chrony 已同步，偏移 ${chrony.offsetMs.toFixed(3)}ms ≤ ${maxOffsetMs}ms`
        : `chrony 状态异常：leapNormal=${chrony.leapNormal}, 偏移 ${chrony.offsetMs.toFixed(3)}ms（阈值 ${maxOffsetMs}ms）`,
    };
  }

  return {
    ok: false,
    code: 2,
    source: 'none',
    offsetMs: null,
    detail: 'timedatectl 与 chronyc 均不可用或输出不可解析，无法证明宿主时钟已同步',
  };
}

function main() {
  const raw = process.env.CLOCK_MAX_OFFSET_MS;
  const maxOffsetMs =
    raw === undefined || raw === '' ? DEFAULT_MAX_OFFSET_MS : Number.parseInt(raw, 10);
  if (!Number.isInteger(maxOffsetMs) || maxOffsetMs < 1 || maxOffsetMs > 60000) {
    console.error('CLOCK_MAX_OFFSET_MS 必须是 1..60000 的整数（毫秒）');
    process.exit(2);
  }
  const result = checkClock(maxOffsetMs);
  // 机器可读一行，便于部署日志/发布单留证
  console.log(
    JSON.stringify({
      check: 'clock_sync',
      ok: result.ok,
      source: result.source,
      offsetMs: result.offsetMs,
      maxOffsetMs,
      detail: result.detail,
    })
  );
  if (!result.ok) console.error(result.detail);
  process.exit(result.code);
}

if (require.main === module) main();

module.exports = {
  DEFAULT_MAX_OFFSET_MS,
  parseNtpSynchronized,
  parseTimesyncOffsetMs,
  parseChronyTracking,
  checkClock,
};
