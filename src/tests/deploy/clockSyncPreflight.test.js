/**
 * 生产主机时钟同步前置检查（P1-5）的判据单测
 *
 * 只测纯解析与裁决：真正执行 timedatectl/chronyc 的路径需要 Linux 宿主，
 * 本地无法伪造系统状态；但"什么算同步、什么算判不了"必须在这里钉死。
 */
'use strict';

const {
  DEFAULT_MAX_OFFSET_MS,
  parseNtpSynchronized,
  parseTimesyncOffsetMs,
  parseChronyTracking,
} = require('../../../scripts/check-clock-sync');

describe('时钟同步前置检查：解析器', () => {
  test('timedatectl NTPSynchronized 只接受明确的 yes/no', () => {
    expect(parseNtpSynchronized('yes')).toBe(true);
    expect(parseNtpSynchronized('NO')).toBe(false);
    expect(parseNtpSynchronized('')).toBeNull();
    expect(parseNtpSynchronized('unknown')).toBeNull();
  });

  test('OffsetUSec 按微秒→毫秒换算并取绝对值', () => {
    expect(parseTimesyncOffsetMs('1500')).toBe(1.5);
    expect(parseTimesyncOffsetMs('-2500')).toBe(2.5);
    expect(parseTimesyncOffsetMs('abc')).toBeNull();
    expect(parseTimesyncOffsetMs('')).toBeNull();
  });

  test('chronyc tracking：System time + Leap status 均可解析', () => {
    const sample = [
      'Reference ID    : A1B2C3D4 (ntp.example)',
      'Stratum         : 2',
      'System time     : 0.000123 seconds slow of NTP time',
      'Last offset     : +0.000045 seconds',
      'Leap status     : Normal',
    ].join('\n');
    const parsed = parseChronyTracking(sample);
    expect(parsed.leapNormal).toBe(true);
    expect(parsed.offsetMs).toBeCloseTo(0.123, 6);
  });

  test('chronyc tracking：缺 Leap status 判为不可解析（不能默认正常）', () => {
    expect(parseChronyTracking('System time : 0.1 seconds fast of NTP time')).toBeNull();
  });

  test('默认阈值是明确的 1000ms，且允许部署单收紧', () => {
    expect(DEFAULT_MAX_OFFSET_MS).toBe(1000);
  });
});
