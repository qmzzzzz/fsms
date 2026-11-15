/**
 * P3：诱饵临时授权行的时间线自洽。
 *
 * 偏移口径（全文件一致）：*OffsetMin 为正 = 过去多少分钟，为负 = 未来多少分钟。
 * 三条不变式：有效期 == 授予时刻 + 时长；active 行的到期在未来、expired 行的到期在过去；
 * revoked 行的吊销落在授予与自然到期之间（"提前回收"语义成立）。
 * hp-g6 曾被钉为反例（granted 70h 前 + 24h 时长，expiresAt 却写在 46h 后，吊销晚于到期）。
 */
const { DECOY_TEMP_GRANTS } = require('../../constants/honeypotDecoyAggregatesData');

describe('诱饵临时授权行时间线自洽（P3）', () => {
  test('有效期 == 授予时刻 + durationHours（逐行）', () => {
    for (const row of DECOY_TEMP_GRANTS) {
      if (row.grantedAtOffsetMin === null || row.expiresAtOffsetMin === null) continue;
      const spanMinutes = row.grantedAtOffsetMin - row.expiresAtOffsetMin;
      expect(spanMinutes).toBe(row.durationHours * 60);
    }
  });

  test('状态与到期方向一致：active 在未来、expired 在过去', () => {
    for (const row of DECOY_TEMP_GRANTS) {
      if (row.status === 'active') {
        expect(row.expiresAtOffsetMin).toBeLessThan(0);
      }
      if (row.status === 'expired') {
        expect(row.expiresAtOffsetMin).toBeGreaterThan(0);
      }
    }
  });

  test('revoked 行：吊销晚于授予、早于自然到期（"提前结束"成立）', () => {
    for (const row of DECOY_TEMP_GRANTS) {
      if (row.status !== 'revoked') continue;
      expect(row.revokedAtOffsetMin).not.toBeNull();
      // 偏移越大越早：granted(早) > revoked > expires(晚)
      expect(row.revokedAtOffsetMin).toBeLessThan(row.grantedAtOffsetMin);
      expect(row.revokedAtOffsetMin).toBeGreaterThan(row.expiresAtOffsetMin);
    }
  });

  test('签批先于生效、申请先于签批（无时序倒挂）', () => {
    for (const row of DECOY_TEMP_GRANTS) {
      for (const approval of row.approvals) {
        expect(approval.atOffsetMin).toBeLessThan(row.requestedAtOffsetMin);
        if (row.grantedAtOffsetMin !== null) {
          expect(approval.atOffsetMin).toBeGreaterThan(row.grantedAtOffsetMin);
        }
      }
    }
  });
});
