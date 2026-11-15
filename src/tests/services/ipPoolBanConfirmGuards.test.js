/**
 * P3：票据确认时刻复核"白名单覆盖"与"段内有真实业务流量"两条护栏。
 *
 * 取票与确认之间最长隔 CONFIRM_TTL_MS（10 分钟）：申请侧判据通过后，白名单可能新上、
 * 段内可能出现真实业务流量——确认时刻不复核就是一条可预期的绕过窗。两条护栏并入
 * ticketJudgementRefusal 后，确认时刻按库内现值重判，不满足走既有拒绝路径（票不消耗）。
 */
jest.mock('../../services/auditOutbox', () => ({
  recordDurably: jest.fn(),
}));

const ban = require('../../services/ipPoolBan');
const ipListService = require('../../services/ipListService');
const liveTraffic = require('../../services/ipPoolLiveTraffic');
const sharedCache = require('../../services/sharedCache');
const { recordDurably } = require('../../services/auditOutbox');

const operatorIp = '10.0.0.5';
const BLOCKED_DOC = { _id: 'e1', ip: '203.0.113.0/24', type: 'black', reason: 't' };

beforeEach(() => {
  ban.resetPoolBanState();
  jest.restoreAllMocks();
  recordDurably.mockReset();
  recordDurably.mockResolvedValue({});
  jest.spyOn(ipListService, 'listActiveEntryIps').mockResolvedValue([]);
  jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([]);
  jest.spyOn(liveTraffic, 'segmentHasLiveTraffic').mockResolvedValue({ live: false, scanned: 0 });
  jest.spyOn(ipListService, 'blockIP').mockResolvedValue(BLOCKED_DOC);
});

describe('P3：票据确认时刻复核两条护栏', () => {
  const ticketFor = async (cidr) => {
    const r = await ban.requestBan({ cidr, reason: 't', operator: 'a', operatorIp });
    expect(r.ok).toBe(true);
    return r.token;
  };

  test('取票后新上的白名单覆盖该段 ⇒ 确认被拒（whitelist_covers），不落库、票写回', async () => {
    const token = await ticketFor('203.0.113.0/24');
    jest.spyOn(ipListService, 'findCoveringEntries').mockResolvedValue([{ ip: '203.0.113.0/24' }]);
    const r = await ban.applyBan({ token, typedConfirm: '203.0.113.0/24' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('whitelist_covers');
    expect(ipListService.blockIP).not.toHaveBeenCalled();
    // 与"敲错不消耗"同口径：护栏拒绝也不消耗票（剩余 TTL 随票写回）
    await expect(sharedCache.get(`${ban.TICKET_KEY_PREFIX}${token}`)).resolves.toMatchObject({
      cidr: '203.0.113.0/24',
    });
  });

  test('取票后段内出现真实业务流量 ⇒ 确认被拒（live_traffic_inside），不落库', async () => {
    const token = await ticketFor('203.0.113.0/24');
    jest.spyOn(liveTraffic, 'segmentHasLiveTraffic').mockResolvedValue({ live: true, scanned: 2 });
    const r = await ban.applyBan({ token, typedConfirm: '203.0.113.0/24' });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('live_traffic_inside');
    expect(ipListService.blockIP).not.toHaveBeenCalled();
  });

  test('两条护栏均未触发 ⇒ 确认照常落库（新复核不误伤正常确认）', async () => {
    const token = await ticketFor('203.0.113.0/24');
    const r = await ban.applyBan({ token, typedConfirm: '203.0.113.0/24' });
    expect(r.ok).toBe(true);
    expect(r.bannedCount).toBe(1);
    expect(ipListService.blockIP).toHaveBeenCalledTimes(1);
  });
});
