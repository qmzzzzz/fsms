/**
 * sessionService 的 fail-soft 路径（覆盖率门禁指出的 4 处未覆盖分支/函数）
 *
 * 这些 catch 分支的语义是「会话表的失败不构成安全结论的失败」——
 * 吊销结论由 tokenVersion 保证、会话表只是设备列表的数据源。
 * 但「会吞掉异常」这件事此前**从未被任何测试证明过**：
 * 一旦有人把这些 catch 改成像调用方抛出，登录/登出/改密主链路就会在
 * 数据库抖动时整体失败，而默认测试全绿（因为没人走过这些分支）。
 *
 * 所以每条用例都断言两件事：
 *  1) 不抛错，且返回该函数契约规定的「无害默认值」；
 *  2) **确实打了 warn 日志** —— 吞异常但不留痕，等价于把故障藏起来。
 */

jest.mock('ua-parser-js', () =>
  jest.fn().mockImplementation(() => {
    throw new Error('ua-parser boom');
  })
);

jest.mock('../../models/UserSession', () => ({
  updateOne: jest.fn(),
  updateMany: jest.fn(),
  find: jest.fn(),
}));

jest.mock('../../utils/logger', () => ({
  warn: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const UserSession = require('../../models/UserSession');
const logger = require('../../utils/logger');
const {
  parseUserAgent,
  revokeSessionSafe,
  revokeAllSessionsSafe,
  listSessions,
} = require('../../services/sessionService');

const rejectWith = (msg) => Promise.reject(new Error(msg));

beforeEach(() => {
  jest.clearAllMocks();
});

describe('parseUserAgent 的解析失败分支（sessionService:118-122）', () => {
  test('UAParser 抛错时返回未知设备而不把登录主链路带崩', async () => {
    const result = await Promise.resolve(parseUserAgent('whatever-ua'));
    expect(result).toBeTruthy();
    expect(result.deviceType == null || result.deviceType === 'unknown').toBe(true);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('User-Agent 解析失败'));
  });
});

describe('revokeSessionSafe（sessionService:462-468）', () => {
  test('DB 抛错 → 返回 false 并留痕（调用点是登出路径，结论由黑名单保证）', async () => {
    UserSession.updateOne.mockReturnValueOnce(rejectWith('write failed'));
    await expect(revokeSessionSafe({ sid: 'abc', userId: 'u1' })).resolves.toBe(false);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('会话吊销失败'));
  });

  test('成功路径仍然返回真实结论（fail-soft 包装不得变成恒 false）', async () => {
    UserSession.updateOne.mockResolvedValueOnce({ modifiedCount: 1 });
    await expect(revokeSessionSafe({ sid: 'abc2', userId: 'u2' })).resolves.toBe(true);
    expect(logger.warn).not.toHaveBeenCalled();
  });
});

describe('revokeAllSessionsSafe（sessionService:482-489）', () => {
  test('DB 抛错 → 返回 0 并留痕（改密/重置 MFA 场景：令牌已由 tokenVersion 全局失效）', async () => {
    UserSession.find.mockReturnValueOnce({
      lean: () => rejectWith('db down'),
    });
    await expect(revokeAllSessionsSafe('u3', 'password_changed')).resolves.toBe(0);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('会话表收敛失败'));
  });
});

describe('listSessions 的惰性过期收敛（sessionService:505-514）', () => {
  test('过期状态收敛写失败 → 列表照常返回，不被辅助性写操作阻断', async () => {
    UserSession.updateMany.mockReturnValueOnce(rejectWith('concurrency wrote conflict'));
    UserSession.find.mockReturnValueOnce({ sort: () => Promise.resolve([]) });
    await expect(listSessions({ userId: 'u4' })).resolves.toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('过期会话状态收敛失败'));
  });
});
