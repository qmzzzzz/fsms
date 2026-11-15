/**
 * P3：蜜罐审计行的 ip 键纪律——"不成就不成键"。
 *
 * 守的是什么：归一化失败（攻击者可控的伪造/畸形地址）不得把原文回落进审计行。
 * 旧实现 `normalizeIP(punishTarget) || punishTarget` 会把解析失败的原文原样落库、
 * 原样交给取证标记与告警 meta——审计集合里从此多一条"看起来像 IP 的攻击者文本"。
 * 修复后：归一化失败 ⇒ 审计行**没有 ip 键**；取证标记与告警 meta 拿到 null，不再传原文。
 *
 * 用替身隔离：AuditLog.create 用 spy 捕获入参（不落库、不触发哈希链）；
 * forensicTrigger 整体 mock；securityAlert 只 spy 判定与派发。
 */
jest.mock('../../services/forensicTrigger', () => ({
  markForensicTarget: jest.fn(),
  isForensicTarget: jest.fn(() => false),
}));

const AuditLog = require('../../models/AuditLog');
const securityAlert = require('../../services/securityAlert');
const honeypotWatch = require('../../services/honeypotWatch');
const forensicTrigger = require('../../services/forensicTrigger');

const UNPARSEABLE_IP = '999.999.999.999'; // 四段超 255：normalizeIP 判 null 的畸形形态
const VALID_IP = '203.0.113.5';

describe('P3 蜜罐审计 ip 键：归一化失败不落原文', () => {
  let dispatchSpy;
  let createSpy;

  beforeAll(() => {
    jest.spyOn(securityAlert, 'shouldSendAlert').mockReturnValue(true);
    dispatchSpy = jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
  });

  beforeEach(() => {
    jest.clearAllMocks();
    createSpy = jest.spyOn(AuditLog, 'create').mockResolvedValue({});
  });

  afterAll(() => jest.restoreAllMocks());

  test('登录审计：畸形 ip ⇒ 审计行无 ip 键、取证标记收 null、告警 meta 记 null', async () => {
    await honeypotWatch.recordHoneypotLogin({
      username: 'hpt_trap',
      ip: UNPARSEABLE_IP,
      userAgent: 'ua',
      method: 'POST',
      path: '/api/auth/login',
    });
    expect(createSpy).toHaveBeenCalledTimes(1);
    const doc = createSpy.mock.calls[0][0];
    expect('ip' in doc).toBe(false); // 不成键：原文不许进审计行
    expect(doc.action).toBe('honeypot_login');
    expect(forensicTrigger.markForensicTarget).toHaveBeenCalledWith(
      null,
      expect.objectContaining({ reason: 'honeypot_login' })
    );
    expect(dispatchSpy.mock.calls[0][3]).toMatchObject({ ip: null });
  });

  test('登录审计：合法 ip ⇒ 照常写归一化后的 ip 键（不伤正常路径）', async () => {
    await honeypotWatch.recordHoneypotLogin({
      username: 'hpt_trap',
      ip: VALID_IP,
      userAgent: 'ua',
      method: 'POST',
      path: '/api/auth/login',
    });
    const doc = createSpy.mock.calls[0][0];
    expect(doc.ip).toBe(VALID_IP);
    expect(forensicTrigger.markForensicTarget).toHaveBeenCalledWith(VALID_IP, expect.anything());
  });

  test('探测审计：畸形 ip ⇒ 审计行无 ip 键（探针侧同口径）', async () => {
    await honeypotWatch.recordHoneypotProbe({
      username: 'hpt_trap',
      ip: UNPARSEABLE_IP,
      method: 'GET',
      path: '/api/devices',
      verdict: 'deny',
      writeAttempt: false,
    });
    const doc = createSpy.mock.calls[0][0];
    expect('ip' in doc).toBe(false);
    expect(doc.action).toBe('honeypot_probe');
  });

  test('探测审计：合法 ip ⇒ 照常写 ip 键', async () => {
    await honeypotWatch.recordHoneypotProbe({
      username: 'hpt_trap',
      ip: VALID_IP,
      method: 'GET',
      path: '/api/devices',
      verdict: 'deny',
      writeAttempt: false,
    });
    expect(createSpy.mock.calls[0][0].ip).toBe(VALID_IP);
  });
});
