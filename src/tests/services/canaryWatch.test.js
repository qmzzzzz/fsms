/**
 * canaryWatch：幽灵名探测的审计、告警与启动期遮蔽对账。
 *
 * 钉住的核心契约：
 *  - 非名单名：热路径零副作用（不写审计、不告警）；
 *  - 命中：审计逐字段落库（action/critical/归一化 IP/取证字段），
 *    网络告警一次（dispatchNotification 的 type/level/载荷契约）；
 *  - 审计与通知解耦：同一哨兵多次探测审计逐条、告警按日只一次；
 *    审计写失败不阻断告警，错误经 errText 进 logger.error；
 *  - init 遮蔽对账：名单名被真实账户占用 → 显式告警且 getStatus 可见；
 *    对账失败按"未检查"处理（checked=false，不伪装成干净）；幂等只跑一次。
 */
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('canaryWatch 幽灵名检测', () => {
  let User;
  let AuditLog;
  let securityAlert;
  let canaryWatch;
  let logger;
  const stamp = `cnw${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const createdUsers = [];
  let dispatchSpy;
  let errorSpy;
  let infoSpy;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    AuditLog = require('../../models/AuditLog');
    securityAlert = require('../../services/securityAlert');
    logger = require('../../utils/logger');
    canaryWatch = require('../../services/canaryWatch');
  });

  afterAll(async () => {
    await User.deleteMany({ _id: { $in: createdUsers } }).catch(() => {});
    await mongoose.connection
      .collection('auditlogs')
      .deleteMany({ username: new RegExp(stamp) })
      .catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  beforeEach(() => {
    dispatchSpy = jest.spyOn(securityAlert, 'dispatchNotification').mockImplementation(() => {});
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    infoSpy = jest.spyOn(logger, 'info').mockImplementation(() => {});
  });

  afterEach(() => {
    dispatchSpy.mockRestore();
    errorSpy.mockRestore();
    infoSpy.mockRestore();
    delete process.env.CANARY_USERNAMES;
    canaryWatch.__resetForTest();
  });

  const canaryRows = (username) =>
    AuditLog.find({ action: 'canary_username_attempt', username }).lean();
  const canaryDispatches = () =>
    dispatchSpy.mock.calls.filter((c) => c[0] === 'canary_username_attempt');

  test('matchCanaryName：大小写/空白不敏感；非名单名/非字符串 → null', () => {
    expect(canaryWatch.matchCanaryName('root')).toBe('root');
    expect(canaryWatch.matchCanaryName('  ROOT ')).toBe('root');
    expect(canaryWatch.matchCanaryName(`${stamp}nobody`)).toBeNull();
    expect(canaryWatch.matchCanaryName(undefined)).toBeNull();
  });

  test('非名单名：不写审计、不告警（热路径零副作用）', async () => {
    await canaryWatch.recordGhostAttempt({ username: `${stamp}plain`, ip: '10.0.0.1' });
    expect(await AuditLog.countDocuments({ username: `${stamp}plain` })).toBe(0);
    expect(dispatchSpy).not.toHaveBeenCalled();
  });

  test('命中：审计逐字段落库 + 告警一次（type/level/载荷契约）', async () => {
    await canaryWatch.recordGhostAttempt({
      username: 'ROOT',
      ip: '::ffff:10.9.8.7',
      userAgent: 'probe-agent',
      fingerprint: 'fp-canary',
      method: 'POST',
      path: '/api/auth/login',
    });

    const rows = await canaryRows('ROOT');
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row.action).toBe('canary_username_attempt');
    expect(row.category).toBe('auth');
    expect(row.success).toBe(false);
    expect(row.riskLevel).toBe('critical');
    expect(row.riskFactors).toEqual(
      expect.arrayContaining(['canary_username_attempt', 'nonexistent_account_probe'])
    );
    expect(row.reason).toBe('canary_username_probe');
    expect(row.body.canary).toBe('root');
    expect(row.ip).toBe('10.9.8.7'); // ::ffff: 已归一化（口径）
    expect(row.userAgent).toBe('probe-agent');
    expect(row.fingerprint).toBe('fp-canary');
    expect(row.method).toBe('POST');
    expect(row.path).toBe('/api/auth/login');

    const calls = canaryDispatches();
    expect(calls).toHaveLength(1);
    expect(calls[0][1]).toBe('critical');
    expect(calls[0][2]).toContain('ROOT');
    expect(calls[0][3]).toEqual({ canary: 'root', ip: '10.9.8.7' });
  });

  test('同哨兵连续两次：审计逐条、告警只一次（频控只挡通知不挡取证）', async () => {
    await canaryWatch.recordGhostAttempt({ username: 'oracle', ip: '10.0.0.2' });
    await canaryWatch.recordGhostAttempt({ username: 'oracle', ip: '10.0.0.3' });
    expect(
      await AuditLog.countDocuments({ action: 'canary_username_attempt', username: 'oracle' })
    ).toBe(2);
    expect(canaryDispatches()).toHaveLength(1);
  });

  test('两个不同哨兵：各自独立频控（去重键含哨兵名），互不遮蔽', async () => {
    await canaryWatch.recordGhostAttempt({ username: 'backup', ip: '10.0.0.4' });
    await canaryWatch.recordGhostAttempt({ username: 'demo', ip: '10.0.0.5' });
    expect(canaryDispatches()).toHaveLength(2);
  });

  test('审计写入失败：函数仍 resolve、仍告警，错误经 errText 进 logger.error', async () => {
    const createSpy = jest.spyOn(AuditLog, 'create').mockRejectedValueOnce(new Error('disk full'));
    await expect(
      canaryWatch.recordGhostAttempt({ username: 'postgres', ip: '10.0.0.6' })
    ).resolves.toBeUndefined();
    createSpy.mockRestore();
    expect(errorSpy.mock.calls.some((c) => String(c[0]).includes('哨兵用户名审计写入失败'))).toBe(
      true
    );
    expect(canaryDispatches()).toHaveLength(1);
  });

  test('CANARY_USERNAMES 覆盖：新名单生效、默认名单同时失效', async () => {
    process.env.CANARY_USERNAMES = ` ${stamp}GHOST ,`;
    expect(canaryWatch.matchCanaryName(`${stamp}ghost`)).toBe(`${stamp}ghost`);
    expect(canaryWatch.matchCanaryName('root')).toBeNull();

    await canaryWatch.recordGhostAttempt({ username: `${stamp}GHOST`, ip: '10.0.0.7' });
    const rows = await canaryRows(`${stamp}GHOST`);
    expect(rows).toHaveLength(1);
    expect(rows[0].body.canary).toBe(`${stamp}ghost`);
  });

  describe('init 遮蔽对账', () => {
    test('名单名被真实账户占用 → 显式告警 + getStatus 可见', async () => {
      const shadowName = `${stamp}shadow`;
      const u = await User.create({
        username: shadowName,
        email: `${shadowName}@example.com`,
        password: randomPassword(),
      });
      createdUsers.push(u._id);

      process.env.CANARY_USERNAMES = shadowName;
      await canaryWatch.init();

      const status = canaryWatch.getStatus();
      expect(status.checked).toBe(true);
      expect(status.shadowed).toEqual([shadowName]);
      expect(status.count).toBe(1);
      expect(errorSpy.mock.calls.some((c) => String(c[0]).includes('遮蔽'))).toBe(true);
    });

    test('干净名单：checked=true、shadowed=[]、info 记录来源', async () => {
      process.env.CANARY_USERNAMES = `${stamp}nobody`;
      await canaryWatch.init();
      expect(canaryWatch.getStatus()).toEqual({
        count: 1,
        fromEnv: true,
        checked: true,
        shadowed: [],
        configErrors: [],
      });
      expect(infoSpy.mock.calls.some((c) => String(c[0]).includes('安全哨兵已生效'))).toBe(true);
    });

    test('幂等：重复调用复用同一 promise，对账只跑一次', async () => {
      const findSpy = jest.spyOn(User, 'find');
      await canaryWatch.init();
      await canaryWatch.init();
      expect(findSpy).toHaveBeenCalledTimes(1);
      findSpy.mockRestore();
    });

    test('对账失败：init 仍 resolve、状态记"未检查"（不伪装成干净）', async () => {
      const findSpy = jest.spyOn(User, 'find').mockImplementationOnce(() => {
        throw new Error('db down');
      });
      await expect(canaryWatch.init()).resolves.toBeUndefined();
      findSpy.mockRestore();
      const status = canaryWatch.getStatus();
      expect(status.checked).toBe(false);
      expect(status.shadowed).toBeNull();
      expect(errorSpy.mock.calls.some((c) => String(c[0]).includes('对账失败'))).toBe(true);
    });
  });

  describe('getStatus 默认口径', () => {
    test('默认名单：10 个、未对账、无配置错误', () => {
      expect(canaryWatch.getStatus()).toEqual({
        count: 10,
        fromEnv: false,
        checked: false,
        shadowed: null,
        configErrors: [],
      });
    });

    test('配置错误经 configErrors 暴露（空条目不静默）', () => {
      process.env.CANARY_USERNAMES = 'root,,  ,demo';
      const status = canaryWatch.getStatus();
      expect(status.count).toBe(2);
      expect(status.fromEnv).toBe(true);
      expect(status.configErrors).toHaveLength(2);
      expect(status.configErrors.every((m) => m.includes('空条目'))).toBe(true);
    });
  });
});
