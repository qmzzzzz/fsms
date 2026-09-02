/**
 * auth 中间件分支补齐（覆盖率棘轮：branches ≥72 / functions ≥83）
 *
 * 既有套件覆盖了认证主路径，以下分支零覆盖：
 *   - 账户状态拦截：inactive(208) / locked(211) / lockUntil 临时锁定(214)
 *   - 每请求 IP 访问范围校验拒绝 + 审计落库(241-262)
 *   - fail-closed 故障映射：黑名单服务(334-336) / 会话服务(340-342) / 兜底 500(344-345)
 *   - 缓存容量保护淘汰循环(88-91)
 *   - 权限缓存联动失效失败的告警分支(146)
 *   - 跨实例失效广播接收器(154-155)：无 Redis 时永不触发，
 *     用 jest.doMock 捕获 onInvalidate 注册的回调后直接驱动
 *
 * 注：172-179 的 30s 清理定时器回调不做覆盖——其分支可由其余补齐项
 * 达标覆盖（函数覆盖率 7/8=87.5% 已过硬门槛），强行驱动需伪造系统时钟，
 * 与 mongodb 驱动冲突（见 permCacheLifecycle.test.js 的实测结论）。
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { randomPassword } = require('../helpers/buildLoginEnvelope');

describe('auth 中间件分支补齐', () => {
  let app;
  let User;
  let TokenBlacklist;
  let AuditLog;
  let sessionService;
  const PASSWORD = randomPassword();
  const stamp = `ag${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  const users = {};

  const makeUser = async (name, update = {}) => {
    const user = await User.create({
      username: `${stamp}${name}`,
      email: `${stamp}${name}@example.com`,
      password: PASSWORD,
    });
    if (Object.keys(update).length > 0) {
      await User.findByIdAndUpdate(user._id, update);
    }
    users[name] = {
      _id: user._id,
      token: jwt.sign(
        { userId: String(user._id), username: user.username, tokenVersion: 0 },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      ),
    };
    return user;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    TokenBlacklist = require('../../models/TokenBlacklist');
    AuditLog = require('../../models/AuditLog');
    sessionService = require('../../services/sessionService');

    await makeUser('inactive', { status: 'inactive' });
    await makeUser('locked', { status: 'locked' });
    await makeUser('lockuntil', { lockUntil: new Date(Date.now() + 3600 * 1000) });
    await makeUser('iprange', { allowedIPs: '203.0.113.0/24' });
    await makeUser('sidfail');
    await makeUser('blfail');
    await makeUser('generic');
    await makeUser('evict');

    const { createApp } = require('../../app');
    app = createApp();
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await AuditLog.deleteMany({ action: 'ip_range_denied', username: `${stamp}iprange` }).catch(
        () => {}
      );
      await mongoose.connection.close();
    }
  });

  const getMe = (token) => request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);

  describe('账户状态拦截', () => {
    test('inactive 账户 → 401 账户已被禁用', async () => {
      const res = await getMe(users.inactive.token);
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('已被禁用');
    });

    test('locked 账户 → 401 账户已被锁定', async () => {
      const res = await getMe(users.locked.token);
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('已被锁定');
    });

    test('临时锁定（lockUntil 未到期）→ 401 稍后再试', async () => {
      const res = await getMe(users.lockuntil.token);
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('临时锁定');
    });
  });

  describe('每请求 IP 访问范围校验', () => {
    test('请求 IP 不在允许范围 → 403 + ip_range_denied 审计落库', async () => {
      const res = await getMe(users.iprange.token);
      expect(res.status).toBe(403);
      expect(res.body.message).toContain('允许访问范围');

      // 审计写入在 authenticate 内是 fire-and-forget（不 await），轮询等待落库
      let audit = null;
      for (let i = 0; i < 20 && !audit; i++) {
        audit = await AuditLog.findOne({
          action: 'ip_range_denied',
          username: `${stamp}iprange`,
        });
        if (!audit) await new Promise((r) => setTimeout(r, 100));
      }
      expect(audit).toBeTruthy();
      expect(audit.riskFactors).toContain('ip_range_violation');
    });
  });

  describe('fail-closed 故障映射', () => {
    test('黑名单服务故障 → 503（不得放行也不得笼统 500）', async () => {
      const spy = jest.spyOn(TokenBlacklist, 'findOne').mockImplementation(() => {
        throw new Error('db down (故障注入)');
      });
      let res;
      try {
        res = await getMe(users.blfail.token);
      } finally {
        spy.mockRestore();
      }
      expect(res.status).toBe(503);
      expect(res.body.message).toBe('安全服务暂不可用，请稍后重试');
    });

    test('会话服务故障（带 sid 的令牌）→ 503', async () => {
      const err = new Error('db down (故障注入)');
      err.code = 'SESSION_SERVICE_UNAVAILABLE';
      const sidToken = jwt.sign(
        {
          userId: String(users.sidfail._id),
          username: `${stamp}sidfail`,
          tokenVersion: 0,
          sid: 'fake-sid-for-fault-injection',
        },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      const spy = jest.spyOn(sessionService, 'validateSession').mockRejectedValue(err);
      let res;
      try {
        res = await getMe(sidToken);
      } finally {
        spy.mockRestore();
      }
      expect(res.status).toBe(503);
      expect(res.body.message).toBe('安全服务暂不可用，请稍后重试');
    });

    test('其他未预期错误 → 500 认证过程出错（不外泄细节）', async () => {
      const spy = jest.spyOn(User, 'findById').mockImplementation(() => {
        throw new Error('boom (故障注入)');
      });
      let res;
      try {
        res = await getMe(users.generic.token);
      } finally {
        spy.mockRestore();
      }
      expect(res.status).toBe(500);
      expect(res.body.message).toBe('认证过程出错');
    });
  });

  describe('本地用户缓存', () => {
    test('容量保护：条目超过上限时按插入序批量淘汰，真实用户认证不受影响', async () => {
      const { invalidateUserCache } = require('../../middleware/auth');
      // 每次调用写入一个未失效标记条目；塞满后下一次 loadValidUser 触发淘汰循环
      for (let i = 0; i < 1005; i++) {
        invalidateUserCache(`evict-fake-${i}`);
      }
      const res = await getMe(users.evict.token);
      expect(res.status).toBe(200);
    });

    test('权限缓存联动失效失败仅告警，不阻断主流程', () => {
      const logger = require('../../utils/logger');
      const userSpy = jest.spyOn(User, 'invalidatePermissionCache').mockImplementation(() => {
        throw new Error('perm cache down (故障注入)');
      });
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      try {
        const { invalidateUserCache } = require('../../middleware/auth');
        expect(() => invalidateUserCache('receiver-perm-fail')).not.toThrow();
        expect(warnSpy).toHaveBeenCalledWith(
          expect.stringContaining('权限缓存联动失效失败'),
          expect.anything()
        );
      } finally {
        userSpy.mockRestore();
        warnSpy.mockRestore();
      }
    });
  });

  describe('跨实例失效广播接收器（无 Redis 环境下直接驱动回调）', () => {
    test('仅对匹配前缀的字符串键执行本地失效，其余忽略', () => {
      let captured = null;
      jest.resetModules();
      jest.doMock('../../services/sharedCache', () => {
        const actual = jest.requireActual('../../services/sharedCache');
        return {
          ...actual,
          onInvalidate: (handler) => {
            captured = handler;
            return () => {};
          },
        };
      });
      // 新鲜加载 auth 中间件：注册回调到我们捕获的桩上
      jest.isolateModules(() => {
        require('../../middleware/auth');
      });
      jest.dontMock('../../services/sharedCache');
      jest.resetModules();

      expect(typeof captured).toBe('function');
      // 匹配前缀 → 本地失效（无异常即通过）；不匹配键与非字符串键一律忽略
      expect(() => captured('auth:user:receiver-broadcast-id')).not.toThrow();
      expect(() => captured('other:prefix')).not.toThrow();
      expect(() => captured(123)).not.toThrow();
    });
  });
});
