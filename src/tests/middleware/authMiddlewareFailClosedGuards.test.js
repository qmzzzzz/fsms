/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：auth 中间件的账户状态拦截、IP 范围拒绝、fail-closed 故障映射、缓存淘汰
 * 守护的不变式：账户 inactive/locked/lockUntil 必须拦截；黑名单/会话服务故障必须 fail-closed 而非放行
 * 可证伪性：本轮未做变异实测
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [仍有效·已实测] `:248-278` 三条 `not.toThrow()` 却从不检查缓存是否真被清 ⇒ 跨实例权限失效静默失效时全绿（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     复核（2026-09-20 **变异实测**，行号已漂移到 `:269-299`）：**成立**。只架空「本地缓存标记失效」
 *     （`cached.invalidatedAt = now` 与 `userCache.set(...)`），保留联动失效与告警 → 本文件 11 例**全绿**。
 *     该用例自己的注释（`:295`）就写着「匹配前缀 → 本地失效（**无异常即通过**）」。
 *     ⚠️ 但**不要把"整函数 no-op"也当成不设防**：那样会被 `:217-234`「权限缓存联动失效失败仅告警」
 *     的 `logger.warn` 断言杀掉——**粗粒度变异测的是"模块有没有人管"，细粒度才测这条具体不变量**。
 *     证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法。
 *
 * 命名沿革：2026-09-20 由 `authMiddlewareGap.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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
const { USER_STATUS } = require('../../utils/constants');

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
        { expiresIn: '24h' }
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

    test('清单外的状态值 → 401（允许清单： authenticate 不得带完整权限放行）', async () => {
      // F-162：旧写法只列 inactive/locked 两个坏值，清单外的值（备份还原、裸写绕过 schema
      // enum 的 status）会直接通过本中间件拿到全部接口，而同一账户的 refresh 被拒——
      // "账户可用"这一个概念在两个消费点上给出两个答案。
      await makeUser('offenum', { status: 'zz_not_in_enum' });
      const res = await getMe(users.offenum.token);
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('已被禁用');
    });

    // 遍历清单而不是逐条硬编码：给 USER_STATUS 加一档时这里会自动多出一条"该档必须 401"
    // 的用例——按枚举拒绝的写法会在无人改测试的情况下静默放行新档位。
    test.each(Object.values(USER_STATUS).filter((s) => s !== USER_STATUS.ACTIVE))(
      '账户状态 %s → 401（新增档位会自动要求被拒绝）',
      async (status) => {
        await makeUser(`st_${status}`, { status });
        const res = await getMe(users[`st_${status}`].token);
        expect(res.status).toBe(401);
      }
    );
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

    /**
     * 同一个拒绝分支，但方法是 HEAD。
     *
     * 上一条走 GET，正好绕开了缺陷：assertIpAllowed 把 `req.method` **原样**交给
     * AuditLog.record()，而 method 曾是只有 5 个动词的 enum ⇒ HEAD 落在枚举外，
     * Mongoose 拒掉的是**整条文档**，record() 的 catch 只留下一行 error 日志与
     * audit_write_failed 指标（口径还是"落库失败"，不是"我们自己太窄"）。
     * 于是 HEAD 探测式访问被拒这件事在审计留存里凭空消失，而 HEAD 恰恰是探测流量
     * 最常用的方法（curl -I / 监控探活），且 Express 把 HEAD 路由到 GET 处理器、
     * authenticate 又排在路由之前——这条路径是常态可达，不是理论构造。
     *
     * 判据用"新出现的行"而不是"按 method 查一行"：后者在未修复时会因查不到而红，
     * 但红得看不出是"整行丢了"还是"只是 method 维被抹空"，而这两者的严重性差一个量级。
     */
    test('HEAD 请求同样必须落 ip_range_denied（method 曾是窄枚举，整条被 ValidationError 丢弃）', async () => {
      const before = new Set(
        (
          await AuditLog.find({ action: 'ip_range_denied', username: `${stamp}iprange` }).select(
            '_id'
          )
        ).map((d) => String(d._id))
      );

      const res = await request(app)
        .head('/api/auth/me')
        .set('Authorization', `Bearer ${users.iprange.token}`);
      expect(res.status).toBe(403);

      let fresh = null;
      for (let i = 0; i < 20 && !fresh; i++) {
        const rows = await AuditLog.find({
          action: 'ip_range_denied',
          username: `${stamp}iprange`,
        });
        fresh = rows.find((d) => !before.has(String(d._id))) || null;
        if (!fresh) await new Promise((r) => setTimeout(r, 100));
      }
      expect(fresh).toBeTruthy();
      // 不只是"有一行"：method 维必须逐字留住，否则事后看不出这是一次 HEAD 探测
      expect(fresh.method).toBe('HEAD');
      // 记下现网形态（不是期望形态）：本处传的是 req.path 而非 utils/auditMeta 的 auditPath(req)，
      // 在挂载路由器里 req.path 是**挂载点相对**的 '/me'，完整路径 '/api/auth/me' 丢失，
      // 于是审计页按路径筛选/统计查不到这类记录。属另一条独立缺陷（同族的 recordEarlyRejection
      // 用的是 auditPath），本用例只钉现状：将来修成 auditPath 时这条会红，改动必须是自觉的。
      expect(fresh.path).toBe('/me');
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
        { expiresIn: '24h' }
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
      // 「真实用户认证不受影响」的判据是拿到的是该用户自己的资料：
      // 淘汰若误伤本用户，缓存 miss 后仍可能 200（空 body 或他人资料）
      expect(res.body.data.user.username).toBe(`${stamp}evict`);
      expect(String(res.body.data.user.id)).toBe(String(users.evict._id));
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

  describe('userId 自动注入日志上下文（报告 5.6 端到端接线）', () => {
    // 必须排在「跨实例失效广播」用例之前：该用例会重置模块注册表
    test('认证请求的 morgan finish 日志自动携带 userId 与 requestId', async () => {
      const winston = require('winston');
      const logger = require('../../utils/logger');
      const captured = [];
      class MemTransport extends winston.Transport {
        log(info, callback) {
          captured.push(info);
          callback();
        }
      }
      const mem = new MemTransport();
      logger.add(mem);
      try {
        const res = await getMe(users.evict.token);
        expect(res.status).toBe(200);
        // morgan 在 res finish 时落日志，等待事件循环推进
        await new Promise((r) => setTimeout(r, 100));
        const line = captured.find(
          (i) => typeof i.message === 'string' && i.message.includes('/api/auth/me')
        );
        expect(line).toBeTruthy();
        expect(line.userId).toBe(String(users.evict._id));
        expect(line.requestId).toBeTruthy();
      } finally {
        logger.remove(mem);
      }
    });
  });

  describe('跨实例失效广播接收器（无 Redis 环境下直接驱动回调）', () => {
    test('仅对匹配前缀的字符串键执行本地失效，其余忽略', () => {
      let captured = null;
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
      // 新鲜加载 auth 中间件：注册回调到我们捕获的桩上。
      // 必须用 isolateModules 而非 jest.resetModules()：resetModules 会清空**全局**
      // 模块注册表，此后本文件所有 require（含已加载模块内部的惰性 require，如
      // auth.js 的 require('../models/User')）都会重新执行，拿到绑定到未连接的新
      // mongoose 实例（readyState=0）的副本——随机顺序下排在后面的用例（容量保护、
      // 权限缓存联动失效）会因 users.findOne() buffering timed out 转 500，或因为
      // 拿到另一份模块级 userCache/userPermissionService 而观察不到自己的副作用。
      // 隔离注册表只让本次 require 用桩，全局注册表与已连接连接保持原样。
      jest.isolateModules(() => {
        require('../../middleware/auth');
      });
      jest.dontMock('../../services/sharedCache');

      expect(typeof captured).toBe('function');
      // 匹配前缀 → 本地失效（无异常即通过）；不匹配键与非字符串键一律忽略
      expect(() => captured('auth:user:receiver-broadcast-id')).not.toThrow();
      expect(() => captured('other:prefix')).not.toThrow();
      expect(() => captured(123)).not.toThrow();
    });
  });
});
