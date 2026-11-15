/**
 * Auth 中间件测试 — 测试项目自身的 authenticate 中间件逻辑
 */

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

/** 黑名单闸的测试开关：impl 非空时替代真实查询；默认透传真实实现，不影响既有用例 */
const mockBlacklistControl = { impl: null };
jest.mock('../../middleware/tokenBlacklist', () => {
  const actual = jest.requireActual('../../middleware/tokenBlacklist');
  return {
    ...actual,
    isTokenBlacklisted: async (token) =>
      mockBlacklistControl.impl
        ? mockBlacklistControl.impl(token)
        : actual.isTokenBlacklisted(token),
  };
});

describe('Auth Middleware', () => {
  const secret = process.env.JWT_SECRET || 'test-jwt-secret-for-testing-only';
  let app;

  beforeAll(async () => {
    // authenticate 内部会查询 TokenBlacklist / User，worker 进程必须先连接内存数据库，
    // 否则黑名单查询 buffering 超时导致中间件返回 500
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }

    // 创建测试用 Express 应用
    app = express();
    app.use(express.json());

    // 加载项目的 authenticate 中间件
    const { authenticate } = require('../../middleware/auth');

    // 受保护的路由
    app.get('/protected', authenticate, (req, res) => {
      res.json({ success: true, userId: req.user.userId });
    });

    // 公开路由
    app.get('/public', (req, res) => {
      res.json({ success: true });
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('authenticate 中间件', () => {
    test('缺少 Authorization 头时应返回 401', async () => {
      const res = await request(app).get('/protected');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    test('非 Bearer 格式的 Authorization 应返回 401', async () => {
      const res = await request(app).get('/protected').set('Authorization', 'Basic sometoken');
      expect(res.status).toBe(401);
      // 非 Bearer 会被 extractAccessToken 视同「没带令牌」，须点名 AUTH_TOKEN_MISSING
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_MISSING');
    });

    test('无效的 JWT 签名应返回 401', async () => {
      const token = jwt.sign({ userId: '123' }, 'wrong-secret');
      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_INVALID');
    });

    test('过期的 JWT 应返回 401', async () => {
      // 直接签入已过期的 exp：不再依赖 expiresIn:'0s' + 一段固定睡眠，
      // 无论调度多慢，verify 看到的都是确定已过期的时间点
      const token = jwt.sign({ userId: '123', exp: Math.floor(Date.now() / 1000) - 10 }, secret);
      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      // 过期与无效签名不同码：前端据此决定「静默刷新」还是「踢回登录页」
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_EXPIRED');
    });

    // 修复（本次改动复审）：原用例用**随机 ObjectId** 签令牌，而 authenticate
    // 第 3 步 loadValidUser 必查库、用户不存在即 401（实测 USER_NOT_FOUND_OR_DELETED）——
    // 该令牌**永远**走不到通过路径，却用 expect([200, 401]) 双可能断言兜住，
    // 于是「有效 JWT 应通过认证」这条用例实际从未验证过 200 分支（恒走 401）。
    // 现拆为两条各自钉死语义的用例：真实用户 + 正确 tokenVersion → 200；
    // 签名有效但用户不存在 → 401（错误码亦钉死，防「401 就算过」再次混淆）。
    test('有效的 JWT + 已存在用户 → 200 并附加用户信息', async () => {
      const User = require('../../models/User');
      require('../../models/Role'); // authenticate 内部 populate('roles') 需要 Role 模型已注册
      const suffix = Date.now().toString(36);
      const user = await User.create({
        username: `validtok_${suffix}`,
        email: `validtok_${suffix}@example.com`,
        password: 'Test@1234Zz9',
      });

      const token = jwt.sign(
        {
          userId: String(user._id),
          username: user.username,
          tokenVersion: user.tokenVersion ?? 0,
        },
        secret,
        { expiresIn: '24h' }
      );

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.userId).toBe(String(user._id));
    });

    test('签名有效但用户不存在 → 401 USER_NOT_FOUND_OR_DELETED（防 401/200 混淆）', async () => {
      const ghostId = new mongoose.Types.ObjectId().toString();
      const token = jwt.sign({ userId: ghostId, username: 'ghost', tokenVersion: 0 }, secret, {
        expiresIn: '24h',
      });

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      expect(res.body.errors.errorCode).toBe('USER_NOT_FOUND_OR_DELETED');
    });

    test('alg:none 攻击应被阻止', async () => {
      // 构造 alg:none 的 token
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ userId: '123', username: 'admin' })).toString(
        'base64url'
      );
      const token = `${header}.${payload}.`;

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      // alg:none 被 jwt.verify 的算法白名单拒绝 → 归入「无效令牌」
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_INVALID');
    });

    test('H-01 回归：省略 tokenVersion 的令牌必须被拒绝（防绕过会话吊销）', async () => {
      const User = require('../../models/User');
      require('../../models/Role'); // authenticate 内部 populate('roles') 需要 Role 模型已注册
      const user = await User.create({
        username: 'tvuser',
        email: 'tv@example.com',
        password: 'Test@1234Zz9',
      });

      // 省略 tokenVersion：即便签名有效也必须拒绝
      const forged = jwt.sign({ userId: String(user._id), username: 'tvuser' }, secret, {
        expiresIn: '24h',
      });
      const res1 = await request(app).get('/protected').set('Authorization', `Bearer ${forged}`);
      expect(res1.status).toBe(401);
      // 省略 tokenVersion 走的是「会话已失效」：伪造者既不能跳过该字段，
      // 也不能靠它伪装成别的失败类型
      expect(res1.body.errors.errorCode).toBe('SESSION_EXPIRED');

      // 携带正确 tokenVersion：应通过
      const legit = jwt.sign(
        { userId: String(user._id), username: 'tvuser', tokenVersion: user.tokenVersion ?? 0 },
        secret,
        { expiresIn: '24h' }
      );
      const res2 = await request(app).get('/protected').set('Authorization', `Bearer ${legit}`);
      expect(res2.status).toBe(200);
    });
  });

  describe('authenticate 的令牌面判别（kid 选钥 / 限算法 / 黑名单 fail-closed）', () => {
    // 原四例测的是 jsonwebtoken 库本身（sign/verify/改密钥/过期），对本仓没有回归判别力：
    // 库自身的行为不归本仓管。本仓的判据在 authenticate 的接线上——kid 选钥、
    // 算法白名单、黑名单闸及其 fail-closed。以下四例分别钉这些接线。

    /** 造一个真实用户 + 与其 tokenVersion 匹配的有效令牌（过 authenticate 的账户闸） */
    const makeUserWithToken = async (name) => {
      const User = require('../../models/User');
      const suffix = `${Date.now().toString(36)}${name}`;
      const user = await User.create({
        username: `authcase${suffix}`,
        email: `authcase${suffix}@example.com`,
        password: 'Test@1234Zz9',
      });
      const token = jwt.sign(
        { userId: String(user._id), username: user.username, tokenVersion: user.tokenVersion ?? 0 },
        secret,
        { expiresIn: '24h' }
      );
      return token;
    };

    test('header.kid 指向未知密钥 → 401 AUTH_TOKEN_INVALID（kid 选钥的拒绝腿）', async () => {
      // 单密钥模式下 currentKid 为空串；配置了密钥集时取一个必然不存在的派生 kid——
      // 两种配置下它都不是有效密钥
      const { signingKids } = require('../../utils/jwtKeys');
      const currentKid = signingKids().access;
      const unknownKid = currentKid ? `${currentKid}-rotated-away` : 'zz-unknown-kid';
      const token = jwt.sign({ userId: '123', tokenVersion: 0 }, secret, {
        expiresIn: '24h',
        header: { kid: unknownKid },
      });

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      // 未知 kid 归入「令牌无效」（401），不得落成 500：前端只在 401 触发刷新/登出
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_INVALID');
    });

    test('非白名单算法（HS512）签名 → 401 AUTH_TOKEN_INVALID（算法白名单收口）', async () => {
      // authenticate 只允许 HS256：同一把密钥换成 HS512 签名必须被拒。
      // 这是 jwt.verify 的 algorithms 白名单判据，比上面 alg:none 一例更一般的形态。
      const token = jwt.sign({ userId: '123', tokenVersion: 0 }, secret, {
        algorithm: 'HS512',
        expiresIn: '24h',
      });

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_INVALID');
    });

    test('已吊销令牌（黑名单命中）→ 401 AUTH_TOKEN_REVOKED', async () => {
      const { blacklistToken } = require('../../middleware/tokenBlacklist');
      const token = await makeUserWithToken('Revoke');
      await blacklistToken(token, Math.floor(Date.now() / 1000) + 3600);

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_REVOKED');
    });

    test('黑名单服务故障必须 fail-closed → 503 SECURITY_SERVICE_UNAVAILABLE', async () => {
      const token = await makeUserWithToken('FailClosed');
      mockBlacklistControl.impl = async () => {
        const err = new Error('Token blacklist service unavailable');
        err.code = 'BLACKLIST_SERVICE_UNAVAILABLE';
        throw err;
      };
      try {
        const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(503);
        // 与 authenticate 的 mapAuthFailure 口径一致：安全服务不可用是 503，
        // 既不是「令牌无效」（401）也不是笼统 500——查不到结论时放行等于取消防线
        expect(res.body.errors.errorCode).toBe('SECURITY_SERVICE_UNAVAILABLE');
      } finally {
        mockBlacklistControl.impl = null; // 还原：不得影响本文件其他用例
      }
    });
  });
});
