/**
 * Auth 中间件测试 — 测试项目自身的 authenticate 中间件逻辑
 */

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

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
      const token = jwt.sign({ userId: '123' }, secret, { expiresIn: '0s' });
      // 等待 token 过期
      await new Promise((r) => setTimeout(r, 10));
      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      // 过期与无效签名不同码：前端据此决定「静默刷新」还是「踢回登录页」
      expect(res.body.errors.errorCode).toBe('AUTH_TOKEN_EXPIRED');
    });

    // P1-29 修复（本次改动复审）：原用例用**随机 ObjectId** 签令牌，而 authenticate
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
        { expiresIn: '1h' }
      );

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.userId).toBe(String(user._id));
    });

    test('签名有效但用户不存在 → 401 USER_NOT_FOUND_OR_DELETED（防 401/200 混淆）', async () => {
      const ghostId = new mongoose.Types.ObjectId().toString();
      const token = jwt.sign({ userId: ghostId, username: 'ghost', tokenVersion: 0 }, secret, {
        expiresIn: '1h',
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
        expiresIn: '1h',
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
        { expiresIn: '1h' }
      );
      const res2 = await request(app).get('/protected').set('Authorization', `Bearer ${legit}`);
      expect(res2.status).toBe(200);
    });
  });

  describe('JWT Token 基础功能', () => {
    test('应生成有效的 JWT token', () => {
      const payload = { userId: '123', username: 'test', role: 'admin' };
      const token = jwt.sign(payload, secret, { expiresIn: '1h' });
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    test('应验证有效 token', () => {
      const payload = { userId: '123', username: 'test' };
      const token = jwt.sign(payload, secret, { expiresIn: '1h' });
      const decoded = jwt.verify(token, secret);
      expect(decoded.userId).toBe('123');
      expect(decoded.username).toBe('test');
    });

    test('应拒绝无效签名', () => {
      const payload = { userId: '123' };
      const token = jwt.sign(payload, secret, { expiresIn: '1h' });
      expect(() => jwt.verify(token, 'wrong-secret')).toThrow();
    });

    test('应拒绝过期的 token', () => {
      const payload = { userId: '123' };
      const token = jwt.sign(payload, secret, { expiresIn: '0s' });
      expect(() => jwt.verify(token, secret)).toThrow(/expired/);
    });
  });
});
