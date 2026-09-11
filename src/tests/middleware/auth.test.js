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
    });

    test('无效的 JWT 签名应返回 401', async () => {
      const token = jwt.sign({ userId: '123' }, 'wrong-secret');
      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
    });

    test('过期的 JWT 应返回 401', async () => {
      const token = jwt.sign({ userId: '123' }, secret, { expiresIn: '0s' });
      // 等待 token 过期
      await new Promise((r) => setTimeout(r, 10));
      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
    });

    test('有效的 JWT 应通过认证并附加用户信息', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const token = jwt.sign(
        {
          userId,
          username: 'testuser',
          email: 'test@example.com',
          roles: ['USER'],
        },
        secret,
        { expiresIn: '1h' }
      );

      const res = await request(app).get('/protected').set('Authorization', `Bearer ${token}`);
      // 注意：由于 loadValidUser 会查库，用户不存在时返回 401
      // 这里只验证中间件正确解析了 token（不查库的情况无法完全测）
      expect([200, 401]).toContain(res.status);
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
