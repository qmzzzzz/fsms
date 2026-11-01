/**
 * 强制改密闸（P1-2）的回归网：放行表、路径规范化、置位/清除两个方向。
 *
 * 判据全部走真实的 authenticate + 真实挂载前缀（req.baseUrl + req.path），
 * 因为这条闸此前的缺陷恰恰出在"按 originalUrl 精确串比对"上——
 * 用桩请求直接喂 path 会把这个缺陷一起桩掉。
 */

const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('强制改密闸：放行表与路径规范化', () => {
  const stamp = `pcg${Date.now()}`.replace(/\d/g, (d) => 'abcdefghij'[Number(d)]);
  // 与通用 concretize 口径一致（sid 段是 UUID 形态，不是 ObjectId）
  const SID = '550e8400-e29b-41d4-a716-446655440000';
  let app;
  let User;
  let user;
  let token;

  const ok = (req, res) => res.json({ success: true });

  const buildApp = () => {
    const { authenticate, invalidateUserCache } = require('../../middleware/auth');
    const server = express();
    server.use(express.json());
    for (const [prefix, paths] of Object.entries({
      '/api/auth': [
        '/password',
        '/password-extra',
        '/me',
        '/logout',
        '/sessions',
        '/sessions/others',
        '/sessions/:sid',
        '/sessions/:sid/extra',
      ],
      '/api/security': ['/change-password', '/change-password-x', '/my-info'],
      '/api/users': ['/'],
    })) {
      const router = express.Router();
      for (const p of paths) router.all(p, authenticate, ok);
      server.use(prefix, router);
    }
    return { server, invalidateUserCache };
  };

  const call = (method, url) => request(app)[method](url).set('Authorization', `Bearer ${token}`);

  const setFlag = async (value) => {
    await User.findByIdAndUpdate(user._id, { mustChangePassword: value });
    require('../../middleware/auth').invalidateUserCache(user._id);
  };

  // 每个用例自带前置：本文件共用同一个 user 与同一条缓存键，而「改密后清位置」那条会把
  // mustChangePassword 置成 false 且不还原。--randomize（CI seed 31337）把它排到前面时，
  // PATTERN/业务路径那几条会读到 false ⇒ 闸放行、断言收到 200。正确做法是跑前统一置位，而不是排顺序。
  beforeEach(async () => {
    if (user) await setFlag(true);
  });

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    User = require('../../models/User');
    // authenticate 的 populate 需要 Role 已注册：生产由 app.js 的模型加载链保证，这里显式要求同一前提
    require('../../models/Role');
    app = buildApp().server;
    user = await User.create({
      username: `${stamp}pcg`,
      email: `${stamp}pcg@example.com`,
      password: 'P@ssw0rd-pcg-2026',
      mustChangePassword: true,
    });
    token = jwt.sign(
      { userId: String(user._id), username: user.username, tokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const ALLOWED = [
    ['put', '/api/auth/password'],
    ['put', '/api/security/change-password'],
    ['get', '/api/auth/me'],
    ['post', '/api/auth/logout'],
    ['get', '/api/security/my-info'],
    ['get', '/api/auth/sessions'],
    ['delete', '/api/auth/sessions/others'],
    // A1（2026-10-30）：设备级踢除原先漏在放行表外（表里有 /sessions 与 /sessions/others，
    // 唯独没有 /sessions/:sid），被闸挡成 403。带参数的形态走 PATTERN 表，判据必须恰好一段。
    ['delete', `/api/auth/sessions/${SID}`],
  ];

  test.each(ALLOWED)('放行表内 %s %s → 200（改密前的唯一出路不能被自己挡死）', async (m, url) => {
    const res = await call(m, url);
    expect(res.status).toBe(200);
  });

  test.each([
    ['put', '/api/auth/password/'],
    ['put', '/API/AUTH/PASSWORD'],
  ])(
    '尾斜杠/大小写变体 %s %s → 200（Express 路由大小写不敏感且 strict:false，闸必须同判据）',
    async (m, url) => {
      const res = await call(m, url);
      expect(res.status).toBe(200);
    }
  );

  test('前缀变体 /api/auth/password-extra → 403（放行表不得被前缀拖成通配）', async () => {
    const res = await call('put', '/api/auth/password-extra');
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('PASSWORD_CHANGE_REQUIRED');
  });

  test('PATTERN 只放行恰好一段：DELETE /api/auth/sessions/<sid>/extra → 403（不得变通配）', async () => {
    const res = await call('delete', `/api/auth/sessions/${SID}/extra`);
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('PASSWORD_CHANGE_REQUIRED');
  });

  /**
   * 反向对照：修复前的放行表（7 个精确串、无 PATTERN 表）在同一套规范化口径下
   * 把 DELETE /api/auth/sessions/<sid> 判成"不许"——即旧形态是红的。
   * 夹具只复述旧判据的形状，不参与生产；生产由上面的 ALLOWED 用例取真实 200。
   */
  test('反向对照：修复前的放行表对同一路径是红的（旧形态不存在于现表）', () => {
    const legacyAllowedPaths = new Set([
      '/api/auth/password',
      '/api/security/change-password',
      '/api/auth/me',
      '/api/auth/logout',
      '/api/security/my-info',
      '/api/auth/sessions',
      '/api/auth/sessions/others',
    ]);
    const legacyGateAllows = (fullPath) => legacyAllowedPaths.has(fullPath.toLowerCase());
    expect(legacyGateAllows(`/api/auth/sessions/${SID}`)).toBe(false);
    // 修前就有的那一支仍为 true（证明夹具判据本身是活的，不是恒 false）
    expect(legacyGateAllows('/api/auth/sessions/others')).toBe(true);
  });

  test.each([
    ['get', '/api/users'],
    ['put', '/api/security/change-password-x'],
  ])('业务路径 %s %s → 403 PASSWORD_CHANGE_REQUIRED', async (m, url) => {
    const res = await call(m, url);
    expect(res.status).toBe(403);
    expect(res.body.errors.errorCode).toBe('PASSWORD_CHANGE_REQUIRED');
  });

  test('未置位时同一业务路径放行（对照组：证明 403 来自本闸而不是路由本身）', async () => {
    await setFlag(false);
    const res = await call('get', '/api/users');
    expect(res.status).toBe(200);
    await setFlag(true);
  });

  test('改密后清位置 + 失效缓存 → 业务路径恢复 200（闸不是一次性粘住的）', async () => {
    const before = await call('get', '/api/users');
    expect(before.status).toBe(403);
    await setFlag(false);
    const after = await call('get', '/api/users');
    expect(after.status).toBe(200);
  });
});
