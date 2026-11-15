const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const config = require('../../config');
const {
  generateToken,
  generateRefreshToken,
  isRefreshTokenValid,
} = require('../../services/tokenService');

describe('tokenService claims', () => {
  test('access token keeps jti and sid separate', () => {
    const token = generateToken(
      'user-1',
      'alice',
      'alice@example.com',
      ['admin'],
      'Alice',
      2,
      'fixed-jti',
      'sid-1'
    );
    const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });

    expect(decoded).toMatchObject({
      userId: 'user-1',
      tokenVersion: 2,
      jti: 'fixed-jti',
      sid: 'sid-1',
    });
  });

  test('refresh token remains unique for same user and sid', () => {
    const first = generateRefreshToken('user-1', 3, 'sid-1');
    const second = generateRefreshToken('user-1', 3, 'sid-1');
    const firstClaims = jwt.verify(first, config.jwt.refreshSecret, { algorithms: ['HS256'] });
    const secondClaims = jwt.verify(second, config.jwt.refreshSecret, { algorithms: ['HS256'] });

    expect(first).not.toBe(second);
    expect(firstClaims.type).toBe('refresh');
    expect(secondClaims.type).toBe('refresh');
    expect(firstClaims.sid).toBe('sid-1');
    expect(secondClaims.sid).toBe('sid-1');
    expect(firstClaims.jti).not.toBe(secondClaims.jti);
  });
});

describe('refresh token 7d 窗口与校验路径（isRefreshTokenValid）', () => {
  let User;
  let UserSession;
  const createdSids = [];

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    UserSession = require('../../models/UserSession');
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      // 本套件造出的用户/会话夹具统一回收（用户名前缀 tsvc 是本文件专用）
      await User.deleteMany({ username: { $regex: '^tsvc' } }).catch(() => {});
      await UserSession.deleteMany({ sid: { $in: createdSids } }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  const makeActiveUser = async () => {
    const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    return User.create({
      username: `tsvc${suffix}`,
      email: `tsvc${suffix}@example.com`,
      password: 'Test@1234Zz9',
    });
  };

  const makeSession = async (userId, sid) => {
    await UserSession.create({
      sid,
      userId,
      status: 'active',
      expiresAt: new Date(Date.now() + 24 * 3600 * 1000), // 会话窗口比 refresh 窗口先到也不影响本组断言
    });
    createdSids.push(sid);
  };

  test('7d 窗口内签发 + 会话有效 + tokenVersion 匹配 → true（完整有效腿）', async () => {
    const user = await makeActiveUser();
    const sid = `sid-${String(user._id)}`;
    await makeSession(user._id, sid);
    const token = generateRefreshToken(String(user._id), 0, sid);
    await expect(isRefreshTokenValid(token)).resolves.toBe(true);
  });

  test('已过期的 refresh（exp 确定性签在过去）→ false 且不抛错', async () => {
    // 不用假时钟（与 mongodb-memory-server 冲突）：直接把 exp 签在确定的过去。
    // 校验路径的仓内口径是"吞错返回 false"（探测接口不向外抛 jwt 错误码），
    // 过期/无效签名/用户缺失在调用方眼里同为 false，与 AUTH_TOKEN_EXPIRED 等映射各归其位
    const token = jwt.sign(
      {
        userId: 'u1',
        type: 'refresh',
        tokenVersion: 0,
        jti: 'jti-expired',
        sid: 'sid-expired',
        exp: Math.floor(Date.now() / 1000) - 10,
      },
      config.jwt.refreshSecret,
      { algorithm: 'HS256' }
    );
    await expect(isRefreshTokenValid(token)).resolves.toBe(false);
  });

  test('无 sid 的 refresh 不可续期 → false（7d 窗口内也不放行）', async () => {
    const token = generateRefreshToken('user-1', 0, null);
    await expect(isRefreshTokenValid(token)).resolves.toBe(false);
  });

  test('access 令牌投给 refresh 校验 → false（type 闸 + 独立密钥双保险）', async () => {
    const token = generateToken(
      'user-1',
      'alice',
      'alice@example.com',
      [],
      '',
      0,
      'jti-a',
      'sid-a'
    );
    await expect(isRefreshTokenValid(token)).resolves.toBe(false);
  });

  test('tokenVersion 已推进（全局吊销）的 refresh → false', async () => {
    const user = await makeActiveUser();
    const sid = `sid-${String(user._id)}`;
    await makeSession(user._id, sid);
    const token = generateRefreshToken(String(user._id), 99, sid); // 库内版本 0，令牌 99
    await expect(isRefreshTokenValid(token)).resolves.toBe(false);
  });

  test('设备会话已吊销的 refresh → false（sid 闸，单设备下线即时生效）', async () => {
    const user = await makeActiveUser();
    const sid = `sid-${String(user._id)}`;
    await makeSession(user._id, sid);
    await UserSession.updateOne({ sid }, { status: 'revoked', revokedAt: new Date() });
    const token = generateRefreshToken(String(user._id), 0, sid);
    await expect(isRefreshTokenValid(token)).resolves.toBe(false);
  });
});
