/**
 * access 与 refresh 令牌的用途分离
 *
 * 背景：两类令牌原本只靠两把签名密钥区分——access 载荷里没有 type 字段。
 * config 侧只分别校验两把密钥的强度，不校验它们是否相同，于是
 * 「JWT_SECRET 与 JWT_REFRESH_SECRET 配成同一个值」这一常见省事做法会让二者完全等价：
 * 7 天有效期的 refresh 令牌可直接当 Bearer access 令牌调用全部 API（它同样带
 * userId / tokenVersion / sid），"access 短有效期 + 频繁换发"这条访问窗口收敛机制整体失效。
 *
 * 两道判据各自成立（不同层、不同失效方式）：
 *   1) config/validate.collectSecretErrors —— 两把密钥相同即致命配置错误（部署期拦）
 *   2) middleware/auth.assertTokenPurpose —— type 存在且非 'access' 即拒（运行期拦）
 *
 * 兼容性是这里刻意保留的：历史 access 令牌没有 type 字段，判据只在字段存在时生效，
 * 因此这次加固不会让已签发令牌集体失效（用例里对应"无 type 的旧令牌仍放行到下一步"）。
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const config = require('../../config');
const { authenticate } = require('../../middleware/auth');
const tokenService = require('../../services/tokenService');
const { collectSecretErrors } = require('../../config/validate');

const strong = () => crypto.randomBytes(32).toString('base64');

const driveAuthenticate = async (token) => {
  const req = {
    headers: token ? { authorization: `Bearer ${token}` } : {},
    ip: '203.0.113.7',
    method: 'GET',
    originalUrl: '/api/anything',
    app: { get: () => undefined },
  };
  const res = {
    statusCode: null,
    payload: null,
    status(c) {
      this.statusCode = c;
      return this;
    },
    json(b) {
      this.payload = b;
      return this;
    },
  };
  const next = jest.fn();
  await authenticate(req, res, next);
  return {
    passed: next.mock.calls.length === 1,
    status: res.statusCode,
    code: res.payload?.errors?.errorCode,
  };
};

describe('配置层：两把 JWT 密钥不得相同', () => {
  const saved = {};
  const KEYS = ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'AES_SECRET_KEY', 'HMAC_SECRET'];

  beforeEach(() => {
    for (const k of KEYS) {
      saved[k] = process.env[k];
      process.env[k] = strong();
    }
  });
  afterEach(() => {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  test('四把密钥各自独立时不报密钥类错误（对照，防"总是报错"骗绿）', () => {
    const errors = [];
    collectSecretErrors(errors);
    expect(errors).toEqual([]);
  });

  test('JWT_SECRET 与 JWT_REFRESH_SECRET 相同 ⇒ 必须报错且指明原因', () => {
    const same = strong();
    process.env.JWT_SECRET = same;
    process.env.JWT_REFRESH_SECRET = same;
    const errors = [];
    collectSecretErrors(errors);
    expect(errors.filter((e) => /JWT_REFRESH_SECRET 与 JWT_SECRET|不得相同/.test(e))).toHaveLength(
      1
    );
    // 强度判据本身仍要通过：这条新增判据不得把"两个相同的强随机值"误判成弱密钥
    expect(errors.some((e) => /至少 32 字符/.test(e))).toBe(false);
  });

  test('一侧为空时不报"相同"（空值由强度判据负责，两条款不重叠）', () => {
    process.env.JWT_SECRET = '';
    process.env.JWT_REFRESH_SECRET = '';
    const errors = [];
    collectSecretErrors(errors);
    expect(errors.filter((e) => /不得相同/.test(e))).toEqual([]);
    // 两条强度判据各自成立（'JWT_REFRESH_SECRET' 里不含 'JWT_SECRET' 子串，
    // 故按报错文案的共同片段计数，而不是按键名子串计数）。
    // AES/HMAC 在本用例里仍是强随机值 ⇒ 只有 JWT 两条款报错。
    expect(errors.filter((e) => /至少 32 字符/.test(e))).toHaveLength(2);
  });
});

describe('运行层：refresh 令牌不得当 access 用', () => {
  const userId = new mongoose.Types.ObjectId().toString();

  beforeAll(async () => {
    require('../../models/User'); // authenticate 会按 userId 反查账户，模型必须先注册
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
  });

  test('密钥相同（错误拓扑）下 refresh 令牌被拒，而 access 令牌通过用途校验', async () => {
    // 刻意把两把密钥设成同一个值：这正是被加固的那个部署形态。
    // 若不做这一步，refresh 令牌在验签阶段就失败，测到的是"密钥不同"而非"用途校验"。
    const savedSecret = config.jwt.secret;
    config.jwt.secret = config.jwt.refreshSecret;
    try {
      const refresh = tokenService.generateRefreshToken(userId, 0, null);
      // 前提自证：这个令牌确实能被 access 侧的密钥验出来，且带 type=refresh
      expect(jwt.verify(refresh, config.jwt.secret, { algorithms: ['HS256'] }).type).toBe(
        'refresh'
      );
      expect(await driveAuthenticate(refresh)).toEqual({
        passed: false,
        status: 401,
        code: 'AUTH_TOKEN_INVALID',
      });

      const access = tokenService.generateToken(userId, 'zzpurpose', 'p@example.com', [], '张', 0);
      // 对照：同一拓扑下的 access 令牌不因用途校验被拒。
      // 这里预期停在 USER_NOT_FOUND_OR_DELETED（用户不存在）——
      // 说明它已经走过了用途校验，进到账户校验那一格。
      const r = await driveAuthenticate(access);
      expect({ passed: r.passed, code: r.code }).toEqual({
        passed: false,
        code: 'USER_NOT_FOUND_OR_DELETED',
      });
    } finally {
      config.jwt.secret = savedSecret;
    }
  });

  test('新签发的 access 令牌确实携带 type=access（否则上面的对照是空的）', async () => {
    const access = tokenService.generateToken(userId, 'zzpurpose2', 'p2@example.com', [], '李', 0);
    expect(jwt.decode(access).type).toBe('access');
  });

  test('历史 access 令牌没有 type 字段仍被接受（加固不得让存量会话集体失效）', async () => {
    const legacy = jwt.sign(
      { userId, username: 'zzlegacy', tokenVersion: 0, jti: 'legacy-jti' },
      config.jwt.secret,
      { expiresIn: '24h' }
    );
    const r = await driveAuthenticate(legacy);
    expect(r.code).toBe('USER_NOT_FOUND_OR_DELETED'); // 不是 AUTH_TOKEN_INVALID
  });
});
