/**
 * P2-3：JWT 多密钥重叠轮换（kid）
 *
 * 单密钥轮换会让全部 access/refresh 立即失效，轮换只能靠"全员重新登录"。
 * 本组用例钉住三条不变量：
 *   1) 未配置密钥集时与单密钥完全一致（不写 kid，仍用 JWT_SECRET 签发/验签）；
 *   2) 重叠期：新钥签发带 kid，旧钥（kid 明确）与轮换前无 kid 的历史令牌都仍可验签；
 *   3) 旧钥从集合移除后，带该 kid 的令牌必须被拒（未知 kid 不得回退当前钥）。
 * 第 3 条是"轮换真的发生了"的判据——若回退，泄露密钥的吊销窗口永远不会关闭。
 *
 * 实现上不能使用 jsonwebtoken 的 secretOrPublicKey 回调（库要求回调形态必须异步
 * verify，本仓验签点全是同步调用），因此选钥走 `decode(complete)` 读 header、
 * 签名校验仍由各调用点的 jwt.verify 完成；本文件用同一条选钥函数验证该语义。
 */

const crypto = require('crypto');

const ROTATION_ENV = [
  'JWT_SECRETS',
  'JWT_CURRENT_KID',
  'JWT_REFRESH_SECRETS',
  'JWT_REFRESH_CURRENT_KID',
];
const SAVED = Object.fromEntries(ROTATION_ENV.map((k) => [k, process.env[k]]));

const strong = () => crypto.randomBytes(32).toString('base64');

const resetRotationEnv = () => {
  for (const key of ROTATION_ENV) delete process.env[key];
};

const loadModules = () => {
  jest.resetModules();
  return {
    jwt: require('jsonwebtoken'),
    config: require('../../config'),
    jwtKeys: require('../../utils/jwtKeys'),
  };
};

const sign = (jwtLib, payload, key, kid) =>
  jwtLib.sign(payload, key, {
    algorithm: 'HS256',
    expiresIn: '5m',
    ...(kid ? { header: { kid, alg: 'HS256' } } : {}),
  });

const verify = (jwtLib, jwtKeys, token, kind = 'access') =>
  jwtLib.verify(token, jwtKeys.verifyKeyFor(token, kind), { algorithms: ['HS256'] });

afterAll(() => {
  for (const key of ROTATION_ENV) {
    if (SAVED[key] === undefined) delete process.env[key];
    else process.env[key] = SAVED[key];
  }
});

describe('单密钥部署：未配置密钥集时行为不变', () => {
  beforeEach(resetRotationEnv);

  test('签发不写 kid，仍用 config.jwt.secret；验签通过', () => {
    const { jwt, config, jwtKeys } = loadModules();
    const token = jwt.sign(
      { userId: 'u1', type: 'access' },
      jwtKeys.signKey('access'),
      jwtKeys.signOptions('access', '5m')
    );

    expect(jwtKeys.signKey('access')).toBe(config.jwt.secret);
    expect(jwt.decode(token, { complete: true }).header.kid).toBeUndefined();
    expect(verify(jwt, jwtKeys, token).userId).toBe('u1');
  });

  test('refresh 侧同样不写 kid，且用 refreshSecret', () => {
    const { jwt, config, jwtKeys } = loadModules();
    const token = jwt.sign(
      { userId: 'u1', type: 'refresh' },
      jwtKeys.signKey('refresh'),
      jwtKeys.signOptions('refresh', '5m')
    );

    expect(jwtKeys.signKey('refresh')).toBe(config.jwt.refreshSecret);
    expect(jwt.decode(token, { complete: true }).header.kid).toBeUndefined();
    expect(verify(jwt, jwtKeys, token, 'refresh').type).toBe('refresh');
  });
});

describe('重叠轮换：新旧密钥并存期', () => {
  let K1;
  let K2;
  let R1;
  let R2;

  beforeEach(() => {
    resetRotationEnv();
    K1 = strong();
    K2 = strong();
    R1 = strong();
    R2 = strong();
    process.env.JWT_SECRETS = JSON.stringify({ k1: K1, k2: K2 });
    process.env.JWT_CURRENT_KID = 'k2';
    process.env.JWT_REFRESH_SECRETS = JSON.stringify({ r1: R1, r2: R2 });
    process.env.JWT_REFRESH_CURRENT_KID = 'r2';
  });

  test('新签发的令牌带当前 kid，并用当前钥验签', () => {
    const { jwt, jwtKeys } = loadModules();
    const token = jwt.sign(
      { userId: 'u1', type: 'access' },
      jwtKeys.signKey('access'),
      jwtKeys.signOptions('access', '5m')
    );

    const header = jwt.decode(token, { complete: true }).header;
    expect(header.kid).toBe('k2');
    expect(jwtKeys.verifyKeyFor(token, 'access')).toBe(K2);
    expect(verify(jwt, jwtKeys, token).userId).toBe('u1');
  });

  test('旧钥签发的令牌（kid=k1）在重叠期仍可验签', () => {
    const { jwt, jwtKeys } = loadModules();
    const oldToken = sign(jwt, { userId: 'u2', type: 'access' }, K1, 'k1');

    expect(jwtKeys.verifyKeyFor(oldToken, 'access')).toBe(K1);
    expect(verify(jwt, jwtKeys, oldToken).userId).toBe('u2');
  });

  test('轮换前无 kid 的历史令牌回退 JWT_SECRET，不因轮换被踢下线', () => {
    const { jwt, config, jwtKeys } = loadModules();
    const legacyToken = sign(jwt, { userId: 'u3', type: 'access' }, config.jwt.secret);

    expect(jwtKeys.verifyKeyFor(legacyToken, 'access')).toBe(config.jwt.secret);
    expect(verify(jwt, jwtKeys, legacyToken).userId).toBe('u3');
  });

  test('原型属性名当 kid 不得冒充有效期密钥（toString/constructor 一律未知）', () => {
    const { jwt, jwtKeys } = loadModules();
    for (const kid of ['toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      expect(jwtKeys.keyForHeader('access', { kid })).toBeNull();
      const forged = sign(jwt, { userId: 'u10', type: 'access' }, strong(), kid);
      expect(() => jwtKeys.verifyKeyFor(forged, 'access')).toThrow(/未知的 JWT key id/);
    }
  });

  test('单密钥为空（密钥集部署下清空 legacy）⇒ 无 kid 令牌一律被拒：轮换收尾唯一的吊销开关', () => {
    const { jwt } = loadModules();
    const legacyToken = sign(
      jwt,
      { userId: 'u11' },
      'dev-jwt-secret-key-at-least-32-chars-long!!!'
    );
    const emptyJwt = {
      secret: '',
      refreshSecret: '',
      secrets: {},
      refreshSecrets: {},
      currentKid: '',
      refreshCurrentKid: '',
    };

    jest.doMock('../../config', () => ({ jwt: emptyJwt }));
    let jwtKeys;
    jest.isolateModules(() => {
      jwtKeys = require('../../utils/jwtKeys');
    });
    jest.dontMock('../../config');

    expect(jwtKeys.keyForHeader('access', null)).toBeNull();
    expect(jwtKeys.keyForHeader('refresh', null)).toBeNull();
    expect(() => jwtKeys.verifyKeyFor(legacyToken, 'access')).toThrow(/未知的 JWT key id/);
  });

  test('未知 kid 显式拒绝，不回退当前钥', () => {
    const { jwt, jwtKeys } = loadModules();
    const forged = sign(jwt, { userId: 'u4', type: 'access' }, strong(), 'k9');

    expect(() => jwtKeys.verifyKeyFor(forged, 'access')).toThrow(/未知的 JWT key id/);
    expect(() => jwtKeys.verifyKeyFor(forged, 'access')).toThrow(
      expect.objectContaining({ code: 'JWT_UNKNOWN_KID' })
    );
  });

  test('旧钥移出密钥集后，带该 kid 的令牌被拒（轮换收尾真的生效）', () => {
    const { jwt } = loadModules();
    const oldToken = sign(jwt, { userId: 'u5', type: 'access' }, K1, 'k1');

    process.env.JWT_SECRETS = JSON.stringify({ k2: K2 });
    const next = loadModules();
    expect(() => next.jwtKeys.verifyKeyFor(oldToken, 'access')).toThrow(/未知的 JWT key id/);
    // 新钥签发的令牌不受影响
    const fresh = sign(next.jwt, { userId: 'u6', type: 'access' }, K2, 'k2');
    expect(verify(next.jwt, next.jwtKeys, fresh).userId).toBe('u6');
  });

  test('access / refresh 密钥域隔离：refresh 钥不能给 access 令牌验签', () => {
    const { jwt, jwtKeys } = loadModules();
    const refreshToken = sign(jwt, { userId: 'u7', type: 'refresh' }, R2, 'r2');

    expect(() => jwtKeys.verifyKeyFor(refreshToken, 'access')).toThrow(/未知的 JWT key id/);
    expect(verify(jwt, jwtKeys, refreshToken, 'refresh').type).toBe('refresh');
  });

  test('tokenService 实际签发路径携带 kid（不是只改了工具函数）', () => {
    const { jwt } = loadModules();
    const { generateToken, generateRefreshToken } = require('../../services/tokenService');
    const access = generateToken('507f1f77bcf86cd799439011', 'alice', 'a@example.com', ['USER']);
    const refresh = generateRefreshToken('507f1f77bcf86cd799439011');

    expect(jwt.decode(access, { complete: true }).header.kid).toBe('k2');
    expect(jwt.decode(refresh, { complete: true }).header.kid).toBe('r2');
    expect(jwt.verify(access, K2, { algorithms: ['HS256'] }).type).toBe('access');
    expect(jwt.verify(refresh, R2, { algorithms: ['HS256'] }).type).toBe('refresh');
  });
});

describe('签发 kid 快照（轮换留痕判据）', () => {
  beforeEach(resetRotationEnv);

  test('未配置密钥集：两侧均为 null（单钥模式的基线）', () => {
    const { jwtKeys } = loadModules();
    expect(jwtKeys.signingKids()).toEqual({ access: null, refresh: null });
  });

  test('返回实际生效的 kid；env 点了名但集合里没有的 kid 不算生效', () => {
    const K = strong();
    process.env.JWT_SECRETS = JSON.stringify({ k2: K });
    process.env.JWT_CURRENT_KID = 'k2';
    expect(loadModules().jwtKeys.signingKids()).toEqual({ access: 'k2', refresh: null });

    // 与 signKey 同源判据：签名回退单钥时，留痕也不能记成"切换到了 k9"
    process.env.JWT_CURRENT_KID = 'k9';
    const next = loadModules();
    expect(next.jwtKeys.signingKids()).toEqual({ access: null, refresh: null });
    expect(next.jwtKeys.signKey('access')).toBe(next.config.jwt.secret);
  });
});

describe('启动期校验：密钥集配置错误必须拒绝启动', () => {
  const { collectJwtRotationErrors } = require('../../config/jwtRotation');
  let K1;
  let K2;

  beforeEach(() => {
    resetRotationEnv();
    K1 = strong();
    K2 = strong();
  });

  const run = () => {
    const errors = [];
    collectJwtRotationErrors(errors);
    return errors;
  };

  test('合法配置不报错（对照，防"总是报错"骗绿）', () => {
    process.env.JWT_SECRETS = JSON.stringify({ k2: K2 });
    process.env.JWT_CURRENT_KID = 'k2';
    expect(run()).toEqual([]);
  });

  test('JWT_SECRETS 不是合法 JSON ⇒ 报错（不得静默退回单密钥）', () => {
    process.env.JWT_SECRETS = '{k2:not-json}';
    process.env.JWT_CURRENT_KID = 'k2';
    expect(run().some((e) => /JWT_SECRETS 必须是 JSON 对象/.test(e))).toBe(true);
  });

  test('密钥集已配置但未指定当前 kid ⇒ 报错', () => {
    process.env.JWT_SECRETS = JSON.stringify({ k1: K1, k2: K2 });
    expect(run().some((e) => /必须同时设置 JWT_CURRENT_KID/.test(e))).toBe(true);
  });

  test('当前 kid 不在密钥集中 ⇒ 报错', () => {
    process.env.JWT_SECRETS = JSON.stringify({ k1: K1 });
    process.env.JWT_CURRENT_KID = 'k2';
    expect(run().some((e) => /JWT_CURRENT_KID="k2" 不存在于 JWT_SECRETS/.test(e))).toBe(true);
  });

  test('集合中的弱密钥 ⇒ 报错并点名 kid', () => {
    process.env.JWT_SECRETS = JSON.stringify({ k2: 'short' });
    process.env.JWT_CURRENT_KID = 'k2';
    const errors = run();
    expect(errors.some((e) => /kid=k2/.test(e) && /至少 32 字符/.test(e))).toBe(true);
  });

  test('点了 kid 却没配密钥集 ⇒ 报错（否则轮换静默不生效，签发连 kid 都不写）', () => {
    process.env.JWT_CURRENT_KID = 'k9';
    expect(run().some((e) => /JWT_CURRENT_KID="k9" 已设置但 JWT_SECRETS 未配置/.test(e))).toBe(
      true
    );
  });

  test('CURRENT_KID 取原型属性名 ⇒ 报错并指出 kid 不存在', () => {
    process.env.JWT_SECRETS = JSON.stringify({ k2: K2 });
    process.env.JWT_CURRENT_KID = 'toString';
    expect(run().some((e) => /JWT_CURRENT_KID="toString" 不存在于 JWT_SECRETS/.test(e))).toBe(true);
  });

  test('access 与 refresh 出现同值密钥 ⇒ 报错', () => {
    const shared = strong();
    process.env.JWT_SECRETS = JSON.stringify({ k2: shared });
    process.env.JWT_CURRENT_KID = 'k2';
    process.env.JWT_REFRESH_SECRETS = JSON.stringify({ r2: shared });
    process.env.JWT_REFRESH_CURRENT_KID = 'r2';
    expect(run().some((e) => /同值密钥/.test(e))).toBe(true);
  });
});
