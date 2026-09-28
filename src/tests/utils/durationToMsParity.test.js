/**
 * ──────────────────────────────────────────────────────────────────────────
 * 被测对象：src/utils/cookie.js 的 durationToMs，以及它的两个消费面
 *           （setAuthCookies 的 cookie maxAge、sessionService.createSession 的 expiresAt）
 * 守护的不变式：**同一个时长配置值只能有一种解释**——令牌的 exp 由 jsonwebtoken
 *   依赖的 `ms` 解析，cookie maxAge 与会话行的 expiresAt 由本仓这段解析；两处口径
 *   一旦分叉，会话行就会比它绑定的 refresh 令牌早死（或反过来），而分叉的方向是
 *   **静默回落到 fallbackMs**，不报错。
 * 可证伪性：期望值一律由 `jwt.sign` + `jwt.decode` 现场反推（不是抄来的常数），
 *   因此任何一侧改口径都会红；变异实测 M1~M4 记录在
 *   deliverables/AGENT工作总账与待办-2026-09-21.md 的 F-176 条目
 * ──────────────────────────────────────────────────────────────────────────
 *
 * 【缺陷本体（F-176）】
 * 原实现的单位集只有 `ms|s|m|h|d|w|y`，而 `ms` 认的是长式 + 单复数 + 可带空格
 * （'2 weeks' / '12 hours' / '1 day' / '15minutes' / '1 h'）。少认一个单位不抛错，
 * 直接落到 fallbackMs（7 天）。实测分叉：
 *   '2 weeks' → 令牌 336h / 本函数 168h；'12 hours' → 12h / 168h；'1 day' → 24h / 168h。
 * 后果不是"配置不好看"：`sessionService.createSession` 的 TTL 与 refresh cookie 的
 * maxAge 都取自本函数，于是第 7～14 天每次刷新都吃 `DEVICE_SESSION_REVOKED`
 * ——fail-closed，方向不致命，但用户表现为"周期性被踢下线"。
 * 还有一处更隐蔽的：`ms` 的 year 取 **365.25 天**（儒略年），原实现写 365，
 * 于是 `'1y'` 两侧每年差 6 小时——紧凑写法也错，不是只有长式才错。
 *
 * 【为什么不能 `require('ms')` 收口成一份】
 * `ms` 是 jsonwebtoken 的传递依赖，不在本仓 package.json 里（任务约束：不新增依赖）。
 * 语法表因此必然存在两份，唯一能把"两份一致"变成事实的办法是让用例从权威一侧
 * （jwt 自己签出来的 exp）反推期望值——与 F-149/F-150 的"清单单一来源 + 漂移门禁"同一路子。
 *
 * 【刻意不做】数值入参（typeof number）本函数按毫秒、jsonwebtoken 按秒，这一条不对称
 * **没有改**：env 读出来的永远是字符串，仓内没有传数值的调用方；改动它是在为不存在的
 * 调用方重塑语义。已作为口径说明写进 durationToMs 的 JSDoc。
 */
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const config = require('../../config');
const { durationToMs, setAuthCookies, REFRESH_COOKIE_NAME } = require('../../utils/cookie');

/** 无法解析时必须走回退，用一个不可能出现的哨兵当 fallbackMs */
const FALLBACK = -123456;

/**
 * 从 jsonwebtoken 现场反推某个写法对应的毫秒数。
 * 返回 null 表示这一写法 jwt 自己就抛错（配置面不可能出现这种值，
 * 因此不构成静默分叉，用例据此改判"我们也必须拒绝"）。
 */
const jwtMsOf = (expr) => {
  try {
    const token = jwt.sign({ probe: 1 }, 'f176-secret', { expiresIn: expr });
    const decoded = jwt.decode(token);
    // exp 是秒级时间戳，iat 也是：差值就是 jwt 赋予这个写法的寿命（秒→毫秒）
    return (decoded.exp - decoded.iat) * 1000;
  } catch {
    return null;
  }
};

const FORMS = [
  // 紧凑式（本仓 .env / .env.example / README 用的就是这一族）
  '30s',
  '15m',
  '2h',
  '7d',
  '2w',
  '1y',
  '1.5d',
  // 纯数字串：jwt 的 timestamp 分支按毫秒处理，本函数的"省略单位"必须同口径
  '5000',
  // 长式 / 单复数 / 带空格 / 缩写：F-176 的分叉面
  '2 weeks',
  '12 hours',
  '1 day',
  '15minutes',
  '1 h',
  '2hrs',
  '3 secs',
  '1msec',
  '60 minutes',
  // 大小写混用：ms 的单位匹配是大小写不敏感的，'1M' 是 1 分钟而不是 1 个月
  '1M',
  '7D',
  // 负值：必须同向解析，不能落到 fallback（那会把"本该立即过期"读成 7 天，方向是放宽）
  '-1h',
];

describe('durationToMs 必须与 jsonwebtoken 的时长语法同口径（F-176）', () => {
  // ---------- 逐写法夹逼：期望值来自 jwt，不是抄来的常数 ----------

  test.each(FORMS)('%s：与 jsonwebtoken 解析结果一致', (form) => {
    const expected = jwtMsOf(form);
    const actual = durationToMs(form, FALLBACK);
    if (expected === null) {
      // jwt 自己抛错的写法，本函数也必须拒绝（返回 fallback），不能给一个数
      expect(actual).toBe(FALLBACK);
      return;
    }
    // jwt 的 exp 是秒级时间戳，亚秒写法（'1msec'）本来就取不到毫秒；
    // 1 秒容差是本命题的唯一可能精度，日/时级别的口径分叉（F-176 的量级）照样跑不掉
    expect(Math.abs(actual - expected)).toBeLessThan(1000);
  });

  test('前提自证：夹逼用的探针真的能区分口径（jwt 与"旧窄语法"在长式上必然不同值）', () => {
    // 这条不看被测函数，只证明上面的表不是空跑：'2 weeks' 的 jwt 值确实不等于 7 天
    expect(jwtMsOf('2 weeks')).toBe(14 * 24 * 60 * 60 * 1000);
    expect(jwtMsOf('2 weeks')).not.toBe(7 * 24 * 60 * 60 * 1000);
    expect(jwtMsOf('12 hours')).toBe(12 * 60 * 60 * 1000);
  });

  test("儒略年钉死：'1y' 是 365.25 天，写 365 每年差 6 小时", () => {
    expect(durationToMs('1y', FALLBACK)).toBe(365.25 * 24 * 60 * 60 * 1000);
    expect(durationToMs('1y', FALLBACK)).not.toBe(365 * 24 * 60 * 60 * 1000);
  });

  test('ms 不认的写法一律回落 fallback，且这些写法 jwt 自身也抛错（不存在静默分叉）', () => {
    for (const bad of ['abc', '1 month', '', '7 天', '10 seconds extra']) {
      expect([bad, jwtMsOf(bad)]).toEqual([bad, null]);
      expect(durationToMs(bad, FALLBACK)).toBe(FALLBACK);
    }
  });

  test('非字符串入参：数值按毫秒（既有语义，仓内无数值调用方）、其它类型走 fallback', () => {
    expect(durationToMs(60000, FALLBACK)).toBe(60000);
    expect(durationToMs(null, FALLBACK)).toBe(FALLBACK);
    expect(durationToMs(undefined, FALLBACK)).toBe(FALLBACK);
    expect(durationToMs({}, FALLBACK)).toBe(FALLBACK);
    expect(durationToMs(NaN, FALLBACK)).toBe(FALLBACK);
  });

  // ---------- 消费面 1：cookie maxAge 必须等于实际令牌寿命 ----------

  describe('setAuthCookies 下发的 maxAge 等于令牌自己的 exp', () => {
    const withRefreshExpire = (expr, fn) => {
      const prev = config.jwt.refreshExpire;
      config.jwt.refreshExpire = expr;
      return Promise.resolve()
        .then(fn)
        .finally(() => {
          config.jwt.refreshExpire = prev;
        });
    };

    const captureCookies = (accessToken, refreshToken) => {
      const jar = {};
      const res = {
        cookie(name, value, opts) {
          jar[name] = { value, opts };
          return this;
        },
      };
      setAuthCookies(res, accessToken, refreshToken);
      return jar;
    };

    test("长式配置（'2 weeks'）下 refresh cookie 的 maxAge 是 14 天而不是回退的 7 天", async () => {
      await withRefreshExpire('2 weeks', () => {
        const refreshToken = jwt.sign({ userId: 'u1' }, config.jwt.refreshSecret, {
          expiresIn: config.jwt.refreshExpire,
          algorithm: 'HS256',
        });
        const decoded = jwt.decode(refreshToken);
        const tokenLifetimeMs = (decoded.exp - decoded.iat) * 1000;
        const jar = captureCookies('access-probe', refreshToken);

        expect(jar[REFRESH_COOKIE_NAME]).toBeDefined();
        expect(jar[REFRESH_COOKIE_NAME].opts.maxAge).toBe(tokenLifetimeMs);
        // 缺陷本体的直接表现：分叉时这里会是 7 天
        expect(jar[REFRESH_COOKIE_NAME].opts.maxAge).not.toBe(7 * 24 * 60 * 60 * 1000);
      });
    });

    test('紧凑配置（7d）下的 maxAge 不受本次改动影响（与令牌寿命仍逐项相等）', async () => {
      await withRefreshExpire('7d', () => {
        const refreshToken = jwt.sign({ userId: 'u2' }, config.jwt.refreshSecret, {
          expiresIn: config.jwt.refreshExpire,
          algorithm: 'HS256',
        });
        const decoded = jwt.decode(refreshToken);
        const jar = captureCookies('access-probe', refreshToken);
        expect(jar[REFRESH_COOKIE_NAME].opts.maxAge).toBe((decoded.exp - decoded.iat) * 1000);
      });
    });
  });

  // ---------- 消费面 2：会话行的 expiresAt 与它绑定的 refresh 令牌同寿 ----------

  describe('sessionService.createSession 的 expiresAt 与 refresh 令牌同寿', () => {
    let UserSession;
    let sessionService;

    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      UserSession = require('../../models/UserSession');
      sessionService = require('../../services/sessionService');
    });

    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    });

    test("JWT_REFRESH_EXPIRE='2 weeks' 时会话行活 14 天（分叉时它只活 7 天）", async () => {
      const prev = config.jwt.refreshExpire;
      config.jwt.refreshExpire = '2 weeks';
      const sid = `f176_${Date.now().toString(36)}`;
      try {
        const refreshToken = jwt.sign({ userId: 'u3' }, config.jwt.refreshSecret, {
          expiresIn: config.jwt.refreshExpire,
          algorithm: 'HS256',
        });
        const tokenLifetimeMs =
          (jwt.decode(refreshToken).exp - jwt.decode(refreshToken).iat) * 1000;

        const { sid: createdSid } = await sessionService.createSession({
          userId: new mongoose.Types.ObjectId(),
          req: { ip: '127.0.0.1', get: () => 'jest-f176' },
          sid: sid,
        });
        const row = await UserSession.findOne({ sid: createdSid }).lean();
        expect(row).not.toBeNull();
        const sessionTtlMs = new Date(row.expiresAt) - new Date(row.createdAt);
        // 两侧都到毫秒级，但落库与签发之间允许极小漂移
        expect(Math.abs(sessionTtlMs - tokenLifetimeMs)).toBeLessThan(2000);
        expect(sessionTtlMs).not.toBeLessThan(13 * 24 * 60 * 60 * 1000);
      } finally {
        config.jwt.refreshExpire = prev;
        await UserSession.deleteMany({ sid }).catch(() => {});
      }
    });
  });
});
