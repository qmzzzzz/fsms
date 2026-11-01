/**
 * 限流器自定义 handler / 键生成器的选项级用例。
 *
 * express-rate-limit 的 handler 只在真正触顶返回 429 时执行；既有套件都跑在
 * "未触顶"路径上，静态面 / 预检 / 头像读取（用户）三个自定义 handler 从未被计数
 * （全量覆盖率 functions 93.33% < 门槛 97%）。这里在模块加载期捕获 rateLimit(options)，
 * 直接驱动 handler 与 keyGenerator，不发洪水请求——预检桶 12000 次 OPTIONS 既慢又会
 * 污染共享桶。
 */
jest.mock('express-rate-limit', () => {
  const real = jest.requireActual('express-rate-limit');
  const captured = [];
  const rateLimit = (options) => {
    captured.push(options);
    return (req, res, next) => next();
  };
  rateLimit.captured = captured;
  // 被测模块用的是 `const rateLimit = require("express-rate-limit")` 直接调用，
  // 故替身本体必须是函数；ipKeyGenerator 等真实导出挂在函数上（键生成器用例要验的是
  // 「限流器自己的键规则」，把它换成空壳等于在测替身）。
  rateLimit.ipKeyGenerator = real.ipKeyGenerator;
  rateLimit.default = rateLimit;
  rateLimit.MemoryStore = real.MemoryStore;
  return rateLimit;
});

jest.mock('../../services/rateLimitEscalation', () => ({
  noteRateLimitHit: () => {
    throw new Error('升级通道不可用');
  },
}));

const rl = require('../../middleware/rateLimit');
const { captured } = require('express-rate-limit');
const logger = require('../../utils/logger');

const mockRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn((body) => {
    res.body = body;
    return res;
  });
  return res;
};

const callHandler = (options, req) => {
  const res = mockRes();
  const next = jest.fn();
  options.handler(req, res, next);
  return { res, next };
};

const safeKey = (options, req) => {
  try {
    return options.keyGenerator ? options.keyGenerator(req) : undefined;
  } catch (e) {
    return undefined;
  }
};

const findOptions = (pred) => {
  const hit = captured.find(pred);
  if (!hit) throw new Error('未捕获到匹配的限流器选项：' + captured.length);
  return hit;
};

const REQ = { method: 'GET', path: '/x', headers: {}, socket: { remoteAddress: '127.0.0.1' } };
const IP_REQ = { headers: {}, socket: { remoteAddress: '1.2.3.4' } };

describe('限流器 handler 与键生成器（选项级）', () => {
  test('加载期确实捕获到全部限流器选项（前提自证）', () => {
    expect(captured.length).toBeGreaterThanOrEqual(10);
  });

  test('静态面 handler：429 + 专用文案，且不接升级信号', () => {
    const options = findOptions(
      (o) => o.message && o.message.message === '静态资源请求过于频繁，请稍后再试'
    );
    const { res, next } = callHandler(options, REQ);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.body).toEqual({ success: false, message: '静态资源请求过于频繁，请稍后再试' });
  });

  test('预检桶 handler：429 + 专用文案', () => {
    const options = findOptions((o) => o.max === rl.PREFLIGHT_MAX_REQUESTS && !o.message);
    const { res } = callHandler(options, { ...REQ, method: 'OPTIONS' });
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.body).toEqual({ success: false, message: '预检请求过于频繁，请稍后再试' });
  });

  test('头像读取（用户）handler：带与不带 userId 都回 429', () => {
    const options = findOptions((o) =>
      String(safeKey(o, { user: { userId: 'u1' } })).startsWith('avatar-user:')
    );
    const withUser = callHandler(options, { user: { userId: 'u7' } });
    expect(withUser.res.body).toEqual({ success: false, message: '头像加载过于频繁，请稍后再试' });
    const withoutUser = callHandler(options, { user: {} });
    expect(withoutUser.res.body.message).toBe('头像加载过于频繁，请稍后再试');
  });

  test('账号维度 handler：带与不带 userId 都回 429，缺 userId 时日志落 "-" 而非 undefined', () => {
    // 谓词必须把 avatar-user: 那个桶排除掉：它也以 -user: 结尾，若用 /-user:u1$/ 匹配到它，
    // 本用例就会退化成把头像桶跑第二遍，而 makeUserBucketLimiter 的 handler 永不计数。
    const options = findOptions((o) => {
      const key = safeKey(o, { user: { userId: 'u1' } });
      return typeof key === 'string' && /^(pwd-change|reauth|report)-user:u1$/.test(key);
    });
    const spy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      const withUser = callHandler(options, {
        user: { userId: 'u7' },
        headers: {},
        socket: { remoteAddress: '1.2.3.4' },
      });
      expect(withUser.res.status).toHaveBeenCalledWith(429);
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('账号维度限流触发'),
        expect.objectContaining({ userId: 'u7' })
      );
      spy.mockClear();
      const withoutUser = callHandler(options, {
        user: undefined,
        headers: {},
        socket: { remoteAddress: '1.2.3.4' },
      });
      expect(withoutUser.res.status).toHaveBeenCalledWith(429);
      expect(spy.mock.calls[0][1].userId).toBe('-'); // 审计里出现 undefined 就再也追溯不到是谁
    } finally {
      spy.mockRestore();
    }
  });

  test('reauth 键生成器：有 userId 用账号键，无 userId 落 IP 键', () => {
    const options = findOptions((o) =>
      String(safeKey(o, { ...IP_REQ, user: { userId: 'u1' } })).startsWith('reauth:')
    );
    expect(safeKey(options, { ...IP_REQ, user: { userId: 'u1' } })).toContain('reauth:u1');
    expect(safeKey(options, { ...IP_REQ, user: undefined })).toContain('reauth-ip:');
    const { res } = callHandler(options, { user: { userId: 'u7' }, headers: {} });
    expect(res.body.message).toBe('二次验证尝试过于频繁，请稍后再试');
    // 未鉴权的客户端也会撞到这个桶：日志里的 userId 必须落 "-"，别写 undefined
    const anon = callHandler(options, { headers: {}, socket: { remoteAddress: '5.6.7.8' } });
    expect(anon.res.body.message).toBe('二次验证尝试过于频繁，请稍后再试');
  });

  test('注册桶 handler：升级信号抛错只告警不阻断 429', () => {
    const options = findOptions((o) => String(safeKey(o, IP_REQ)).startsWith('register:'));
    const { res } = callHandler(options, { headers: {}, socket: { remoteAddress: '10.0.0.1' } });
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.body.message).toBe('注册过于频繁，请稍后再试');
  });

  test('isAvatarReadRequest：非 GET/HEAD、无 originalUrl、非头像路径都为 false', () => {
    expect(rl.isAvatarReadRequest({ method: 'POST', originalUrl: '/api/avatars' })).toBe(false);
    expect(rl.isAvatarReadRequest({ method: 'GET' })).toBe(false);
    expect(rl.isAvatarReadRequest({ method: 'GET', originalUrl: '/api/users?page=1' })).toBe(false);
    expect(rl.isAvatarReadRequest({ method: 'GET', originalUrl: '/api/avatars?size=20' })).toBe(
      true
    );
    expect(rl.isAvatarReadRequest({ method: 'HEAD', originalUrl: '/api/avatars/abc' })).toBe(true);
  });
});
