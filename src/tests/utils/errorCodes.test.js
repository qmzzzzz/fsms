/**
 * 错误码注册表与 ApiResponse.codeError 单测
 *
 * 核心断言：
 * 1. 注册表完整性：每个码有合法 status 与非空 message（validateRegistry 返回空）
 * 2. codeError 响应形状：errorCode 抵达 errors.errorCode（前端契约），message/status 取自注册表
 * 3. 未注册码：日志告警 + 兜底 400，不抛错
 * 4. 快捷方法透传 errors——回归锁定 FULL_RANGE_FORBIDDEN 死码 bug
 *    （forbidden 此前忽略第三参，前端映射从未收到过码）
 */

const { ERROR_CODES, validateRegistry } = require('../../utils/errorCodes');
const ApiResponse = require('../../utils/apiResponse');

// mock logger：断言告警调用且不产生真实 IO
jest.mock('../../utils/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

const logger = require('../../utils/logger');

const mockRes = () => {
  const res = {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
  return res;
};

describe('errorCodes 注册表', () => {
  test('注册表完整性：status 合法且 message 非空', () => {
    // 原为 toBeGreaterThanOrEqual(19)：注册表实际有 194 个码，删到只剩 19 个
    // 也照样绿——弱阈值对「注册表被大规模删空」这种退化毫无约束力。
    // 改为断言与前端映射表逐码对齐（见下方 describe），此处锁定下界防输入笔误。
    expect(Object.keys(ERROR_CODES).length).toBeGreaterThan(150);
    expect(validateRegistry()).toEqual([]);
  });

  test('关键防枚举路径使用统一凭证码（M-5）：三种账户状态真实登录返回同一码', async () => {
    // M-5 口径（2026-09-15 收紧后对齐）：登录/凭据校验失败一律返回
    // AUTH_INVALID_CREDENTIALS。注册表中的 ACCOUNT_DISABLED/LOCKED 等码
    // 仅供管理端操作与前端结构化错误映射使用。
    const forbiddenCodes = ['AUTH_ACCOUNT_INACTIVE', 'AUTH_ACCOUNT_LOCKED'];
    forbiddenCodes.forEach((c) => expect(ERROR_CODES[c]).toBeUndefined());
    // 统一凭证码必须存在
    expect(ERROR_CODES.AUTH_INVALID_CREDENTIALS).toBeDefined();

    // 【本轮改造：源码 grep → 真实登录行为】
    // 原断言只 grep authService.js 源码里没有 `errorCodes.ACCOUNT_DISABLED` 之类的
    // 字面量。它拦不住真正的回归：只要换一种写法返回区分性码
    //（例如 `throw new AppError(ERROR_CODES[...])`、变量拼接、在 controller 层
    // 覆盖 response），源码 grep 依然全绿，而外部响应已经变成枚举预言机。
    // 现在真跑 createApp() + supertest，对三种账户状态各登录一次，
    // 断言响应**逐字段一致**（status / errorCode / message）。
    const mongoose = require('mongoose');
    const request = require('supertest');
    const { randomPassword } = require('../helpers/buildLoginEnvelope');

    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    const User = require('../../models/User');
    require('../../models/TokenBlacklist');

    const stamp = `ec${Date.now().toString(36)}`;
    const PASSWORD = randomPassword();
    let app;
    try {
      const { createApp } = require('../../app');
      app = createApp();

      // 三种「不应泄露账户状态」的失败态：
      //   ghost  = 用户根本不存在
      //   inactive = 账户被禁用
      //   locked   = 账户处于临时锁定窗口内
      await User.create([
        { username: `${stamp}inactive`, email: `${stamp}inactive@example.com`, password: PASSWORD, status: 'inactive' },
        { username: `${stamp}locked`, email: `${stamp}locked@example.com`, password: PASSWORD, lockUntil: new Date(Date.now() + 10 * 60 * 1000) },
      ]);

      const login = (username, password) =>
        request(app).post('/api/auth/login').send({ username, password });

      const ghost = await login(`${stamp}ghost`, PASSWORD);
      const inactive = await login(`${stamp}inactive`, PASSWORD);
      const locked = await login(`${stamp}locked`, PASSWORD);

      // 三种状态必须返回**同一个** 401 + AUTH_INVALID_CREDENTIALS + 同一文案
      for (const r of [ghost, inactive, locked]) {
        expect(r.status).toBe(401);
        expect(r.body.errors?.errorCode).toBe('AUTH_INVALID_CREDENTIALS');
        expect(r.body.message).toBe(ERROR_CODES.AUTH_INVALID_CREDENTIALS.message);
      }
      // 逐字段一致（防「码相同但文案/状态不同」的次级枚举面）
      expect(inactive.body).toEqual(ghost.body);
      expect(locked.body).toEqual(ghost.body);
      expect(inactive.status).toBe(ghost.status);
      expect(locked.status).toBe(ghost.status);
    } finally {
      await User.deleteMany({ username: new RegExp(`^${stamp}`) }).catch(() => {});
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    }
  });

  test('状态码均为 4xx/5xx 错误区间', () => {
    Object.values(ERROR_CODES).forEach((def) => {
      expect(def.status).toBeGreaterThanOrEqual(400);
      expect(def.status).toBeLessThanOrEqual(599);
    });
  });

  test('超管不可变约束码已注册（前端 i18n 依赖这批码翻译）', () => {
    const required = [
      'CANNOT_DELETE_SELF',
      'CANNOT_DELETE_SUPER_ADMIN',
      'CANNOT_DISABLE_SUPER_ADMIN',
      'CANNOT_LOCK_SUPER_ADMIN',
      'CANNOT_RESET_MFA_SUPER_ADMIN',
      'CANNOT_GRANT_SUPER_ADMIN_ON_CREATE',
      'SUPER_ADMIN_ROLE_NOT_DETACHABLE',
      'SUPER_ADMIN_ROLE_NOT_GRANTABLE',
      'SUPER_ADMIN_ROLE_PERMISSIONS_LOCKED',
      'SUPER_ADMIN_ROLE_NOT_CLONABLE',
    ];
    // jest 的 expect 不支持第二个自定义消息参数（那是 vitest 的能力），
    // 故用「缺失码列表」整体比对，失败时 diff 直接给出缺哪些码
    const missing = required.filter((code) => !ERROR_CODES[code]);
    expect(missing).toEqual([]);
    // 删除自身是客户端参数问题（400），其余均为权限约束（403）
    expect(ERROR_CODES.CANNOT_DELETE_SELF.status).toBe(400);
    required
      .filter((c) => c !== 'CANNOT_DELETE_SELF')
      .forEach((code) => expect(ERROR_CODES[code].status).toBe(403));
  });
});

describe('ApiResponse.codeError', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('errorCode 抵达 errors.errorCode，message/status 取自注册表', () => {
    const res = mockRes();
    ApiResponse.codeError(res, 'MFA_CODE_INVALID');
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({
      success: false,
      message: '两步验证码错误',
      errors: { errorCode: 'MFA_CODE_INVALID' },
    });
  });

  test('params 合并进 errors（供前端动态文案使用）', () => {
    const res = mockRes();
    ApiResponse.codeError(res, 'AUTH_INVALID_CREDENTIALS', { params: { retry: 3 } });
    expect(res.body.errors).toEqual({
      errorCode: 'AUTH_INVALID_CREDENTIALS',
      retry: 3,
    });
  });

  test('未注册码：不抛错，日志告警，兜底 400', () => {
    const res = mockRes();
    expect(() => ApiResponse.codeError(res, 'NOT_A_REAL_CODE')).not.toThrow();
    expect(logger.error).toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body.errors.errorCode).toBe('NOT_A_REAL_CODE');
    expect(res.body.message).toBe('操作失败');
  });

  test('options 覆盖注册表的 message 与 statusCode（动态文案场景）', () => {
    const res = mockRes();
    ApiResponse.codeError(res, 'AUTH_INVALID_CREDENTIALS', {
      message: '自定义文案',
      statusCode: 401,
    });
    expect(res.body.message).toBe('自定义文案');
    expect(res.statusCode).toBe(401);
  });
});

describe('快捷方法透传 errors（FULL_RANGE_FORBIDDEN 死码回归）', () => {
  test('forbidden 第三参抵达 errors——修复前被签名丢弃', () => {
    const res = mockRes();
    ApiResponse.forbidden(res, '权限不足说明', {
      errorCode: 'FULL_RANGE_FORBIDDEN',
      ip: '0.0.0.0/0',
    });
    expect(res.statusCode).toBe(403);
    expect(res.body.errors).toEqual({
      errorCode: 'FULL_RANGE_FORBIDDEN',
      ip: '0.0.0.0/0',
    });
  });

  test('unauthorized/notFound/serverError 同样透传', () => {
    const r1 = mockRes();
    ApiResponse.unauthorized(r1, '未授权', { errorCode: 'X1' });
    expect(r1.body.errors.errorCode).toBe('X1');

    const r2 = mockRes();
    ApiResponse.notFound(r2, '不存在', { errorCode: 'X2' });
    expect(r2.body.errors.errorCode).toBe('X2');

    const r3 = mockRes();
    ApiResponse.serverError(r3, '内部错误', { errorCode: 'X3' });
    expect(r3.body.errors.errorCode).toBe('X3');
  });

  test('既有二参调用不受影响（errors 为 null）', () => {
    const res = mockRes();
    ApiResponse.forbidden(res, '您没有执行此操作的权限');
    expect(res.statusCode).toBe(403);
    expect(res.body.errors).toBeNull();
  });
});

/**
 * 前后端错误码契约（2026-09-18 新增）
 *
 * 为什么需要：后端 ERROR_CODES 是「码 → status + 中文文案」的单一事实来源，
 * 前端 web-admin/src/utils/api.js 的 ERROR_CODE_I18N_MAP 是它的**手工镜像**
 * （码 → i18n key），两处相隔两个包、无构建期约束。历史事实：两者当前恰好
 * 194 码对齐（本次实测），但此前**没有任何测试守护**这个对齐——后端新增一个码
 * 而前端漏加映射时，用户看到的是未翻译的原始 message（或英文键名），
 * 却不会有任何门禁转红。本守卫把「漏加映射」变成红灯。
 *
 * 反向也查：前端映射里出现后端注册表没有的码（拼写错误/后端已删码），
 * 该映射永不命中，属死配置。
 */
describe('前后端错误码契约（防漂移）', () => {
  const readFrontendMap = () => {
    const p = require('path').join(__dirname, '../../../web-admin/src/utils/api.js');
    const src = require('fs').readFileSync(p, 'utf8');
    const start = src.indexOf('const ERROR_CODE_I18N_MAP = {');
    expect(start).toBeGreaterThan(-1); // 映射表被重命名/删除即红灯
    // 终止符是按行首 `}` 定位的，不是 indexOf('};')：映射表最后一个条目之后
    // 是裸 `}`（无分号），用 '};' 会得到 -1、block 变成空串、三条断言全部假绿。
    const rest = src.slice(start);
    const endMatch = rest.match(/^\}/m);
    expect(endMatch).not.toBeNull();
    const end = start + endMatch.index;
    expect(end).toBeGreaterThan(start);
    const block = src.slice(start, end);
    const codes = new Set();
    for (const m of block.matchAll(/^\s*([A-Z][A-Z0-9_]+)\s*:/gm)) codes.add(m[1]);
    return codes;
  };

  test('后端每个错误码都在前端 i18n 映射表中（漏加映射 → 用户看到未翻译文案）', () => {
    const fe = readFrontendMap();
    const missing = Object.keys(ERROR_CODES).filter((c) => !fe.has(c));
    expect(missing).toEqual([]);
  });

  test('前端映射表不含后端未注册的码（死配置/拼写错误）', () => {
    const fe = readFrontendMap();
    const extra = [...fe].filter((c) => !ERROR_CODES[c]);
    expect(extra).toEqual([]);
  });

  test('契约非空校验（防止两侧同时被清空而上述两条恒真）', () => {
    // 两个「差集为空」断言在两侧都为空的极端情形下都会通过：
    // 显式钉住规模下界，使「映射表被整体删除」必然转红。
    const fe = readFrontendMap();
    expect(fe.size).toBeGreaterThan(150);
    expect(Object.keys(ERROR_CODES).length).toBeGreaterThan(150);
  });
});

/**
 * validateRegistry 的「检测能力」测试（2026-09-18）
 *
 * 为什么需要：validateRegistry 是错误码注册表的自检函数，此前只有一条
 * `expect(validateRegistry()).toEqual([])` 断言「当前注册表干净」——但从未验证
 * 它**能报出脏数据**。若有人把 `def.status < 400` 改成恒 false，或删掉 message
 * 分支，该断言依然全绿：自检函数退化成「永远返回空数组」也不会被发现。
 * 这里向真实注册表临时注入非法条目（对象未冻结，可写），断言它逐条报出，
 * 再在 finally 中删除——不改源码即可驱动两个上报分支。
 */
describe('validateRegistry 检测能力（自检函数必须能报出非法条目）', () => {
  // 注入 → 运行 → 无条件删除（断言失败也走 finally，不污染后续用例）
  const withTempCode = (code, def, fn) => {
    ERROR_CODES[code] = def;
    try {
      return fn(validateRegistry());
    } finally {
      delete ERROR_CODES[code];
    }
  };

  test('status 非法（越界 / 非整数 / 非 number）→ 逐条报「status 非法」且值原样回显', () => {
    const cases = [
      [200, '200'],
      [399, '399'],
      [600, '600'],
      [700, '700'],
      ['500', '500'],
      [undefined, 'undefined'],
      [null, 'null'],
      [Number.NaN, 'NaN'],
      // 非整数：typeof 为 number 且落在区间内，但 Express res.status() 会抛 TypeError
      [400.5, '400.5'],
      [500.0001, '500.0001'],
      [Infinity, 'Infinity'],
      [-Infinity, '-Infinity'],
    ];
    for (const [status, shown] of cases) {
      withTempCode('__TMP_STATUS', { status, message: '临时' }, (problems) => {
        expect(problems).toEqual([`__TMP_STATUS: status 非法（${shown}）`]);
      });
    }
  });

  test('message 缺失 / 空串 / 纯空白 / 非 string → 报「message 缺失」（非字符串不得触发 .trim() 崩溃）', () => {
    const cases = [undefined, '', '   ', 123, null, {}, []];
    for (const message of cases) {
      withTempCode('__TMP_MESSAGE', { status: 400, message }, (problems) => {
        expect(problems).toEqual(['__TMP_MESSAGE: message 缺失']);
      });
    }
  });

  test('status 与 message 同时非法 → 两条都报（不短路）', () => {
    withTempCode('__TMP_BOTH', { status: 200, message: '' }, (problems) => {
      expect(problems).toEqual(['__TMP_BOTH: status 非法（200）', '__TMP_BOTH: message 缺失']);
    });
  });

  test('对照组：注入合法条目零问题（证明上面报的是「非法」而不是「有注入」）', () => {
    withTempCode('__TMP_OK', { status: 418, message: 'I am a teapot' }, (problems) => {
      expect(problems).toEqual([]);
    });
  });

  test('边界值恰好合法：400 与 599 通过，非空 message 通过', () => {
    withTempCode('__TMP_EDGE', { status: 400, message: 'x' }, (problems) => {
      expect(problems).toEqual([]);
    });
    withTempCode('__TMP_EDGE', { status: 599, message: 'x' }, (problems) => {
      expect(problems).toEqual([]);
    });
  });

  test('用例自身不污染注册表：临时条目已全部删除，真实注册表仍为零问题', () => {
    expect(Object.keys(ERROR_CODES).filter((c) => c.startsWith('__TMP_'))).toEqual([]);
    expect(validateRegistry()).toEqual([]);
    expect(Object.keys(ERROR_CODES).length).toBeGreaterThan(150);
  });
});
