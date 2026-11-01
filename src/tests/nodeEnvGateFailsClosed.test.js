/**
 * NODE_ENV 拼写不得决定生产硬闸是否生效
 *
 * 复现（修复前，两条命令只差 NODE_ENV 的字面量）：
 *   NODE_ENV=prod         JWT_SECRET=change-this-secret  → 静默启动，零校验
 *   NODE_ENV=production   JWT_SECRET=change-this-secret  → 8 条致命 + exit(1)
 * `change-this-secret` 是 WEAK_SECRETS 黑名单里的字面量，即"最该被拦下的密钥"。
 * 连带 isDocsEnabled 用同一种字面量比较，prod 下 API 文档还会**默认打开**。
 *
 * 判据设计成 fail-closed 而非"猜一个默认"：
 *   开发家族（development/dev/local/test/ci）可跳过；生产家族执行硬闸；**不认识的值也
 *   执行硬闸并额外报一条**；**未设置同样拒绝启动**（2026-10-30 收紧：缺失时无法区分
 *   "开发机裸跑"与"生产容器漏配"，按开发语义放行等于四类生产校验一起静默跳过）。
 *   猜错方向的代价必须是"启动不起来"，不是"生产以零校验启动"。
 *
 * 第三轮（2026-10-30，D1）：**staging/stage 从"可跳过"表里移出**，默认与 production 同判。
 * 原边界（ADR-005）只在"预发是隔离环境"这个前提成立时才对，而全仓只有 docker-compose
 * 强制它；同一条 NODE_ENV 取值曾同时关掉 9 类启动硬闸、把 /api-docs 默认打开、让会话
 * cookie 丢掉 Secure。放宽改为显式声明 FSMS_ALLOW_STAGING_LENIENT=true，且放宽的后果
 * 由启动日志逐条打印（否则与"一个变量关掉整张生产校验表"没有区别）。
 */

const WEAK_ONLY_ENV = {
  JWT_SECRET: 'change-this-secret',
  // 其余生产必填项一律缺席：让"是否被拦下"完全由 NODE_ENV 判据决定
};

const loadAndRun = (nodeEnv, extra = {}) => {
  jest.resetModules();
  process.env = { ...WEAK_ONLY_ENV, ...extra };
  if (nodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = nodeEnv;
  delete process.env.ENABLE_API_DOCS;

  const mod = require('../config/validate');
  const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
    throw new Error('process.exit called');
  });
  const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  return { mod, exitSpy, consoleSpy };
};

const stopsBoot = (nodeEnv, extra) => {
  const { mod, exitSpy, consoleSpy } = loadAndRun(nodeEnv, extra);
  try {
    let threw = false;
    try {
      mod.validateConfig();
    } catch (_) {
      threw = true;
    }
    const exited = exitSpy.mock.calls.length > 0;
    // "抛了异常"本身不构成"启动被闸停"：process.exit 被桩成抛错，所以任何无关的
    // TypeError 也会让 threw 为真（评审指出：只断言 threw 时，一次无害重构即可假绿）。
    // 因此要求两者同起同落，判据最终落在"是否真的调用过 process.exit"。
    expect({ threw, exited }).toEqual({ threw: exited, exited });
    return exited;
  } finally {
    exitSpy.mockRestore();
    consoleSpy.mockRestore();
  }
};

describe('NODE_ENV 归一：生产硬闸不再押在字面量拼写上', () => {
  const originalEnv = process.env;

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  // 对照组：既有语义必须一字不变
  test('production 仍被拦下（既有行为，回归保护）', () => {
    expect(stopsBoot('production')).toBe(true);
  });

  test.each([
    ['prod（部署里最常见的简写）', 'prod'],
    ['Production（大小写差异）', 'Production'],
    ['" production "（首尾空白）', ' production '],
    ['live', 'live'],
  ])('%s 必须与 production 同判据被拦下', (_label, value) => {
    expect(stopsBoot(value)).toBe(true);
  });

  test.each([
    ['development', 'development'],
    ['dev', 'dev'],
    ['local', 'local'],
    ['test', 'test'],
    ['ci', 'ci'],
  ])('%s 仍允许跳过生产校验（本地开发口径，判据未改）', (_label, value) => {
    expect(stopsBoot(value)).toBe(false);
  });

  test.each([
    ['staging（第三轮起：预发默认同生产）', 'staging'],
    ['stage', 'stage'],
  ])('%s 必须与 production 同判据被拦下', (_label, value) => {
    expect(stopsBoot(value)).toBe(true);
  });

  test('预发放宽必须显式声明，且跳过了什么、放宽了什么都要写进启动日志', () => {
    const { mod, exitSpy, consoleSpy } = loadAndRun('staging', {
      FSMS_ALLOW_STAGING_LENIENT: 'true',
    });
    const logger = require('../utils/logger');
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    try {
      mod.validateConfig();
      expect(exitSpy).not.toHaveBeenCalled();
      const text = warnSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(text).toContain('FSMS_ALLOW_STAGING_LENIENT'); // 声明本身
      expect(text).toContain('ALLOWED_HOSTS'); // 跳过了哪些硬闸
      expect(text).toContain('/api-docs'); // 同时生效的放宽项之一
      expect(text).toContain('Secure'); // 之二（cookie）
    } finally {
      warnSpy.mockRestore();
      exitSpy.mockRestore();
      consoleSpy.mockRestore();
    }
  });

  test('反向对照：宽松开关只在预发生效，production 下照旧拒绝启动', () => {
    expect(stopsBoot('production', { FSMS_ALLOW_STAGING_LENIENT: 'true' })).toBe(true);
  });

  // 「未设置」自 2026-10-30 起从上面那张表里移出（原断言 false，随实现收紧而失效）：
  // validate.js 现在把「NODE_ENV 缺失」直接判为拒绝启动，理由写在实现处——
  // 缺失时无法区分"开发机裸跑"与"生产容器漏配"，按开发语义放行等于弱密钥 /
  // Host / Redis / TLS 四类校验全部静默跳过。故裸跑入口必须显式写 development
  // （README 部署清单与 .env.example 均已同口径）。这条与下面 F-216 的「空串」
  // 一格互补：空串是"配了但没值"，未设置是"根本没配"，两者都 fail-closed。
  test('未设置（不是空串，而是键根本不存在）同样拒绝启动，不按开发语义放行', () => {
    expect(stopsBoot(undefined)).toBe(true);
  });

  test('无法识别的取值按生产处理，且错误文案点名 NODE_ENV（fail-closed 而非静默跳过）', () => {
    // reportConfigErrors 走 logger.error（L-05），不是 console.error——
    // 因此必须桩 logger 才能拿到文案。resetModules 之后两侧 require 命中同一实例。
    const { mod, exitSpy } = loadAndRun('prodution'); // 典型漏字母拼
    const logger = require('../utils/logger');
    const logSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(() => mod.validateConfig()).toThrow('process.exit called');
      const text = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(text).toContain('NODE_ENV');
      expect(text).toContain('prodution');
      // 同时仍报告真实的生产项，避免运维只看到"拼写不认识"却不知道还缺什么
      expect(text).toContain('JWT_SECRET');
    } finally {
      logSpy.mockRestore();
      consoleSpy.mockRestore();
      exitSpy.mockRestore();
    }
  });

  describe('F-216：配了但为空 ≠ 没配（`NODE_ENV=` 曾让整块生产硬闸跳过）', () => {
    // 上面那张对照表漏掉的正是这一格：'prodution' 一类拼错已被 fail-closed 兜住，
    // 而空串走的是 `value || 'development'` 的右半边 ⇒ 归一成 development ⇒
    // requiresProductionSemantics() 为 false ⇒ validateConfig() 第一行就 return，
    // 生产以零校验启动且一行日志都不打。触发方式在真实部署里极其常见：
    // compose 的 `environment:` 只写键名、Dockerfile 的 `ARG NODE_ENV=` 未传值、
    // 或 .env 里留了一行 `NODE_ENV=`。
    test.each([
      ['空串', ''],
      ['只有空格', '   '],
      ['制表符', '\t'],
    ])('%s 必须与 production 同判据被拦下', (_label, value) => {
      expect(stopsBoot(value)).toBe(true);
    });

    test('反向对照：未设置时归一值仍是 development，但启动闸不因此放行', () => {
      // 两件事必须分开钉：
      //   ① 归一函数（normalizeNodeEnv）对 undefined 仍返回 'development' —— 它只回答
      //      "这个值看起来像什么环境"，其他模块（logger/errorHandler/trust proxy）
      //      依赖这个结果，改成抛错或返回哨兵会波及一圈无关判据；
      //   ② 但 validateConfig 在归一**之前**就拦下"键不存在"这一格，不进入
      //      "开发家族 ⇒ 跳过生产校验"的分支。
      // 原用例（2026-10-30 前）断言 stopsBoot(undefined) === false，正是被 ② 推翻的那半。
      expect(stopsBoot(undefined)).toBe(true);
      const { mod, exitSpy, consoleSpy } = loadAndRun(undefined);
      const logger = require('../utils/logger');
      const logSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
      try {
        expect(mod.normalizeNodeEnv()).toBe('development');
        expect(mod.requiresProductionSemantics()).toBe(false);
        // 文案必须点名 NODE_ENV 与"未设置"，否则运维只会看到一条无头错误
        expect(() => mod.validateConfig()).toThrow('process.exit called');
        const text = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
        expect(text).toContain('NODE_ENV');
        expect(text).toContain('必须显式设置');
      } finally {
        logSpy.mockRestore();
        exitSpy.mockRestore();
        consoleSpy.mockRestore();
      }
    });

    test('空串被拦下时文案点名"未被识别"，而不是让整块校验凭空消失', () => {
      const { mod, exitSpy } = loadAndRun('');
      const logger = require('../utils/logger');
      const logSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      try {
        expect(() => mod.validateConfig()).toThrow('process.exit called');
        const text = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
        expect(text).toContain('NODE_ENV');
        expect(text).toContain('未被识别');
        expect(text).toContain('JWT_SECRET');
      } finally {
        logSpy.mockRestore();
        consoleSpy.mockRestore();
        exitSpy.mockRestore();
      }
    });

    test('normalizeNodeEnv 把空串留在"未识别"哨兵值本身（不是 development）', () => {
      const { mod, exitSpy, consoleSpy } = loadAndRun('');
      try {
        expect(mod.normalizeNodeEnv()).toBe('');
        expect(mod.isProductionLikeEnv()).toBe(false);
        expect(mod.requiresProductionSemantics()).toBe(true);
      } finally {
        exitSpy.mockRestore();
        consoleSpy.mockRestore();
      }
    });
  });

  describe('isDocsEnabled 用同一判据（修掉"闸被跳过而文档打开"的反向组合）', () => {
    const docsFor = (nodeEnv) => {
      const { mod, exitSpy, consoleSpy } = loadAndRun(nodeEnv);
      try {
        return mod.isDocsEnabled();
      } finally {
        exitSpy.mockRestore();
        consoleSpy.mockRestore();
      }
    };

    test.each(['production', 'prod', 'Production', 'live', 'prodution', 'staging', 'stage'])(
      '%s → 文档默认关闭',
      (value) => {
        expect(docsFor(value)).toBe(false);
      }
    );

    test.each(['development', 'dev', 'local', 'test', undefined])(
      '%s → 文档默认开启（本地开发口径，保持既有语义）',
      (value) => {
        expect(docsFor(value)).toBe(true);
      }
    );

    test('预发显式宽松时才默认开启（文档位与硬闸共用同一判据，不再各按一把尺）', () => {
      const { mod, exitSpy, consoleSpy } = loadAndRun('staging', {
        FSMS_ALLOW_STAGING_LENIENT: 'true',
      });
      try {
        expect(mod.isDocsEnabled()).toBe(true);
      } finally {
        exitSpy.mockRestore();
        consoleSpy.mockRestore();
      }
    });

    test('显式 ENABLE_API_DOCS 仍优先于环境判据', () => {
      const { mod, exitSpy, consoleSpy } = loadAndRun('production');
      try {
        process.env.ENABLE_API_DOCS = 'true';
        expect(mod.isDocsEnabled()).toBe(true);
        process.env.NODE_ENV = 'development';
        process.env.ENABLE_API_DOCS = 'false';
        expect(mod.isDocsEnabled()).toBe(false);
      } finally {
        exitSpy.mockRestore();
        consoleSpy.mockRestore();
      }
    });
  });

  test('导出的共用判据可被其他按环境分叉的模块复用（避免再各写字面量比较）', () => {
    const { mod, exitSpy, consoleSpy } = loadAndRun('prod');
    try {
      expect(typeof mod.isProductionLikeEnv).toBe('function');
      expect(mod.isProductionLikeEnv()).toBe(true);
      expect(mod.normalizeNodeEnv()).toBe('prod');
      process.env.NODE_ENV = ' PRODUCTION ';
      expect(mod.isProductionLikeEnv()).toBe(true);
      process.env.NODE_ENV = 'staging';
      expect(mod.isProductionLikeEnv()).toBe(false);
    } finally {
      exitSpy.mockRestore();
      consoleSpy.mockRestore();
    }
  });

  describe('同一拼写不得让会话 cookie 的 Secure 位静默关闭（真实后果面）', () => {
    // 走 setAuthCookies 这个真出口，读它交给 res.cookie 的属性——
    // 比"检查源码里有没有 'production' 字样"的文本断言强：删掉调用点文本断言照样绿。
    const optionsFor = (nodeEnv, extra = {}) => {
      jest.resetModules();
      process.env = { ...WEAK_ONLY_ENV, ...extra };
      if (nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = nodeEnv;
      if (extra.COOKIE_SECURE === undefined) delete process.env.COOKIE_SECURE;
      const cookie = require('../utils/cookie');
      const captured = {};
      const res = {
        cookie(name, value, opts) {
          captured[name] = opts;
          return this;
        },
      };
      cookie.setAuthCookies(res, 'zz-access', 'zz-refresh');
      // 2026-11-01 __Host- 前缀迁移：安全模式下写侧改用带前缀名（见 cookie.js
      // ACCESS_COOKIE_NAME_SECURED），非安全模式仍是普通名。取「实际写入的那枚」。
      return captured[cookie.ACCESS_COOKIE_NAME_SECURED] || captured[cookie.ACCESS_COOKIE_NAME];
    };

    test.each(['production', 'prod', 'Production', 'live', 'prodution', 'staging', 'stage'])(
      '%s → Secure 必须为 true',
      (value) => {
        expect(optionsFor(value).secure).toBe(true);
      }
    );

    test('预发显式宽松时 Secure 才由 COOKIE_SECURE 决定（不再因 NODE_ENV 静默关闭）', () => {
      expect(optionsFor('staging', { FSMS_ALLOW_STAGING_LENIENT: 'true' }).secure).toBe(false);
      expect(
        optionsFor('staging', { FSMS_ALLOW_STAGING_LENIENT: 'true', COOKIE_SECURE: 'true' }).secure
      ).toBe(true);
    });

    test.each(['development', 'test', 'local'])(
      '%s → Secure 为 false（本地 HTTP 可用）',
      (value) => {
        expect(optionsFor(value).secure).toBe(false);
      }
    );

    test('非生产环境下 COOKIE_SECURE=true 仍可显式打开，且同源策略另一半不被削弱', () => {
      jest.resetModules();
      process.env = { ...WEAK_ONLY_ENV, NODE_ENV: 'development', COOKIE_SECURE: 'true' };
      const cookie = require('../utils/cookie');
      const captured = {};
      const res = {
        cookie(name, value, opts) {
          captured[name] = opts;
          return this;
        },
      };
      cookie.setAuthCookies(res, 'zz-access', 'zz-refresh');
      const opts =
        captured[cookie.ACCESS_COOKIE_NAME_SECURED] || captured[cookie.ACCESS_COOKIE_NAME];
      expect(opts.secure).toBe(true);
      expect(opts.httpOnly).toBe(true);
      expect(opts.sameSite).toBe('strict');
    });
  });

  describe('__Host- 前缀名切换（2026-11-01 参考研读 P1-1）', () => {
    // 与 Secure 位同一判据（isSecureCookie）驱动写侧 cookie 名：
    // 安全模式写 '__Host-access_token'（浏览器强制 Secure+Path=/+无 Domain，
    // 兄弟子域无法投毒主域令牌 cookie），开发模式保持普通名（非 HTTPS 下
    // 带前缀 cookie 会被浏览器静默丢弃）。读侧双名兼容由 activeAccessCookieNames
    // 提供，本组只钉写侧与读取序列。
    const captureAccessNames = (nodeEnv, extra = {}) => {
      jest.resetModules();
      process.env = { ...WEAK_ONLY_ENV, ...extra };
      process.env.NODE_ENV = nodeEnv;
      if (extra.COOKIE_SECURE === undefined) delete process.env.COOKIE_SECURE;
      const cookie = require('../utils/cookie');
      const captured = {};
      const res = {
        cookie(name, _value, opts) {
          captured[name] = opts;
          return this;
        },
        clearCookie(name, _opts) {
          captured[name] = null;
          return this;
        },
      };
      cookie.setAuthCookies(res, 'zz-access', 'zz-refresh');
      return { cookie, captured };
    };

    test.each(['production', 'prod', 'staging'])(
      '%s → access cookie 必须用 __Host- 前缀名',
      (value) => {
        const { cookie, captured } = captureAccessNames(value);
        expect(captured[cookie.ACCESS_COOKIE_NAME_SECURED]).toBeDefined();
        expect(captured[cookie.ACCESS_COOKIE_NAME]).toBeUndefined();
        expect(cookie.ACCESS_COOKIE_NAME_SECURED).toBe('__Host-access_token');
        // __Host- 前缀的三个浏览器硬条件，本实现必须全满足：
        expect(captured[cookie.ACCESS_COOKIE_NAME_SECURED].secure).toBe(true);
        expect(captured[cookie.ACCESS_COOKIE_NAME_SECURED].path).toBe('/');
        // 不传 domain 属性（express 不默认加），res.cookie 的 options 上不应出现 domain
        expect(captured[cookie.ACCESS_COOKIE_NAME_SECURED].domain).toBeUndefined();
      }
    );

    test.each(['development', 'test'])(
      '%s → 保持普通名（前缀 cookie 在 http 下会被浏览器丢弃）',
      (value) => {
        const { cookie, captured } = captureAccessNames(value);
        expect(captured[cookie.ACCESS_COOKIE_NAME]).toBeDefined();
        expect(captured[cookie.ACCESS_COOKIE_NAME_SECURED]).toBeUndefined();
      }
    );

    test('refresh cookie 永不加前缀（__Host- 强制 Path=/，与其 /api/auth 收窄路径冲突）', () => {
      const { cookie, captured } = captureAccessNames('production');
      expect(cookie.REFRESH_COOKIE_NAME).toBe('refresh_token');
      expect(captured[cookie.REFRESH_COOKIE_NAME]).toBeDefined();
      expect(captured[cookie.REFRESH_COOKIE_NAME].path).toBe('/api/auth');
    });

    test('读取序列：安全模式双名兼容（存量旧名会话零感知），非安全模式只认普通名', () => {
      jest.resetModules();
      process.env = { ...WEAK_ONLY_ENV, NODE_ENV: 'production' };
      let cookie = require('../utils/cookie');
      expect(cookie.activeAccessCookieNames()).toEqual([
        cookie.ACCESS_COOKIE_NAME_SECURED,
        cookie.ACCESS_COOKIE_NAME,
      ]);

      jest.resetModules();
      process.env = { ...WEAK_ONLY_ENV, NODE_ENV: 'development' };
      cookie = require('../utils/cookie');
      expect(cookie.activeAccessCookieNames()).toEqual([cookie.ACCESS_COOKIE_NAME]);

      // pickCookieValue：按优先级取第一个非空值，全缺返回 null（供 auth/WS 握手共用）
      expect(cookie.pickCookieValue({ foo: '1' }, ['bar', 'foo'])).toBe('1');
      expect(cookie.pickCookieValue({ bar: '', baz: '2' }, ['bar', 'baz'])).toBe('2');
      expect(cookie.pickCookieValue(undefined, ['bar'])).toBeNull();
      expect(cookie.pickCookieValue({}, ['bar'])).toBeNull();
    });

    test('登出清除：新旧两枚 access 名 + refresh 三者都发过期指令（迁移窗口无残留）', () => {
      jest.resetModules();
      process.env = { ...WEAK_ONLY_ENV, NODE_ENV: 'production' };
      const cookie = require('../utils/cookie');
      const cleared = [];
      const res = {
        clearCookie(name) {
          cleared.push(name);
          return this;
        },
      };
      cookie.clearAuthCookies(res);
      expect(cleared).toEqual([
        cookie.ACCESS_COOKIE_NAME_SECURED,
        cookie.ACCESS_COOKIE_NAME,
        cookie.REFRESH_COOKIE_NAME,
      ]);
    });
  });
});
