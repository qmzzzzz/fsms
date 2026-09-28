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
 *   开发/预发家族可跳过；生产家族执行硬闸；**不认识的值也执行硬闸并额外报一条**——
 *   猜错方向的代价必须是"启动不起来"，不是"生产以零校验启动"。
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
    ['staging（ADR-005 的既有边界，不得改动）', 'staging'],
    ['stage', 'stage'],
    ['未设置', undefined],
  ])('%s 仍允许跳过生产校验', (_label, value) => {
    expect(stopsBoot(value)).toBe(false);
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

    test('反向对照：真正未设置仍归一为 development（不得把本地开发也闸停）', () => {
      expect(stopsBoot(undefined)).toBe(false);
      const { mod, exitSpy, consoleSpy } = loadAndRun(undefined);
      try {
        expect(mod.normalizeNodeEnv()).toBe('development');
        expect(mod.requiresProductionSemantics()).toBe(false);
      } finally {
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

    test.each(['production', 'prod', 'Production', 'live', 'prodution'])(
      '%s → 文档默认关闭',
      (value) => {
        expect(docsFor(value)).toBe(false);
      }
    );

    test.each(['development', 'dev', 'local', 'test', 'staging', undefined])(
      '%s → 文档默认开启（保持既有语义）',
      (value) => {
        expect(docsFor(value)).toBe(true);
      }
    );

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
    const optionsFor = (nodeEnv) => {
      jest.resetModules();
      process.env = { ...WEAK_ONLY_ENV };
      if (nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = nodeEnv;
      delete process.env.COOKIE_SECURE;
      const cookie = require('../utils/cookie');
      const captured = {};
      const res = {
        cookie(name, value, opts) {
          captured[name] = opts;
          return this;
        },
      };
      cookie.setAuthCookies(res, 'zz-access', 'zz-refresh');
      return captured[cookie.ACCESS_COOKIE_NAME];
    };

    test.each(['production', 'prod', 'Production', 'live', 'prodution'])(
      '%s → Secure 必须为 true',
      (value) => {
        expect(optionsFor(value).secure).toBe(true);
      }
    );

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
      const opts = captured[cookie.ACCESS_COOKIE_NAME];
      expect(opts.secure).toBe(true);
      expect(opts.httpOnly).toBe(true);
      expect(opts.sameSite).toBe('strict');
    });
  });
});
