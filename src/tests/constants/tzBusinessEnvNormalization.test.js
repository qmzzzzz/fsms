/**
 * TZ_BUSINESS 的归一化口径：启动闸门与运行期消费方必须是同一句话
 *
 * 缺陷形态（2026-09-25 实测，F-152）：`config/validate.js` 的 collectTimezoneErrors
 * 读 env 后 `.trim()` 再构造 Intl.DateTimeFormat 做校验，而 `constants/timezone.js`
 * 的 BUSINESS_TIMEZONE 直接用裸 env（`process.env.TZ_BUSINESS || 'Asia/Shanghai'`）。
 * 两侧对"同一个值是否合法"给出相反答案：
 *   TZ_BUSINESS=' Asia/Shanghai' → 闸门 pass，运行期 businessDateParts 抛 RangeError；
 *   TZ_BUSINESS='   '           → 闸门当作"未配置"pass，运行期因 `'   ' ||` 判真
 *                                  而**连默认值都拿不到**，模块加载期即抛。
 * 而闸门自己的注释写着"判定方式与运行期完全一致……避免「校验通过但运行期仍抛」"——
 * 那句话此前是承诺，不是事实。
 *
 * 本文件两层：
 * 1) 行为层：真按各种 env 值重新加载模块，断言取到的时区名可被 Intl 接受、
 *    且 businessDateParts 不抛（修之前这两条都会以 RangeError 失败）。
 * 2) 写法层（同 F-149/150/151 的教训）：断言**两个文件里都带 trim**。只断言取值
 *    挡不住"把闸门也去掉 trim"这种同错方向的对齐，所以判据要钉在引用点上；
 *    并按既有纪律给写法断言自身配正对照（先证明"手抄无 trim 的版本"会被判红）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SRC_ROOT = path.join(__dirname, '../..');
// CRLF→LF 归一：本仓 core.autocrlf=true，Windows 工作区里 src/**.js 是 CRLF 而 CI 是 LF。
// 本套件的写法层判据要按 `\n}\n` 切函数体，不归一时在 Windows 上切出空串（红得莫名），
// 归一之后两侧同一份视图。
const read = (rel) => fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8').replace(/\r\n/g, '\n');

/** 去掉块注释与行注释，避免"注释里提了一句 trim"被当成代码（F-128 同法） */
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/([^:])\/\/.*$/gm, '$1');

/** 在指定 TZ_BUSINESS 取值下重新加载 constants/timezone.js（模块加载期即读 env） */
const loadTimezone = (value) => {
  const saved = process.env.TZ_BUSINESS;
  if (value === undefined) delete process.env.TZ_BUSINESS;
  else process.env.TZ_BUSINESS = value;
  try {
    let mod;
    jest.isolateModules(() => {
      mod = require('../../constants/timezone');
    });
    return mod;
  } finally {
    if (saved === undefined) delete process.env.TZ_BUSINESS;
    else process.env.TZ_BUSINESS = saved;
  }
};

const isConstructible = (tz) => {
  try {
    new Intl.DateTimeFormat('en-CA', { timeZone: tz });
    return true;
  } catch (_) {
    return false;
  }
};

/**
 * 生产口径下跑一次**真闸门**（config/validate.validateConfig），只看时区项是否被判致命。
 * 除 TZ_BUSINESS 外的环境项一律给合法值，避免别的致命项混进 messages；
 * 其余环境变量在 finally 里整份还原（本文件其余用例依赖干净的 env）。
 */
const VALID_PROD_ENV = {
  NODE_ENV: 'production',
  JWT_SECRET: 'strong-random-jwt-secret-that-is-long-enough',
  JWT_REFRESH_SECRET: 'strong-random-refresh-secret-long-enough',
  AES_SECRET_KEY: 'test-aes-key-with-32-chars-minimum!!',
  HMAC_SECRET: 'strong-random-hmac-secret-that-is-long-enough',
  MONGODB_URI: 'mongodb://prod-server:27017/db',
  CORS_ORIGIN: 'https://example.com',
  ENABLE_HTTPS: 'true',
  ALLOWED_HOSTS: 'api.example.com',
  REDIS_URL: 'redis://redis.example.com:6379',
  TRUST_PROXY_HOPS: '1',
};

const realGateVerdict = (raw) => {
  const saved = { ...process.env };
  const logger = require('../../utils/logger');
  const { validateConfig, requiresProductionSemantics } = require('../../config/validate');
  const messages = [];
  const errSpy = jest.spyOn(logger, 'error').mockImplementation((m) => messages.push(String(m)));
  const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
  const exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
    throw new Error('process.exit called');
  });
  try {
    Object.assign(process.env, VALID_PROD_ENV);
    process.env.TZ_BUSINESS = raw;
    // 前提自证：这一臂必须真的在生产口径下跑，否则 validateConfig 整体早退，
    // 下面的循环会退化成"什么都不判也全绿"——那正是被本文件抄成分权证时踩过的坑。
    if (!requiresProductionSemantics()) {
      throw new Error('前提失效：NODE_ENV=production 但未按生产口径校验');
    }
    try {
      validateConfig();
    } catch (e) {
      if (e.message !== 'process.exit called') throw e;
    }
    return /TZ_BUSINESS/.test(messages.join('\n')) ? 'fatal' : 'pass';
  } finally {
    errSpy.mockRestore();
    warnSpy.mockRestore();
    exitSpy.mockRestore();
    for (const key of Object.keys(process.env)) {
      if (!(key in saved)) delete process.env[key];
    }
    Object.assign(process.env, saved);
  }
};

describe('TZ_BUSINESS：消费侧归一化与启动闸门同口径', () => {
  const ORIGINAL = process.env.TZ_BUSINESS;
  afterAll(() => {
    if (ORIGINAL === undefined) delete process.env.TZ_BUSINESS;
    else process.env.TZ_BUSINESS = ORIGINAL;
  });

  test('带空格的合法时区名：取值归一化后可被 Intl 接受（修前在这里抛 RangeError）', () => {
    const { BUSINESS_TIMEZONE } = loadTimezone(' Asia/Shanghai');
    expect(BUSINESS_TIMEZONE).toBe('Asia/Shanghai');
    expect(isConstructible(BUSINESS_TIMEZONE)).toBe(true);
  });

  test('尾随空格同样归一化（env-file / yaml 折行的常见形态）', () => {
    expect(loadTimezone('America/Los_Angeles ').BUSINESS_TIMEZONE).toBe('America/Los_Angeles');
  });

  test('纯空格不再当作有效配置：回退默认时区而不是把 "   " 交给 Intl', () => {
    const { BUSINESS_TIMEZONE } = loadTimezone('   ');
    expect(BUSINESS_TIMEZONE).toBe('Asia/Shanghai');
  });

  test('未配置 → 默认 Asia/Shanghai；正常配置 → 原样生效（不改语义）', () => {
    expect(loadTimezone(undefined).BUSINESS_TIMEZONE).toBe('Asia/Shanghai');
    expect(loadTimezone('Etc/GMT+12').BUSINESS_TIMEZONE).toBe('Etc/GMT+12');
  });

  test('行为层：带空格配置下 businessDateParts 真跑通，不向调用方抛 RangeError', () => {
    const { businessDateParts } = loadTimezone(' Asia/Shanghai');
    const parts = businessDateParts(new Date('2026-09-25T03:30:00Z'));
    expect(parts.dateStr).toBe('2026-09-25');
  });

  test('真闸门与运行期对同一批取值给出同一答案（生产口径：放行 ⟺ 加载不抛）', () => {
    // 判据必须来自**真闸门**（validateConfig），不是本文件早先抄的那份 JS 复制品。
    // 原实现（F-152 落地时）写的是 `const gateVerdict = (raw) => { trim + isConstructible }`，
    // 注释里还写着"照抄 collectTimezoneErrors 的逻辑"——那与 sharedCacheBackends 的假 Redis
    // 把 Lua 守卫用 JS 重写一遍同族：闸门自己判自己，永远一致，真实闸门怎么改都不红。
    // 实测过的两种变异都能逃过那份复制品：给 collectTimezoneErrors 加 `if (!requiresProductionSemantics()) return;`
    // 或把 trim 去掉，本文件 12 例全绿。
    const values = [' Asia/Shanghai', 'Asia/Shanghai ', '   ', 'UTC', '+08:00', 'Asia/Shangai'];
    for (const raw of values) {
      const verdict = realGateVerdict(raw);
      if (verdict === 'fatal') {
        expect(() => loadTimezone(raw)).toThrow(RangeError);
      } else {
        expect(isConstructible(loadTimezone(raw).BUSINESS_TIMEZONE)).toBe(true);
      }
    }
  });

  test('探测器有牙齿：真闸门对拼错的时区名确实判致命、对合法名确实放行（否则上一条是空转）', () => {
    expect(realGateVerdict('Asia/Shangai')).toBe('fatal');
    expect(realGateVerdict('Asia/Shanghai')).toBe('pass');
  });

  test('口径边界（实测记录，不是"这样正确"的断言）：非生产整体早退，运行期照样抛', () => {
    // validate.js:365 `if (!requiresProductionSemantics()) {` ⇒ dev/test/ci/local/staging
    // 连时区项都不看；而 constants/timezone.js 无条件构造 Intl。所以在开发环境里，
    // TZ_BUSINESS 拼名的失败形态是首次 require 抛 RangeError，而不是启动期一句配置致命错。
    // 本用例钉的是**当前不对称**：若哪天把时区项挪出环境分叉（生产口径同校验），
    // 第一条 expect 会红——那时请连同本注释一起改判，而不是顺手删掉这条。
    const saved = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';
    try {
      const { validateConfig, requiresProductionSemantics } = require('../../config/validate');
      expect(requiresProductionSemantics()).toBe(false);
      expect(() => validateConfig()).not.toThrow();
      expect(() => loadTimezone('Asia/Shangai')).toThrow(RangeError);
    } finally {
      if (saved === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = saved;
    }
  });
});

describe('TZ_BUSINESS：两个引用点都必须带 trim（写法层，防同向对齐）', () => {
  const TZ_READ = /\(\s*process\.env\.TZ_BUSINESS\s*(?:\|\|\s*'[^']*'\s*)?\)\s*\.trim\(\)/;

  test('正对照：常量侧的真实写法能被本判据认出', () => {
    const code = stripComments(read('constants/timezone.js'));
    expect(code).toMatch(TZ_READ);
  });

  test('变异自证：把 trim 摘掉（回到 F-152 的原始缺陷写法）会被本判据判红', () => {
    const code = stripComments(read('constants/timezone.js'));
    const laundered = code.replace(
      /\(process\.env\.TZ_BUSINESS \|\| ''\)\.trim\(\)/,
      'process.env.TZ_BUSINESS'
    );
    expect(laundered).not.toBe(code); // 替换本身必须生效，否则判据是空跑
    expect(laundered).not.toMatch(TZ_READ);
  });

  test('闸门侧同样 trim：两处口径同源，缺一个就会重新出现"放行但运行期抛"', () => {
    const gate = stripComments(read('config/validate.js'));
    const at = gate.indexOf('function collectTimezoneErrors');
    // 两处定位失败都必须**响**：静默 slice 会切出空串或切到别的函数体上——后者更糟，
    // 因为别的函数里同样可能有 `process.env.TZ_BUSINESS).trim()`，判据会假绿。
    if (at < 0) throw new Error('闸门侧找不到 function collectTimezoneErrors，写法层判据已失效');
    const fn = gate.slice(at);
    const endAt = fn.indexOf('\n}\n');
    if (endAt < 0) throw new Error('找不到 collectTimezoneErrors 的收尾大括号，函数体边界不可信');
    const body = fn.slice(0, endAt + 1);
    expect(body).toContain('process.env.TZ_BUSINESS');
    expect(body).toMatch(/\.trim\(\)/);
  });
});
