/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：constants/timezone.js 的 businessMonthStart + userController 聚合管道
 * 守护的不变式：「本月」窗口必须与「今日」窗口同用业务时区口径，且控制器必须真的把该瞬间塞进管道
 * 可证伪性：变异实测（N=8 + flake 守卫 + `--no-cache`）：杀 1/9，基线 11 passed（`eq-flip@34` → 9 failed / 2 passed）
 *
 * 命名沿革：2026-09-20 更名（旧名带已废弃的会话前缀，逐字旧名见 `git log --follow`）。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   会话前缀已全仓清除，故不再逐字保留旧名；按旧名回溯请用 `git log --follow <本文件>`。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 「本月」统计窗口必须与「今日」窗口同用时区口径，且控制器要真的用上它
 *
 * 缺陷形态：`getUserStats` 的 thisMonth 分支原先按
 *   `new Date(); setDate(1); setHours(0,0,0,0)`
 * 取月界——那是**服务器本地时区**。而「今日」窗口早已统一为 businessDayBounds()
 * （业务时区）。容器裸跑 UTC 时两个口径互相矛盾：业务时区每月 1 日 00:00–08:00
 * 之间新建的账号，按业务口径属本月、按服务器口径属上月 → 恒被 thisMonth 漏计。
 *
 * 本文件分三层钉住：
 *  1) businessMonthStart() 的绝对正确性——参照物用与实现无关的 Intl 渲染，
 *     外加 UTC+14 / UTC−12 / UTC+8 三个固定偏移区的显式 UTC 瞬间；
 *  2) 前提：本机时区与所选业务时区的月首确实差得开（≥8h）——否则第 3 层的
 *     差异化断言会在"两个实现恰好同值"的机器上假绿；
 *  3) 控制器确实把该瞬间塞进了聚合管道（深搜 createdAt.$gte），并显式断言
 *     它**不是**服务器本地月首（那正是被修掉的写法）。
 */

const HOUR = 60 * 60 * 1000;

const FIXED_OFFSET_HOURS = {
  'Pacific/Kiritimati': 14, // 无夏令时的最东时区
  'Etc/GMT+12': -12, // 无夏令时的最西时区（POSIX 记号：GMT+12 实为 UTC−12）
  'Asia/Shanghai': 8, // 默认业务时区
};

const ENV_KEYS = ['TZ_BUSINESS', 'TZ'];

const withEnv = (vars, fn) => {
  const saved = {};
  Object.keys(vars).forEach((k) => {
    saved[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k];
    else process.env[k] = vars[k];
  });
  try {
    return fn();
  } finally {
    Object.keys(saved).forEach((k) => {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    });
  }
};

// 在指定业务时区下加载一份全新的模块图（BUSINESS_TIMEZONE 是模块加载期常量）
const loadIsolated = (tz, specs) =>
  withEnv({ TZ_BUSINESS: tz }, () => {
    const out = {};
    jest.isolateModules(() => {
      Object.entries(specs).forEach(([name, path]) => {
        out[name] = require(path);
      });
    });
    return out;
  });

const loadTz = (tz) => loadIsolated(tz, { timezone: '../constants/timezone' }).timezone;

/** 与实现无关的参照：用 Intl 把瞬间渲染成业务时区的墙上时间 */
const renderIn = (tz, at, precise) =>
  new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    ...(precise ? { second: '2-digit', fractionalSecondDigits: 3 } : {}),
    hour12: false,
    hourCycle: 'h23',
  })
    .format(at)
    .replace(', ', ' ');

const monthOfInZone = (tz, at) => {
  const [year, month] = renderIn(tz, at, false).slice(0, 7).split('-').map(Number);
  return { year, month };
};

/** 服务器本地时区的月首（被修掉的写法），用于反向对照 */
const localMonthStart = () => {
  const d = new Date();
  d.setDate(1);
  d.setHours(0, 0, 0, 0);
  return d;
};

const FACET_RESULT = [
  {
    total: [{ count: 3 }],
    active: [{ count: 2 }],
    inactive: [{ count: 1 }],
    thisMonth: [{ count: 1 }],
    byDepartment: [],
    byRole: [],
  },
];

jest.mock('../services/statsCache', () => ({
  get: () => ({ hit: false }),
  set: () => {},
  invalidateByUserId: () => {},
}));

jest.mock('../middleware/rbac', () => ({
  getDataScope: async () => ({ type: 'all' }),
  buildDataScopeFilter: () => ({}),
  assertRecordInScope: async () => ({ allowed: true }),
}));

jest.mock('../middleware/auth', () => ({ invalidateUserCache: () => {} }));

jest.mock('../services/userService', () => ({
  aggregateStats: jest.fn(async () => [{}]),
}));

// 深搜聚合管道里的 createdAt.$gte —— 取不到即为「月窗口不存在」，本身就是要防的回归
const findCreatedAtGte = (input) => {
  const stack = [input];
  while (stack.length > 0) {
    const cur = stack.pop();
    if (Array.isArray(cur)) {
      cur.forEach((x) => stack.push(x));
    } else if (cur && typeof cur === 'object') {
      const gte = cur.createdAt && cur.createdAt.$gte;
      if (gte && Object.prototype.toString.call(gte) === '[object Date]') return gte;
      Object.values(cur).forEach((v) => stack.push(v));
    }
  }
  return null;
};

const makeFakeRes = () => {
  const res = { statusCode: null, body: null };
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body) => {
    res.body = body;
    return res;
  };
  return res;
};

/**
 * 以指定业务时区跑一次 getUserStats，回读它真正塞进聚合管道的月界。
 * 控制器与 userService 桩必须在同一个隔离模块图里取，否则拿到的是另一份 mock 实例。
 */
const probeControllerMonthWindow = async (tz) => {
  const { userController, timezone, userService } = loadIsolated(tz, {
    userController: '../controllers/userController',
    timezone: '../constants/timezone',
    userService: '../services/userService',
  });
  userService.aggregateStats.mockImplementation(async () => FACET_RESULT);
  userService.aggregateStats.mockClear();

  const req = { user: { userId: '000000000000000000000001', username: 'probe' } };
  const res = makeFakeRes();
  await userController.getUserStats(req, res, () => {});

  const calls = userService.aggregateStats.mock.calls;
  expect(calls.length).toBe(1);
  return {
    gte: findCreatedAtGte(calls[0][0]),
    body: res.body,
    monthStart: timezone.businessMonthStart(),
  };
};

// 本机时区恰好与某业务时区同月首时，差异化断言会失去鉴别力 → 运行时挑一个差得开的
const pickDivergentTz = () => {
  const local = localMonthStart().getTime();
  const candidates = ['Pacific/Kiritimati', 'Etc/GMT+12'];
  const found = candidates.find(
    (tz) => Math.abs(loadTz(tz).businessMonthStart().getTime() - local) >= 8 * HOUR
  );
  return { local, tz: found };
};

describe('businessMonthStart 的绝对口径', () => {
  afterAll(() => {
    // 让后续套件拿到的模块图不受本次 isolateModules 影响
    loadTz('Asia/Shanghai');
  });

  test('固定偏移区：月首正是「业务区 1 日 00:00」换算出的 UTC 瞬间', () => {
    Object.entries(FIXED_OFFSET_HOURS).forEach(([tz, offsetHours]) => {
      const { businessMonthStart } = loadTz(tz);
      const { year, month } = monthOfInZone(tz, new Date());
      const expected = Date.UTC(year, month - 1, 1) - offsetHours * HOUR;
      expect({ tz, got: businessMonthStart().getTime() }).toEqual({ tz, got: expected });
    });
  });

  test('正向判据：业务区内渲染恰为 1 日 00:00:00.000，回退 1ms 即属上月', () => {
    const zones = ['Pacific/Kiritimati', 'Etc/GMT+12', 'Asia/Shanghai', 'America/Los_Angeles'];
    const violations = [];
    zones.forEach((tz) => {
      const { businessMonthStart } = loadTz(tz);
      const start = businessMonthStart();
      const { year, month } = monthOfInZone(tz, new Date());
      const pad = (n) => String(n).padStart(2, '0');
      const rendered = renderIn(tz, start, true);
      const expected = `${year}-${pad(month)}-01 00:00:00.000`;
      if (rendered !== expected) violations.push({ tz, rendered, expected });
      const prevMonth = monthOfInZone(tz, new Date(start.getTime() - 1));
      const crossedBack =
        prevMonth.year < year || (prevMonth.year === year && prevMonth.month < month);
      if (!crossedBack) violations.push({ tz, crossedBack });
    });
    expect(violations).toEqual([]);
  });

  test('窗口方向没写反：月首不晚于当前时刻、且不早于 31 天前', () => {
    const { businessMonthStart } = loadTz('Asia/Shanghai');
    const now = Date.now();
    const start = businessMonthStart().getTime();
    expect(start).toBeLessThanOrEqual(now);
    expect(now - start).toBeLessThan(31 * 24 * HOUR);
  });

  test('跨年：传入 1 月初的时刻得到上一自然年的 12 月月首', () => {
    const { businessMonthStart } = loadTz('Asia/Shanghai');
    const start = businessMonthStart(new Date('2026-01-05T00:30:00+08:00'));
    expect(start.toISOString()).toBe('2025-12-31T16:00:00.000Z');
  });

  test('跨月界两侧：UTC 月末的同一瞬间在不同业务区可分属两个月', () => {
    const at = new Date('2026-08-31T17:00:00Z');
    const east = loadTz('Pacific/Kiritimati').businessMonthStart(at);
    const west = loadTz('Etc/GMT+12').businessMonthStart(at);
    // +14 已是 9 月 → 9-01 00:00+14 = 08-31T10:00Z；−12 仍是 8 月 → 8-01 12:00Z
    expect(east.toISOString()).toBe('2026-08-31T10:00:00.000Z');
    expect(west.toISOString()).toBe('2026-08-01T12:00:00.000Z');
  });
});

describe('用户统计 thisMonth 使用业务时区月界', () => {
  test('前提：能挑出一个与本机月首相差 ≥8h 的业务时区（否则下面的断言无鉴别力）', () => {
    const { tz } = pickDivergentTz();
    expect(typeof tz).toBe('string');
  });

  test('createdAt.$gte 等于 businessMonthStart()，且不是服务器本地月首', async () => {
    const { tz, local } = pickDivergentTz();
    const { gte, monthStart, body } = await probeControllerMonthWindow(tz);
    expect(gte).not.toBeNull();
    expect(gte.getTime()).toBe(monthStart.getTime());
    expect(Math.abs(gte.getTime() - local)).toBeGreaterThanOrEqual(8 * HOUR);
    expect(body.success).toBe(true);
    expect(body.data.thisMonth).toBe(1);
  });

  test('换区即换值：Asia/Shanghai 下月界落在 UTC 16:00（东八区 1 日零点）', async () => {
    const { gte, monthStart } = await probeControllerMonthWindow('Asia/Shanghai');
    expect(gte.getTime()).toBe(monthStart.getTime());
    // 东八区偏移恒为 +8，故任何自然月的月首在 UTC 侧都落在 16:00
    expect(gte.toISOString()).toMatch(/T16:00:00\.000Z$/);
  });

  test('夏令时区不被固定偏移假设带偏：月首为 1 日 07:00Z 或 08:00Z', async () => {
    const { gte, monthStart } = await probeControllerMonthWindow('America/Los_Angeles');
    expect(gte.getTime()).toBe(monthStart.getTime());
    expect(gte.toISOString()).toMatch(/-01T0[78]:00:00\.000Z$/);
  });

  test('缓存未命中时才查库：命中路径不得重算月界（口径只有一处）', async () => {
    const { userController, userService, statsCache } = loadIsolated('Asia/Shanghai', {
      userController: '../controllers/userController',
      userService: '../services/userService',
      statsCache: '../services/statsCache',
    });
    statsCache.get = () => ({ hit: true, data: { thisMonth: 42 } });
    userService.aggregateStats.mockClear();
    const res = makeFakeRes();
    await userController.getUserStats(
      { user: { userId: '000000000000000000000001', username: 'probe' } },
      res,
      () => {}
    );
    expect(userService.aggregateStats.mock.calls.length).toBe(0);
    expect(res.body.data.thisMonth).toBe(42);
  });
});

describe('环境隔离', () => {
  test('本文件不改写宿主进程的 TZ_BUSINESS / TZ', () => {
    const before = ENV_KEYS.map((k) => process.env[k]);
    withEnv({ TZ_BUSINESS: 'Etc/GMT+12', TZ: 'UTC' }, () => loadTz('Pacific/Kiritimati'));
    expect(ENV_KEYS.map((k) => process.env[k])).toEqual(before);
  });
});
