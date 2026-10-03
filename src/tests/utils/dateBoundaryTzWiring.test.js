/**
 * 报表/审计日期边界的两条口径（业务时区 vs 宿主时区）与 ?tz 的出口接线平价。
 *
 * 起因（第 17 轮，全部**实测**得出，不是读注释）：
 *  1. 好行为：date-only（`2026-10-01`）按业务时区整天、与宿主 TZ 无关；带偏移的串
 *     （`2026-10-01T00:00:00+08:00`）偏移被保留。
 *  2. 欠账 A：`2026-10-01T00:00:00`（**无偏移、无 Z**）落到 `new Date(str)` ⇒ 按**宿主**时区解释，
 *     且 `boundary`（start/end）被忽略。同一入参在 TZ=UTC 与 TZ=Asia/Shanghai 下差整 8 小时。
 *     后果：生产容器与开发机 TZ 不同时窗口静默平移，既不 400 也不提示；而 endDate 带时间时
 *     `$lte` 就是那个瞬间，"含当天"里当天剩余部分整段掉出窗口。
 *     （`src/tests/utils/dateParamForms.test.js` 把"带时间的串原样透传"记为**刻意保留的既有契约**——那条说的是
 *     入口不拒它；这里说的是透传的**落点**：`new Date(str)` 的落点由宿主 TZ 决定，且 end 被当成 start。
 *     两者不冲突，但后者至今没有任何地方记账。）
 *     测法：不改本进程 `process.env.TZ`，而是另起子进程注入 TZ——`src/tests/illegalCalendarDayWithTime.test.js`
 *     用 `runnerIsBusinessTZ` 分支回避宿主差异，这里一次跑出两个宿主的答案，把差值直接钉成 -8h。
 *  3. 欠账 B：报警报表把校验过的 ?tz 传给 `buildDateRangeFilter`
 *     （src/controllers/reportController.js:108、src/controllers/reportController.js:237），
 *     设备/巡检报表走 src/services/reportStatsService.js:34、src/services/reportStatsService.js:93
 *     的**两参**调用 ⇒ 同一个 ?tz 在两类出口一个生效一个无效（同一次请求、两个页面、两套"今天"）。
 *     这两处出口各自的文件里都写了实情（注释里有 `buildDateRangeFilter(...)` 的调用形状），
 *     所以采集器必须跑在剥注释的视图上——否则注释里的形状会被当成真调用点。
 *
 * 本闸不"顺手修"这两条，理由不是省事：
 *  - 改 A 是**对外契约变更**（一批现存的无偏移时间串会换窗口），需要拍板；
 *  - 改 B 需要控制器把已校验的 tz 下传给 stats service，而 `reportController.js` 此刻在他人手里是脏文件；
 *    在 service 里再校验一次等于把"什么时区合法"写两份（本仓反复踩过的口径漂移源）。
 * 所以这里把两条钉成**可数的欠账**：形状一变（修好了、修歪了、或新增同类出口）闸就红，
 * 逼回来更新台账，而不是让它们在注释里过期。
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const {
  parseDateBoundary,
  isValidDateParam,
  buildDateRangeFilter,
} = require('../../utils/helpers');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');

const SRC = path.join(__dirname, '..', '..');
const HELPERS = path.join(SRC, 'utils', 'helpers.js');

/** 欠账 A 的形状：无偏移、无 Z 的本地时间串 */
const NAIVE = '2026-10-01T00:00:00';

/**
 * 在指定**宿主** TZ 的子进程里求 parseDateBoundary 的瞬间。
 * 为什么起子进程而不是在测试里改 process.env.TZ：V8 的本地时区在进程首次用到 Date 时定住，
 * 运行中改 TZ 对已加载的 Date 不可靠——只有另起进程才是"另一个部署环境"的真答案。
 */
const probeInstant = (tz, dateStr, boundary) =>
  execFileSync(
    process.execPath,
    [
      '-e',
      `const {parseDateBoundary}=require(${JSON.stringify(HELPERS)});` +
        `process.stdout.write(parseDateBoundary(${JSON.stringify(dateStr)},${JSON.stringify(
          boundary
        )}).toISOString());`,
    ],
    { env: { ...process.env, TZ: tz }, encoding: 'utf8', cwd: SRC }
  );

/** 一个源文件的「只剩代码」视图（口径取自本仓唯一实现，注释里的字样不算接线） */
const codeViewOf = (rel) => jsCodeOnly(fs.readFileSync(path.join(SRC, rel), 'utf8'));

/**
 * 一个调用点的实参算术（只按逗号数）。
 * 实参里还带括号（`buildDateRangeFilter(a, b, resolveQueryTimezone(req, res))`）就意味着这串文本
 * 不在建模范围内 ⇒ 标 `unparsed`，保守不参与欠账判定：宁可漏记一条，也不能把"传了 tz"数成"没传"。
 */
const siteFromArgs = (module, argsText, code) => {
  const args = argsText.trim();
  return {
    module,
    arity: args === '' ? 0 : args.split(',').length,
    unparsed: /[()]/.test(args),
    code,
  };
};

/**
 * 在一个文件的「只剩代码」视图里找 buildDateRangeFilter 调用点。
 * 必须跑在代码视图上：注释里写一句"以前这里是 buildDateRangeFilter(startDate, endDate)"不是接线，
 * 把它当成 2 参调用点会虚增欠账台账，把它当成 3 参则会把真欠账洗白。
 */
const callSitesInCode = (module, code) =>
  [...code.matchAll(/buildDateRangeFilter\(([^)]*)\)/g)].map((m) =>
    siteFromArgs(module, m[1], code)
  );

/** 普查：src 下全部非测试源文件的调用点（逐文件走 callSitesInCode，判定只有一份定义） */
const dateFilterCallSites = () => {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'tests' || entry.name === 'node_modules') continue;
        walk(full);
      } else if (entry.name.endsWith('.js')) {
        const rel = path.relative(SRC, full).replace(/\\/g, '/');
        out.push(...callSitesInCode(rel, jsCodeOnly(fs.readFileSync(full, 'utf8'))));
      }
    }
  };
  walk(SRC);
  return out;
};

/**
 * 欠账判据：调用点没把 tz 传下去（<3 参）**且**该文件自己不解析 ?tz。
 * 真清单与合成形状反证都走这一个函数——判据与接线只有一份定义。
 */
const tzWiringGaps = (sites) =>
  sites
    .filter((s) => !s.unparsed)
    .filter((s) => s.arity < 3 && !/resolveQueryTimezone/.test(s.code))
    .map((s) => `${s.module} (${s.arity} 参)`);

describe('日期边界与 ?tz 接线', () => {
  test('好行为正向钉死：date-only 走业务时区且与宿主 TZ 无关，带偏移的串保留偏移', () => {
    // 业务时区 Asia/Shanghai 的 2026-10-01 整天 = 前一日 16:00Z 到当日 15:59:59.999Z
    expect(parseDateBoundary('2026-10-01', 'start').toISOString()).toBe('2026-09-30T16:00:00.000Z');
    expect(parseDateBoundary('2026-10-01', 'end').toISOString()).toBe('2026-10-01T15:59:59.999Z');
    // 子进程 + TZ 注入这条通道本身可用（否则下面的"实测"可以是空转）
    expect(probeInstant('UTC', '2026-01-01', 'start')).toBe('2025-12-31T16:00:00.000Z');
    expect(probeInstant('America/Sao_Paulo', '2026-10-01', 'end')).toBe('2026-10-01T15:59:59.999Z');
    // 显式偏移必须被保留（这是对的，不该被"业务时区"覆盖）
    expect(probeInstant('UTC', '2026-10-01T00:00:00+08:00', 'start')).toBe(
      '2026-09-30T16:00:00.000Z'
    );
    // 上界含端点：$lte 用的就是 23:59:59.999 这一档
    expect(buildDateRangeFilter('2026-10-01', '2026-10-01')).toEqual({
      $gte: new Date('2026-09-30T16:00:00.000Z'),
      $lte: new Date('2026-10-01T15:59:59.999Z'),
    });
  });

  test('欠账 A 有形状：无偏移带时间的串按宿主 TZ 解释、boundary 被忽略（修好就必须红）', () => {
    expect(isValidDateParam(NAIVE)).toBe(true); // 可达：上游不会把它 400 掉
    const utc = probeInstant('UTC', NAIVE, 'start');
    const shanghai = probeInstant('Asia/Shanghai', NAIVE, 'start');
    // 钉的是"差多少"而不是"差不差"：一旦让它与宿主无关，这个 -8h 就归零 ⇒ 本条转红 ⇒ 台账要退休
    expect(new Date(shanghai) - new Date(utc)).toBe(-8 * 60 * 60 * 1000);
    expect(utc).toBe('2026-10-01T00:00:00.000Z');
    expect(shanghai).toBe('2026-09-30T16:00:00.000Z');
    // 同一条串传 end 与传 start 结果相同 ⇒ 上界不是当天末尾，当天剩余部分掉出窗口
    expect(probeInstant('UTC', NAIVE, 'end')).toBe(utc);
    expect(parseDateBoundary(NAIVE, 'end')).toEqual(parseDateBoundary(NAIVE, 'start'));
    // 反证（判据不空转）：date-only 那两个宿主的答案相同，说明 -8h 只在"带时间"时成立
    expect(probeInstant('UTC', '2026-10-01', 'end')).toBe(
      probeInstant('Asia/Shanghai', '2026-10-01', 'end')
    );
  });

  test('欠账 B 有台账：同一 ?tz 在各类报表出口的接线状态必须逐条可数', () => {
    const sites = dateFilterCallSites();
    // 普查规模地板：调用点数掉下来说明扫描器瞎了（改名/换写法），不是问题消失了
    expect(sites.length).toBeGreaterThanOrEqual(4);
    expect(tzWiringGaps(sites)).toEqual([
      'services/reportStatsService.js (2 参)',
      'services/reportStatsService.js (2 参)',
    ]);
    // 三种形状各钉一次，走同一个 tzWiringGaps（不另写一遍条件）
    const shape = (arity, resolvesTz) =>
      tzWiringGaps([
        {
          module: 'synthetic.js',
          arity,
          unparsed: false,
          code: resolvesTz ? 'const tz = resolveQueryTimezone(req, res);' : 'const tz = q.tz;',
        },
      ]);
    expect(shape(3, false)).toEqual([]); // 传了 tz ⇒ 无欠账
    expect(shape(2, true)).toEqual([]); // 自己解析 ⇒ 无欠账
    expect(shape(2, false)).toEqual(['synthetic.js (2 参)']); // 两参且不解析 ⇒ 记欠账
    // 没建模的形态保守不参与（嵌套实参不许被数成 2 参而误记欠账）
    expect(tzWiringGaps([{ module: 'synthetic.js', arity: 1, unparsed: true, code: '' }])).toEqual(
      []
    );
    // 注释里写 resolveQueryTimezone 不算接线（判据跑在代码视图上）
    expect(
      tzWiringGaps([
        {
          module: 'synthetic.js',
          arity: 2,
          unparsed: false,
          code: jsCodeOnly('// 这里本该调 resolveQueryTimezone(req, res)\nconst f = 1;\n'),
        },
      ])
    ).toEqual(['synthetic.js (2 参)']);
  });

  test('采集器自身的两条腿：注释里的调用不算，嵌套实参保守放行，真清单逐条可数', () => {
    // 同一份文本：剥注释后 0 个调用点、留注释 1 个 ⇒ 证明采集器跑在代码视图上（两个方向都钉）
    const commented = '// 以前这里是 buildDateRangeFilter(startDate, endDate)\nconst x = 1;\n';
    expect(callSitesInCode('synthetic.js', jsCodeOnly(commented))).toEqual([]);
    expect(callSitesInCode('synthetic.js', commented)).toHaveLength(1);
    // 实参算术：0/2/3 参各钉一次，带括号的嵌套实参必须标 unparsed（不许被逗号数误判成 3 参）
    expect(siteFromArgs('synthetic.js', '', '')).toMatchObject({ arity: 0, unparsed: false });
    expect(siteFromArgs('synthetic.js', 'startDate, endDate', '')).toMatchObject({
      arity: 2,
      unparsed: false,
    });
    // 嵌套实参这条是实测出来的：逗号数会把 `resolveQueryTimezone(req, res)` 数成两个实参 ⇒ arity=4，
    // 比真实的 3 参**多**。这正是 `unparsed` 的全部意义：算术在没建模的形态上是错的，所以判据
    // 必须在 unparsed 的点上作废 arity（而不是拿它去记欠账——数多了会把"没传 tz"漏记）。
    expect(siteFromArgs('synthetic.js', 'a, b, resolveQueryTimezone(req, res)', '')).toMatchObject({
      arity: 4,
      unparsed: true,
    });
    // 接线方向：真清单由 callSitesInCode 逐文件拼出来。清单写死成 4 条 ⇒ 扫描器一瞎（改名、
    // 漏目录、跳过某个文件）这条就红，而不是只剩"总数不够"这种弱信号。
    expect(
      dateFilterCallSites()
        .map((s) => `${s.module}:${s.arity}`)
        .sort()
    ).toEqual([
      'controllers/reportController.js:3',
      'controllers/reportController.js:3',
      'services/reportStatsService.js:2',
      'services/reportStatsService.js:2',
    ]);
  });

  test('接线：真实调用点的 code 视图确实来自文件（采集器不挂在空气上）', () => {
    const stats = codeViewOf('services/reportStatsService.js');
    expect(stats).toMatch(/buildDateRangeFilter\(startDate, endDate\)/);
    expect(/resolveQueryTimezone/.test(stats)).toBe(false);
    const ctrl = codeViewOf('controllers/reportController.js');
    expect(ctrl).toMatch(/buildDateRangeFilter\(startDate, endDate, tz\)/);
    expect(/resolveQueryTimezone/.test(ctrl)).toBe(true);
  });
});
