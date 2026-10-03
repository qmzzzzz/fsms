/**
 * 测试钩子导出门禁：`_` / `__` 前缀的生产导出必须有真实消费者。
 *
 * 【契约】
 * 下划线前缀是仓内既有的"仅供用例使用的内部细节"惯例（`__resetForTest`、`_store`、
 * `__MIN_INTERVAL_MS`…）。它同时是最容易腐烂的导出面：用例改名或删掉之后，生产侧
 * 仍挂着这个键，而"挂着"看起来像"有契约"——下一个读代码的人以为阈值被钉住了，
 * 实际上没有任何用例在钉。本轮实测到 3 个这种孤儿（生产码、用例树、scripts/、e2e/
 * 全部零引用），已删：
 *   services/auditChainMonitor.js  __DEFAULT_INTERVAL_MS / __MAX_WINDOW_RECORDS
 *   utils/metricsRuntime.js        _readyzChecks
 *
 * 【判据】
 * 1) 钩子面 = 两种导出形态的并集：
 *    a. `module.exports = {…}` 的**深度 1** 键（嵌套对象里的键如
 *       `__test: { dashboardCache }` 不是模块契约的一部分，不能被当钩子统计）；
 *    b. 属性式 `module.exports.X = …` / `exports.X = …`（本仓 6 个真实站点用的就是这种，
 *       老版本扫描器对它失明——R10-D 变异 M1 实测 SURVIVED，已修）。
 *    两个解析器各用真实文件 + 合成样例双向自证（见第 1、2 条用例）；再叠一条
 *    "导出形态完整性"（第 3 条）：写了 `module.exports` 却两种口径都认不出的文件
 *    必须进封闭清单，第三种形态（Object.assign / 动态挂键）因此无法静默隐身。
 * 2) 宽口径消费：钩子名作为标识符出现在 用例树 / scripts / e2e。
 * 3) 严口径消费：出现该名字的那个文件还得 require 产出模块 —— 只满足宽口径
 *    就是"同名标识符假绿"（别的模块里恰好也有 `__test`）。唯一例外走登记表，
 *    并且当场验证例外成立的前提（重导出那一行确实存在），登记表本身也不会腐烂。
 * 4) 数量钉死：钩子总数只许减不许增（与 permissionCatalogRouteParity 同口径，
 *    钉的是"不许再多一个"，不是"应当为 0"）。
 *
 * 【为什么不在这里 require 生产模块】
 * auditBuffer / auditChainMonitor / metricsRuntime 等在加载期会起定时器或连 Redis，
 * 纯静态门禁把它们拉进 worker 只会带来悬挂句柄与并发串扰。键名由静态解析保证存在；
 * 值是否可用属于各模块自己的用例面。
 */
const fs = require('fs');
const path = require('path');

const SRC_DIR = path.resolve(__dirname, '../..');
const ROOT_DIR = path.resolve(SRC_DIR, '..');

/** 生产码文件（跳过 tests 与 node_modules），与仓内其余静态闸同口径 */
function listProdFiles(dir = SRC_DIR, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listProdFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/** 消费侧：用例树全量（含 helper，不只 *.test.js）+ scripts + e2e */
function listJsRecursive(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listJsRecursive(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

const CONSUMER_ROOTS = [
  path.join(SRC_DIR, 'tests'),
  path.join(ROOT_DIR, 'scripts'),
  path.join(ROOT_DIR, 'e2e'),
];

/**
 * 行注释与块注释都剥掉：注释里提到钩子名不算消费。
 * 口径取自 helpers/jsCodeOnly（全仓唯一实现），不再用本文件早先那份局部 stripComments：
 * 那份只删"整行注释"，**行尾** `foo; // __resetForTest` 会原样留下——于是一个只写在
 * 行尾注释里的钩子名，配上同文件里的 require，就能冒充严口径消费者（假绿）。
 * 已探针实测：当前树上两类差集都是 0，所以这条腿必须由下面的合成反例喂，不能指望真数据。
 */
const { jsCodeOnly: stripComments } = require('../helpers/jsCodeOnly');

/**
 * 取 `module.exports = {…}` 里深度 1 的键名。
 * 手写小解析器而不是正则：正则的 `[\s\S]*?^\}` 会在导出块里出现嵌套对象闭行时
 * 提前截断，把后面的键整段漏掉——那正是"门看起来在跑、其实什么都看不见"的形态。
 */
function topLevelExportKeys(src) {
  const start = src.search(/^module\.exports\s*=\s*\{/m);
  if (start === -1) return [];
  const open = src.indexOf('{', start);
  const keys = [];
  let depth = 0;
  let token = '';
  const flush = () => {
    const m = token.match(/([A-Za-z_$][\w$]*)/);
    if (m && depth === 1) keys.push(m[1]);
    token = '';
  };
  for (let i = open; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '{' || ch === '[' || ch === '(') depth += 1;
    else if (ch === '}' || ch === ']' || ch === ')') {
      // 深度 1 的闭括号就是导出块本身：先按"仍在块内"结算最后一个键，再返回
      if (depth === 1) {
        flush();
        return keys;
      }
      depth -= 1;
    } else if (depth === 1 && (ch === ',' || ch === '\n')) flush();
    else if (depth > 1) continue;
    if (depth >= 1) token += ch;
  }
  return keys; // 未闭合（理论上不该发生）：返回已收集部分，由自证用例发现
}

const HOOK = /^_{1,2}[A-Za-z]/;

/**
 * 第二种导出形态：属性式 `module.exports.X = …` / `exports.X = …`，
 * 以及等价的下标式 `module.exports['X'] = …`。
 * 只认第一种（`module.exports = {…}`）时，本仓 6 个真实站点
 * （middleware/errorHandler.js:199-200、middleware/queryLimit.js:164-165、
 * routes/wellKnownRoutes.js:269-270）整块对扫描器隐形：往那里加一个
 * `module.exports.__orphan = …` 钩子数不变、宽严两口径都用不上，门禁全绿——
 * 2026-10-01 R10-D 变异实测 SURVIVED（mut-round11 M1），本函数即其修复。
 * `=(?!=)` 是必要的：`module.exports.x === y` 是读不是写，读不该算导出。
 */
function propertyExportKeys(src) {
  const names = new Set();
  for (const m of src.matchAll(
    /^[\t ]*(?:module\.)?exports\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*['"]([A-Za-z_$][\w$]*)['"]\s*\])\s*=(?!=)/gm
  )) {
    names.add(m[1] || m[2]);
  }
  return [...names];
}

const prodSrc = new Map(
  listProdFiles().map((f) => [
    path.relative(SRC_DIR, f).replace(/\\/g, '/'),
    stripComments(fs.readFileSync(f, 'utf8')),
  ])
);

/** 一个文件的钩子面 = 两种导出形态的并集里带 `_`/`__` 前缀的那些 */
function hookNamesOf(src) {
  return [...new Set([...topLevelExportKeys(src), ...propertyExportKeys(src)]).keys()].filter((k) =>
    HOOK.test(k)
  );
}

const hooks = [];
for (const [rel, src] of prodSrc) {
  for (const name of hookNamesOf(src)) hooks.push({ rel, name, module: path.basename(rel, '.js') });
}
hooks.sort((a, b) => a.rel.localeCompare(b.rel) || a.name.localeCompare(b.name));

/**
 * 本文件自身不算消费侧。不是洁癖，是实测：给"严口径"补一条正向反例（文本里同时出现
 * `__test` 与 `require('../services/reportDashboardService')`）之后，`例外登记表可被证伪`
 * 那条用例当场由 0 变 1——消费扫描把**自己的合成样本**当成了真实消费者，于是
 * "这个钩子确实没人直接 require"这一登记前提被闸自己造了出来。
 * 残余（闸管不到的那半）：任何测试文件里的合成样本文本都算消费者，本闸只能保证自己不干这事。
 */
const SELF_REL = path.relative(ROOT_DIR, __filename).replace(/\\/g, '/');
const consumerFiles = CONSUMER_ROOTS.flatMap((d) => listJsRecursive(d))
  .map((f) => ({
    rel: path.relative(ROOT_DIR, f).replace(/\\/g, '/'),
    src: stripComments(fs.readFileSync(f, 'utf8')),
  }))
  .filter((f) => f.rel !== SELF_REL);

const wordRe = (name) => new RegExp(`\\b${name.replace(/\$/g, '\\$')}\\b`);
/**
 * 两个口径都按"文件表 + 钩子"求值，真消费树与合成反例共用同一份实现。
 * 为什么必须能喂文件表：反例要证的是"**这把尺子**认不出同名不同源的文件"。此前反例把
 * 两条 filter 手抄在用例里（`wordRe('__test')` + 一条自己写的 require 正则），于是把下面
 * strictConsumersIn 的 require 匹配改窄/改宽时，真清单用例照绿、反例也照绿——判据与自证各量各的。
 */
const looseConsumersIn = (files, h) => files.filter((f) => wordRe(h.name).test(f.src));
const strictConsumersIn = (files, h) =>
  looseConsumersIn(files, h).filter((f) =>
    new RegExp(`require\\([^)]*['"][^'"]*/${h.module}['"]`).test(f.src)
  );
const looseConsumers = (h) => looseConsumersIn(consumerFiles, h);
const strictConsumers = (h) => strictConsumersIn(consumerFiles, h);

/**
 * 登记表：宽口径命中但严口径不命中 = 经由生产侧重导出的间接消费。
 * 例外不是免检——第 5 条用例当场验证它成立的前提行存在。
 */
const INDIRECT_EXPORT = [
  {
    rel: 'services/reportDashboardService.js',
    name: '__test',
    via: 'controllers/reportController.js',
    premise: '...dashboardService.__test',
    reason: 'reportController.__test 展开复用本模块 __test，用例 require 的是 controller',
  },
  {
    rel: 'utils/metricsAuditDrops.js',
    name: '_auditDrops',
    via: 'utils/metrics.js',
    premise: '_auditDrops: auditDropMetrics._auditDrops',
    reason:
      'metrics.js 汇总转发出站指标钩子，用例经 metrics 门面消费（src/tests/observability/auditDropMetrics.test.js）',
  },
];

const keyOf = (h) => `${h.rel}::${h.name}`;
const registered = (h) => INDIRECT_EXPORT.some((e) => `${e.rel}::${e.name}` === keyOf(h));

/**
 * 前提行的判据（空白不敏感）：登记一条例外要说"某个重导出语句确实存在"，而源码里的换行/缩进
 * 排版随时可能被 prettier 改动，所以按"抹掉所有空白后的包含"来判。
 * 抽成一处是因为它必须能被合成反例喂：只用真树判的话，`toContain` 换成 `()=>true` 门禁全绿
 * （R30-6 的刀口），而"这条腿到底在不在数"没有任何证据。
 */
const premiseHolds = (src, premise) =>
  String(src).replace(/\s+/g, '').includes(String(premise).replace(/\s+/g, ''));

/**
 * 第三种导出形态的"零容忍"清单：写了 `module.exports` 但两个扫描器都认不出的文件。
 * 实测这 36 个全部是**单值导出**（`module.exports = router` / `mongoose.model(...)` /
 * 一个 class 或 service 实例），本身不具名 ⇒ 没有钩子面。清单的意义不是"文件数恰好如此"，
 * 而是：有人往这些文件加**任何一种具名导出**时，该文件立刻从清单里掉出去、门禁变红，
 * 逼一次评审；`Object.assign(module.exports, {__x})`、循环动态挂键等真正的新形态同理无处藏。
 */
const EXPORT_FORM_UNRECOGNISED = [
  // 中间件/工具：导出单个函数或类
  'middleware/requestId.js',
  'utils/ApiError.js',
  'utils/apiResponse.js',
  'utils/logger.js',
  'plugins/autoIncrement.js',
  'config/database.js',
  'docs/generate.js',
  // 模型：`module.exports = mongoose.model(...)`
  'models/AuditLog.js',
  'models/FireAlarm.js',
  'models/FireDevice.js',
  'models/IPBlacklist.js',
  'models/Inspection.js',
  'models/Permission.js',
  'models/Role.js',
  'models/SystemConfig.js',
  'models/TokenBlacklist.js',
  'models/User.js',
  'models/UserSession.js',
  // 路由：`module.exports = router`
  'routes/alarmRoutes.js',
  'routes/authRoutes.js',
  'routes/deviceRoutes.js',
  'routes/inspectionRoutes.js',
  'routes/permissionRoutes.js',
  'routes/reportRoutes.js',
  'routes/roleRoutes.js',
  'routes/securityRoutes.js',
  'routes/userRoutes.js',
  // 服务：导出单例实例
  'services/AlarmService.js',
  'services/DeviceService.js',
  'services/InspectionService.js',
  'services/permissionService.js',
  'services/roleService.js',
  'services/userService.js',
  'services/websocketService.js',
].sort();

function unaccountedExportFiles() {
  const out = [];
  for (const [rel, src] of prodSrc) {
    if (!/module\.exports/.test(src)) continue;
    if (topLevelExportKeys(src).length + propertyExportKeys(src).length === 0) out.push(rel);
  }
  return out.sort();
}

describe('测试钩子导出门禁：`_`/`__` 前缀的生产导出必须有真实消费者', () => {
  it('解析器自证：真实文件的深度 1 键清单 = 源码字面清单；嵌套键不计入', () => {
    // 真样本：auditChainMonitor 的导出块就是这 8 个键
    expect(topLevelExportKeys(prodSrc.get('services/auditChainMonitor.js')).sort()).toEqual(
      [
        '__MIN_INTERVAL_MS',
        '__MIN_ROUND_BUDGET_MS',
        '__resetForTest',
        'getHealth',
        'isRunning',
        'runVerification',
        'start',
        'stop',
      ].sort()
    );

    // 合成样本 1：嵌套对象的键不得算作顶层导出（否则 `__test` 的下级会被重复统计）
    const nested = `module.exports = {\n  getDashboardData,\n  __test: {\n    dashboardCache,\n    DASHBOARD_CACHE_MAX_ENTRIES,\n  },\n};`;
    expect(topLevelExportKeys(nested)).toEqual(['getDashboardData', '__test']);

    // 合成样本 2：导出块里出现"行首 }"形态的嵌套对象时，正则式 [\s\S]*?^\} 会提前截断；
    // 本解析器必须仍然看到后面的键（这就是不用正则的理由，反向对照）
    const tricky =
      'module.exports = {\n  a,\n  fn: () => {\n    return 1;\n  },\n  __afterTricky: 2,\n};';
    expect(topLevelExportKeys(tricky)).toEqual(['a', 'fn', '__afterTricky']);

    // 合成样本 3：单行导出
    expect(topLevelExportKeys('module.exports = { __one, two };')).toEqual(['__one', 'two']);
  });

  it('属性式导出扫描器自证：三个真实站点逐字点名 + 读不算写', () => {
    // 真样本：这三个文件用的是 `module.exports = fn;` + 属性式追加，
    // 老版本扫描器对它们完全失明（R10-D 变异 M1 的实测依据）
    expect(propertyExportKeys(prodSrc.get('middleware/errorHandler.js'))).toEqual([
      'asyncHandler',
      'markResponseAbortedByError',
    ]);
    expect(propertyExportKeys(prodSrc.get('middleware/queryLimit.js'))).toEqual([
      'queryLengthLimit',
      'queryScalarGuard',
    ]);
    expect(propertyExportKeys(prodSrc.get('routes/wellKnownRoutes.js'))).toEqual([
      'buildSecurityTxt',
      'normalizeReport',
    ]);
    // 前提自证：真实站点确实≥6 个名字，否则上面三条可能是空转
    const realNames = new Set([...prodSrc.values()].flatMap((src) => propertyExportKeys(src)));
    expect(realNames.size).toBeGreaterThanOrEqual(6);

    // 合成：块式与属性式不重叠（同一份源码，各扫各的形态）
    expect(propertyExportKeys('module.exports = { __one, two };')).toEqual([]);
    expect(hookNamesOf('module.exports = { __one, two };')).toEqual(['__one']);
    // 合成：属性式钩子必须进钩子面（M1 修复的对偶用例）
    expect(hookNamesOf('module.exports.__mutOrphanProbe = { hits: 1 };')).toEqual([
      '__mutOrphanProbe',
    ]);
    expect(hookNamesOf('exports._alias = 1;\nmodule.exports.__b = 2;')).toEqual(['_alias', '__b']);
    // `===` 是读不是写：比较语句不该被当成导出（否则消费侧一行 `x.__y === z` 就冒充契约）
    expect(propertyExportKeys('if (module.exports.__maybe === 1) throw new Error("x");')).toEqual(
      []
    );
  });

  it('导出形态完整性：写了 module.exports 却两种口径都认不出的文件必须逐一登记', () => {
    const unaccounted = unaccountedExportFiles();
    expect(unaccounted).toEqual(EXPORT_FORM_UNRECOGNISED);
    // 前提自证：清单里的每个文件确实"只有一个导出值"——注释里的分类不是想当然
    for (const rel of EXPORT_FORM_UNRECOGNISED) {
      const lines = prodSrc
        .get(rel)
        .split(/\r?\n/)
        .filter((l) => /^module\.exports\s*=/.test(l));
      expect(lines).toHaveLength(1);
      // 单值导出：等号右边不是 `{`（那属于块式，会被第一个扫描器认下）
      expect(lines[0]).not.toMatch(/^module\.exports\s*=\s*\{/);
    }
    // 反向对照：把其中一条改成具名导出，它必须从清单里掉出去（=门禁响）
    const mutated = prodSrc
      .get('middleware/requestId.js')
      .replace(/^module\.exports\s*=\s*requestId;/m, 'module.exports = { requestId, __probe };');
    expect(topLevelExportKeys(mutated)).toEqual(['requestId', '__probe']);
    expect(hookNamesOf(mutated)).toEqual(['__probe']);
    // 下标式具名导出同样不能隐身（第三种语法形态）
    expect(hookNamesOf("module.exports['__bracket'] = 1;")).toEqual(['__bracket']);
    expect(propertyExportKeys('const v = module.exports["_read"];')).toEqual([]);
  });

  it('钩子总数钉死：只许减不许增（当前 30 个），且成员可点名', () => {
    expect(hooks.length).toBe(30);
    const keys = hooks.map(keyOf);
    for (const must of [
      'services/auditBuffer.js::__resetForTest',
      'services/auditChainMonitor.js::__MIN_ROUND_BUDGET_MS',
      'utils/metrics.js::_counters',
      'services/statsCache.js::_store',
      'utils/loginCipher.js::_resetForTests',
      // 单行导出块（`module.exports = { a, _resetForTests };`）——正则口径会整块漏掉，
      // 实测漏掉 utils/transaction.js:102 与 utils/metricsAuditDrops.js:87 两处
      'utils/transaction.js::_resetForTests',
      'utils/metricsAuditDrops.js::_auditDrops',
    ])
      expect(keys).toContain(must);
  });

  it('本轮删掉的 3 个孤儿钩子不得回来', () => {
    const gone = [
      ['services/auditChainMonitor.js', '__DEFAULT_INTERVAL_MS'],
      ['services/auditChainMonitor.js', '__MAX_WINDOW_RECORDS'],
      ['utils/metricsRuntime.js', '_readyzChecks'],
    ];
    for (const [rel, name] of gone) {
      const src = prodSrc.get(rel);
      expect(src).toBeDefined();
      expect(topLevelExportKeys(src)).not.toContain(name);
      expect(hooks.map(keyOf)).not.toContain(`${rel}::${name}`);
    }
  });

  it('宽口径：每个钩子至少被 用例树 / scripts / e2e 引用一次', () => {
    const orphans = hooks.filter((h) => looseConsumers(h).length === 0).map(keyOf);
    expect(orphans).toEqual([]);
  });

  it('严口径：引用它的文件必须真的 require 了产出模块（同名标识符不算消费）', () => {
    const unpaired = hooks
      .filter((h) => !registered(h) && strictConsumers(h).length === 0)
      .map(
        (h) =>
          `${keyOf(h)} <- ${looseConsumers(h)
            .map((f) => f.rel)
            .slice(0, 2)
            .join(',')}`
      );
    expect(unpaired).toEqual([]);
  });

  it('例外登记表可被证伪：间接重导出的前提行确实存在，且它确实是宽过严不过', () => {
    for (const e of INDIRECT_EXPORT) {
      const hook = hooks.find((h) => keyOf(h) === `${e.rel}::${e.name}`);
      expect(hook).toBeDefined(); // 登记的钩子若已被删，这条就是腐烂的例外
      const viaSrc = prodSrc.get(e.via);
      expect(viaSrc).toBeDefined();
      expect(premiseHolds(viaSrc, e.premise)).toBe(true);
      // 同一把尺子必须也能说"不"，否则上面那条 true 可能只是判据恒真
      expect(premiseHolds(viaSrc, `${e.premise}__NOT_IN_SOURCE`)).toBe(false);
      expect(premiseHolds('', e.premise)).toBe(false);
      expect(looseConsumers(hook).length).toBeGreaterThan(0);
      expect(strictConsumers(hook).length).toBe(0);
    }
  });

  it('登记表既不能缺也不能多：宽过严不过的钩子集合与 INDIRECT_EXPORT 逐字相等', () => {
    // 缺 ⇒ 有钩子靠"同名假绿"蒙过严口径却没人负责；多 ⇒ 有人新增一条免检项把真违规登记掉。
    // 只断言"每条登记都成立"（上一条用例）拦不住"多"，所以这里做双向集合相等。
    const violators = hooks
      .filter((h) => looseConsumers(h).length > 0 && strictConsumers(h).length === 0)
      .map(keyOf)
      .sort();
    expect(violators).toEqual(INDIRECT_EXPORT.map((e) => `${e.rel}::${e.name}`).sort());
  });

  it('反向对照：合成死钩子被宽口径拦下；同名但未 require 被严口径识破', () => {
    const synthProd = 'module.exports = {\n  x,\n  __deadHookForControl: 1,\n};\n';
    expect(topLevelExportKeys(synthProd)).toEqual(['x', '__deadHookForControl']);
    // 两条口径都跑在**同一个实现**上（looseConsumersIn / strictConsumersIn），只是喂合成文件表
    const files = (rel, src) => [{ rel, src }];
    const deadHook = { rel: 'services/x.js', name: '__deadHookForControl', module: 'x' };
    const unrelated = files('a.test.js', `const a = require('../services/unrelated');\na.__other;`);
    expect(looseConsumersIn(unrelated, deadHook)).toHaveLength(0);
    expect(strictConsumersIn(unrelated, deadHook)).toHaveLength(0);
    // 同一条文件表喂真钩子必须命中，否则上面两条"零命中"可能只是喂了张空表
    expect(
      looseConsumersIn(files('b.test.js', 'svc.__deadHookForControl;'), deadHook)
    ).toHaveLength(1);

    // 同名标识符假绿：引用 `__test` 的文件 require 的是别的模块
    const testHook = {
      rel: 'services/reportDashboardService.js',
      name: '__test',
      module: 'reportDashboardService',
    };
    const fake = files(
      'b.test.js',
      `const c = require('../controllers/reportController');\nc.__test;`
    );
    expect(looseConsumersIn(fake, testHook)).toHaveLength(1);
    expect(strictConsumersIn(fake, testHook)).toHaveLength(0);
    // 反过来：require 了产出模块的文件必须被严口径认下（否则严口径可以是"恒不命中"）
    expect(
      strictConsumersIn(
        files('c.test.js', `const d = require('../services/reportDashboardService');\nd.__test;`),
        testHook
      )
    ).toHaveLength(1);
  });

  it('注释剥离这条腿有合成反例：消费侧看行尾注释，生产侧看块注释里的赋值（真树上两类命中实测 0 处）', () => {
    const h = { rel: 'services/auditBuffer.js', name: '__resetForTest', module: 'auditBuffer' };
    const files = (rel, src) => [{ rel, src }];
    // 消费侧：钩子名只出现在**行尾**注释里。本文件早先那份局部 stripComments 看不见这一层，
    // 于是"注释里提到"会被当成消费——这正是"防御性剥离在树上无对抗输入时不可观测"的形态。
    const trailing =
      'const m = require("../services/auditBuffer");\nm.reset(); // 旧名 __resetForTest';
    expect(stripComments(trailing)).not.toContain('__resetForTest');
    expect(stripComments(trailing)).toContain('require("../services/auditBuffer")');
    // 判据跑在视图上：同一份原文喂进去=消费者，喂剥过的视图=不是消费者（两条都要，缺一腿可恒真）
    expect(looseConsumersIn(files('t.test.js', trailing), h)).toHaveLength(1);
    expect(looseConsumersIn(files('t.test.js', stripComments(trailing)), h)).toHaveLength(0);

    // 生产侧：块注释里独起一行的 `module.exports.__x = 1;` 会被属性式扫描器的 `^` 锚点命中，
    // 剥注释之后那行只剩空格 ⇒ 不计入钩子面（否则文档里的示例代码会冒充真导出）
    const documented = '/*\nmodule.exports.__inBlock = 1;\n*/\nmodule.exports = { a };\n';
    expect(propertyExportKeys(documented)).toEqual(['__inBlock']);
    expect(hookNamesOf(stripComments(documented))).toEqual([]);
    // 整行 `//` 与 ` *` 续写行同样必须在视图里消失：顶层导出解析器逐字符走，注释对它不透明，
    // 不剥就会把注释里的示例键当真导出（下面两行分别是"原文命中/视图不命中"的两向证据）
    const inline = 'module.exports = {\n  a,\n  // __inLineComment,\n};\n';
    expect(hookNamesOf(inline)).toEqual(['__inLineComment']);
    expect(hookNamesOf(stripComments(inline))).toEqual([]);
    expect(topLevelExportKeys(stripComments(inline))).toEqual(['a']);
  });

  it('口径自证：消费侧根目录不是空集（scripts / e2e 真被扫到）', () => {
    expect(consumerFiles.filter((f) => f.rel.startsWith('src/tests/')).length).toBeGreaterThan(300);
    expect(consumerFiles.filter((f) => f.rel.startsWith('scripts/')).length).toBeGreaterThan(0);
    expect(consumerFiles.filter((f) => f.rel.startsWith('e2e/')).length).toBeGreaterThan(0);
    // 自排除两头都有牙：本文件确实落在消费根之一里（删掉 filter 就会被扫进，正向反例正是这样
    // 把自己数成消费者的），而消费表里查不到它。
    expect(
      listJsRecursive(CONSUMER_ROOTS[0]).some((f) => path.resolve(f) === path.resolve(__filename))
    ).toBe(true);
    expect(consumerFiles.map((f) => f.rel)).not.toContain(SELF_REL);
  });
});
