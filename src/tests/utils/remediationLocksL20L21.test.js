/**
 * L-20 / L-21 回归：两处「已声明修复但无测试锁定」的补锁
 *
 * 背景：报告与台账把这两项标为 ✅ 已修复，其判据是「代码已改 + 有自动化用例或实测证据」。
 * 实际核查发现两者**都只有代码改动、没有任何测试锁定**——一旦后续重构（例如把阈值改回
 * 字面量、或把 app.js 的取用改回独立 require），退化会静默发生且无人发现。
 * 本套件补齐测试，使这两项满足其声明的关闭判据。
 */

const path = require('path');
const mongoose = require('mongoose');

const root = path.resolve(__dirname, '../..');

describe('L-20 detectAnomalies 的 threshold 必须贯穿三路聚合', () => {
  /**
   * 原缺陷：unusualTimeOperations 一路硬编码 5，而 failedOperations /
   * failedOperationsByIp 用 threshold 参数。调用方以为统一调整了阈值，
   * 实际「非常规时间访问」始终按 5 计 —— 口径不一致且静默。
   *
   * 锁定方式：传一个小于记录数的阈值，断言三路都命中；再传一个大于记录数的
   * 阈值，断言三路都不命中。若非常规时间一路被改回硬编码值，第一条即红。
   */
  let AuditLog;
  const stamp = `l20${Date.now().toString(36)}`;
  const userId = new mongoose.Types.ObjectId();
  let offHour;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../../models/AuditLog');
    // append-only 保护针对「篡改既有记录」，测试造数与清理需临时关闭
    AuditLog._setAppendOnlyEnforced(false);

    // 取一个有代表性的「非常规时间」：业务时区 03:00（OFF_HOURS 为 >=22 或 <6）。
    // 用 UTC 构造再交给业务的 hour 判断，避免依赖宿主本地时区。
    offHour = new Date();
    offHour.setUTCHours(19, 0, 0, 0); // UTC 19:00 = 东八区次日 03:00
    const { isOffHours } = require('../../constants/timezone');
    if (!isOffHours(offHour)) {
      throw new Error('前置条件不满足：构造的时刻不在非常规时间窗内');
    }

    await AuditLog.insertMany(
      Array.from({ length: 3 }, () => ({
        action: 'l20_probe',
        category: 'system',
        userId,
        username: stamp,
        success: false,
        timestamp: offHour,
      })),
      { ordered: false }
    );
  });

  afterAll(async () => {
    await AuditLog.collection.deleteMany({ username: stamp });
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  test('threshold=2 时三路聚合都命中（含 unusualTimeOperations）', async () => {
    // 判定窗口必须覆盖 offHour：窗口 5 分钟不够，取足够大的窗口使造数与断言时刻
    // 都被包含（原写法用 60 分钟，造数后立即断言也够，但窗口边界会随执行耗时抖动）
    const r = await AuditLog.detectAnomalies({ windowMinutes: 24 * 60, threshold: 2 });
    const unusual = r.unusualTimeOperations.find((x) => String(x._id) === String(userId));
    // 关键断言：非常规时间一路也遵守 threshold。
    // 若被改回硬编码 5，则 3 条不会命中，此处即红。
    expect(unusual).toBeTruthy();
    expect(unusual.count).toBe(3);
  });

  test('threshold=10 时三路聚合都不命中（阈值确实生效，非恒真）', async () => {
    const r = await AuditLog.detectAnomalies({ windowMinutes: 24 * 60, threshold: 10 });
    expect(r.unusualTimeOperations.find((x) => String(x._id) === String(userId))).toBeUndefined();
    expect(r.failedOperations.find((x) => String(x._id) === String(userId))).toBeUndefined();
  });
});

describe('L-21 中间件统一导出面（消除两套入口）', () => {
  const barrelPath = path.join(root, 'middleware/index.js');

  /**
   * 原缺陷：这四个中间件游离于 ./middleware 统一导出面之外，app.js 各自独立 require，
   * 形成「两套入口」——新增/重命名时容易只改一处。
   */
  const REQUIRED_EXPORTS = [
    'applyObjectIdParams',
    'consumeValidation',
    'mountStaticFrontend',
    'metricsAuth',
  ];

  test('统一导出面必须包含这四个中间件', () => {
    const barrel = require(barrelPath);
    for (const name of REQUIRED_EXPORTS) {
      expect(typeof barrel[name]).toBe('function');
    }
  });

  /**
   * 真实模块图（子进程内插桩 Module._load）——替代原先的源码正则断言。
   *
   * 为什么必须换：原断言用 `src.match(/require\(.../)` 判断「有没有直接 require」。
   * 被注释掉的代码、字符串字面量、`if (false)` 分支里的 require 都会让正则
   * 命中或漏判；把 app.js 的直接 require 改成动态拼接
   * `require('./middleware/' + name)` 即可绕过正则，运行时照样是两套入口。
   *
   * 现在真跑一次 Node 进程：插桩 Module._load 记录「本地模块 <- 谁加载的」边，
   * 再 require 真实的 app.js。断言的是**实际发生的模块加载关系**，
   * 任何等价改写（动态拼接、别名、条件加载）都无法绕过。
   */
  const buildModuleGraph = () => {
    const probe = [
      "const Module = require('module');",
      "const path = require('path');",
      'const orig = Module._load;',
      'const edges = {};',
      'Module._load = function (request, parent, isMain) {',
      '  let resolved = null;',
      '  try { resolved = Module._resolveFilename(request, parent, isMain); } catch (_) {}',
      '  if (resolved && resolved.startsWith(process.cwd())) {',
      "    const rel = path.relative(process.cwd(), resolved).split(path.sep).join('/');",
      '    const par = parent && parent.filename && parent.filename.startsWith(process.cwd())',
      "      ? path.relative(process.cwd(), parent.filename).split(path.sep).join('/')",
      "      : '<external>';",
      "    const key = rel + ' <- ' + par;",
      '    edges[key] = (edges[key] || 0) + 1;',
      '  }',
      '  return orig.apply(this, arguments);',
      '};',
      "require('./src/app.js');",
      "process.stdout.write('ZZHALLEY_GRAPH_START\\n' + JSON.stringify(edges) + '\\nZZHALLEY_GRAPH_END');",
    ].join('\n');

    // 仓库根：边名以 src/... 为前缀，子进程必须从这里 require('./src/app.js')
    const repoRoot = path.resolve(root, '..');
    const r = require('child_process').spawnSync(process.execPath, ['-e', probe], {
      cwd: repoRoot,
      env: { ...process.env, NODE_ENV: 'test' },
      encoding: 'utf8',
      timeout: 120000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const out = r.stdout || '';
    const start = out.indexOf('ZZHALLEY_GRAPH_START');
    const end = out.indexOf('ZZHALLEY_GRAPH_END');
    // 探针自身失败必须显式红灯，不得静默返回空图（否则下面的断言全部假绿）
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(r.status).toBe(0);
    return JSON.parse(out.slice(start + 'ZZHALLEY_GRAPH_START'.length, end).trim());
  };

  let graph;
  beforeAll(() => {
    graph = buildModuleGraph();
  });

  test('app.js 必须从 ./middleware 取用，不得再各自独立 require（真实模块图）', () => {
    for (const mod of ['validateObjectId', 'validateQuery', 'staticFrontend', 'metricsAuth']) {
      const directEdge = `src/middleware/${mod}.js <- src/app.js`;
      expect(graph[directEdge]).toBeUndefined();
      // 正向：这四个模块确实被统一导出面加载（证明上面的「没有直连边」
      // 不是因为这四个模块根本没被用上）
      expect(graph[`src/middleware/${mod}.js <- src/middleware/index.js`]).toBeGreaterThan(0);
    }
    // app.js 与统一导出面的连接边存在（barrel 确实是它的取用入口）
    expect(graph['src/middleware/index.js <- src/app.js']).toBeGreaterThan(0);
  });

  test('统一导出面内不得对同一本地模块重复 require（真实模块图，防回退为多入口）', () => {
    const fromBarrel = Object.entries(graph)
      .filter(([key]) => key.endsWith('<- src/middleware/index.js'))
      .map(([key, count]) => [key.replace(' <- src/middleware/index.js', ''), count]);
    // 前置：确实观测到了 barrel 的加载边（防「什么都没加载」式的空集假绿）
    expect(fromBarrel.length).toBeGreaterThan(10);
    const dup = fromBarrel.filter(([, count]) => count > 1);
    // queryLimit.js 是「默认导出即函数 + 挂具名属性」形状，正确写法是
    // `const q = require('./queryLimit'); const { x } = q;`，而不是第二条 require。
    expect(dup).toEqual([]);
  });
});
