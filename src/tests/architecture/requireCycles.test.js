/**
 * 依赖图无环断言
 *
 * 本测试做三件事：
 *   1. 静态解析 src 下所有模块的**顶层** require 边，断言不存在环；
 *   2. 断言函数体内 require 形成的强连通分量（SCC）与 LAZY_SCC 登记一致；
 *   3. 断言这些模块可以被正常加载——静态分析看不见的加载顺序问题由真实
 *      require 兜住；外加每条相对 require 都能解析到真实文件（F-193）。
 *
 * 为什么用静态解析而不是运行时探测：运行时 require 在测试环境里往往
 * 「碰巧」按正确顺序加载，环可能被掩盖；静态图能确定性地暴露它。
 */

const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname, '../../');
/** 仓库相对路径（统一成正斜杠，断言里读得动） */
const relOf = (f) => path.relative(SRC_DIR, f).replace(/\\/g, '/');

/** 递归收集 src 下全部 .js 文件（跳过测试目录自身） */
const collectSourceFiles = (dir, acc = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'tests' || entry.name === 'node_modules') continue;
      collectSourceFiles(full, acc);
    } else if (entry.name.endsWith('.js')) {
      acc.push(full);
    }
  }
  return acc;
};

/**
 * 从源码中提取顶层（模块级）require 的相对路径依赖
 *
 * 只认「位于函数体外」的 require：通过花括号深度判断。函数内的 require
 * （深度 > 0）是刻意打破循环依赖的手段，不构成模块级依赖边。
 *
 * 块注释必须先整段剥掉（与 `codeOnly` 同口径）：注释里描述历史依赖的
 * 引号加 `.` 开头的 require 字样不执行，但会被正则当成真边，凭空造出环。
 * @param {string} source
 * @returns {string[]} 相对路径（原样，未解析）
 */
const extractTopLevelRequires = (source) => {
  const deps = [];
  let depth = 0;
  // 逐字符累计花括号深度：字符串里的花括号仍会干扰深度，但只会把边**藏进**函数体
  // （方向偏保守：漏算不会凭空造环），而注释已由 codeOnly 剥除。
  for (const line of codeOnly(source).split('\n')) {
    const matches = [...line.matchAll(/require\(\s*'(\.[^']+)'\s*\)/g)];
    if (depth === 0) {
      for (const m of matches) deps.push(m[1]);
    }
    for (const ch of line) {
      if (ch === '{') depth += 1;
      else if (ch === '}') depth = Math.max(0, depth - 1);
    }
  }
  return deps;
};

/** 解析相对 require 路径为 src 下的真实文件路径 */
const resolveDep = (fromFile, rel) => {
  const base = path.resolve(path.dirname(fromFile), rel);
  const candidates = [base, `${base}.js`, path.join(base, 'index.js')];
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) return path.normalize(c);
  }
  return null;
};

/** 代码视图：块注释与行注释都剥掉，判据只看会被执行的 require */
const codeOnly = (src) => src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');

/** 全量相对 require（顶层与函数体内都算——解析成不成文件与深度无关） */
const extractRelativeRequires = (src) =>
  [...codeOnly(src).matchAll(/require\(\s*['"](\.[^'"]*)['"]\s*\)/g)].map((m) => m[1]);

/**
 * 解析体检。吃 {file, source} 数组而不是直接读盘：反向臂要喂一份改过的 source，
 * 读盘版探测器只能"对着真实文件断言 0 条解析不到"，永远证不了自己有牙。
 * @param {Array<{file: string, source: string}>} modules
 * @returns {{total: number, unresolved: Array<{file: string, spec: string}>}}
 */
const surveyRequires = (modules) => {
  const unresolved = [];
  let total = 0;
  for (const { file, source } of modules) {
    for (const spec of extractRelativeRequires(source)) {
      total += 1;
      if (resolveDep(file, spec) === null) {
        unresolved.push({ file: relOf(file), spec });
      }
    }
  }
  return { total, unresolved };
};

/**
 * Tarjan 强连通分量（只返回"真环"：节点数 > 1，或带自环的单点）
 *
 * 独立成函数而不是内联，是为了让判据能被合成图反证（见用例里的正向/反向自证）。
 * 入参是 Map<节点, 邻居数组>，与真实文件系统无关。
 * @param {Map<string, string[]>} graph
 * @returns {string[][]} 每个分量的节点（顺序取决于出栈次序，调用方自行排序）
 */
const stronglyConnected = (graph) => {
  const index = new Map();
  const low = new Map();
  const onStack = new Set();
  const stack = [];
  const out = [];
  let counter = 0;

  const connect = (v) => {
    index.set(v, counter);
    low.set(v, counter);
    counter += 1;
    stack.push(v);
    onStack.add(v);
    for (const w of graph.get(v) || []) {
      if (!index.has(w)) {
        connect(w);
        low.set(v, Math.min(low.get(v), low.get(w)));
      } else if (onStack.has(w)) {
        low.set(v, Math.min(low.get(v), index.get(w)));
      }
    }
    if (low.get(v) === index.get(v)) {
      const comp = [];
      let w;
      do {
        w = stack.pop();
        onStack.delete(w);
        comp.push(w);
      } while (w !== v);
      const selfLoop = (graph.get(v) || []).includes(v);
      if (comp.length > 1 || selfLoop) out.push(comp);
    }
  };

  for (const v of graph.keys()) {
    if (!index.has(v)) connect(v);
  }
  return out;
};

/**
 * 已登记的惰性环分量：2 个分量 / 25 个模块（2026-11-03 实测）
 *
 * 2026-10-30 新增成员 `config/jwtRotation.js`（P2-3 密钥轮换）：validate.js 需要按
 * 轮换配置判错，jwtRotation 又要复用 validate 的弱密钥判据，两边都用函数体 require
 * 打断顶层环——于是它并入本分量。方向不变（判据词表 → 配置校验），不是新的依赖倒置。
 *
 * 这一个分量是**有意的双向依赖**，不是遗漏：
 *   · 配置校验要用 metrics 记账，metrics 的告警又经审计缓冲落库，审计缓冲回读配置；
 *   · `constants/runtime` 的就绪探测与 sharedCache 门面互指；
 *   · auditBuffer ↔ auditBufferDocs / auditWal* 是「写入与文档化/容量控制」的双向编排。
 * 消除它需要把审计写入收敛成独立 writer 并迁移 metrics 的初始化边界，属独立一轮重构。
 * 登记在此：新增或消失都会红，逼改动者重新审视依赖方向（整改过程见 CHANGELOG 2026-10-26）。
 *
 * `utils/cookie.js` 为何在分量里（2026-11-02 补登记，不是顺手加一条例外）：
 *   1. 它必须有一条**惰性**边 `utils/cookie.js -> config/validate.js`：cookie 的 Secure 位
 *      要按生产硬闸判据（requiresProductionHardening）定，而 validate.js 在**顶层**已经
 *      require 了 cookie 的 durationToMs（collectJwtDurationErrors，同一实现两处消费）。
 *      若 cookie 顶层再 require validate，加载期即闭环，两侧都拿到半初始化对象。
 *   2. 谁**不能**把这条边提到顶层：任何人（包括本文件的登记者）。提了之后 `require('../utils/cookie')`
 *      在 validate 的加载途中会拿到 { durationToMs: undefined, ... } 而**不报错**，
 *      症状是启动期 collectJwtDurationErrors 静默跳过（校验看起来通过、实际没跑）。
 *      本分量的「惰性边清单」用例守的正是这一点：那条边被提回顶层就会从清单里消失 ⇒ 必红。
 *   3. 分量成员集合的意义：cookie 之所以卷进**这一个**分量（而不是自成一个小环），是因为它同时被
 *      `config/index.js` 顶层引用（config/index.js -> utils/cookie.js 是真实边），而 config/index.js
 *      本身已在分量内（config/index.js -> config/validate.js 惰性）。即：cookie 的入口有两处——
 *      config/index.js（顶层）与 config/validate.js（惰性），前者把它拖进分量，后者提供闭环的那条边。
 *
 * 第 2 个分量 {services/honeypotWatch.js, services/websocketService/handshake.js}
 * （2026-11-03 ，P2-7 WS 侧蜜罐痕迹）：判据在 watch、取址在 handshake——handshake 顶层引用
 * isHoneypotSocket（蜜罐会话的 WS 判据与拒绝痕迹都在本模块）；WS 探测痕迹又要按握手链同一套取址语义算 IP，
 * 反向边只能惰性（提回顶层即加载期互引成环，两侧拿到半初始化对象）。
 */
const LAZY_SCC = [
  [
    'config/deploymentCredentialGuards.js',
    'config/immutableConfigGuard.js',
    'config/index.js',
    'config/jwtRotation.js',
    'config/legacyCbcGuard.js',
    'config/loginEncryptGuard.js',
    'config/validate.js',
    'constants/runtime.js',
    'models/AuditLog.js',
    'models/auditLogHooks.js',
    'models/auditLogWriteStatics.js',
    'services/auditBuffer.js',
    'services/auditBufferDocs.js',
    'services/auditBufferWal.js',
    'services/auditWalCap.js',
    'services/auditWalPermissions.js',
    'services/sharedCache/index.js',
    'services/sharedCacheLocks.js',
    'utils/auditChain.js',
    'utils/auditWriteFailure.js',
    'utils/cookie.js',
    'utils/metrics.js',
    'utils/metricsAuditDrops.js',
    'utils/passwordHistory.js',
  ],
  ['services/honeypotWatch.js', 'services/websocketService/handshake.js'],
];

/**
 * 取出某个分量内部的「只以惰性形式存在」的边（全深度图有、顶层图没有）。
 *
 * 这才是登记 SCC 真正要守的东西：分量是用全深度图算的，把一条惰性边提到顶层时
 * 全深度图不变、分量不变，上一条用例照样绿，而半初始化风险已经落地。把「惰性边清单」
 * 钉住，任何一条被提回顶层就会从清单里消失 ⇒ 本用例转红。
 * @param {string[]} component 分量成员（仓库相对路径）
 * @param {Map<string, Set<string>>} allEdges 全深度 require 图
 * @param {Map<string, Set<string>>} topEdges 顶层 require 图
 * @returns {string[]} 形如 "from -> to"，已排序
 */
const lazyIntraComponentEdges = (component, allEdges, topEdges) => {
  const members = new Set(component);
  const out = [];
  for (const from of component) {
    for (const to of allEdges.get(from) || []) {
      if (!members.has(to)) continue;
      if ((topEdges.get(from) || new Set()).has(to)) continue;
      out.push(`${from} -> ${to}`);
    }
  }
  return out.sort();
};

describe('依赖图无环断言', () => {
  const files = collectSourceFiles(SRC_DIR);
  const known = new Set(files.map((f) => path.normalize(f)));
  const modules = files.map((f) => ({ file: f, source: fs.readFileSync(f, 'utf8') }));
  const resolved = surveyRequires(modules);

  test('src 下存在可分析的文件（防扫描路径漂移导致假绿）', () => {
    expect(files.length).toBeGreaterThan(100);
  });

  // F-193：上面那条"无环"用例对**解析不到**的 require 是瞎的——它 `.filter(d => d && known.has(d))`
  // 把解析失败的目标直接丢掉，于是「把 services/auditBufferDocs.js 改名而漏改调用点」这种改动
  // 既不成环也不变红，只在下一次真实加载时 MODULE_NOT_FOUND。src/ 是整目录 COPY 进镜像的，
  // tests/deploy/imageRequireClosure.test.js 只管"被单独 COPY 的文件"，也看不见这一类。
  //
  // 范围只到 src（不含 tests/）：scripts/ 里合法地嵌着给子进程 `-e` 的 require 字符串
  // （实测：scripts/production-drill.js:198 的 './src/config/validate.js' 按 cwd 而非按
  // 文件解析），literal 解析在那边必须配一份豁免清单，而清单本身会漂移成新的洞。
  test('每条相对 require 都能解析到 src 下的真实文件（改名/删除不再静默消失）', () => {
    expect(resolved.unresolved).toEqual([]);
  });

  test('自检：探测器对"凭空多一条解析不到的 require"必须报红', () => {
    // 地板取自实测 701（155 个生产文件）：正则漂移时会掉到 0，本行先红，
    // 于是上一条的 `toEqual([])` 不会在一个空集合上空转。
    expect(resolved.total).toBeGreaterThan(400);
    // **替换**第一条而不是往数组尾巴上追加：追加会把被改文件自己的 require 再算一遍
    // （实测 +13 而不是 +1），total 的账就说不清"多出来的那一条"到底是谁。
    const [first, ...rest] = modules;
    expect(rest).toHaveLength(modules.length - 1);
    const mutant = surveyRequires([
      { file: first.file, source: `${first.source}\nrequire('./zz_幽灵模块');` },
      ...rest,
    ]);
    expect(mutant.total).toBe(resolved.total + 1);
    expect(mutant.unresolved).toEqual([{ file: relOf(first.file), spec: './zz_幽灵模块' }]);
  });

  test('模块级 require 图无环', () => {
    const graph = new Map();
    for (const f of files) {
      const deps = extractTopLevelRequires(fs.readFileSync(f, 'utf8'))
        .map((rel) => resolveDep(f, rel))
        .filter((d) => d && known.has(d));
      graph.set(path.normalize(f), deps);
    }

    // DFS 三色标记找环，并把环路径完整打印出来（便于直接定位）
    const WHITE = 0;
    const GRAY = 1;
    const BLACK = 2;
    const color = new Map();
    for (const n of graph.keys()) color.set(n, WHITE);
    const stack = [];
    const cycles = [];

    const visit = (node) => {
      color.set(node, GRAY);
      stack.push(node);
      for (const next of graph.get(node) || []) {
        if (color.get(next) === GRAY) {
          const start = stack.indexOf(next);
          cycles.push([...stack.slice(start), next].map((p) => path.relative(SRC_DIR, p)));
        } else if (color.get(next) === WHITE) {
          visit(next);
        }
      }
      stack.pop();
      color.set(node, BLACK);
    };

    for (const n of graph.keys()) {
      if (color.get(n) === WHITE) visit(n);
    }

    expect(cycles).toEqual([]);
  });

  /**
   * 惰性 require 带来的环：**允许存在，但必须被清点**
   *
   * 上面那条"模块级无环"只统计顶层边——函数体内的 require 是有意用来打断环的，
   * 于是它们在静态图里是"隐形的"，而这正是风险所在：环仍然存在，只是被推迟到
   * 调用时刻才结算。谁把其中一条 require 提到顶层，或者在上游模块顶层读对方的
   * 导出，拿到的就是半初始化的对象（症状是 undefined，不报错）。
   *
   * 判据取**强连通分量（SCC）**而不是"环的条数"：同一条回路在环枚举下会被重复
   * 计数（实测该图有 70 条简单环，却只落在 4 个分量里），条数随枚举顺序与深度上限
   * 漂移，分量是唯一且与遍历顺序无关的不变量。2026-10-25 七维审计写的"19 条"
   * 就是环枚举口径下的一个数，本用例以分量口径取代它（见报告 §4.2 的更正）。
   *
   * 分量成员被**逐条登记**：新增一个惰性环、或某条惰性边被提回顶层（分量消失），
   * 都会让本用例变红并要求重新审视，而不是悄悄通过。
   */
  test('惰性 require 形成的强连通分量必须与登记一致', () => {
    const graph = new Map();
    for (const f of files) {
      const deps = extractRelativeRequires(fs.readFileSync(f, 'utf8'))
        .map((rel) => resolveDep(f, rel))
        .filter((d) => d && known.has(d));
      graph.set(
        path.normalize(f),
        deps.map((d) => path.normalize(d))
      );
    }

    const actual = stronglyConnected(graph)
      .map((comp) => comp.map((p) => relOf(p)).sort())
      .sort((a, b) => (a[0] < b[0] ? -1 : 1));

    expect(actual).toEqual(LAZY_SCC.map((comp) => [...comp].sort()));

    // 前提自证：判据对"真环"必须报出来，否则上面那条只是空转
    expect(
      stronglyConnected(
        new Map([
          ['a', ['b']],
          ['b', ['a']],
        ])
      ).map((comp) => comp.sort())
    ).toEqual([['a', 'b']]);
    // 反向自证：单向链不是环
    expect(
      stronglyConnected(
        new Map([
          ['a', ['b']],
          ['b', []],
        ])
      )
    ).toEqual([]);
  });

  /**
   * 惰性边清单（分量内部、只以函数体 require 存在的边）。
   *
   * 27 条 / 2 个分量（2026-11-03 实测）。这张表是**登记表**，不是白名单：
   * 新增一条惰性 require、或把某条提到顶层（清单里少一条），都必须先解释清楚再改这里。
   * 与 LAZY_SCC 的分工：那张表守「哪些模块卷进了环」，这张表守「环是靠哪几条边撑住的」。
   */
  const LAZY_EDGES = [
    'config/deploymentCredentialGuards.js -> config/validate.js',
    'config/immutableConfigGuard.js -> utils/metrics.js',
    'config/immutableConfigGuard.js -> utils/passwordHistory.js',
    'config/index.js -> config/validate.js',
    'config/jwtRotation.js -> config/validate.js',
    'config/legacyCbcGuard.js -> config/immutableConfigGuard.js',
    'config/legacyCbcGuard.js -> utils/metrics.js',
    'config/loginEncryptGuard.js -> utils/metrics.js',
    'config/validate.js -> config/jwtRotation.js',
    'constants/runtime.js -> services/sharedCache/index.js',
    'models/auditLogHooks.js -> utils/auditChain.js',
    'models/auditLogHooks.js -> utils/metrics.js',
    'models/auditLogWriteStatics.js -> utils/metrics.js',
    'services/auditBuffer.js -> utils/auditChain.js',
    'services/auditBuffer.js -> utils/metrics.js',
    'services/auditBufferDocs.js -> utils/metrics.js',
    'services/auditWalCap.js -> utils/metricsAuditDrops.js',
    'services/auditWalPermissions.js -> utils/metrics.js',
    'services/honeypotWatch.js -> services/websocketService/handshake.js',
    'services/sharedCache/index.js -> constants/runtime.js',
    'utils/auditChain.js -> config/index.js',
    'utils/auditWriteFailure.js -> utils/metrics.js',
    'config/validate.js -> utils/cookie.js',
    'utils/cookie.js -> config/validate.js',
    'utils/metricsAuditDrops.js -> services/auditBuffer.js',
    'utils/metricsAuditDrops.js -> services/auditWalCap.js',
    'utils/passwordHistory.js -> config/index.js',
  ];

  describe('惰性边清单', () => {
    const files = collectSourceFiles(SRC_DIR);
    const known = new Set(files.map((f) => path.normalize(f)));
    const build = (extract) => {
      const graph = new Map();
      for (const f of files) {
        const deps = extract(fs.readFileSync(f, 'utf8'))
          .map((rel) => resolveDep(f, rel))
          .filter((d) => d && known.has(d))
          .map((d) => relOf(d));
        graph.set(relOf(f), new Set(deps));
      }
      return graph;
    };

    test('分量内部的惰性边与登记表一致（提回顶层会从清单里消失 ⇒ 必红）', () => {
      const allEdges = build(extractRelativeRequires);
      const topEdges = build(extractTopLevelRequires);
      const actual = LAZY_SCC.flatMap((comp) => lazyIntraComponentEdges(comp, allEdges, topEdges));
      // 两侧都排序：SCC 的遍历序不是语义，只有集合相等才是判据（2026-10-30）
      expect([...actual].sort()).toEqual([...LAZY_EDGES].sort());

      // 自证：同一条边若也出现在顶层图里，它就不再是「惰性边」，判据必须让它消失——
      // 真实图里现在一条都没有，不喂合成反例就证不了这条判据会不会响。
      const comp = ['a', 'b'];
      const all = new Map([
        ['a', new Set(['b'])],
        ['b', new Set(['a'])],
      ]);
      expect(lazyIntraComponentEdges(comp, all, new Map())).toEqual(['a -> b', 'b -> a']);
      expect(lazyIntraComponentEdges(comp, all, new Map([['a', new Set(['b'])]]))).toEqual([
        'b -> a',
      ]);
      // 反向：指向分量外的边不算（否则清单会把普通依赖也算进来）
      expect(lazyIntraComponentEdges(comp, new Map([['a', new Set(['c'])]]), new Map())).toEqual(
        []
      );
    });
  });

  test('涉及循环依赖的模块可被正常加载（加载顺序不炸）', () => {
    // 静态图无环 + 惰性 require 就位后，这里再做一次真实加载兜底：
    // 若某天模块初始化逻辑变化导致加载即抛错，本用例会先于业务用例报错。
    // 覆盖原四个分量的两端与抽出的叶子模块：任何一处把"共享叶子"改回"反向 require"
    // 都会先在这里或上一条分量用例变红。
    expect(() => require('../../services/userPermissionService')).not.toThrow();
    expect(() => require('../../middleware/tokenBlacklist')).not.toThrow();
    expect(() => require('../../middleware/auth')).not.toThrow();
    expect(() => require('../../middleware/userAuthCache')).not.toThrow();
    expect(() => require('../../services/securityAlert')).not.toThrow();
    expect(() => require('../../services/securityAlertPermissionAbuse')).not.toThrow();
    expect(() => require('../../middleware/security')).not.toThrow();
    expect(() => require('../../middleware/originCheck')).not.toThrow();
  });
});
