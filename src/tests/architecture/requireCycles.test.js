/**
 * 依赖图无环断言（E-04）
 *
 * 背景：仓内有 3 处**故意**使用「函数内 require」以打破循环依赖的地方，
 * 报告 E-04 记录了这一事实，并给出两条整改路径：补注释，或加架构测试断言
 * 依赖图无环。本文件选择后者——注释只能提醒读代码的人，无法阻止
 * 「把 require 提到文件顶部」这种看起来无害的重构（那会引入加载顺序 bug：
 * 拿到的 module.exports 尚不完整，症状是 undefined 而非报错，极难定位）。
 *
 * 本测试做四件事：
 *   1. 静态解析 src 下所有模块的 require 边，断言不存在环；
 *      （环的存在说明某处惰性 require 被误提到顶层）
 *   2. 断言 3 处关键惰性 require 仍在函数体内（即未被提到顶层）；
 *   3. 断言这些模块可以被正常加载——静态分析看不见的加载顺序问题，
 *      由「真实 require 一遍」兜住。
 *   4. 断言每条相对 require 都能解析到真实文件（F-193）——前三条都建立在
 *      「解析得到的边」之上，解析失败的边在图的构造里就被丢掉了，
 *      所以那一类必须由第 4 条单独记账，否则改名/删除是无红的。
 *
 * 为何用静态解析而不是运行时探测：运行时 require 在测试环境里往往
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
 * @param {string} source
 * @returns {string[]} 相对路径（原样，未解析）
 */
const extractTopLevelRequires = (source) => {
  const deps = [];
  let depth = 0;
  // 逐字符去掉字符串与模板串里的花括号干扰：用行级粗筛 + 深度累计
  for (const rawLine of source.split('\n')) {
    const line = rawLine.replace(/\/\/.*$/, ''); // 去行注释
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

describe('依赖图无环断言（E-04）', () => {
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

  test('3 处关键惰性 require 仍在函数体内（未被提到顶层）', () => {
    // 每项：[文件, 必须出现在函数体内(缩进)的片段, 说明]
    const LAZY = [
      [
        'services/userPermissionService.js',
        "return require('../models/User');",
        'service ↔ model 潜在循环依赖',
      ],
      ['middleware/tokenBlacklist.js', "require('./auth')", 'auth ↔ tokenBlacklist 循环依赖'],
      [
        'services/securityAlert.js',
        "require('../middleware/security')",
        'securityAlert ↔ security 循环依赖',
      ],
    ];

    for (const [rel, snippet, why] of LAZY) {
      const source = fs.readFileSync(path.join(SRC_DIR, rel), 'utf8');
      const lines = source.split('\n');
      const hit = lines.find((l) => l.includes(snippet));
      expect({ file: rel, why, found: Boolean(hit) }).toEqual({ file: rel, why, found: true });
      // 缩进即函数体内：顶层 require 缩进为 0
      expect({ file: rel, indented: /^\s+\S/.test(hit) }).toEqual({ file: rel, indented: true });
    }
  });

  test('涉及循环依赖的模块可被正常加载（加载顺序不炸）', () => {
    // 静态图无环 + 惰性 require 就位后，这里再做一次真实加载兜底：
    // 若某天模块初始化逻辑变化导致加载即抛错，本用例会先于业务用例报错
    expect(() => require('../../services/userPermissionService')).not.toThrow();
    expect(() => require('../../middleware/tokenBlacklist')).not.toThrow();
    expect(() => require('../../services/securityAlert')).not.toThrow();
  });
});
