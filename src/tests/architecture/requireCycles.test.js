/**
 * 依赖图无环断言（E-04）
 *
 * 背景：仓内有 3 处**故意**使用「函数内 require」以打破循环依赖的地方，
 * 报告 E-04 记录了这一事实，并给出两条整改路径：补注释，或加架构测试断言
 * 依赖图无环。本文件选择后者——注释只能提醒读代码的人，无法阻止
 * 「把 require 提到文件顶部」这种看起来无害的重构（那会引入加载顺序 bug：
 * 拿到的 module.exports 尚不完整，症状是 undefined 而非报错，极难定位）。
 *
 * 本测试做三件事：
 *   1. 静态解析 src 下所有模块的 require 边，断言不存在环；
 *      （环的存在说明某处惰性 require 被误提到顶层）
 *   2. 断言 3 处关键惰性 require 仍在函数体内（即未被提到顶层）；
 *   3. 断言这些模块可以被正常加载——静态分析看不见的加载顺序问题，
 *      由「真实 require 一遍」兜住。
 *
 * 为何用静态解析而不是运行时探测：运行时 require 在测试环境里往往
 * 「碰巧」按正确顺序加载，环可能被掩盖；静态图能确定性地暴露它。
 */

const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname, '../../');

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

describe('依赖图无环断言（E-04）', () => {
  const files = collectSourceFiles(SRC_DIR);
  const known = new Set(files.map((f) => path.normalize(f)));

  test('src 下存在可分析的文件（防扫描路径漂移导致假绿）', () => {
    expect(files.length).toBeGreaterThan(100);
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
