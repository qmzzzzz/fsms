'use strict';

/**
 * 镜像文件集合必须闭合满足运行期加载文件的相对 require（D-3 的补闸）。
 *
 * 存在的理由：deploy.js 在**应用容器里**跑 `migrate-mongo status|up`，而
 * migrate-mongo-config.js 顶层 require('./scripts/destructiveGuard')。
 * Dockerfile 当时只 COPY src/ 与 migrations/，于是容器内加载配置即
 * MODULE_NOT_FOUND。既有部署测试用桩 docker 观测"发起了哪些命令"，
 * 看不到容器里有哪些文件——这道闸在 CI 全绿的情况下断了三次真实部署路径。
 *
 * 判据形状（三条都有牙齿，见文末反向前提用例）：
 * 1. 逐个检查"被单独 COPY 进镜像的文件"（非整目录）的相对 require；
 * 2. 递归跟进这些 require 的目标（否则第二跳会漏）；
 * 3. 每个结论都基于解析 Dockerfile 的 COPY 指令，不抄写文件清单——
 *    抄清单等于又造一份会漂移的事实来源。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const DOCKERFILE = path.join(ROOT, 'Dockerfile');

/** 把 `package*.json` 这类构建上下文 glob 转成针对相对路径的正则 */
function globToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return new RegExp(`^${escaped}$`);
}

/**
 * 解析 Dockerfile 里"从构建上下文复制"的 COPY 指令（跳过 --from= 的阶段间搬运：
 * 阶段里的内容本就来自构建上下文，递归跟进会重复计同一份仓库文件）。
 * @returns {{files: string[], dirs: string[]}} 仓库相对路径（目录以 / 结尾）
 */
function parseBuildContextCopies(src) {
  const files = [];
  const dirs = [];
  for (const rawLine of src.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!/^COPY\b/.test(line) || line.includes('--from=')) continue;
    const tokens = line
      .replace(/^COPY\b/, '')
      .trim()
      .split(/\s+/);
    const args = tokens.filter((t) => !t.startsWith('--'));
    // 末位是目标路径（镜像内），其余都是构建上下文里的源
    for (const spec of args.slice(0, -1)) {
      if (spec.endsWith('/')) dirs.push(spec.slice(0, -1));
      else files.push(spec);
    }
  }
  return { files, dirs };
}

/** 该仓库相对路径是否落在 COPY 集合内（整目录复制按前缀算） */
function isInImage(copies, relPath) {
  const dirs = copies.dirs.filter((d) => relPath === d || relPath.startsWith(`${d}/`));
  if (dirs.length > 0) return true;
  return copies.files.some((spec) => globToRegExp(spec).test(relPath));
}

/** 从源码里取相对 require 的说明符（在剥掉注释的视图上做，防"注释里的例子"命中） */
function relativeRequires(code) {
  const stripped = code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const found = [];
  for (const m of stripped.matchAll(/require\(\s*['"](\.[^'"]+)['"]\s*\)/g)) {
    found.push(m[1]);
  }
  return found;
}

/** 相对说明符 → 仓库相对路径（补 .js / /index.js，与 Node 解析一致） */
function resolveToLocal(fromRel, specifier) {
  const base = path.posix.join(path.posix.dirname(fromRel), specifier);
  const candidates = [base, `${base}.js`, `${base}.json`, path.posix.join(base, 'index.js')];
  for (const c of candidates) {
    if (fs.existsSync(path.join(ROOT, c)) && fs.statSync(path.join(ROOT, c)).isFile()) {
      return c;
    }
  }
  return null;
}

/**
 * 从给定入口出发做闭包，返回"被 require 但不在镜像里"的边。
 * @param {string[]} entryRels 仓库相对路径的入口文件
 * @param {{dirs: string[], files: string[]}} [copiesArg] 注入 COPY 集合（缺省解析 Dockerfile），
 *        注入是为了能合成"少复制一个文件"的场景，见反向前提用例
 * @returns {{missing: Array<{from: string, to: string, specifier: string}>, checked: number, visited: number}}
 */
function findUnclosedRequires(entryRels, copiesArg) {
  const copies =
    copiesArg ||
    parseBuildContextCopies(fs.readFileSync(DOCKERFILE, 'utf8').replace(/\r\n/g, '\n'));
  const missing = [];
  const visited = new Set();
  let checked = 0;
  const queue = [...entryRels];
  while (queue.length > 0) {
    const rel = queue.shift();
    if (visited.has(rel)) continue;
    visited.add(rel);
    const code = fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');
    for (const specifier of relativeRequires(code)) {
      const target = resolveToLocal(rel, specifier);
      if (target === null) continue;
      checked += 1;
      if (!isInImage(copies, target)) {
        missing.push({ from: rel, to: target, specifier });
      }
      queue.push(target);
    }
  }
  return { missing, checked, visited: visited.size };
}

/** 被"单独 COPY"（非整目录）进镜像的文件——它们是最容易只复制一半的一批 */
function individuallyCopiedFiles() {
  const src = fs.readFileSync(DOCKERFILE, 'utf8').replace(/\r\n/g, '\n');
  const { files } = parseBuildContextCopies(src);
  const entries = [];
  for (const spec of files) {
    if (spec.includes('*')) {
      const dir = path.posix.dirname(spec);
      const re = globToRegExp(path.posix.basename(spec));
      for (const name of fs.readdirSync(path.join(ROOT, dir))) {
        if (re.test(name)) entries.push(path.posix.join(dir, name));
      }
      continue;
    }
    if (fs.existsSync(path.join(ROOT, spec))) entries.push(spec);
  }
  // 同一个文件会被多条 COPY（builder 与最终阶段）各抽中一次，去重后才是"镜像里的文件"
  return [...new Set(entries)];
}

describe('镜像 COPY 集合对相对 require 的闭合性', () => {
  test('解析器确实抽到了 COPY 指令（判据空转会伪装成"通过"）', () => {
    const src = fs.readFileSync(DOCKERFILE, 'utf8').replace(/\r\n/g, '\n');
    const { files, dirs } = parseBuildContextCopies(src);
    // 规模下界：镜像至少要带 src/ 与 migrations/ 两个目录、以及迁移配置
    expect(dirs).toEqual(expect.arrayContaining(['src', 'migrations']));
    expect(files.length).toBeGreaterThanOrEqual(2);
    expect(files).toEqual(expect.arrayContaining(['migrate-mongo-config.js']));
  });

  test('容器里跑的迁移配置，其相对 require 全部随镜像分发', () => {
    const { missing, checked } = findUnclosedRequires(['migrate-mongo-config.js']);
    expect(checked).toBeGreaterThanOrEqual(2);
    expect(missing).toEqual([]);
  });

  test('所有被单独 COPY 的文件都不含指向镜像外代码的相对 require', () => {
    const entries = individuallyCopiedFiles();
    expect(entries).toContain('migrate-mongo-config.js');
    const { missing, checked, visited } = findUnclosedRequires(entries);
    // 规模下界：每个入口都要真被走过，且至少抽出两条边（secrets + destructiveGuard），
    // 否则"entries 非空但一条都没扫"会伪装成 missing=[]
    expect(visited).toBeGreaterThanOrEqual(entries.length);
    expect(checked).toBeGreaterThanOrEqual(2);
    expect(missing).toEqual([]);
  });

  test('反向前提：判据有牙齿——少复制一个文件就会被点到名字', () => {
    // 合成"镜像里没有 scripts/"这一场景，走真判据（不是只测谓词本身）
    const withoutGuard = { dirs: ['src', 'migrations'], files: ['migrate-mongo-config.js'] };
    const { missing } = findUnclosedRequires(['migrate-mongo-config.js'], withoutGuard);
    expect(missing).toEqual([
      {
        from: 'migrate-mongo-config.js',
        to: 'scripts/destructiveGuard.js',
        specifier: './scripts/destructiveGuard',
      },
    ]);
    // 正对照：同一份源码在真实 COPY 集合下必须干净，否则上面那条红说明不了问题
    const real = findUnclosedRequires(['migrate-mongo-config.js']);
    expect(real.missing).toEqual([]);
    expect(real.checked).toBeGreaterThanOrEqual(2);
  });

  test('整目录复制不误报、目录内深层文件也算在内', () => {
    const copies = { dirs: ['src'], files: [] };
    expect(isInImage(copies, 'src/middleware/security.js')).toBe(true);
    expect(isInImage(copies, 'scripts/deploy.js')).toBe(false);
    // 前缀边界：`src` 目录不能顺手放行 `src2/...` 这种同前缀的不同目录
    expect(isInImage(copies, 'src2/x.js')).toBe(false);
  });

  test('require 抽取不看注释（本仓三次把注释里的例子当成命中）', () => {
    const code = [
      "// 反例：require('./scripts/ghost.js') 曾经漏打包",
      "const a = require('./src/config/secrets');",
      "/* 块注释里的 require('./scripts/another-ghost.js') */",
      "const b = (() => require('./scripts/destructiveGuard'))();",
    ].join('\n');
    const specs = relativeRequires(code);
    expect(specs).toContain('./scripts/destructiveGuard');
    expect(specs).toContain('./src/config/secrets');
    expect(specs).toHaveLength(2);
  });
});
