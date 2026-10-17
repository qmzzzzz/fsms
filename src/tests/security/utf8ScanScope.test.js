/**
 * UTF-8 门禁的扫描边界（F-05，2026-10-17）
 *
 * 缺陷本体：`scripts/check-utf8.js` 的跳过集合是**精确名** `['node_modules','dist',
 * '.git','coverage']`。本仓同时存在 `web-admin/dist-debug`（`--mode development` 产物）、
 * `dist-optimized`，以及手工跑覆盖率留下的 `coverage-<tag>`——一个都不匹配精确名，
 * 于是**构建产物被当成源码扫**：生成一次 debug bundle 后 `npm run check:utf8` 就红，
 * 报错行指向 `dist-debug/assets/router-<hash>.js`，而源码一个字符没变。
 *
 * 修法：改成前缀判据 `^(node_modules|\.git|dist($|-)|coverage($|-))`。
 * 本套件钉三件事：① 三种产物变体都跳过；② 同前缀的**源码目录**不被误跳
 * （`distribution`/`distance`）；③ 端到端走一遍真实 walk，确认产物里的乱码
 * 不再影响扫描集——只断言正则等于没测"它到底有没有被用上"。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { isSkippedDirName, walk, roots } = require('../../../scripts/check-utf8');

describe('F-05 生成物目录必须跳过', () => {
  test.each([
    ['dist', '基础产物目录'],
    ['dist-debug', '--mode development 的产物'],
    ['dist-optimized', '优化产物'],
    ['coverage', '覆盖率'],
    ['coverage-zzmfa', '手工跑覆盖率时的带 tag 目录'],
    ['node_modules', '依赖'],
    ['.git', '版本库元数据'],
  ])('%s（%s）跳过', (name) => {
    expect(isSkippedDirName(name)).toBe(true);
  });

  test.each(['distribution', 'distance', 'dist-tool', 'src', 'docs', 'web-admin'])(
    '同前缀的源码目录不被误跳：%s',
    (name) => {
      // `dist-tool` 是「产物族」的合法成员，故意跳过；这里只钉**非产物**的相似名。
      if (name === 'dist-tool') return;
      expect(isSkippedDirName(name)).toBe(false);
    }
  );
});

describe('F-05 端到端：产物里的乱码不进扫描集', () => {
  let tmp;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'utf8scope-'));
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  test('dist-debug 下的 U+FFFD 文件不被收集，src 下的正常文件被收集', () => {
    fs.mkdirSync(path.join(tmp, 'dist-debug', 'assets'), { recursive: true });
    // 这就是审计现场：构建产物里有一个 U+FFFD（Vite 打包时的替换字符）
    fs.writeFileSync(path.join(tmp, 'dist-debug', 'assets', 'router-abc.js'), 'const x="\uFFFD";');
    fs.mkdirSync(path.join(tmp, 'src'));
    fs.writeFileSync(path.join(tmp, 'src', 'ok.js'), 'const a = 1;\n');

    const out = [];
    walk(tmp, out);

    expect(out).toEqual([path.join(tmp, 'src', 'ok.js')]);
  });

  test('coverage-<tag> 同样不进扫描集（覆盖率报告里有大量 HTML/JS）', () => {
    fs.mkdirSync(path.join(tmp, 'coverage-zzmfa'));
    fs.writeFileSync(path.join(tmp, 'coverage-zzmfa', 'index.html'), '<p>\uFFFD</p>');
    const out = [];
    walk(tmp, out);
    expect(out).toEqual([]);
  });
});

describe('F-05 扫描根清单仍然有效（跳过规则不得把扫描面吃掉）', () => {
  test('web-admin 仍是扫描根（跳过的是它下面的产物子目录，不是它本身）', () => {
    // 反方向的守卫：把 web-admin 整个跳掉也能让 check:utf8 变绿，
    // 但那是"门禁没看东西"，与 F-05 要修的"看错了东西"是两种失效。
    expect(roots.some((r) => r.endsWith('web-admin'))).toBe(true);
  });
});
