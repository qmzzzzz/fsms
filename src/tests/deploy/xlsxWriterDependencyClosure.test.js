/**
 * xlsx 写入器的依赖闭包：**零第三方包**，且这条不被无声回退
 *
 * 由来（2026-11）：报表导出用 exceljs 写 xlsx，而 exceljs 的生产依赖链是
 * `exceljs → archiver@5 → archiver-utils@2 → glob@7 → minimatch@3`（另有
 * `readdir-glob → minimatch@5`、`unzipper → fstream → rimraf → glob@7`）。
 * 根因公告 `GHSA-g3hv-75wg-m249`（minimatch < 11.0.1）在上游：升 archiver 也没用
 * ——archiver@8 用的 readdir-glob@3 仍依赖 `minimatch@^10.2.2`。于是
 * `npm audit --omit=dev` 长期 8 条 moderate、RC=1。
 *
 * 修法是把写入器改成自研（`utils/xlsxWriter` + `utils/zipContainer`，只用 `node:zlib`），
 * exceljs 降为 devDependency 仅供测试读回。本套件钉住这条修法不被无声回退——
 * 回退的形态不止一种，每种单独判据：
 *   1) 有人把 exceljs 挪回 dependencies（`--omit=dev` 立刻重新变红）；
 *   2) 有人换成另一个写库（write-excel-file / excel4node / jszip / fflate…），
 *      以为"零传递依赖"就等于干净——fflate@0.8.2 的 GHSA-px8p-9vwx-vf98 正是反例；
 *   3) 有人在写入器里加了一行 `require('某包')`，绕过了 package.json 那一层。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const pkg = require('../../../package.json');
const lock = require('../../../package-lock.json');

/** 写入器的两个实现文件：ZIP 容器 + OOXML 生成 */
const WRITER_FILES = ['src/utils/zipContainer.js', 'src/utils/xlsxWriter.js'];

/** 生产依赖里不允许出现的 xlsx/zip 写库（换任何一个都等于把"上游何时修"重新引进来） */
const FORBIDDEN_PROD_DEPS = [
  'exceljs',
  'write-excel-file',
  'excel4node',
  'xlsx-populate',
  'node-xlsx',
  'xlsx',
  'jszip',
  'fflate',
  'adm-zip',
  'archiver',
];

/**
 * 允许出现在写入器里的模块名：Node 内置 zlib（裸写或 node: 前缀）+ 同目录相对路径。
 * 判的是**模块名**而非整行，所以 `const { buildZip } = require('./zipContainer')`
 * 这类解构写法、以及藏在行中间的 require 都跑不掉。
 */
const ALLOWED_MODULE = /^(node:)?zlib$|^\.\/[A-Za-z][A-Za-z0-9]*$/;

const requireSpecifiers = (file) =>
  Array.from(
    fs.readFileSync(path.join(ROOT, file), 'utf8').matchAll(/require\(\s*'([^']+)'\s*\)/g),
    (m) => m[1]
  );

describe('xlsx 写入器不引入第三方依赖', () => {
  test('exceljs 只在 devDependencies（测试读回用），不在 dependencies', () => {
    expect(pkg.dependencies.exceljs).toBeUndefined();
    expect(pkg.devDependencies.exceljs).toBeTruthy();
  });

  test('生产依赖里没有任何 xlsx/zip 写库', () => {
    for (const name of FORBIDDEN_PROD_DEPS) {
      expect(pkg.dependencies[name]).toBeUndefined();
    }
  });

  test('lockfile 的根声明与 package.json 一致，且 exceljs 闭包带 dev 标记', () => {
    // 根声明不一致时 npm ci 会直接拒绝，属更早的红；这里钉的是"改了 package.json
    // 却忘了重拍锁文件"这一格——它会让 `--omit=dev` 的判定与实际安装的树不是同一棵。
    expect(lock.packages[''].dependencies.exceljs).toBeUndefined();
    expect(lock.packages[''].devDependencies.exceljs).toBe(pkg.devDependencies.exceljs);
    // 抽样：exceljs 本体与其两条主要传染链都必须是 dev-only
    for (const key of [
      'node_modules/exceljs',
      'node_modules/archiver',
      'node_modules/archiver-utils',
      'node_modules/readdir-glob',
    ]) {
      expect(lock.packages[key]).toBeTruthy();
      expect(lock.packages[key].dev).toBe(true);
    }
  });

  test.each(WRITER_FILES)('%s 只 require zlib 或同目录相对路径', (file) => {
    const specifiers = requireSpecifiers(file);
    // 至少有一条（两个文件都要 require 点什么，否则说明文件被换掉了）
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) {
      expect(specifier).toMatch(ALLOWED_MODULE);
    }
  });

  test('两个 service 都不再 require exceljs', () => {
    for (const file of [
      'src/services/reportWorkbookService.js',
      'src/services/honeypotDecoyFiles.js',
    ]) {
      const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
      expect(source).not.toMatch(/require\('exceljs'\)/);
    }
  });
});
