/**
 * F-02（2026-10-17）：migrate-mongo 的依赖闭包必须在 lockfile 内闭合
 *
 * 缺陷本体：镜像 runtime 阶段先 `npm ci --omit=dev`，再单独执行
 *   `npm i --no-save --no-package-lock --omit=dev migrate-mongo@<lockfile 版本>`
 * 这只锚住 migrate-mongo **自身**。`--no-package-lock` 让 npm 完全不读 lockfile，
 * 于是它的传递依赖树在**构建期重新解析**：
 *   - 同一个 Git 提交可以产出依赖闭包不同的镜像；
 *   - SBOM 里记的是主包版本，实际运行的迁移器依赖树无人知道；
 *   - 回滚到旧应用代码时，迁移工具未必是当时验证过的那棵树。
 *
 * 修法（审计建议的首选方案）：把它移进 `dependencies`，让 `npm ci --omit=dev`
 * 一次装完。本套件钉住这条修法不被无声回退——四类回退各有独立判据，
 * 因为它们的失效形态不同（改回 devDeps / 改回补装 / 删 COPY / 锚没更新）。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const readRoot = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const pkg = require('../../../package.json');
const lock = require('../../../package-lock.json');

/** migrate-mongo 的生产闭包（自身 + 传递依赖）。实测 11 个包，这里只钉关键三件。 */
const CLOSURE_KEYS = [
  'node_modules/migrate-mongo',
  'node_modules/cli-table3',
  'node_modules/commander',
];

describe('F-02 依赖声明：migrate-mongo 属于生产闭包', () => {
  test('在 dependencies 里，且不在 devDependencies 里（两边都写会让 --omit=dev 语义失效）', () => {
    expect(pkg.dependencies['migrate-mongo']).toBeTruthy();
    expect(pkg.devDependencies['migrate-mongo']).toBeUndefined();
  });

  test('lockfile 里它及传递依赖都不带 dev 标记（否则 npm ci --omit=dev 仍会漏掉）', () => {
    for (const key of CLOSURE_KEYS) {
      const entry = lock.packages[key];
      expect(entry).toBeTruthy();
      expect(entry.dev).not.toBe(true);
    }
  });

  test('lockfile 的根声明与 package.json 一致（不一致时 npm ci 直接拒绝，属更早的红）', () => {
    const rootDecl = lock.packages[''].dependencies || {};
    expect(rootDecl['migrate-mongo']).toBe(pkg.dependencies['migrate-mongo']);
    expect(lock.packages[''].devDependencies['migrate-mongo']).toBeUndefined();
  });
});

describe('F-02 镜像构建：不得再有构建期二次解析', () => {
  const dockerfile = readRoot('Dockerfile');
  /**
   * 只取**指令行**（去掉注释行）。
   * 注释里会叙述历史（"当时的补法是 npm i --no-save --no-package-lock"），
   * 按全文匹配会把那段说明本身当成违例——判据必须落在"构建真的会执行什么"上，
   * 而不是"文件里出现过这串字"。
   */
  const instructions = dockerfile
    .split(/\r?\n/)
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');

  test('指令行里不存在 `npm i --no-save` / `--no-package-lock`', () => {
    // 这两者是"构建期重新解析依赖树"的直接指纹。改回去就等于把 F-02 复活，
    // 而它**不会**让任何既有测试变红（镜像照样能构建、应用照样能跑）。
    expect(instructions).not.toMatch(/npm\s+i\s+--no-save/);
    expect(instructions).not.toContain('--no-package-lock');
  });

  test('生产依赖仍由 `npm ci --omit=dev` 一次装好', () => {
    expect(instructions).toMatch(/npm ci --omit=dev/);
  });

  test('node_modules 仍归属非 root 用户（补装段删除后 chown 不能跟着消失）', () => {
    // 原 chown 挂在那条被删掉的 RUN 段末尾；删段时若没把它搬走，
    // node_modules 归 root，nodejs 用户在运行期写入即 EACCES——启动期才暴露。
    expect(instructions).toMatch(/chown -R nodejs:nodejs node_modules/);
  });

  test('迁移能力没丢：migrations/ 与配置文件仍被 COPY 进镜像', () => {
    expect(instructions).toMatch(/COPY .*migrations/);
    expect(instructions).toMatch(/COPY .*migrate-mongo-config\.js/);
  });
});
