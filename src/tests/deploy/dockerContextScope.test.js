/**
 * Docker 构建上下文的边界（F-10，2026-10-17）
 *
 * 缺陷本体：`.dockerignore` 只写了 `web-admin/dist`，而 Dockerfile 的 web-builder 阶段是
 * `COPY web-admin/ ./`。本地排障时用 `--mode development` 生成的 `dist-debug`、
 * 以及 `dist-optimized` 都**不进**这条排除规则（docker 的 `dist` 只匹配该目录名本身，
 * 与 `coverage` / `coverage-*` 是同一条通配语义——那批已经在 F-09 之前修过）。
 *
 * 后果不只是"context 变大"：
 *   - debug bundle 带完整 source map，体积是产物目录的数倍；
 *   - 更糟的是**构建结果依赖开发者本地有没有生成过它**——同一份源码在不同机器上
 *     得到不同的 builder 缓存，"前端产物由 Dockerfile 自己构建"这个单一来源被破坏；
 *   - 与当前源码不匹配的旧静态产物可能被打进 builder 阶段。
 *
 * 解析器与 F-09（密钥载体）共用 `helpers/dockerignore.js`：同一份 `.dockerignore`
 * 语义只能有一处实现。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const { makeDockerIgnored } = require('./helpers/dockerignore');

const ROOT = path.resolve(__dirname, '../../..');
const ignored = makeDockerIgnored(fs.readFileSync(path.join(ROOT, '.dockerignore'), 'utf8'));

describe('F-10 前端生成物不进构建上下文', () => {
  // 只判**目录本身**是否被模式命中，不判 `web-admin/dist-debug/assets/x.js` 这类子路径：
  // docker 的真实语义是"目录被排除 ⇒ 整棵子树都不进上下文"，在测试里复现那套求值
  // （含"父目录排除后子项反选无效"那个坑）等于自己写第二个解析器——
  // 与 secretCarriersIgnored.test.js 同一条纪律。
  test.each([
    ['web-admin/dist', '基础产物（F-10 之前就在）'],
    ['web-admin/dist-debug', '--mode development 的产物'],
    ['web-admin/dist-optimized', '优化产物'],
  ])('%s（%s）被排除', (p) => {
    expect({ p, ignored: ignored(p) }).toMatchObject({ p, ignored: true });
  });

  test('源码目录不被误排除（`dist-*` 的前缀不能吃掉 src/assets）', () => {
    for (const p of ['web-admin/src', 'web-admin/public', 'web-admin/index.html']) {
      expect({ p, ignored: ignored(p) }).toMatchObject({ p, ignored: false });
    }
  });

  test('`dist-*` 用的是产物族通配，不是逐个枚举（新增产物目录名不会再漏）', () => {
    // 这条判据的意义：若有人把规则改回"逐个列 dist-debug / dist-optimized"，
    // 下一个产物目录名（比如 dist-staging）又会静默漏掉。
    const text = fs.readFileSync(path.join(ROOT, '.dockerignore'), 'utf8');
    expect(text).toMatch(/^web-admin\/dist-\*$/m);
    expect(ignored('web-admin/dist-staging')).toBe(true);
  });
});

describe('F-10 上下文体积的两个已知大头', () => {
  test('coverage 与 coverage-* 仍被排除（F-09 已修，回归守卫）', () => {
    expect(ignored('web-admin/coverage')).toBe(true);
    expect(ignored('web-admin/coverage-zzmfa')).toBe(true);
  });

  test('deliverables/ 仍被排除（含带 file:line 的审计细节，绝不进构建上下文）', () => {
    expect(ignored('deliverables')).toBe(true);
  });
});
