#!/usr/bin/env node
/**
 * OpenAPI 产物漂移门禁（D-1 / 2026-10-25 七维审计）
 *
 * `src/docs/generate.js` 被 require 时只导出 spec、不写盘（L-24）。本脚本把
 * 「生成器当前输出」与「已提交的 src/docs/openapi.json」做深度比较：
 * 改完路由/生成器却忘记重跑 `npm run docs:generate` 时，CI 直接失败，
 * 而不是让文档悄悄落后于实现。
 *
 * 用 JSON 往返归一（与原测试同一口径）：Date/undefined 等非 JSON 值不应进入
 * 规范；对象键顺序无关，数组顺序仍参与比较。
 */

const path = require('path');
const { isDeepStrictEqual } = require('util');

const generated = JSON.parse(JSON.stringify(require('../src/docs/generate')));
const committed = require('../src/docs/openapi.json');

if (!isDeepStrictEqual(generated, committed)) {
  console.error('OpenAPI 产物与生成器不一致。请运行 `npm run docs:generate` 后提交差异。');
  console.error(`生成器：${path.relative(process.cwd(), require.resolve('../src/docs/generate'))}`);
  console.error(
    `产物：  ${path.relative(process.cwd(), require.resolve('../src/docs/openapi.json'))}`
  );
  process.exit(1);
}

console.log(
  `OpenAPI 产物一致（${Object.keys(generated.paths).length} 个 path，` +
    `${Object.values(generated.paths).reduce((n, p) => n + Object.keys(p).length, 0)} 个 operation）`
);
