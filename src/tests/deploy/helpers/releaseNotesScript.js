'use strict';

/**
 * 从 workflow YAML 里抽出指定 `name:` 步骤的 `run:` 体。
 *
 * 为什么要有这个 helper：`src/tests/deploy/**` 有多个门禁要"真跑工作流里的脚本"
 * （release.yml 的发布说明抽取、ci.yml 的 mongod 预置…）。各自手写一份抽取器或
 * 各自手抄一份脚本副本，都会让判据与被测对象脱钩——本仓已经吃过这个亏：
 * releaseWorkflow.test.js 的"真命令"用例曾把管线**手抄**进测试里跑，
 * 于是工作流的 awk/tail/grep 被改坏时该用例照样绿（第八轮审计 R-8）。
 *
 * 用 YAML 解析（js-yaml，本仓 scripts/config-drift-check.js 已在用同一库）而不是正则切行：
 * 块标量 `run: |` 的缩进由解析器统一处理，`run: >`、单行 `run: xxx` 也都覆盖。
 */

const yaml = require('js-yaml');

/**
 * @param {string} yamlText workflow 原文
 * @param {string} stepName 步骤的 `name:` 字面量（必须完全相等）
 * @returns {string[]} 每个匹配步骤的 run 体（同名步骤出现在多个 job 时全都返回）
 */
function extractStepRuns(yamlText, stepName) {
  const doc = yaml.load(yamlText) || {};
  const jobs = doc.jobs || {};
  const out = [];
  for (const job of Object.values(jobs)) {
    const steps = (job && job.steps) || [];
    for (const step of steps) {
      if (!step || step.name !== stepName) continue;
      if (typeof step.run !== 'string') continue;
      out.push(step.run);
    }
  }
  return out;
}

module.exports = { extractStepRuns };
