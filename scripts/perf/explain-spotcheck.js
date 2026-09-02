#!/usr/bin/env node

/**
 * 重查询 explain 抽查（E-2/E-1 配套）
 *
 * 对高量级列表的代表性查询跑 explain('executionStats')，
 * 把「有没有走索引、扫了多少行」变成可留档的数字，而不是靠猜。
 *
 * 用法：
 *   node scripts/perf/explain-spotcheck.js          # 需 MONGODB_URI（走 .env）
 *
 * 只读脚本：只执行 explain，不改数据、不建索引；
 * 输出 IXSCAN/COLLSCAN 与 totalDocsExamined，COLLSCAN 即需要补索引的信号。
 */

'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('缺少 MONGODB_URI（.env 或环境变量）');
  process.exit(1);
}

const cases = [
  {
    name: '告警列表（发生时间降序 + 分页）',
    run: () =>
      mongoose
        .model('FireAlarm')
        .find({})
        .sort({ occurredAt: -1 })
        .limit(20)
        .explain('executionStats'),
  },
  {
    name: '巡检列表（计划开始时间降序 + 分页）',
    run: () =>
      mongoose
        .model('Inspection')
        .find({})
        .sort({ planStartTime: -1 })
        .limit(20)
        .explain('executionStats'),
  },
  {
    name: '设备列表（编码升序游标形态：范围 + 排序）',
    run: () =>
      mongoose
        .model('FireDevice')
        .find({})
        .sort({ deviceCode: 1 })
        .limit(20)
        .explain('executionStats'),
  },
  {
    name: '审计日志（时间降序 + 分页）',
    run: () =>
      mongoose
        .model('AuditLog')
        .find({})
        .sort({ timestamp: -1 })
        .limit(20)
        .explain('executionStats'),
  },
];

function summarize(explained) {
  const exec = explained.queryPlanner?.winningPlan;
  const stats = explained.executionStats || {};
  const stageOf = (node) => {
    if (!node) return 'UNKNOWN';
    if (node.inputStage) return `${node.stage} -> ${stageOf(node.inputStage)}`;
    if (node.inputStages) return `${node.stage} -> [${node.inputStages.map(stageOf).join(', ')}]`;
    return node.stage;
  };
  return {
    plan: stageOf(exec),
    nReturned: stats.nReturned,
    totalKeysExamined: stats.totalKeysExamined,
    totalDocsExamined: stats.totalDocsExamined,
    executionTimeMillis: stats.executionTimeMillis,
    isCollScan: JSON.stringify(exec).includes('COLLSCAN'),
  };
}

(async () => {
  await mongoose.connect(uri);
  console.log(`目标库：${mongoose.connection.name}\n`);
  let badCount = 0;
  for (const c of cases) {
    try {
      const explained = await c.run();
      const s = summarize(explained);
      const mark = s.isCollScan ? '[COLLSCAN 需处理]' : '[OK]';
      if (s.isCollScan) badCount += 1;
      console.log(`${mark} ${c.name}`);
      console.log(`    计划: ${s.plan}`);
      console.log(
        `    返回=${s.nReturned} 索引扫描=${s.totalKeysExamined} 文档扫描=${s.totalDocsExamined} 耗时=${s.executionTimeMillis}ms`
      );
    } catch (err) {
      console.log(`[SKIP] ${c.name}：${err.message}`);
    }
  }
  await mongoose.disconnect();
  console.log(
    badCount === 0
      ? '\n结论：全部走索引'
      : `\n结论：${badCount} 个查询存在 COLLSCAN，需补索引后复测`
  );
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
