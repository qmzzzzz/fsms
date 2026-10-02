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
 * 只读脚本：只执行 explain，不改数据；除 Mongoose autoIndex 本来就会建的
 * 声明式索引外不额外建索引（脚本只等待其构建完成，见 main 里的 init()）；
 * 输出 IXSCAN/COLLSCAN 与 totalDocsExamined，COLLSCAN 即需要补索引的信号。
 *
 * 退出码契约（复核只看这个，不看措辞）：
 *   0 = 每个用例都拿到了「可判定」的执行计划（计划里含 IXSCAN 或 COLLSCAN），且无 COLLSCAN
 *   1 = 有用例没跑成（缺 MONGODB_URI、抛错、无计划）／计划不可判定／存在 COLLSCAN
 * 依据 本脚本曾不 require 任何模型，4 个用例全部抛 MissingSchemaError
 * 并被 [SKIP] 静默吞掉，于是「一条都没测到」被印成「结论：全部走索引」且退出 0。
 * 依据 F-63b：空集合上 MongoDB 直接回 stage=EOF（没有文档可返回），
 * 既不是 IXSCAN 也不是 COLLSCAN，同样不该被读成「走索引」——
 * 所以「不可判定」与「没测到」一律记红，并提示按 README 造数 ≥10k 后复测。
 * 「没测到」与「测过且干净」是两件事，必须由退出码区分。
 */

'use strict';

require('dotenv').config();
// <NAME>_FILE 部署下必须在此回填，否则下面直读的 MONGODB_URI 是空串 ⇒ 用例全部抛错
// （不变量见 src/tests/config/scriptSecretHydration.test.js）。
require('../../src/config/secrets').hydrateSecretsFromFiles();
const mongoose = require('mongoose');

// 模型注册是显式前置条件：mongoose.model(name) 只查已注册的 schema，
// 删掉下面任何一行都会让对应用例抛 MissingSchemaError。
// （原实现只有 mongoose 一个 require，于是四个用例一个都没跑成。）
require('../../src/models/FireAlarm');
require('../../src/models/Inspection');
require('../../src/models/FireDevice');
require('../../src/models/AuditLog');

const PAGE_SIZE = 20;

/**
 * 用例的 sort 必须与**服务层调用点的 .sort() 逐字段一致**，否则这里量到的是
 * 一条生产环境根本不执行的查询，抽查结论归零。
 * 三个时间排序都带 `_id` 次级键（游标续页的平局裁决方向，见
 * docs/adr/ADR-006-高量级列表游标分页选型.md）：去掉 `_id` 会让本脚本绿灯
 * 与线上 COLLSCAN 同时成立 —— 而 COLLSCAN 才是真实形态。
 * 对应的 `{field:-1,_id:-1}` 复合索引由 models 声明 + 迁移
 * migrations/20260926000000-cursor-tiebreak-compound-indexes.js 落地；
 * 缺索引时这里的 stage 会含 SORT→COLLSCAN，退出码 1。
 */
const cases = [
  {
    name: '告警列表（发生时间降序 + _id 平局裁决 + 分页）',
    model: 'FireAlarm',
    sort: { occurredAt: -1, _id: -1 },
  },
  {
    name: '巡检列表（计划开始时间降序 + _id 平局裁决 + 分页）',
    model: 'Inspection',
    sort: { planStartTime: -1, _id: -1 },
  },
  {
    name: '设备列表（编码升序游标形态：范围 + 排序）',
    model: 'FireDevice',
    sort: { deviceCode: 1 },
  },
  {
    name: '审计日志（时间降序 + _id 平局裁决 + 分页）',
    model: 'AuditLog',
    sort: { timestamp: -1, _id: -1 },
  },
];

function runCase(c) {
  return mongoose.model(c.model).find({}).sort(c.sort).limit(PAGE_SIZE).explain('executionStats');
}

function stageOf(node) {
  if (!node) return 'UNKNOWN';
  if (node.inputStage) return `${node.stage} -> ${stageOf(node.inputStage)}`;
  if (node.inputStages) return `${node.stage} -> [${node.inputStages.map(stageOf).join(', ')}]`;
  return node.stage;
}

function summarize(explained) {
  const exec = explained && explained.queryPlanner && explained.queryPlanner.winningPlan;
  const stats = (explained && explained.executionStats) || {};
  const plan = stageOf(exec);
  const isCollScan = plan.includes('COLLSCAN');
  return {
    // decidable=false 表示这个计划回答不了「走索引还是全表扫」：
    // 既可能是没拿到 winningPlan，也可能是空集合上的 EOF 之类的短路计划。
    decidable: Boolean(exec) && (isCollScan || plan.includes('IXSCAN')),
    hasPlan: Boolean(exec),
    plan,
    nReturned: stats.nReturned,
    totalKeysExamined: stats.totalKeysExamined,
    totalDocsExamined: stats.totalDocsExamined,
    executionTimeMillis: stats.executionTimeMillis,
    // 一点数据都没碰过：计划选型有效，但容量结论无效（空库抽查的典型症状）
    noWork: !(stats.totalKeysExamined > 0) && !(stats.totalDocsExamined > 0),
    // 判定与展示同源：都取自 stageOf 走出来的计划串
    isCollScan,
  };
}

/**
 * 汇总为退出码。不可判定优先于 COLLSCAN：
 * 一次没跑成的抽查不能只报「补索引后复测」，那等于承认本次结论有效。
 *
 * zeroTouch（扫描 0 条索引键的用例数）不改变退出码：计划选型确实是 IXSCAN，
 * 结论成立；但「空库上的 IXSCAN」抄进基线表就是误导，所以单独印一行提示。
 */
function decideExit({ total, collscan, inconclusive, zeroTouch = 0 }) {
  if (inconclusive > 0) {
    return {
      code: 1,
      line:
        `结论：${inconclusive}/${total} 个用例未取得可判定的执行计划，本次抽查无效` +
        `（多为集合为空/数据量过小，需按 scripts/perf/README.md 造数 ≥10k 后复测）`,
      note: '',
    };
  }
  if (collscan > 0) {
    return {
      code: 1,
      line: `结论：${collscan}/${total} 个查询存在 COLLSCAN，需补索引后复测`,
      note: '',
    };
  }
  return {
    code: 0,
    line: `结论：${total}/${total} 个查询全部走索引`,
    note:
      zeroTouch > 0
        ? `⚠ ${zeroTouch}/${total} 个用例索引扫描与文档扫描均为 0：集合为空或数据量过小，` +
          `此处只证明「查询选型走了索引」，不代表真实容量下的表现，勿抄进基线表`
        : '',
  };
}

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('缺少 MONGODB_URI（.env 或环境变量）');

  await mongoose.connect(uri);
  console.log(`目标库：${mongoose.connection.name}\n`);

  // Mongoose 的 autoIndex 在连接后于后台构建模型声明过的索引；不等它们落地就 explain，
  // 索引可能尚未可见 → 报出假 COLLSCAN。init() 只是等同步完成，不新建声明之外的索引。
  await Promise.all(cases.map((c) => mongoose.model(c.model).init()));

  let collscan = 0;
  let inconclusive = 0;
  let zeroTouch = 0;
  try {
    for (const c of cases) {
      try {
        const s = summarize(await runCase(c));
        if (!s.decidable) {
          inconclusive += 1;
          console.log(
            `[INCONCLUSIVE] ${c.name}：${
              s.hasPlan
                ? `计划「${s.plan}」既无 IXSCAN 也无 COLLSCAN（集合为空/索引未就绪）`
                : 'explain 未返回 winningPlan，无法判定'
            }`
          );
          continue;
        }
        if (s.isCollScan) collscan += 1;
        if (s.noWork) zeroTouch += 1;
        console.log(`${s.isCollScan ? '[COLLSCAN 需处理]' : '[OK]'} ${c.name}`);
        console.log(`    计划: ${s.plan}`);
        console.log(
          `    返回=${s.nReturned} 索引扫描=${s.totalKeysExamined} 文档扫描=${s.totalDocsExamined} 耗时=${s.executionTimeMillis}ms`
        );
      } catch (err) {
        inconclusive += 1;
        console.log(`[FAIL] ${c.name}：${err.message}`);
      }
    }
  } finally {
    await mongoose.disconnect();
  }

  const verdict = decideExit({ total: cases.length, collscan, inconclusive, zeroTouch });
  console.log(`\n${verdict.line}`);
  if (verdict.note) console.log(verdict.note);
  return verdict.code;
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      console.error(err && err.message ? err.message : err);
      process.exitCode = 1;
    });
}

module.exports = { PAGE_SIZE, cases, runCase, stageOf, summarize, decideExit, main };
