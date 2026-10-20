#!/usr/bin/env node
/**
 * 运维关键路径 E2E（T-1 / P2-3）
 *
 * 四条旅程：告警投递探针、部署失败→自动回滚、备份→恢复→校验、跨部门越权。
 * 与 e2e/ 下的 Playwright 旅程分开：后者有 `skipped==0` + MIN_PASSED 的硬门禁，
 * 这里的目标是进程/数据库/脚本级路径，不经过浏览器，也不应把浏览器旅程数改花。
 *
 * 每条旅程在独立子进程中运行（`src/index.js` 是 require 即启动，内存 Mongo、mongoose
 * 全局连接与端口都不能在同一进程里反复初始化）。默认全部使用临时资源：
 * 内存 Mongo、临时密钥目录、随机端口、本地假 Alertmanager；不触达仓库 .env 指向的
 * 真实库/告警通道。可在预发机重复执行 `npm run test:ops-e2e`。
 *
 * 用法：
 *   node scripts/ops-e2e.js                 # 跑全部四条
 *   node scripts/ops-e2e.js --only backup-restore,alert-delivery
 *   node scripts/ops-e2e.js --list
 *   node scripts/ops-e2e.js --keep          # 保留临时目录供排查
 *
 * 退出码：0 全部通过 / 1 有旅程失败 / 2 参数不合法
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const JOURNEY_ENTRY = path.join(ROOT, 'scripts', 'ops-e2e', 'journey.js');
const JOURNEYS = [
  {
    id: 'alert-delivery',
    desc: '告警投递探针：真实 HTTP 投递 → 记录 queued-unacked → --ack → ok，并验证失败可见',
  },
  {
    id: 'deploy-rollback',
    desc: '部署失败→自动回滚：真实 deploy.js 子进程，校验备份→迁移→切换→健康失败→回滚顺序',
  },
  {
    id: 'backup-restore',
    desc: '备份→恢复→校验：内存 Mongo + run-rollback-drill.js 真快照/清空/回灌，验证 BSON 无损与留档',
  },
  {
    id: 'cross-department',
    desc: '跨部门越权：完整启动 app，两个部门账号登录后只能读到本部门设备，越界详情 403',
  },
];
const JOURNEY_IDS = JOURNEYS.map((j) => j.id);

function parseArgs(argv) {
  const args = { only: null, keep: false, list: false, errors: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--list') {
      args.list = true;
      continue;
    }
    if (token === '--keep') {
      args.keep = true;
      continue;
    }
    if (token === '--only') {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        args.errors.push('--only 缺少旅程名（逗号分隔）');
        continue;
      }
      const ids = value
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const unknown = ids.filter((id) => !JOURNEY_IDS.includes(id));
      if (unknown.length > 0) {
        args.errors.push(`未知旅程：${unknown.join(', ')}（可选：${JOURNEY_IDS.join(', ')}）`);
      } else {
        args.only = ids;
      }
      i += 1;
      continue;
    }
    args.errors.push(`未知参数：${token}（只接受 --only <旅程> / --list / --keep）`);
  }
  return args;
}

function printList() {
  console.log('可用旅程：');
  for (const j of JOURNEYS) console.log(`  ${j.id.padEnd(18)} ${j.desc}`);
}

function runJourney(journey, configPath, timeoutMs) {
  console.log(`\n===== [ops-e2e] ${journey.id} =====`);
  console.log(journey.desc);
  const result = spawnSync(process.execPath, [JOURNEY_ENTRY, journey.id, configPath], {
    cwd: ROOT,
    env: process.env,
    stdio: 'inherit',
    timeout: timeoutMs,
    windowsHide: true,
  });
  if (result.error) {
    console.error(`[ops-e2e] ${journey.id} 启动失败：${result.error.message}`);
    return false;
  }
  if (result.signal) {
    console.error(`[ops-e2e] ${journey.id} 被信号 ${result.signal} 终止（超时 ${timeoutMs}ms？）`);
    return false;
  }
  if (result.status !== 0) {
    console.error(`[ops-e2e] ${journey.id} 失败（退出码 ${result.status}）`);
    return false;
  }
  return true;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.errors.length > 0) {
    console.error('参数不合法，未执行任何旅程：');
    for (const e of args.errors) console.error(`  ✗ ${e}`);
    process.exit(2);
  }
  if (args.list) {
    printList();
    process.exit(0);
  }

  const selected = args.only ? JOURNEYS.filter((j) => args.only.includes(j.id)) : JOURNEYS;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-ops-e2e-'));
  const configPath = path.join(tmpDir, 'config.json');
  fs.writeFileSync(
    configPath,
    JSON.stringify(
      {
        root: ROOT,
        tmpDir,
        node: process.execPath,
      },
      null,
      2
    ),
    { mode: 0o600 }
  );

  console.log('[ops-e2e] 运维关键路径 E2E');
  console.log(`[ops-e2e] 临时目录：${tmpDir}`);
  console.log(`[ops-e2e] 计划 ${selected.length} 条：${selected.map((j) => j.id).join(' / ')}`);

  const failed = [];
  try {
    for (const journey of selected) {
      if (!runJourney(journey, configPath, 180000)) failed.push(journey.id);
    }
  } finally {
    if (args.keep) {
      console.log(`\n[ops-e2e] --keep：临时目录保留在 ${tmpDir}`);
    } else {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  console.log('\n===== [ops-e2e] 汇总 =====');
  if (failed.length > 0) {
    console.error(`[ops-e2e] ${selected.length - failed.length}/${selected.length} 通过`);
    console.error(`[ops-e2e] 失败：${failed.join(' / ')}`);
    process.exit(1);
  }
  console.log(`[ops-e2e] ${selected.length}/${selected.length} 通过`);
}

if (require.main === module) {
  main();
}

module.exports = { JOURNEYS, parseArgs };
