#!/usr/bin/env node
/**
 * 审计哈希链签名检查点（外部锚点）
 *
 * 用法:
 *   node scripts/audit-chain-checkpoint.js create [--file=logs/audit-chain-checkpoints.jsonl]
 *   node scripts/audit-chain-checkpoint.js verify [--file=logs/audit-chain-checkpoints.jsonl]
 *
 * 环境变量:
 *   MONGODB_URI   必填，MongoDB 连接串（勿用命令行参数传，会泄露到 ps）
 *   HMAC_SECRET   必填（或 HMAC_SECRET_FILE）：检查点签名与审计链 hmac 共用
 *
 * 与 verify-audit-chain.js 的分工：后者校验链内自洽性，天然看不见「在已知锚点后
 * 插枝」与「尾部截断」；本脚本把某一时刻的链尾与记录数签成检查点，核验时比对
 * 计数/hash/当前链尾，补上这两类盲区。检查点文件本身可（且应当）周期性复制到
 * WORM/对象存储/时间戳服务——本脚本只产出与验证，不做传输。
 *
 * 退出码:
 *   0 = 全部检查点签名有效、链头与计数一致、当前链尾未倒退
 *   1 = 任一检查点失配、文件不可读、未配置密钥，或运行错误
 */

require('dotenv').config();
require('../src/config/secrets').hydrateSecretsFromFiles();

const path = require('path');
const mongoose = require('mongoose');
const {
  DEFAULT_CHECKPOINT_FILE,
  createCheckpoint,
  verifyCheckpoints,
} = require('../src/services/auditChainCheckpoint');

const COMMANDS = ['create', 'verify'];

/** 解析 `create|verify` 与 `--file=...`；未知参数一律报错，不静默忽略。 */
function parseArgs(argv) {
  const out = { command: undefined, filePath: undefined };
  for (const arg of argv) {
    if (!out.command && !arg.startsWith('-')) {
      if (!COMMANDS.includes(arg)) {
        throw new Error(`未知子命令：${arg}（支持 ${COMMANDS.join(' / ')}）`);
      }
      out.command = arg;
      continue;
    }
    const m = /^--file=(.+)$/.exec(arg);
    if (m) {
      out.filePath = m[1];
      continue;
    }
    throw new Error(`无法识别的参数：${arg}（支持 --file=路径）`);
  }
  if (!out.command) throw new Error(`缺少子命令（支持 ${COMMANDS.join(' / ')}）`);
  return out;
}

function resolveCheckpointFile(raw) {
  return raw ? path.resolve(process.cwd(), raw) : DEFAULT_CHECKPOINT_FILE;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const filePath = resolveCheckpointFile(args.filePath);
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('错误：未提供 MONGODB_URI，请通过环境变量或 .env 指定（命令行传参会泄露到 ps）');
    process.exit(1);
  }

  await mongoose.connect(uri);
  const AuditLog = require('../src/models/AuditLog');
  try {
    if (args.command === 'create') {
      const { record } = await createCheckpoint({ model: AuditLog, filePath });
      console.log(`检查点已写入 ${filePath}`);
      console.log(JSON.stringify(record, null, 2));
      return 0;
    }

    const result = await verifyCheckpoints({ model: AuditLog, filePath });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      console.error(`VERDICT: FAIL — 发现 ${result.errors.length} 处检查点失配`);
      return 1;
    }
    console.log(`VERDICT: PASS（${result.checked} 个检查点签名、链头、计数与链尾均一致）`);
    return 0;
  } finally {
    await mongoose.connection.close();
  }
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error('检查点脚本运行失败：', err.message);
      try {
        mongoose.connection.close().finally(() => process.exit(1));
      } catch (_) {
        process.exit(1);
      }
    });
}

module.exports = { parseArgs, resolveCheckpointFile, COMMANDS };
