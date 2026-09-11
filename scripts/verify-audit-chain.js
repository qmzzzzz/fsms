#!/usr/bin/env node
/**
 * 审计日志哈希链完整性校验脚本
 *
 * 用法:
 *   node scripts/verify-audit-chain.js [--limit=N] [--from=latest|earliest]
 *
 * 环境变量:
 *   MONGODB_URI  MongoDB 连接串（默认从 .env / 环境读取）
 *   注意：不再支持从命令行位置参数传连接串——含密码的 URI 会出现在 ps/proc 中，
 *   对同机其他用户可见。
 *
 * 校验逻辑集中在 src/services/auditChainVerify.js，与在线接口
 * GET /api/security/audit-logs/verify 共用同一实现，避免两处口径漂移。
 *
 * 退出码:
 *   0 = 完整（无断裂）
 *   1 = 有断裂或运行错误
 */

require('dotenv').config();

const mongoose = require('mongoose');
const { verifyAuditChain, HARD_MAX_RECORDS } = require('../src/services/auditChainVerify');

/** 解析 --key=value 形式的参数 */
function parseArgs(argv) {
  const out = {};
  for (const arg of argv) {
    const m = /^--([\w-]+)=(.*)$/.exec(arg);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('错误：未提供 MONGODB_URI，请通过环境变量或 .env 指定（命令行传参会泄露到 ps）');
    process.exit(1);
  }

  await mongoose.connect(uri);
  const AuditLog = require('../src/models/AuditLog');

  // 脚本默认全量校验（离线执行，无响应时间约束）
  const result = await verifyAuditChain(AuditLog, {
    maxRecords: args.limit ? parseInt(args.limit, 10) : HARD_MAX_RECORDS,
    fromLatest: args.from !== 'earliest',
  });

  console.log(JSON.stringify(result, null, 2));

  await mongoose.connection.close();
  process.exit(result.breaks > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('校验脚本运行失败：', err.message);
  try {
    mongoose.connection.close().finally(() => process.exit(1));
  } catch (_) {
    process.exit(1);
  }
});
