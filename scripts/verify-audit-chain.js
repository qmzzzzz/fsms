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
 * 退出码（修正：原实现只要 breaks===0 就退 0，把"没验完"和"验过且干净"混成同一个绿）:
 *   0 = **全量**校验完成、无断裂、且 hmac 层确实参与校验
 *   1 = 发现断裂/失配（或运行错误）
 *   2 = 校验不完整，**不得当作"链是好的"**：
 *         · 命中 maxRecords 上限（只覆盖了窗口，其余没看）
 *         · 未配置 HMAC_SECRET —— 此时只有无密钥的 SHA-256 在跑，
 *           拿到 DB 写权限的人可整条链重算（hmac 才是唯一真正的防线，
 *           见 auditChainVerify.js 头注释）。确要在无 hmac 环境跑，
 *           显式加 --allow-no-hmac（运维知情放行，而不是默认绿）。
 *         · 审计集合一条记录都没有：无对象可验。这一条尤其不能默认放过——
 *           绕过模型钩子的直连 deleteMany({}) 就能造出"0 条且无断裂"的现场，
 *           退 0 等于校验器为灭迹现场签发合格证明。新装库确要放行加 --allow-empty。
 *         · 扫到的记录**全部无哈希**：一条都没有经过哈希校验。"链启用前的存量集合"
 *           与"整表 $unset 掉 hash/prevHash/hmac"（直连驱动/mongosh 可绕过中间件）
 *           在数据上不可区分，后者是彻底灭迹。旧判据把整窗 legacy 全数吸收 ⇒ breaks=0
 *           ⇒ 退 0，**抹得越干净反而判得越干净**（只抹链尾退 1、整表全抹退 0）。
 *           确要在"链从未启用"的存量库上放行加 --allow-all-legacy。
 *         · 报告里有"算 hash 失败后无哈希落库"的记录（hashComputeFailed > 0）：链上
 *           存在无法追认的缺口。没有豁免开关——"我知道有几条算失败"不是可以一次性放行的
 *           口径，它要么修好要么留红。
 *
 * 四个豁免彼此独立：--allow-no-hmac 只豁免 hmac，--allow-empty 只豁免空集合，
 * --allow-all-legacy 只豁免"整窗无哈希"，任一未豁免的不完整理由都会把退出码钉在 2
 * （见 computeVerdict 的真值表用例）。
 *
 * 尾部截断（删掉最新若干条）不在本脚本能力范围内：链本身仍自洽，需要外部
 * 锚点（如周期性签名水位记录）才能发现，属独立设计项，此处如实不做承诺。
 */

require('dotenv').config();
// 容器里密钥只以 <NAME>_FILE 挂载，必须在此回填：本脚本既读 MONGODB_URI，
// 也依赖 HMAC_SECRET 参与校验（缺 hmac 时判据只会退成「校验不完整」）。
// 不能指望 src/config 的 hydrate——它在懒 require 里执行，读 env 时还没跑过
// （不变量见 src/tests/config/scriptSecretHydration.test.js）。
require('../src/config/secrets').hydrateSecretsFromFiles();

const mongoose = require('mongoose');
const {
  verifyAuditChain,
  computeChainVerdict,
  HARD_MAX_RECORDS,
} = require('../src/services/auditChainVerify');

/** 解析 --key=value 与 --flag 形式的参数；未知参数一律报错，不静默忽略 */
function parseArgs(argv) {
  const out = {
    limit: undefined,
    from: undefined,
    allowNoHmac: false,
    allowEmpty: false,
    allowAllLegacy: false,
  };
  for (const arg of argv) {
    if (arg === '--allow-no-hmac') {
      out.allowNoHmac = true;
      continue;
    }
    if (arg === '--allow-empty') {
      out.allowEmpty = true;
      continue;
    }
    if (arg === '--allow-all-legacy') {
      out.allowAllLegacy = true;
      continue;
    }
    const m = /^--([\w-]+)=(.*)$/.exec(arg);
    if (!m)
      throw new Error(
        `无法识别的参数：${arg}（支持 --limit=N --from=latest|earliest ` +
          '--allow-no-hmac --allow-empty --allow-all-legacy）'
      );
    const [, key, value] = m;
    if (key === 'limit') out.limit = value;
    else if (key === 'from') out.from = value;
    else throw new Error(`不支持的选项：--${key}`);
  }
  return out;
}

/**
 * maxRecords 的取值必须是"用户给的正整数"或"缺省全量上限"。
 * 原实现 `parseInt(args.limit, 10)` 对 `--limit=abc` 得到 NaN ⇒ NaN 是 falsy ⇒
 * 静默退回 DEFAULT_MAX_RECORDS（运维以为按窗口跑了，实际跑的是另一套范围）。
 */
function resolveMaxRecords(rawLimit) {
  if (rawLimit === undefined) return HARD_MAX_RECORDS;
  if (!/^\d+$/.test(String(rawLimit))) {
    throw new Error(`--limit 必须是正整数，收到「${rawLimit}」`);
  }
  const n = Number(rawLimit);
  if (n < 1) throw new Error(`--limit 必须是正整数，收到「${rawLimit}」`);
  return n;
}

/**
 * 退出码判定：委托给 src/services/auditChainVerify.computeChainVerdict。
 *
 * 为什么必须委托而不是各写一份：同一个"能否宣称链完整"的判据此前有两处实现——
 * 这里纳入 truncated/empty/hmac 三类不完整，而在线接口只看 intact && hmacChecked，
 * 于是脚本退 2 说"不得当作链完整"的同时，接口却回答「审计链完整」并把核验审计记成 low。
 * 判据收在一处，CLI 这层只负责把 code 映射成退出码与话术。
 */
function computeVerdict(args) {
  return computeChainVerdict(args);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.from !== undefined && !['latest', 'earliest'].includes(args.from)) {
    throw new Error(`--from 只能是 latest 或 earliest，收到「${args.from}」`);
  }
  const maxRecords = resolveMaxRecords(args.limit);
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('错误：未提供 MONGODB_URI，请通过环境变量或 .env 指定（命令行传参会泄露到 ps）');
    process.exit(1);
  }

  await mongoose.connect(uri);
  const AuditLog = require('../src/models/AuditLog');
  // 集合总量仅用于区分"全部看完"与"卡在上限"，用元数据级估算（O(1)）。
  // 注意它只是**参考**：估算滞后时可能低于实际扫到的条数，判据据此把
  // "窗口打满 + 两个数不一致"一律判 INCOMPLETE（见 computeChainVerdict 的 truncated 一段），
  // 不再沿用"追平即可"的旧口径——那正是估算偏低时撤销截断否决的那一行。
  const collectionTotal = await AuditLog.estimatedDocumentCount();

  // 默认全量校验（离线执行，无响应时间约束）；一旦落到上限就是"只看了窗口"，
  // 下面用 truncated 显式区分，不再让"没验完"退成 0。
  const result = await verifyAuditChain(AuditLog, {
    maxRecords,
    fromLatest: args.from !== 'earliest',
  });

  console.log(JSON.stringify(result, null, 2));
  await mongoose.connection.close();

  const verdict = computeVerdict({
    breaks: result.breaks,
    total: result.total,
    maxRecords: result.scanned.maxRecords,
    collectionTotal,
    hmacChecked: result.hmacChecked,
    // 整窗无哈希（全 legacy）同样不得背书：见 computeChainVerdict 的 nothingHashed 一段
    legacy: result.legacy,
    // 报告里"算 hash 失败后无哈希落库"的条数：>0 时判据拒绝 code 0。
    // 这个字段 verifyAuditChain **恒回填**，不回传不是"少一条理由"，而是把
    // 报告自己已经看见的缺口在出口处丢掉——手册正是按退出码 0 验收这一步
    // （deployment/rollback-drill.md:111、deployment/secret-rotation.md:397），
    // 于是"链尾有 N 条不可追认"也能拿到 PASS。
    // 判据对缺该字段的调用按 0 处理（不像 scanned/legacy 那样 fail-closed），
    // 所以这一行由 src/tests/verifyChainExitCode.test.js 的「判据调用方必须把报告字段回传全」钉住，漏传即红。
    hashComputeFailed: result.hashComputeFailed,
    // 扫描口径由报告回显：判据缺它时按"局部校验"处理（宁 INCOMPLETE，不假 PASS）
    scanned: result.scanned,
    allowNoHmac: args.allowNoHmac,
    allowEmpty: args.allowEmpty,
    allowAllLegacy: args.allowAllLegacy,
  });
  const label =
    verdict.code === 0
      ? 'PASS（全量、无断裂、hmac 已校验）'
      : verdict.code === 1
        ? 'FAIL（断裂）'
        : 'INCOMPLETE（不得当作链完整）';
  console.log(
    `VERDICT: ${label}${verdict.reasons.length ? ` — ${verdict.reasons.join('；')}` : ''}`
  );
  process.exit(verdict.code);
}

// 仅在直接执行时跑（与 lint-ratchet.js 同一条 E-02 教训：无条件调用 main()
// 会让任何 require() 本文件的单测连带连库 + 改写退出码）。
if (require.main === module) {
  main().catch((err) => {
    console.error('校验脚本运行失败：', err.message);
    try {
      mongoose.connection.close().finally(() => process.exit(1));
    } catch (_) {
      process.exit(1);
    }
  });
}

module.exports = { computeVerdict, parseArgs, resolveMaxRecords };
