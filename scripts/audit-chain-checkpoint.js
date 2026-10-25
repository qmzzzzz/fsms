#!/usr/bin/env node
/**
 * 审计哈希链签名检查点（外部锚点）
 *
 * 用法:
 *   node scripts/audit-chain-checkpoint.js create [--file=logs/audit-chain-checkpoints.jsonl] [--ship]
 *   node scripts/audit-chain-checkpoint.js ship   [--file=logs/audit-chain-checkpoints.jsonl]
 *   node scripts/audit-chain-checkpoint.js verify [--file=...] [--anchors[=sink] | --no-anchors]
 *
 * 环境变量:
 *   MONGODB_URI             必填，MongoDB 连接串（勿用命令行参数传，会泄露到 ps）
 *   HMAC_SECRET             必填（或 HMAC_SECRET_FILE）：检查点签名与审计链 hmac 共用
 *   AUDIT_ANCHOR_SINK       锚点存储：`file:<路径>` 或 `http(s)://<基址>`；未配置则 ship 报错
 *   AUDIT_ANCHOR_ALLOWLIST  http sink 的主机白名单（逗号分隔）；配了就校验，没配只警告
 *
 * 与 verify-audit-chain.js 的分工：后者校验链内自洽性，天然看不见「在已知锚点后
 * 插枝」与「尾部截断」；本脚本把某一时刻的链尾与记录数签成检查点，核验时比对
 * 计数/hash/当前链尾，补上这两类盲区。
 *
 * 与「外锚」的分工（2026-10-24 补）：检查点文件默认与本机 Mongo 同主权，攻击者
 * 改完链可以**删掉检查点文件再重新 create**，为篡改后的链重新签出一套自洽锚点——
 * 上面那些判据一条都不会触发，且全程不需要 HMAC_SECRET。`--ship` / `ship` 把锚点
 * 追加到外部存储（WORM/对象存储/另一台主机），`verify --anchors` 再把外部副本读回来
 * 双向比对：**外部有、本地无** 就是「本地检查点被删除/截断/重写」。
 * 外部存储必须 append-only 且由另一个主体持有，否则攻击者把副本一起改掉即可。
 *
 * 推荐 cron 形态（把 create 到 ship 的窗口压到最小）：
 *   每小时  node scripts/audit-chain-checkpoint.js create --ship
 *   每天    node scripts/audit-chain-checkpoint.js verify --anchors
 *
 * 退出码:
 *   0 = 全部检查点签名有效、链头与计数一致、当前链尾未倒退（且外锚比对通过）
 *   1 = 任一检查点失配、外发失败、文件不可读、未配置密钥，或运行错误
 *   2 = 判据不可用：配了 AUDIT_ANCHOR_SINK 却既没加 --anchors 也没加 --no-anchors，
 *       或锚点存储读不出来。**不能**把这种情形算成 0（未核验 ≠ 通过）。
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
const {
  SINK_ENV,
  resolveSink,
  readAnchorStore,
  shipCheckpoints,
} = require('../src/services/auditAnchorSink');

const COMMANDS = ['create', 'verify', 'ship'];
const USAGE =
  '支持 --file=路径 / --ship（仅 create）/ --anchors[=sink] / --no-anchors（仅 verify）';

/**
 * 解析 `create|verify|ship` 与各选项；未知参数一律报错，不静默忽略。
 *
 * 新增的 flag 默认值是 `undefined` 而不是 `false`：既有断言用
 * `toEqual({command, filePath})` 比较，`false` 是「已定义」的键会让它失败，
 * `undefined` 在 toEqual 里被忽略，因此旧契约逐字不变。
 */
function parseArgs(argv) {
  const out = {
    command: undefined,
    filePath: undefined,
    ship: undefined,
    anchors: undefined,
    anchorsDisabled: undefined,
  };
  for (const arg of argv) {
    if (!out.command && !arg.startsWith('-')) {
      if (!COMMANDS.includes(arg)) {
        throw new Error(`未知子命令：${arg}（支持 ${COMMANDS.join(' / ')}）`);
      }
      out.command = arg;
      continue;
    }
    if (arg === '--ship') {
      out.ship = true;
      continue;
    }
    if (arg === '--anchors') {
      out.anchors = true;
      continue;
    }
    if (arg === '--no-anchors') {
      out.anchorsDisabled = true;
      continue;
    }
    const fileMatch = /^--file=(.+)$/.exec(arg);
    if (fileMatch) {
      out.filePath = fileMatch[1];
      continue;
    }
    const anchorMatch = /^--anchors=(.+)$/.exec(arg);
    if (anchorMatch) {
      out.anchors = anchorMatch[1];
      continue;
    }
    throw new Error(`无法识别的参数：${arg}（${USAGE}）`);
  }
  if (!out.command) throw new Error(`缺少子命令（支持 ${COMMANDS.join(' / ')}）`);

  // 交叉校验：把「参数放错子命令」变成显式报错，而不是被悄悄忽略。
  // `verify --ship` 若被忽略，运维会以为锚点已外发，实际一次都没发。
  if (out.ship && out.command !== 'create') {
    throw new Error('--ship 只能与 create 一起使用（单独外发请用 ship 子命令）');
  }
  if (out.command !== 'verify' && (out.anchors || out.anchorsDisabled)) {
    throw new Error('--anchors / --no-anchors 只能与 verify 一起使用');
  }
  if (out.anchors && out.anchorsDisabled) {
    throw new Error('--anchors 与 --no-anchors 不能同时使用');
  }
  return out;
}

function resolveCheckpointFile(raw) {
  return raw ? path.resolve(process.cwd(), raw) : DEFAULT_CHECKPOINT_FILE;
}

/** 外发并打印结果；返回退出码。create --ship 与 ship 共用。 */
async function shipAndReport(filePath) {
  const result = await shipCheckpoints({ filePath });
  for (const warning of result.warnings) console.error(`警告：${warning}`);

  if (!result.ok) {
    console.error(`外发失败：${result.error}${result.detail ? `（${result.detail}）` : ''}`);
    if (result.error === 'sink_not_configured') {
      console.error(`请设置 ${SINK_ENV}（file:<路径> 或 http(s)://<基址>）`);
    }
    if (result.error === 'hmac_not_configured') {
      console.error('未配置 HMAC_SECRET：无密钥时既签不出新锚点，也验不了旧锚点');
    }
    if (result.error === 'local_checkpoint_invalid') {
      for (const item of result.invalid) {
        console.error(`  第 ${item.line} 行签名不匹配：headId=${item.headId} @ ${item.createdAt}`);
      }
      console.error(
        '拒绝外发：把未验签的检查点推进 append-only 存储会**永久污染**锚点（WORM 删不掉），' +
          '之后每次核验都要面对它。请先查清该行是被改写还是 HMAC_SECRET 已轮换。'
      );
    }
    console.error(`VERDICT: FAIL — 有 ${result.pending} 个检查点尚未外发`);
    return 1;
  }

  console.log(`已外发 ${result.shipped} 个检查点（存储中已存在 ${result.alreadyAnchored} 个）`);
  console.log('VERDICT: PASS — 外部锚点已与本地检查点同步');
  return 0;
}

/**
 * verify 的外锚准备：解析 sink、读回外部副本。
 *
 * 三条分支的取舍：
 *   · 显式 `--anchors`      → 比对，读不出来就判「判据不可用」（2）
 *   · 显式 `--no-anchors`   → 跳过，但大声说明本次结论不含哪一项
 *   · 都没给但配了 sink     → 判「判据不可用」（2），**不**默默降级成弱校验。
 *     这条是新增的硬闸，但因为 `AUDIT_ANCHOR_SINK` 是本次新引入的变量，
 *     不存在「升级后旧 cron 突然变红」的回归面。
 */
async function prepareExternalAnchors(args) {
  if (args.anchorsDisabled) {
    if (process.env[SINK_ENV]) {
      console.error(
        `注意：--no-anchors 已显式跳过外锚比对。本次结论**不含**「本地检查点被删除/截断/重写（重新锚定）」这一项。`
      );
    }
    return { externalAnchors: undefined, code: 0 };
  }

  const explicit = Boolean(args.anchors);
  if (!explicit && !process.env[SINK_ENV]) {
    return { externalAnchors: undefined, code: 0 };
  }

  const sink = resolveSink(args.anchors === true ? undefined : args.anchors);
  for (const warning of sink.warnings) console.error(`警告：${warning}`);
  if (!sink.kind) {
    console.error(`无法解析锚点存储：${sink.reason}`);
    console.error('VERDICT: INCONCLUSIVE — 外锚判据不可用（未完成核验，不能算通过）');
    return { externalAnchors: undefined, code: 2 };
  }

  const store = await readAnchorStore(sink);
  if (!store.ok) {
    console.error(`读取锚点存储失败：${store.error}${store.detail ? `（${store.detail}）` : ''}`);
    console.error('VERDICT: INCONCLUSIVE — 外锚判据不可用（未完成核验，不能算通过）');
    return { externalAnchors: undefined, code: 2 };
  }
  return { externalAnchors: store.anchors, code: 0 };
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
      if (!args.ship) return 0;
      // 检查点已经落盘：外发失败**不能**回滚或改写它，只能退出非 0 让 cron 报警。
      // 下一次 ship 会补发（存储按 signature 幂等），因此这里不重试、不吞错。
      return shipAndReport(filePath);
    }

    if (args.command === 'ship') {
      return shipAndReport(filePath);
    }

    const prepared = await prepareExternalAnchors(args);
    if (prepared.code !== 0) return prepared.code;

    const result = await verifyCheckpoints({
      model: AuditLog,
      filePath,
      externalAnchors: prepared.externalAnchors,
    });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      console.error(`VERDICT: FAIL — 发现 ${result.errors.length} 处失配`);
      return 1;
    }
    console.log(
      `VERDICT: PASS（${result.checked} 个检查点签名、链头、计数与链尾均一致` +
        `${result.anchors ? `；外锚比对 ${result.anchors.compared} 条` : ''}）`
    );
    if (result.anchors && result.anchors.pending > 0) {
      // 未外发的检查点不在外部锚点保护范围内。这是运维信号而非失配：
      // 正常的 create→ship 间隔里必然出现，因此只警告不判红。
      console.error(
        `警告：${result.anchors.pending} 个检查点尚未外发（最近一次 ship 未覆盖），` +
          '它们不在外锚保护范围内；请检查 ship 是否按 cron 在跑'
      );
    }
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
