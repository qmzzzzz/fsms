/**
 * HMAC_SECRET 轮换配套脚本：重签 auditlogs.hmac（R-1）
 *
 * 背景：审计记录的防篡改标签为 `hmac = HMAC-SHA256(HMAC_SECRET, hash)`
 * （见 utils/auditChain.js computeHmac）。hmac 只覆盖 hash 本身，与记录内容、
 * 旧密钥均无关——因此换钥后**无需旧密钥**即可用新钥对存量记录的 hash 重签，
 * 哈希链（prevHash/hash）不受任何影响。
 *
 * 不重签的后果：auditChainVerify 会把全部存量记录判为 hmac 失配，
 * 审计链完整性校验失去意义（告警被噪声淹没）。
 *
 * 步骤（维护窗口内执行）：
 *   1. 停应用，避免迁移期间新记录用旧钥签名
 *   2. node scripts/resign-audit-hmac.js --new-key <新KEY>                     # 演练
 *   3. ALLOWED_SOURCE_DB=<库名> node scripts/resign-audit-hmac.js \
 *        --new-key <新KEY> --apply --yes                                      # 执行
 *      （L-26：--apply 需 ALLOWED_SOURCE_DB 白名单 + --yes 双标志，与同族脚本一致）
 *   4. 更新密钥载体（.env 或 secrets/hmac_secret）为新 KEY，启动应用
 *   5. 运行 node scripts/verify-audit-chain.js 复核（预期零 hmac 失配）
 *
 * 注意：校验脚本只能证明「当前库内数据自洽」，不能区分「从未被篡改」与
 * 「被篡改后用新钥重签」——因此重签前建议先跑一次 verify 留档，
 * 确认轮换时点之前链条是干净的。
 *
 * ⚠️ 上面那句"建议"为什么已经不够，以及本脚本现在硬性做什么：
 * `hash` 是无密钥的 SHA-256，所以**只有 DB 写权限**的攻击者改内容时可以顺手把
 * hash 重算自洽——链条结构照旧，此时防篡改链上唯一会红的一层就是 hmac。
 * 若本脚本像早期版本那样「对不上新钥就一律重签」，运维照 Runbook 跑完 --apply 之后
 * verify 会对一份被改过的库报「完整」：灭迹现场由官方轮换工具签发了合格证。
 * 因此现在写库之前必须先跑一遍**只读预检**：凡"带 hmac、但在当前钥下解不开"的记录
 * 记为 suspect，默认拒绝执行（要越权必须显式 --allow-suspect-hmac）；
 * 预检拿不到当前 HMAC_SECRET 时记为 unverifiable，同样默认拒绝——
 * 那种情形下重签不构成任何完整性背书，不能悄悄给出去。
 * 演练（无 --apply）只把同一份报告打出来并退出 0：它一行未改，拒绝码要留给真要改写的执行，
 * 否则 Runbook 第 2 步的"常规体检"会因为报告本身而失败。
 * 顺序要求：**预检必须早于任何改写**，否则"拒绝"时已经改了一半（原实现边扫边写）。
 */

require('dotenv').config();
require('../src/config/secrets').hydrateSecretsFromFiles();

const crypto = require('crypto');
const mongoose = require('mongoose');

// M-08：破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');

const BATCH_SIZE = 1000;
const SAMPLE_LIMIT = 10;

// L-26：与同族脚本（resign-audit-chain-v3.js / run-rollback-drill.js）统一为
// 「--apply + --yes」双标志。原先只有本脚本是单标志，而它批量改写的是
// auditlogs.hmac——审计完整性证据本身，破坏性与重签整条链同级甚至更高
// （后者至少还能靠 verify 发现不自洽，重签 hmac 会让失配记录重新「通过」）。
const CONFIRM_FLAG = '--yes';

function parseArgs(argv) {
  const args = { apply: false, confirmYes: false, newKey: null, allowSuspect: false };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--apply') args.apply = true;
    else if (argv[i] === CONFIRM_FLAG) args.confirmYes = true;
    else if (argv[i] === '--allow-suspect-hmac') args.allowSuspect = true;
    else if (argv[i] === '--new-key') args.newKey = argv[++i];
    else {
      console.error(`未知参数：${argv[i]}`);
      process.exit(2);
    }
  }
  return args;
}

const hmacOf = (secret, hash) =>
  crypto.createHmac('sha256', secret).update(hash, 'utf8').digest('hex');

/**
 * 单条记录在"换钥重签"这件事上的状态。
 *
 * 分成五格的核心原因：「hmac 对不上新钥」有两种含义完全不同的成因——
 * 从没签过（补签即可）与**当前钥也解不开**（篡改的唯一证据，重签即灭迹）。
 * 早期版本把两者合并成"一律重签"，正是文件头警告的那条路径。
 */
function classifyHmacState({ hasHmac, matchesNewKey, hasCurrentKey, matchesCurrentKey }) {
  if (matchesNewKey) return 'already_signed';
  if (!hasHmac) return 'never_signed';
  if (!hasCurrentKey) return 'unverifiable';
  return matchesCurrentKey ? 'clean' : 'suspect';
}

const SCAN_STATES = ['already_signed', 'never_signed', 'clean', 'suspect', 'unverifiable'];

const AUDITED_FILTER = { hash: { $exists: true, $ne: null } };
const AUDITED_PROJECTION = { _id: 1, hash: 1, hmac: 1 };

/**
 * 第一遍：只分类、只计数，**不写库**。
 * @returns {Promise<{counts: Object, samples: Array<{state: string, id: string}>}>}
 */
async function tallyHmacStates(coll, { newKey, currentKey }) {
  const counts = {};
  for (const state of SCAN_STATES) counts[state] = 0;
  const samples = [];
  const cursor = coll
    .find(AUDITED_FILTER, { projection: AUDITED_PROJECTION })
    .batchSize(BATCH_SIZE);
  for await (const doc of cursor) {
    const state = classifyHmacState({
      hasHmac: Boolean(doc.hmac),
      matchesNewKey: doc.hmac === hmacOf(newKey, doc.hash),
      hasCurrentKey: Boolean(currentKey),
      matchesCurrentKey: Boolean(currentKey) && doc.hmac === hmacOf(currentKey, doc.hash),
    });
    counts[state] += 1;
    const evidentiary = state === 'suspect' || state === 'unverifiable';
    if (evidentiary && samples.length < SAMPLE_LIMIT) samples.push({ state, id: String(doc._id) });
  }
  return { counts, samples };
}

/** 第二遍：判定放行之后才改写。已是新钥签名的跳过，其余（含被越权放行的 suspect）重签。 */
async function writeResignatures(coll, { newKey }) {
  let buffer = [];
  let resigned = 0;
  const flush = async () => {
    if (buffer.length === 0) return;
    await Promise.all(
      buffer.map((op) => coll.updateOne({ _id: op._id }, { $set: { hmac: op.hmac } }))
    );
    buffer = [];
  };
  const cursor = coll
    .find(AUDITED_FILTER, { projection: AUDITED_PROJECTION })
    .batchSize(BATCH_SIZE);
  for await (const doc of cursor) {
    const expected = hmacOf(newKey, doc.hash);
    if (doc.hmac === expected) continue;
    resigned += 1;
    buffer.push({ _id: doc._id, hmac: expected });
    if (buffer.length >= BATCH_SIZE) await flush();
  }
  await flush();
  return { resigned };
}

/** 预检报告：五格计数 + 取证样本。演练与正式执行打印同一份，工单附件就是这段输出。 */
function printPrecheckReport({ counts, samples }) {
  console.log('预检分类（早于任何改写；这段输出就是轮换工单该留的档）：');
  console.log(`  已是新钥签名（跳过）     ：${counts.already_signed}`);
  console.log(`  原本无 hmac（首次签发）  ：${counts.never_signed}`);
  console.log(`  当前钥自洽（可安全重签） ：${counts.clean}`);
  console.log(`  当前钥解不开（疑似被改） ：${counts.suspect}`);
  console.log(`  缺当前密钥、无法预检     ：${counts.unverifiable}`);
  if (samples.length > 0) {
    console.log(`  样本 _id（最多 ${SAMPLE_LIMIT} 条）：`);
    for (const s of samples) console.log(`    [${s.state}] ${s.id}`);
  }
}

/**
 * 预检裁决。返回 false = 必须拒绝（调用方断开连接并 exit 2）。
 *
 * 退出码只留给"真的要做坏事"的那次执行：演练模式一行未改，让它退出 0，运维才能把
 * Runbook 第 2 步（演练）当常规体检跑；同一份报告在 --apply 下才升级为拒绝。
 */
function decidePrecheckVerdict({ counts, apply, allowSuspect }) {
  const blocking = counts.suspect + counts.unverifiable;
  if (blocking === 0) return true;
  console.error(
    `\n发现灭迹风险：${counts.suspect} 条带 hmac 却在当前 HMAC_SECRET 下解不开，` +
      `${counts.unverifiable} 条因缺少当前密钥无法预检。`
  );
  console.error(
    '重签这些记录会让 verify-audit-chain 对被改过的库报「完整」——那是灭迹，不是修复。\n' +
      '请先按上面的样本 _id 排查取证，确认无误才追加 --allow-suspect-hmac。'
  );
  if (allowSuspect) {
    console.log(`\n已按 --allow-suspect-hmac 越权放行 ${blocking} 条：其 hmac 失配证据将被覆盖。`);
    return true;
  }
  if (!apply) {
    console.log('\n演练模式未改写任何记录。加上 --apply 时会因上述报告被拒绝。');
    return true;
  }
  console.error('拒绝执行：以上记录使本次重签不具备完整性背书。');
  return false;
}

module.exports = { classifyHmacState, SCAN_STATES, hmacOf };

// 可被 require 的脚本不在模块级跑副作用：判定要能被单测取走而不触发连库。
if (require.main === module) {
  (async () => {
    const args = parseArgs(process.argv);
    const newKey = args.newKey || process.env.NEW_HMAC_SECRET;
    const currentKey = process.env.HMAC_SECRET;

    if (!newKey) {
      console.error('缺少新密钥：请用 --new-key 提供，或设置 NEW_HMAC_SECRET 环境变量');
      process.exit(2);
    }
    if (currentKey && currentKey === newKey) {
      console.log('新密钥与当前 HMAC_SECRET 相同，无需重签');
      process.exit(0);
    }

    const { uri, dbName, host, isFallback } = resolveMongoUri({
      scriptName: 'resign-audit-hmac.js',
    });

    // M-08 / L-26：fail-closed 白名单 + 双标志，与同族脚本口径一致。
    // 原先只需单个 --apply 即可批量改写 auditlogs.hmac（等于重写审计完整性
    // 证据），且默认回退本地库，误在生产 shell 执行时不会因库名不符而中止。
    //
    // 顺序：两道确认都必须在 connect **之前**（本次改动统一的就是这一维）。
    // 被拒绝的执行不该向目标库（可能就是生产库）发起 TCP + 鉴权握手；
    // 库不可达时原先会卡在 30s serverSelection 超时里，连"我该被拒绝"都要等连接失败才知道。
    if (
      !assertApplyAllowed({
        scriptName: 'resign-audit-hmac.js',
        dbName,
        host,
        isFallback,
        apply: args.apply,
      })
    ) {
      process.exit(2);
    }
    if (args.apply && !args.confirmYes) {
      console.error(
        `错误：--apply 将批量改写 auditlogs.hmac（重写审计完整性证据），需再传 ${CONFIRM_FLAG} 确认。`
      );
      process.exit(2);
    }

    await mongoose.connect(uri);
    console.log(
      `已连接：${mongoose.connection.host}:${mongoose.connection.port}/${mongoose.connection.name}`
    );
    console.log(
      args.apply ? '模式：APPLY（将实际修改数据）' : '模式：DRY-RUN（仅报告，加 --apply 才执行）'
    );

    const coll = mongoose.connection.collection('auditlogs');

    // 无 hash 的记录（早期/降级落库）没有可签对象，跳过
    const total = await coll.countDocuments(AUDITED_FILTER);
    console.log(`待检查审计记录：${total}`);

    const { counts, samples } = await tallyHmacStates(coll, { newKey, currentKey });
    printPrecheckReport({ counts, samples });
    if (!decidePrecheckVerdict({ counts, apply: args.apply, allowSuspect: args.allowSuspect })) {
      await mongoose.disconnect();
      process.exit(2);
    }

    // 演练不改库，所以报"将会重签多少条"；APPLY 报真正改写的条数。
    let resigned;
    if (args.apply) {
      resigned = (await writeResignatures(coll, { newKey })).resigned;
    } else {
      resigned = counts.never_signed + counts.clean + counts.suspect + counts.unverifiable;
    }

    await mongoose.disconnect();

    console.log('\n重签报告：');
    console.log(
      `  需重签：${resigned}${args.apply ? `（已改写 ${resigned} 条）` : '，演练未写库'}`
    );

    if (!args.apply) {
      console.log(
        '\n演练完成。确认无误后追加 --apply 执行；执行前建议先运行 verify-audit-chain.js 留档。'
      );
    } else {
      console.log(
        '\n重签完成。下一步：更新 HMAC_SECRET 载体并重启，然后运行 verify-audit-chain.js 复核。'
      );
    }
  })().catch((err) => {
    console.error(`重签脚本执行失败：${err.message}`);
    process.exit(1);
  });
}
