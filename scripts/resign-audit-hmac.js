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
 *   2. node scripts/resign-audit-hmac.js --new-key <新KEY>            # 演练
 *   3. node scripts/resign-audit-hmac.js --new-key <新KEY> --apply    # 执行
 *   4. 更新密钥载体（.env 或 secrets/hmac_secret）为新 KEY，启动应用
 *   5. 运行 node scripts/verify-audit-chain.js 复核（预期零 hmac 失配）
 *
 * 注意：校验脚本只能证明「当前库内数据自洽」，不能区分「从未被篡改」与
 * 「被篡改后用新钥重签」——因此重签前建议先跑一次 verify 留档，
 * 确认轮换时点之前链条是干净的。
 */

require('dotenv').config();
require('../src/config/secrets').hydrateSecretsFromFiles();

const crypto = require('crypto');
const mongoose = require('mongoose');

// M-08：破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');

const BATCH_SIZE = 1000;

function parseArgs(argv) {
  const args = { apply: false, newKey: null };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--apply') args.apply = true;
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

  const { uri, dbName } = resolveMongoUri({ scriptName: 'resign-audit-hmac.js' });
  await mongoose.connect(uri);
  console.log(
    `已连接：${mongoose.connection.host}:${mongoose.connection.port}/${mongoose.connection.name}`
  );
  console.log(
    args.apply ? '模式：APPLY（将实际修改数据）' : '模式：DRY-RUN（仅报告，加 --apply 才执行）'
  );

  // M-08：fail-closed——--apply 类操作必须显式声明 ALLOWED_SOURCE_DB。
  // 原先只需单个 --apply 即可批量改写 auditlogs.hmac（等于重写审计完整性
  // 证据），且默认回退本地库，误在生产 shell 执行时不会因库名不符而中止。
  if (!assertApplyAllowed({ scriptName: 'resign-audit-hmac.js', dbName, apply: args.apply })) {
    await mongoose.disconnect();
    process.exit(2);
  }

  const coll = mongoose.connection.collection('auditlogs');

  // 无 hash 的记录（早期/降级落库）没有可签对象，跳过
  const total = await coll.countDocuments({ hash: { $exists: true, $ne: null } });
  console.log(`待检查审计记录：${total}`);

  let alreadySigned = 0;
  let toResign = 0;
  let noHmac = 0;
  const cursor = coll
    .find({ hash: { $exists: true, $ne: null } }, { projection: { _id: 1, hash: 1, hmac: 1 } })
    .batchSize(BATCH_SIZE);

  let buffer = [];
  const flush = async () => {
    if (buffer.length === 0) return;
    if (args.apply) {
      await Promise.all(
        buffer.map((op) => coll.updateOne({ _id: op._id }, { $set: { hmac: op.hmac } }))
      );
    }
    buffer = [];
  };

  for await (const doc of cursor) {
    const expected = hmacOf(newKey, doc.hash);
    if (doc.hmac === expected) {
      alreadySigned += 1;
      continue;
    }
    if (!doc.hmac) noHmac += 1;
    toResign += 1;
    buffer.push({ _id: doc._id, hmac: expected });
    if (buffer.length >= BATCH_SIZE) await flush();
  }
  await flush();

  console.log('\n重签报告：');
  console.log(`  已是新钥签名（跳过）：${alreadySigned}`);
  console.log(
    `  需重签：${toResign}（其中原无 hmac 字段：${noHmac}）${args.apply ? '' : '，演练未写库'}`
  );

  await mongoose.disconnect();

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
