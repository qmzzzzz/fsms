/**
 * AES_SECRET_KEY 轮换配套脚本：重加密 users.mfaSecret（R-1）
 *
 * 背景：mfaSecret 以 `enc:v1:` + AES-256-GCM 密文落库（见 utils/mfaSecret.js）。
 * 直接替换 AES_SECRET_KEY 会导致全部存量 MFA 种子解密失败——用户登录时
 * TOTP 校验恒失败，且 decryptMfaSecret 静默返回空串，症状是「验证码总是错」，
 * 没有显眼报错，排查方向极易被带偏。轮换必须先迁移数据再换钥。
 *
 * 步骤（维护窗口内执行）：
 *   1. 停应用（或停止 MFA enroll/登录写入），避免迁移期间新数据用旧钥写入
 *   2. node scripts/migrate-mfa-secret.js --new-key <新KEY>            # 演练
 *   3. node scripts/migrate-mfa-secret.js --new-key <新KEY> --apply    # 执行
 *   4. 更新密钥载体（.env 或 secrets/aes_secret_key）为新 KEY
 *   5. 启动应用；旧 KEY 建议密封留档至确认无回滚需要后再销毁
 *
 * 参数（命令行优先于环境变量）：
 *   --old-key <hex>        旧 AES_SECRET_KEY；缺省取当前环境（.env / *_FILE 注入）
 *   --new-key <hex>        新 AES_SECRET_KEY；也可经 NEW_AES_SECRET_KEY 环境变量提供
 *   --apply                实际写库；缺省为演练模式（只报告不改动）
 *
 * 安全性：
 *   - 每条记录迁移后立即用新钥回读校验，不一致则拒绝写入该条（宁可少迁不可写坏）
 *   - 存量明文（无 enc:v1: 前缀，迁移期兼容遗留）顺带加密为密文
 *   - 幂等：新旧钥相同时直接退出；全量已是新钥密文时回读校验通过、零改动
 */

require('dotenv').config();
// *_FILE 密钥文件注入：与启动路径同一入口，保证容器/文件注入环境可用
require('../src/config/secrets').hydrateSecretsFromFiles();

const mongoose = require('mongoose');
const { AESCipher } = require('../src/utils/encryption');
const { ENC_PREFIX } = require('../src/utils/mfaSecret');

function parseArgs(argv) {
  const args = { apply: false, oldKey: null, newKey: null };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--apply') args.apply = true;
    else if (argv[i] === '--old-key') args.oldKey = argv[++i];
    else if (argv[i] === '--new-key') args.newKey = argv[++i];
    else {
      console.error(`未知参数：${argv[i]}`);
      process.exit(2);
    }
  }
  return args;
}

(async () => {
  const args = parseArgs(process.argv);
  const oldKey = args.oldKey || process.env.AES_SECRET_KEY;
  const newKey = args.newKey || process.env.NEW_AES_SECRET_KEY;

  if (!oldKey) {
    console.error('缺少旧密钥：请用 --old-key 提供，或确保 .env / *_FILE 已注入 AES_SECRET_KEY');
    process.exit(2);
  }
  if (!newKey) {
    console.error('缺少新密钥：请用 --new-key 提供，或设置 NEW_AES_SECRET_KEY 环境变量');
    process.exit(2);
  }
  if (oldKey === newKey) {
    console.log('新旧密钥相同，无需迁移');
    process.exit(0);
  }

  const oldCipher = new AESCipher(oldKey);
  const newCipher = new AESCipher(newKey);

  const uri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/fire_safety_db';
  await mongoose.connect(uri);
  console.log(
    `已连接：${mongoose.connection.host}:${mongoose.connection.port}/${mongoose.connection.name}`
  );
  console.log(
    args.apply ? '模式：APPLY（将实际修改数据）' : '模式：DRY-RUN（仅报告，加 --apply 才执行）'
  );

  const coll = mongoose.connection.collection('users');
  // mfaSecret 在 schema 中 select:false，这里用原生集合直接投影读取
  const cursor = coll.find(
    { mfaSecret: { $exists: true, $nin: [null, ''] } },
    { projection: { _id: 1, username: 1, mfaSecret: 1 } }
  );

  let encryptedCount = 0;
  let plaintextCount = 0;
  let migrated = 0;
  let unchanged = 0;
  const failures = [];

  for await (const doc of cursor) {
    const stored = doc.mfaSecret;
    if (typeof stored !== 'string' || stored.length === 0) continue;

    let plain;
    if (stored.startsWith(ENC_PREFIX)) {
      encryptedCount += 1;
      try {
        plain = oldCipher.decrypt(stored.slice(ENC_PREFIX.length));
      } catch (err) {
        // 常见原因：doc 已经是用新密钥加密的（重复执行/部分迁移后重跑）。
        // 验证：新钥能解开即视为已迁移，跳过；否则记为失败，绝不盲改。
        try {
          newCipher.decrypt(stored.slice(ENC_PREFIX.length));
          unchanged += 1;
          continue;
        } catch {
          failures.push({
            id: String(doc._id),
            username: doc.username,
            reason: `新旧密钥均无法解密：${err.message}`,
          });
          continue;
        }
      }
    } else {
      // 迁移期遗留明文（utils/mfaSecret 读取路径兼容无前缀值）：顺带加密
      plaintextCount += 1;
      plain = stored;
    }

    const next = ENC_PREFIX + newCipher.encrypt(plain);
    // 回读校验：写坏一条 = 锁死一个账户的 MFA，必须逐条把关
    let roundTripOk = false;
    try {
      roundTripOk = newCipher.decrypt(next.slice(ENC_PREFIX.length)) === plain;
    } catch {
      roundTripOk = false;
    }
    if (!roundTripOk) {
      failures.push({
        id: String(doc._id),
        username: doc.username,
        reason: '新密钥回读校验失败，拒绝写入',
      });
      continue;
    }

    if (args.apply) {
      await coll.updateOne({ _id: doc._id }, { $set: { mfaSecret: next } });
    }
    migrated += 1;
  }

  console.log('\n迁移报告：');
  console.log(`  存量密文（enc:v1:）：${encryptedCount}`);
  console.log(`  存量明文（顺带加密）：${plaintextCount}`);
  console.log(`  本次迁移：${migrated}${args.apply ? '' : '（演练未写库）'}`);
  console.log(`  已是新钥密文跳过：${unchanged}`);
  console.log(`  失败：${failures.length}`);
  failures.forEach((f) => console.log(`    - ${f.username || f.id}: ${f.reason}`));

  await mongoose.disconnect();

  if (failures.length > 0) {
    console.error('\n存在失败记录：请勿切换 AES_SECRET_KEY，先人工处理上述账户');
    process.exit(1);
  }
  if (!args.apply) {
    console.log('\n演练完成。确认无误后追加 --apply 执行实际迁移。');
  } else {
    console.log(
      '\n迁移完成。下一步：把密钥载体（.env 或 secrets/aes_secret_key）更新为新密钥并重启应用。'
    );
  }
})().catch((err) => {
  console.error(`迁移脚本执行失败：${err.message}`);
  process.exit(1);
});
