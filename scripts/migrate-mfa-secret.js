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
 *   2. node scripts/migrate-mfa-secret.js --new-key-file <新KEY文件>       # 演练
 *   3. ALLOWED_SOURCE_DB=<库名> node scripts/migrate-mfa-secret.js \
 *        --new-key-file <新KEY文件> --apply                                # 执行（M-08：无白名单直接拒绝）
 *   4. 更新密钥载体（.env 或 secrets/aes_secret_key）为新 KEY
 *   5. 启动应用；旧 KEY 建议密封留档至确认无回滚需要后再销毁
 *
 * 参数（命令行优先于环境变量）：
 *   --old-key-file <路径>  旧 AES_SECRET_KEY；缺省取当前环境（.env / *_FILE 注入）
 *   --new-key-file <路径>  新 AES_SECRET_KEY；也可经 NEW_AES_SECRET_KEY 环境变量提供
 *   --apply                实际写库；缺省为演练模式（只报告不改动）
 *   密钥文件＝单行纯 ASCII，无 BOM/换行/缩进。原先的 --old-key/--new-key 已移除：
 *   把密钥写在命令行上会同时落进 /proc/<pid>/cmdline（同机任意本地用户可读）与 shell 历史。
 *
 * 安全性：
 *   - 每条记录两道校验：先在内存用新钥回读（解不出原文就不碰库），写库后再从库里
 *     回读比对（updateOne 的 matchedCount 必须为 1，库里必须是这条新密文）。
 *     任一不过 ⇒ 记入 failures、计入"失败"、退出码 1，绝不报"迁移完成"。
 *   - 存量明文（无 enc:v1: 前缀，迁移期兼容遗留）顺带加密为密文
 *   - 幂等：新旧钥相同时直接退出；全量已是新钥密文时回读校验通过、零改动
 */

require('dotenv').config();
// *_FILE 密钥文件注入：与启动路径同一入口，保证容器/文件注入环境可用
require('../src/config/secrets').hydrateSecretsFromFiles();

const mongoose = require('mongoose');
const { AESCipher } = require('../src/utils/encryption');
const { ENC_PREFIX } = require('../src/utils/mfaSecret');

// M-08：破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');

// 密钥来源的统一判据（--*-file 或环境变量；错误信息只点名路径，不回显内容）
const { resolveSecretSource } = require('./secretFileArg');

// 已移除的 argv 形态密钥选项 → 替代写法。保留一个**具名**分支而不是落到"未知参数"：
// 默认分支会打印 argv[i]，而循环下一步就是那个密钥本身——那等于把同一次泄漏又抄进 stderr/CI 日志。
const REMOVED_KEY_FLAGS = { '--old-key': '--old-key-file', '--new-key': '--new-key-file' };

function parseArgs(argv) {
  const args = { apply: false, oldKeyFile: null, newKeyFile: null };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--apply') args.apply = true;
    else if (argv[i] === '--old-key-file') args.oldKeyFile = argv[++i];
    else if (argv[i] === '--new-key-file') args.newKeyFile = argv[++i];
    else if (REMOVED_KEY_FLAGS[argv[i]]) {
      console.error(
        `已移除 ${argv[i]}：写在命令行上的密钥会出现在 /proc/<pid>/cmdline（同机任意本地用户可读）` +
          `与 shell 历史里。\n` +
          `   请改用 ${REMOVED_KEY_FLAGS[argv[i]]} <路径>（单行纯 ASCII），` +
          `或环境变量 AES_SECRET_KEY / NEW_AES_SECRET_KEY。`
      );
      process.exit(2);
    } else {
      console.error(`未知参数：${argv[i]}`);
      process.exit(2);
    }
  }
  return args;
}

// 迁移前用应用自身的密钥强度判据（validate.js 的 isWeakSecret——启动校验对 AES_SECRET_KEY
// 用的就是它）挡弱密钥。放行 <32 字符 / 低熵 / 命中黑名单的 key，会把全部 MFA 种子重加密到弱密钥之下，
// 而这类问题只有下次启动 validate 才暴露（届时数据已改写、不可逆）。用同一判据 ⇒ 能过启动校验的 key 必过此关，不误伤合法轮换。
function guardNewKeyStrength(newKey) {
  if (require('../src/config/validate').isWeakSecret(newKey)) {
    console.error(
      '拒绝迁移：新 AES 密钥未通过强度校验（长度 <32 / 命中弱密钥黑名单 / 低熵）。' +
        '请用 `openssl rand -hex 32` 生成强随机密钥后经 --new-key-file 或 NEW_AES_SECRET_KEY 提供。'
    );
    process.exit(2);
  }
}

/**
 * 写库并回读核验。返回 null=成功，字符串=失败原因（由调用方计入 failures）。
 *
 * 为什么不能只看"没抛异常"：原实现是
 *   await coll.updateOne({ _id: doc._id }, { $set: { mfaSecret: next } });
 *   migrated += 1;
 * 结果对象被整个丢弃 ⇒ matchedCount=0（并发删除、集合名写错、写关注降级）照样记成
 * "已迁移"，报告说 N 条、退出码 0，运维照着第 4 步换钥——那部分账户的 mfaSecret
 * 仍是旧钥密文，而 decryptMfaSecret 解不开时静默返回空串，症状就是本脚本头部
 * 要防的那个："验证码总是错"，且没有任何显眼报错。
 * 所以这里三层都要问：抛没抛、命没命中、库里是不是这条新密文。
 */
async function writeAndVerify(coll, doc, next, apply) {
  if (!apply) return null; // 演练模式：不写库，自然也谈不上落库核验
  try {
    const res = await coll.updateOne({ _id: doc._id }, { $set: { mfaSecret: next } });
    if (res.matchedCount !== 1) {
      return `更新未命中文档（matchedCount=${res.matchedCount}），该条仍为旧钥密文`;
    }
    const back = await coll.findOne({ _id: doc._id }, { projection: { mfaSecret: 1 } });
    if (!back) return '回读时文档已不存在';
    if (back.mfaSecret !== next) return '落库回读与预期密文不一致';
  } catch (err) {
    return `写入/回读抛错：${err.message}`;
  }
  return null;
}

/**
 * 逐条迁移主循环。单独成函数是为了能被真实调用路径测到——
 * 内嵌在 IIFE 里时，脚本的"报了多少条"根本没有判据可写。
 */
async function migrateAll({ coll, oldCipher, newCipher, apply }) {
  const stat = {
    encryptedCount: 0,
    plaintextCount: 0,
    migrated: 0,
    unchanged: 0,
    failures: [],
  };
  const cursor = coll.find(
    { mfaSecret: { $exists: true, $nin: [null, ''] } },
    { projection: { _id: 1, username: 1, mfaSecret: 1 } }
  );

  for await (const doc of cursor) {
    const stored = doc.mfaSecret;
    if (typeof stored !== 'string' || stored.length === 0) continue;

    let plain;
    const payload = stored.slice(ENC_PREFIX.length);
    if (stored.startsWith(ENC_PREFIX)) {
      stat.encryptedCount += 1;
      try {
        plain = oldCipher.decrypt(payload);
      } catch (err) {
        // 常见原因：doc 已经是用新密钥加密的（重复执行/部分迁移后重跑）。
        // 验证：新钥能解开即视为已迁移，跳过；否则记为失败，绝不盲改。
        try {
          newCipher.decrypt(payload);
          stat.unchanged += 1;
          continue;
        } catch {
          stat.failures.push({
            id: String(doc._id),
            username: doc.username,
            reason: `新旧密钥均无法解密：${err.message}`,
          });
          continue;
        }
      }
    } else {
      // 迁移期遗留明文（utils/mfaSecret 读取路径兼容无前缀值）：顺带加密
      stat.plaintextCount += 1;
      plain = stored;
    }

    const next = ENC_PREFIX + newCipher.encrypt(plain);
    // 内存回读校验：先确认"新钥解得出这条明文"，再去碰库（写坏一条 = 锁死一个账户的 MFA）
    let roundTripOk = false;
    try {
      roundTripOk = newCipher.decrypt(next.slice(ENC_PREFIX.length)) === plain;
    } catch {
      roundTripOk = false;
    }
    if (!roundTripOk) {
      stat.failures.push({
        id: String(doc._id),
        username: doc.username,
        reason: '新密钥回读校验失败，拒绝写入',
      });
      continue;
    }

    const writeError = await writeAndVerify(coll, doc, next, apply);
    if (writeError) {
      stat.failures.push({ id: String(doc._id), username: doc.username, reason: writeError });
      continue;
    }
    stat.migrated += 1;
  }
  return stat;
}

const runCli = async () => {
  const args = parseArgs(process.argv);
  let oldKey;
  let newKey;
  try {
    oldKey = resolveSecretSource({
      filePath: args.oldKeyFile,
      envValue: process.env.AES_SECRET_KEY,
      label: '旧 AES 密钥',
      flagName: '--old-key-file',
      envName: 'AES_SECRET_KEY（.env / *_FILE 注入）',
    });
    newKey = resolveSecretSource({
      filePath: args.newKeyFile,
      envValue: process.env.NEW_AES_SECRET_KEY,
      label: '新 AES 密钥',
      flagName: '--new-key-file',
      envName: 'NEW_AES_SECRET_KEY',
    });
  } catch (err) {
    // 只转述 err.message：它按构造只含标签与路径，不含任何密钥内容
    console.error(`参数错误：${err.message}`);
    process.exit(2);
  }

  if (oldKey === newKey) {
    console.log('新旧密钥相同，无需迁移');
    process.exit(0);
  }

  guardNewKeyStrength(newKey);

  const oldCipher = new AESCipher(oldKey);
  const newCipher = new AESCipher(newKey);

  const { uri, dbName, host, isFallback } = resolveMongoUri({
    scriptName: 'migrate-mfa-secret.js',
  });

  // M-08：fail-closed——--apply 类操作必须显式声明 ALLOWED_SOURCE_DB。
  // 原先只需单个 --apply 即可批量改写 users.mfaSecret（两因素凭据密文），
  // 且默认回退本地库。
  //
  // 顺序：白名单校验必须在 connect **之前**（本次改动把三个脚本统一到这一口径）。
  // 未获准的执行不该先向目标库（可能就是生产库）发起 TCP + 鉴权握手再被拒；
  // 库不可达时原先会卡在 30s serverSelection 超时里，看起来像"脚本挂了"而不是"被护栏拦下"。
  if (
    !assertApplyAllowed({
      scriptName: 'migrate-mfa-secret.js',
      dbName,
      host,
      isFallback,
      apply: args.apply,
    })
  ) {
    process.exit(2);
  }

  await mongoose.connect(uri);
  console.log(
    `已连接：${mongoose.connection.host}:${mongoose.connection.port}/${mongoose.connection.name}`
  );
  console.log(
    args.apply ? '模式：APPLY（将实际修改数据）' : '模式：DRY-RUN（仅报告，加 --apply 才执行）'
  );

  const coll = mongoose.connection.collection('users');
  const stat = await migrateAll({ coll, oldCipher, newCipher, apply: args.apply });
  const { encryptedCount, plaintextCount, migrated, unchanged, failures } = stat;

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
};

if (require.main === module) {
  runCli().catch((err) => {
    console.error(`迁移脚本执行失败：${err.message}`);
    process.exit(1);
  });
}

module.exports = { parseArgs, migrateAll, writeAndVerify };
