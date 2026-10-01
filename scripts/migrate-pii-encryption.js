/**
 * PII 加密迁移 / 密钥轮换（P1-②，2026-09-30）
 *
 * 用法（与 resign-audit-hmac.js 同族的门禁口径：--apply 需 ALLOWED_SOURCE_DB + --yes）：
 *   node scripts/migrate-pii-encryption.js                        # 演练：只读扫描并出报告
 *   ALLOWED_SOURCE_DB=<库名> node scripts/migrate-pii-encryption.js --apply --yes
 *                                                                 # 把存量明文 phone 加密
 *      （realName 暂不加密——2026-09-30 决策：保留姓名模糊检索；
 *        若有行在加密窗口内被加密过，本脚本会自动解回明文自愈）
 *   ALLOWED_SOURCE_DB=<库名> PII_ROTATION_OLD_AES_KEY=<旧KEY> \
 *     node scripts/migrate-pii-encryption.js --apply --yes --rotate
 *                                                                 # 用旧主密钥解密 → 当前主密钥重加密
 *
 * 背景：User.realName / User.phone 自 2026-09-30 起 at-rest 加密（utils/piiCrypto.js，
 * AES-256-GCM 随机 IV，格式 `enc.v1.<iv>.<data>`）。模型层对存量明文**透读取**、
 * 修改时才加密——本脚本负责把「尚未修改的存量行」一次性收口，并承担密钥轮换时
 * 的全列重加密。两件事是同一套管道：都是「按当前密钥解密 → 按目标密钥加密 →
 * 同步检索键」，只是解密密钥来源不同（存量明文不需要解密）。
 *
 * 安全属性：
 *   - 演练模式一行不改，报告先行（多少行待加密 / 已加密 / 损坏不可解）；
 *   - 损坏行（形似密文但解不开）**绝不覆盖**，点名留待人工：GCM 认证失败
 *     意味着密钥不符或数据被改，静默跳过会让"被改过的数据"伪装成"未迁移"；
 *   - 检索键（phoneKey）随密文一起重算：轮换后旧键检索键全部失效，
 *     不同步等于按手机号找人的能力静默归零。
 */

const mongoose = require('mongoose');
require('../src/config/secrets').hydrateSecretsFromFiles();
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');
const {
  encryptPii,
  decryptPii,
  piiSearchKey,
  requireMasterSecret,
  VERSION_PREFIX,
} = require('../src/utils/piiCrypto');

function parseArgs() {
  const args = { apply: false, confirmYes: false, rotate: false };
  for (const a of process.argv.slice(2)) {
    if (a === '--apply') args.apply = true;
    if (a === '--yes') args.confirmYes = true;
    if (a === '--rotate') args.rotate = true;
  }
  return args;
}

/** 判断一个值是否已是本模块的密文形态（迁移与轮换共用的分拣判据） */
const isEncrypted = (v) => typeof v === 'string' && v.startsWith(VERSION_PREFIX);

/**
 * 主密钥可用性必须在**连库之前**判，且两道判据都是复用而不是另抄一份常量：
 * 少传 AES_SECRET_KEY 时，`process.env.PII_ROTATION_CURRENT_KEY = process.env.AES_SECRET_KEY`
 * 会把 undefined 强转成字符串 "undefined"，非空校验恒真通过 ⇒ 全表 PII 静默迁到一把
 * 谁都能从源码算出来的密钥上，而脚本照样打印「✅ 轮换完成」。
 * 单独成函数是为了不把 main 的 complexity 推过棘轮上限（这条闸本身就是新增分支）。
 */
function assertMasterKeyUsable() {
  let key;
  try {
    key = requireMasterSecret();
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
  // 第二道：强度判据，与同族脚本 migrate-mfa-secret.js 用的是同一把尺
  // （src/config/validate.js 的 isWeakSecret，启动校验对 AES_SECRET_KEY 也用它）。
  // requireMasterSecret 只拦退化字面量：实测 `AES_SECRET_KEY=abc`、`.env.example`
  // 里的原文占位符 `<CHANGE_ME>`、以及 40 个同一字符都能通过它，于是全表 PII 被
  // 重加密到一把可穷举的密钥上，而脚本照样打印「✅ 轮换完成」——这类改写不可逆，
  // 等下次启动 validate 才响已经晚了。判据复用而不是再抄一份长度/黑名单常量。
  if (require('../src/config/validate').isWeakSecret(key)) {
    console.error(
      'Error: AES_SECRET_KEY 未通过强度校验（长度 <32 / 命中弱密钥黑名单或占位符形态 / 低熵）。' +
        '本脚本会把 users 的 PII 列改写在该密钥之下，弱密钥一旦落库不可逆。' +
        '请用 `openssl rand -hex 32` 生成后经环境变量提供。'
    );
    process.exit(2);
  }
}

async function main() {
  const args = parseArgs();
  if (args.rotate && !process.env.PII_ROTATION_OLD_AES_KEY) {
    console.error('Error: --rotate 需要 PII_ROTATION_OLD_AES_KEY=<轮换前的 AES_SECRET_KEY>');
    process.exit(1);
  }
  // 主密钥判据见 assertMasterKeyUsable 的头注释：必须在连库与快照当前密钥**之前**响
  assertMasterKeyUsable();
  // 轮换前快照当前主密钥（hydrate 之后）：decryptWith 在新旧两把之间切换派生源
  if (args.rotate) process.env.PII_ROTATION_CURRENT_KEY = process.env.AES_SECRET_KEY;

  // M-08 / L-26 同族口径：resolveMongoUri 的回退库拒绝 + ALLOWED_SOURCE_DB 白名单
  // + 「--apply --yes」双标志，且都在 connect **之前**（被拒绝的执行不该向目标库握手）
  const { uri, dbName, host, isFallback } = resolveMongoUri({
    scriptName: 'migrate-pii-encryption.js',
  });
  if (
    !assertApplyAllowed({
      scriptName: 'migrate-pii-encryption.js',
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
      '错误：--apply 将批量改写 users 的 PII 列（明文 → 密文 / 跨密钥重加密），需再传 --yes 确认。'
    );
    process.exit(2);
  }

  await mongoose.connect(uri);
  const stats = await scanAndRewrite(mongoose.connection.collection('users'), args);

  const report = {
    mode: args.apply ? 'APPLY' : 'DRY-RUN（未改写任何记录）',
    rotate: args.rotate,
    ...stats,
  };
  console.log(JSON.stringify(report, null, 2));

  if (stats.corrupt.length > 0) {
    console.error(
      '\n存在解密失败的行（上方 corrupt 列表）：确认 PII_ROTATION_OLD_AES_KEY 是否正确，'
    );
    console.error('或按 id 人工核查——这些行本次**未被覆盖**，伪造的"成功"比失败更危险。');
  }
  // 轮换成功后的清理提示：这是本脚本唯一能主动"提醒清理旧钥"的位置，
  // 而运维跑完就在看这个输出——比任何文档的命中率都高（见 immutableConfigGuard.js
  // 的 piiOldKeyLingeringMessage 与 deployment/secret-rotation.md 收尾清单）。
  // 只在 apply + 无损坏行时打印：演练模式还没真换钥，损坏行时先处理完再说。
  if (args.rotate && args.apply && stats.corrupt.length === 0) {
    console.log('\n✅ 轮换完成。**现在请从生产环境移除 PII_ROTATION_OLD_AES_KEY**：');
    console.log('   它是本次轮换的输入参数，不是运行时配置；留在环境里等于轮换白做');
    console.log('   （旧钥 + 轮换前的备份归档仍可解出当时全部 PII）。');
    console.log('   移除后重启，并确认启动日志不再出现 pii_rotation_old_key_lingering 告警。');
  }
  if (!args.apply) {
    console.log('\n演练模式未改写任何记录。加 --apply --yes（并配置 ALLOWED_SOURCE_DB）执行。');
  }

  await mongoose.disconnect();
  // 演练退出 0（当常规体检跑）；apply 带损坏行时以非零退出，让调用方无法忽略
  process.exit(args.apply && stats.corrupt.length > 0 ? 1 : 0);
}

/** 解密辅助：轮换模式用旧主密钥解密（临时替换派生用的环境变量），其余用当前密钥 */
function decryptWith(value, useOldKey) {
  if (!useOldKey) return decryptPii(value);
  process.env.AES_SECRET_KEY = process.env.PII_ROTATION_OLD_AES_KEY;
  try {
    return decryptPii(value);
  } finally {
    process.env.AES_SECRET_KEY = process.env.PII_ROTATION_CURRENT_KEY;
  }
}

/** 单字段分拣：明文 → 加密 + 检索键；轮换模式下的密文 → 跨密钥重加密。返回 $set 片段 */
function resolveFieldUpdate(doc, field, args) {
  const stored = doc[field];
  if (!stored) return null;
  const encrypted = isEncrypted(stored);
  if (encrypted && !args.rotate) return { skip: 'encrypted' };
  if (!encrypted) {
    // 明文：当前密钥直接加密（检索键同步重算——存量明文行的检索键本来是空的，
    // 这是迁移要补齐的另一半）
    return { update: { [field]: encryptPii(stored), [`${field}Key`]: piiSearchKey(stored) } };
  }
  // 轮换：旧密钥解密 → 当前密钥加密。解不开 = 密钥不符或数据被改，点名不覆盖
  try {
    const plain = decryptWith(stored, true);
    return { update: { [field]: encryptPii(plain), [`${field}Key`]: piiSearchKey(plain) } };
  } catch (e) {
    return { corrupt: { id: String(doc._id), field, reason: e.message } };
  }
}

/** 全表扫描分拣与（apply 模式下的）改写 */
async function scanAndRewrite(coll, args) {
  const stats = { scanned: 0, plaintextRows: 0, encryptedRows: 0, corrupt: [], rewritten: 0 };
  const cursor = coll.find(
    {
      $or: [
        { realName: { $exists: true, $nin: ['', null] } },
        { phone: { $exists: true, $nin: ['', null] } },
      ],
    },
    { projection: { realName: 1, phone: 1, _id: 1 } }
  );

  for await (const doc of cursor) {
    stats.scanned += 1;
    const update = {};

    // realName 暂不加密（2026-09-30 决策：姓名模糊检索是用户列表的日常能力）。
    // 若某行在加密窗口内已带密文（本脚本早期版本或手工操作产物），这里解回
    // 明文自愈——窗口期密文都是「当前密钥」产物，直接用当前密钥解；
    // 解不开按损坏行点名（与 phone 同一口径）。
    if (isEncrypted(doc.realName)) {
      try {
        update.realName = decryptPii(doc.realName);
      } catch (e) {
        stats.corrupt.push({ id: String(doc._id), field: 'realName', reason: e.message });
      }
    }

    for (const field of ['phone']) {
      const result = resolveFieldUpdate(doc, field, args);
      if (!result) continue;
      if (result.skip) {
        stats.encryptedRows += 1;
        continue;
      }
      if (result.corrupt) {
        stats.corrupt.push(result.corrupt);
        continue;
      }
      stats.plaintextRows += 1;
      Object.assign(update, result.update);
    }
    if (Object.keys(update).length > 0) {
      stats.rewritten += 1;
      if (args.apply) {
        await coll.updateOne({ _id: doc._id }, { $set: update });
      }
    }
  }
  return stats;
}

// 轮换模式在连接前快照当前主密钥：decryptWith 在新旧之间临时切换环境变量
if (process.argv.includes('--rotate')) {
  process.env.PII_ROTATION_CURRENT_KEY = process.env.AES_SECRET_KEY;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
