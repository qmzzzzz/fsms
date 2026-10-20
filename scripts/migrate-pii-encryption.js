/**
 * PII 加密迁移 / 密钥轮换（2026-09-30；2026-10-16 扩到报警上报人电话与用户邮箱）
 *
 * 用法（与 resign-audit-hmac.js 同族的门禁口径：--apply 需 ALLOWED_SOURCE_DB + --yes）：
 *   node scripts/migrate-pii-encryption.js                        # 演练：只读扫描并出报告
 *   ALLOWED_SOURCE_DB=<库名> node scripts/migrate-pii-encryption.js --apply --yes
 *                                                                 # 存量明文加密（v2）+ enc.v1 行升级到 v2（AAD 行绑定）
 *      （realName 暂不加密——2026-09-30 决策：保留姓名模糊检索；
 *        若有行在加密窗口内被加密过，本脚本会自动解回明文自愈）
 *   ALLOWED_SOURCE_DB=<库名> node scripts/migrate-pii-encryption.js --keys-only --apply --yes
 *                                                                 # 【阶段 1】只回填检索键 + 子串盲索引，
 *                                                                 #   **绝不触碰明文列**（可在线、可重复跑）
 *   ALLOWED_SOURCE_DB=<库名> node scripts/migrate-pii-encryption.js --encrypt --apply --yes
 *                                                                 # 【阶段 4】只加密明文列（键在同一次 $set 里同步）
 *   ALLOWED_SOURCE_DB=<库名> PII_ROTATION_OLD_AES_KEY=<旧KEY> \
 *     node scripts/migrate-pii-encryption.js --apply --yes --rotate
 *                                                                 # 用旧主密钥解密 → 当前主密钥重加密（v2）
 *
 * **为什么有 --keys-only / --encrypt 两档**（A3 的 email 唯一索引引入的顺序约束）：
 * `User.email` 加密后，唯一约束要从明文列 `email_1` 搬到 HMAC 列 `emailKey_1`，
 * 而唯一索引把「字段缺失」与「空串」都视作同一个键（实测：两行缺失即
 * `E11000 dup key: { emailKey: null }`，两行空串同样建不起来）。于是四阶段不可换序：
 *   ① `--keys-only` 回填 emailKey（本档）→ ② 建 emailKey_1（schema autoIndex）
 *   → ③ 代码发布（写密文 + getter 读 + 查重走 emailKey）→ ④ `--encrypt` 加密列
 * 把「改键」与「改列」拆成两档，是为了让阶段 1 能在**代码还没发布**时先跑完
 * ——那时读路径还没有 getter，一旦本档顺手把 email 列加密，读到的密文会直接透传给用户。
 * 默认（不加档）仍是"两者都做"，与 A1 时代的既有用法逐字兼容。
 *
 * 背景：`User.phone` 自 2026-09-30 起 at-rest 加密，`FireAlarm.reporter.phone`
 * 与 `User.email` 自 2026-10-16 起同轨加密（均走 utils/piiCrypto.js，AES-256-GCM 随机 IV）。
 * 密文格式两代：`enc.v1.<iv>.<data>`（无行绑定，2026-10-01 审计发现同一派生钥下
 * 可跨行搬运）→ `enc.v2.<iv>.<data>`（AAD 绑定 pii:v2:<_id>:<field>，
 * 跨行复制在解密侧认证失败）。模型层对存量明文**透读取**、修改时才加密
 * （写侧一律产 v2）——本脚本负责把「尚未修改的存量行」一次性收口
 * （明文加密 + v1 全列升级），并承担密钥轮换时的全列重加密。
 *
 * **为什么受管列必须由同一个脚本、同一次运行处理**：轮换 AES_SECRET_KEY 时，
 * 漏掉任一列 = 该列密文在新钥下永久解不开（GCM 认证失败），而报警上报人电话
 * 恰恰是**只写不读**的列（读接口已收窄，见 AlarmService 的 ALARM_READ_SELECT），
 * 坏掉之后没有任何日常路径会暴露它——只会在某天要回拨上报人时才被发现。
 * 把「受管 PII 列清单」收敛成下方 PII_TARGETS 一处，新增 PII 列时只改这里，
 * 轮换覆盖面不会因为"忘了跑第二个脚本"而缺角。
 *
 * 安全属性：
 *   - 演练模式一行不改，报告先行（多少行待加密 / 已加密 / 损坏不可解）；
 *   - 损坏行（形似密文但解不开）**绝不覆盖**，点名留待人工：GCM 认证失败
 *     意味着密钥不符或数据被改，静默跳过会让"被改过的数据"伪装成"未迁移"；
 *   - 检索键随密文一起重算：轮换后旧键检索键全部失效，
 *     不同步等于按手机号/邮箱找人的能力静默归零（reporter.phone 无检索键，不涉及）。
 */

const mongoose = require('mongoose');
require('../src/config/secrets').hydrateSecretsFromFiles();
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');
const {
  encryptPii,
  decryptPii,
  piiSearchKey,
  piiSubstringKeys,
  requireMasterSecret,
  VERSION_PREFIX,
  VERSION_PREFIX_V2,
} = require('../src/utils/piiCrypto');

function parseArgs() {
  const args = {
    apply: false,
    confirmYes: false,
    rotate: false,
    keysOnly: false,
    encryptOnly: false,
  };
  for (const a of process.argv.slice(2)) {
    if (a === '--apply') args.apply = true;
    if (a === '--yes') args.confirmYes = true;
    if (a === '--rotate') args.rotate = true;
    if (a === '--keys-only') args.keysOnly = true;
    if (a === '--encrypt') args.encryptOnly = true;
  }
  return args;
}

/** 判断一个值是否已是本模块的密文形态（迁移与轮换共用的分拣判据；v1/v2 都算） */
const isEncrypted = (v) =>
  typeof v === 'string' && (v.startsWith(VERSION_PREFIX) || v.startsWith(VERSION_PREFIX_V2));

/**
 * 受管 PII 列清单（**单一声明**）。
 *
 * `path` 同时是文档里的取值路径与 AAD 的 field 名——必须与模型写侧逐字一致
 * （models/User.js 用 `field: 'phone'`，models/FireAlarm.js 用 `field: 'reporter.phone'`），
 * 不一致的后果是**新写**的行（v2，绑定 A 字段）与**本脚本迁移**的行（绑定 B 字段）
 * 互相解不开：同一列里两套绑定并存，读侧随机成功/失败。
 * 故新增列时必须回到模型确认写侧的 field 字面量。
 */
const PII_TARGETS = [
  {
    collection: 'users',
    // A3：email 的 `keyField` 是**唯一索引**列（emailKey_1），`gramField` 是子串盲索引
    // （emailGrams，多键非唯一）。两者都在模型写侧由 pre('validate') 同步写入，
    // 本脚本负责给"尚未被改过的存量行"补上——顺序约束见文件头。
    fields: [
      { path: 'phone', keyField: 'phoneKey', gramField: null },
      {
        path: 'email',
        keyField: 'emailKey',
        gramField: 'emailGrams',
        // 迁移期补归一化：schema 的 `lowercase` setter 已随 A3 摘掉（它会吃掉钩子写入的
        // base64 密文），新写入由模型钩子在明文阶段归一。存量行没经过钩子 ⇒ 若不在这里
        // 归一，加密进去的就是原始大小写，读侧解出来是 `Alice@Example.com`，
        // 而「落库解密后为小写」是 A3 的验收判据之一（改前 schema 保证过这一点）。
        normalize: (v) => v.trim().toLowerCase(),
      },
    ],
    // realName 保持明文（2026-09-30 决策：姓名模糊检索是用户列表的日常能力）；
    // 仅对"加密窗口内被误加密"的行做解回明文自愈。
    legacyPlaintextSelfHeal: ['realName'],
  },
  {
    collection: 'firealarms',
    // reporter.phone 无检索需求（全仓消费方为零）⇒ 不建 HMAC 检索键，
    // 这是它比 users.email 便宜的地方。
    fields: [{ path: 'reporter.phone', keyField: null, gramField: null }],
    legacyPlaintextSelfHeal: [],
  },
];

/** 按点分路径取值（驱动返回的是普通对象，`doc['reporter.phone']` 取不到嵌套值） */
const getPath = (doc, path) => path.split('.').reduce((o, k) => (o == null ? o : o[k]), doc);

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
        '本脚本会把 users / firealarms 的 PII 列改写在该密钥之下，弱密钥一旦落库不可逆。' +
        '请用 `openssl rand -hex 32` 生成后经环境变量提供。'
    );
    process.exit(2);
  }
}

/**
 * 轮换成功后的清理提示（从 main 里抽出：main 的圈复杂度贴着 lint 上限，而这段
 * 只是输出，不含任何判断价值）。
 *
 * 这是本脚本唯一能主动"提醒清理旧钥"的位置，而运维跑完就在看这个输出——
 * 比任何文档的命中率都高（见 immutableConfigGuard.js 的 piiOldKeyLingeringMessage
 * 与 deployment/secret-rotation.md 收尾清单）。
 * 只在 apply + 无损坏行时打印：演练模式还没真换钥，损坏行时先处理完再说。
 */
function printRotationCleanupHint({ rotate, apply, corruptTotal }) {
  if (!rotate || !apply || corruptTotal > 0) return;
  console.log('\n✅ 轮换完成。**现在请从生产环境移除 PII_ROTATION_OLD_AES_KEY**：');
  console.log('   它是本次轮换的输入参数，不是运行时配置；留在环境里等于轮换白做');
  console.log('   （旧钥 + 轮换前的备份归档仍可解出当时全部 PII）。');
  console.log('   移除后重启，并确认启动日志不再出现 pii_rotation_old_key_lingering 告警。');
}

/**
 * 档位与轮换参数的前置校验（从 main 里抽出：main 的圈复杂度贴着 lint 棘轮上限，
 * 而这段只是三条 fail-closed 判据，不含任何业务价值）。
 *
 * 三条都是"参数自相矛盾就不该向目标库握手"：
 *   · `--keys-only` 只回填键、`--encrypt` 只加密列，同时给等于没说要做什么；
 *   · `--keys-only` 不改写明文列，而 `--rotate` 的定义就是整列重加密；
 *   · `--rotate` 没有旧钥输入时无法解密存量 v2 行。
 */
function assertModeArgs(args) {
  if (args.keysOnly && args.encryptOnly) {
    console.error(
      'Error: --keys-only 与 --encrypt 互斥（前者只回填检索键、后者只加密明文列）；' +
        '不加档即两者都做。'
    );
    process.exit(2);
  }
  if (args.keysOnly && args.rotate) {
    console.error(
      'Error: --keys-only 只回填检索键、不改写明文列，与 --rotate（必须整列重加密）冲突。' +
        '轮换请用不带档位的默认模式。'
    );
    process.exit(2);
  }
  if (args.rotate && !process.env.PII_ROTATION_OLD_AES_KEY) {
    console.error('Error: --rotate 需要 PII_ROTATION_OLD_AES_KEY=<轮换前的 AES_SECRET_KEY>');
    process.exit(1);
  }
}

async function main() {
  const args = parseArgs();
  assertModeArgs(args);
  // 主密钥判据见 assertMasterKeyUsable 的头注释：必须在连库与快照当前密钥**之前**响
  assertMasterKeyUsable();
  // 轮换前快照当前主密钥（hydrate 之后）：decryptWith 在新旧两把之间切换派生源
  if (args.rotate) process.env.PII_ROTATION_CURRENT_KEY = process.env.AES_SECRET_KEY;

  // 同族口径：resolveMongoUri 的回退库拒绝 + ALLOWED_SOURCE_DB 白名单
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
      '错误：--apply 将批量改写 users / firealarms 的 PII 列（明文 → 密文 / 跨密钥重加密），需再传 --yes 确认。'
    );
    process.exit(2);
  }

  await mongoose.connect(uri);

  // 逐集合扫描；任一集合有损坏行都让退出码非零（调用方无法忽略）
  const collections = {};
  const corrupt = [];
  for (const target of PII_TARGETS) {
    const stats = await scanAndRewrite(
      mongoose.connection.collection(target.collection),
      target,
      args
    );
    collections[target.collection] = stats;
    corrupt.push(...stats.corrupt.map((c) => ({ collection: target.collection, ...c })));
  }

  const report = {
    mode: args.apply ? 'APPLY' : 'DRY-RUN（未改写任何记录）',
    scope: args.keysOnly
      ? 'KEYS-ONLY（只回填检索键/盲索引）'
      : args.encryptOnly
        ? 'ENCRYPT-ONLY（只加密明文列）'
        : 'FULL（键 + 列）',
    rotate: args.rotate,
    collections,
    corruptTotal: corrupt.length,
  };
  console.log(JSON.stringify(report, null, 2));

  if (corrupt.length > 0) {
    console.error(
      '\n存在解密失败的行（上方 corrupt 列表）：确认 PII_ROTATION_OLD_AES_KEY 是否正确，'
    );
    console.error('或按 id 人工核查——这些行本次**未被覆盖**，伪造的"成功"比失败更危险。');
  }
  printRotationCleanupHint({
    rotate: args.rotate,
    apply: args.apply,
    corruptTotal: corrupt.length,
  });
  if (!args.apply) {
    console.log('\n演练模式未改写任何记录。加 --apply --yes（并配置 ALLOWED_SOURCE_DB）执行。');
  }

  await mongoose.disconnect();
  // 演练退出 0（当常规体检跑）；apply 带损坏行时以非零退出，让调用方无法忽略
  process.exit(args.apply && corrupt.length > 0 ? 1 : 0);
}

/** 解密辅助：轮换模式用旧主密钥解密（临时替换派生用的环境变量），其余用当前密钥。
 * aadContext 必须透传：v2 密文没有绑定上下文时解密在形态层就被拒（buildAad 抛错），
 * 轮换会把整列 v2 行误报成损坏行。 */
function decryptWith(value, useOldKey, aadContext) {
  if (!useOldKey) return decryptPii(value, aadContext);
  process.env.AES_SECRET_KEY = process.env.PII_ROTATION_OLD_AES_KEY;
  try {
    return decryptPii(value, aadContext);
  } finally {
    process.env.AES_SECRET_KEY = process.env.PII_ROTATION_CURRENT_KEY;
  }
}

/** 键与盲索引的 $set 片段（明文 → HMAC 检索键 + n-gram 子串盲索引）；无对应列时为空对象 */
function keysUpdate(plain, keyField, gramField) {
  const update = {};
  if (keyField) update[keyField] = piiSearchKey(plain);
  if (gramField) update[gramField] = piiSubstringKeys(plain);
  return update;
}

/**
 * 已有的键是否与将写入的逐字段相等？
 * 相等即不写——否则 `--keys-only` 每次运行都会对全表产生一次"没有变更的变更"
 * （updatedAt 漂移 + 审计上出现无意义的改写），且幂等性无从验证。
 */
function keysUnchanged(doc, update) {
  return Object.entries(update).every(([path, next]) => {
    const current = getPath(doc, path);
    if (Array.isArray(next)) {
      return (
        Array.isArray(current) &&
        current.length === next.length &&
        current.every((v, i) => v === next[i])
      );
    }
    return current === next;
  });
}

/**
 * 解出明文：存量明文直接透传（与读侧 decryptPii 同一口径），随后补迁移期归一化。
 * 单独成函数是为了不把 resolveFieldUpdate 的圈复杂度推过 lint 棘轮上限。
 * @returns {{plain: string} | {corrupt: {id: string, field: string, reason: string}}}
 */
function plaintextOf(doc, spec, stored, args) {
  const { path: field, normalize } = spec;
  const isCipher = stored.startsWith(VERSION_PREFIX) || stored.startsWith(VERSION_PREFIX_V2);
  if (!isCipher) return { plain: normalize ? normalize(stored) : stored };
  let plain;
  try {
    plain = decryptWith(stored, args.rotate, { subjectId: String(doc._id), field });
  } catch (e) {
    return { corrupt: { id: String(doc._id), field, reason: e.message } };
  }
  return { plain: normalize ? normalize(plain) : plain };
}

/**
 * `--keys-only`（阶段 1）分支：只回填键与盲索引，**绝不触碰明文列**。
 * 触碰了就会破坏阶段 3 之前的读路径（那时代码还没有 getter，读到密文会直接透传给用户）。
 */
function resolveKeysOnly(doc, spec, stored, args) {
  const { keyField, gramField } = spec;
  // 该列没有键（如 reporter.phone）：阶段 1 无事可做，且绝不能顺手加密明文列
  if (!keyField && !gramField) return { skip: 'no-key-field' };
  const got = plaintextOf(doc, spec, stored, args);
  if (got.corrupt) return got;
  const update = keysUpdate(got.plain, keyField, gramField);
  if (keysUnchanged(doc, update)) return { skip: 'keys-present' };
  return { update, keyOnly: true };
}

/**
 * 单字段分拣（返回 $set 片段）。
 *
 * 三档语义（由 args 选择，见文件头的四阶段说明）：
 *   - 默认（两者都做）：明文 → v2 加密 + 键；v1 → 升级为 v2 + 重算键；
 *     v2 且非轮换 → 跳过（已是目标形态）；
 *   - `--keys-only`（阶段 1）：见 resolveKeysOnly；
 *   - `--encrypt`（阶段 4）：只加密明文列（键在同一次 $set 里同步，避免中间态不可检索）。
 *
 * 解不开 = 密钥不符或数据被改，点名不覆盖（任何档位都不例外）。
 */
function resolveFieldUpdate(doc, spec, args) {
  const { path: field } = spec;
  const stored = getPath(doc, field);
  if (!stored) return null;
  const isV2 = stored.startsWith(VERSION_PREFIX_V2);
  const isV1 = stored.startsWith(VERSION_PREFIX);

  if (args.keysOnly) return resolveKeysOnly(doc, spec, stored, args);
  if (isV2 && !args.rotate) return { skip: 'encrypted-v2' };

  const got = plaintextOf(doc, spec, stored, args);
  if (got.corrupt) return got;
  // 键与密文必须同一次 $set：分两次写会出现"密文已换、检索键还是旧的"的中间态，
  // 那段时间按手机号/邮箱查不到这行。
  return {
    update: {
      ...keysUpdate(got.plain, spec.keyField, spec.gramField),
      [field]: encryptPii(got.plain, { subjectId: String(doc._id), field }),
    },
    plaintext: !isV2 && !isV1,
    upgrade: isV1 && !args.rotate,
  };
}

/** 全表扫描分拣与（apply 模式下的）改写；按 target 决定扫哪些列、有无检索键与盲索引 */
async function scanAndRewrite(coll, target, args) {
  const stats = {
    scanned: 0,
    plaintextRows: 0,
    aadUpgraded: 0,
    encryptedRows: 0,
    keysBackfilled: 0,
    corrupt: [],
    rewritten: 0,
  };
  const paths = [...target.fields.map((f) => f.path), ...target.legacyPlaintextSelfHeal];
  // 投影必须带上键列：`--keys-only` 靠比对"已有键 vs 将写入的键"来决定是否重写
  const keyPaths = target.fields.flatMap((f) => [f.keyField, f.gramField]).filter(Boolean);
  const projection = Object.fromEntries(
    [...new Set([...paths, ...keyPaths, '_id'])].map((p) => [p, 1])
  );
  const cursor = coll.find(
    { $or: paths.map((p) => ({ [p]: { $exists: true, $nin: ['', null] } })) },
    { projection }
  );

  for await (const doc of cursor) {
    stats.scanned += 1;
    const update = {};

    // legacyPlaintextSelfHeal（当前只有 users.realName）：这些列**刻意保持明文**，
    // 若某行在加密窗口内已带密文（本脚本早期版本或手工操作产物），这里解回
    // 明文自愈——窗口期密文都是「当前密钥」产物，直接用当前密钥解；
    // 解不开按损坏行点名（与受管列同一口径）。
    for (const field of target.legacyPlaintextSelfHeal) {
      if (isEncrypted(getPath(doc, field))) {
        try {
          update[field] = decryptPii(getPath(doc, field));
        } catch (e) {
          stats.corrupt.push({ id: String(doc._id), field, reason: e.message });
        }
      }
    }

    for (const spec of target.fields) {
      const result = resolveFieldUpdate(doc, spec, args);
      if (!result) continue;
      if (result.skip) {
        if (result.skip === 'encrypted-v2') stats.encryptedRows += 1;
        continue;
      }
      if (result.corrupt) {
        stats.corrupt.push(result.corrupt);
        continue;
      }
      if (result.keyOnly) stats.keysBackfilled += 1;
      else if (result.upgrade) stats.aadUpgraded += 1;
      else stats.plaintextRows += 1;
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
