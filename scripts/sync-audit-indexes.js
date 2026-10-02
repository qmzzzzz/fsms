/**
 * 审计日志索引对账脚本
 *
 * 用途：将 auditlogs 集合的实际索引与 models/AuditLog.js 的声明对齐。
 * 背景：模型层删掉 index 声明后，MongoDB 中已建好的旧索引不会自动消失
 * （Mongoose 的 autoIndex 只负责创建，从不删除），需要显式 dropIndex。
 *
 * 用法：
 *   node scripts/sync-audit-indexes.js          # 只报告差异，不做修改（默认）
 *   ALLOWED_SOURCE_DB=<库名> node scripts/sync-audit-indexes.js --apply  # 执行创建缺失索引 + 删除冗余索引
 *
 * 安全约束：
 *  - 绝不删除 _id 索引
 *  - 索引一致性按 key + 关键选项（TTL/稀疏/部分过滤）综合判定：
 *    key 相同但选项不一致的索引不会静默跳过，归入 needsAction 提示人工介入
 *    （对 TTL/部分索引执行 drop+create 有风险，不做自动处理）
 *  - 只删除「模型未声明」的索引，逐条打印后再执行
 *  - --apply 缺省时为演练模式，便于先在生产核对
 *
 * 退出码（--apply 时；演练模式恒为 0，它是报告不是动作）：
 *   0 = 同步后残余差异为 0（冗余/缺失/选项不一致 均 0，即**真的对齐了**）
 *   1 = 有操作失败，或操作都没失败但仍有残余差异需人工处理（"同步未彻底完成"）
 *   2 = 前置护栏拒绝（未配置 ALLOWED_SOURCE_DB 白名单 / 目标库不在白名单，未碰任何数据）
 *
 * 为什么"未彻底完成"也算 1 而不是 0：脚本头原先只承诺"部分失败 ⇒ 非零"，
 * 于是 `--apply` 遇到 needsAction（恰恰是"仍未与模型对齐"）会以 0 退出——
 * 运维/CI 读到 0 就以为对齐了，而 `deployment/rollback-drill-record.md` 的验收栏
 * 写的是"冗余 0 / 缺失 0 / 选项不一致 0"三条同时成立。退出码现在与那条验收判据同义。
 */

require('dotenv').config();
// <NAME>_FILE 部署下必须在此回填，否则下面直读的 MONGODB_URI 是空串 ⇒ 脚本直接退出
// （不变量见 src/tests/config/scriptSecretHydration.test.js）。
require('../src/config/secrets').hydrateSecretsFromFiles();
const mongoose = require('mongoose');

// M-08 / P1-20：破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明。
// 本脚本 --apply 会 dropIndex（含删除历史遗留索引），属「--apply 类」破坏性操作。
const { dbNameFromUri, hostFromUri, assertApplyAllowed } = require('./destructiveGuard');

const APPLY = process.argv.includes('--apply');

/**
 * 将索引 key 规范化为可比较的字符串
 * @param {object} key 索引键定义
 * @returns {string} 形如 category:1|timestamp:-1
 */
const keySignature = (key) =>
  Object.entries(key)
    .map(([k, v]) => `${k}:${v}`)
    .join('|');

// 参与 diff 的关键选项：这些选项不同即视为不同索引
// （TTL 值变更、稀疏性变更、部分过滤条件变更都会改变索引语义）
const OPTION_KEYS = ['expireAfterSeconds', 'sparse', 'partialFilterExpression', 'unique'];

/**
 * 索引完整签名：key + 关键选项一并序列化，
 * 避免「key 相同但 TTL/稀疏等选项不同」被仅看 key 的对比误判为一致
 * @param {object} key 索引键定义
 * @param {object} [options] 索引选项（模型声明与数据库实际均适用）
 * @returns {string} 形如 timestamp:-1|{"expireAfterSeconds":15552000}
 */
const fullSignature = (key, options = {}) =>
  `${keySignature(key)}|${JSON.stringify(
    Object.fromEntries(OPTION_KEYS.map((k) => [k, options[k]]).filter(([, v]) => v !== undefined))
  )}`;

/**
 * 差分：把「模型声明」与「数据库实际」两份索引清单算成三个桶。
 * 抽成纯函数是因为**同步后还要用同一套判据复核一次**（见文件末尾），
 * 两处各写一遍就会漂移——尤其是 needsAction 的"选项一致"口径。
 * @param {Array<{signature:string, fullSig:string, key:object, options:object}>} declared
 * @param {Array<object>} list 数据库实际索引（coll.indexes() 的返回，会被就地补 fullSig）
 */
function diffIndexes(declared, list) {
  const declaredByKey = new Map(declared.map((d) => [d.signature, d]));
  list.forEach((e) => {
    // 选项平铺在索引描述顶层，直接透传即可
    e.fullSig = fullSignature(e.key, e);
  });
  const redundant = list.filter(
    (e) => e.name !== '_id_' && !declaredByKey.has(keySignature(e.key))
  );
  const missing = declared.filter((d) => !list.some((e) => keySignature(e.key) === d.signature));
  const needsAction = [];
  for (const e of list) {
    const d = declaredByKey.get(keySignature(e.key));
    if (!d || d.fullSig === e.fullSig) continue;
    needsAction.push({ existing: e, declared: d });
  }
  return { redundant, missing, needsAction };
}

/** 一行汇总：与 deployment/rollback-drill-record.md 里"冗余 x / 缺失 y / 选项不一致 z"的记法同序 */
const verdictLine = ({ redundant, missing, needsAction }) =>
  `冗余 ${redundant.length} / 缺失 ${missing.length} / 选项不一致 ${needsAction.length}`;

const main = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('未配置 MONGODB_URI，退出');
    process.exit(1);
  }

  // 未设置白名单即拒绝（fail-closed）：索引删除不可逆，必须先显式声明目标库。
  if (
    !assertApplyAllowed({
      scriptName: 'sync-audit-indexes.js',
      dbName: dbNameFromUri(uri),
      host: hostFromUri(uri),
      apply: APPLY,
    })
  ) {
    process.exit(2);
  }

  await mongoose.connect(uri);
  console.log(`已连接：${mongoose.connection.host}:${mongoose.connection.port}\n`);

  const AuditLog = require('../src/models/AuditLog');
  const coll = AuditLog.collection;

  // 模型声明的索引（不含 _id），附完整签名（key + 关键选项）
  const declared = AuditLog.schema.indexes().map(([key, options]) => {
    const opts = options || {};
    return {
      signature: keySignature(key),
      fullSig: fullSignature(key, opts),
      key,
      options: opts,
    };
  });

  const existing = await coll.indexes();

  console.log('=== 模型声明的索引 ===');
  declared.forEach((d) =>
    console.log(
      `  ${d.signature}${d.options.expireAfterSeconds !== undefined ? `  TTL=${d.options.expireAfterSeconds}s` : ''}`
    )
  );

  console.log('\n=== 数据库实际索引 ===');
  existing.forEach((e) =>
    console.log(
      `  ${e.name.padEnd(34)} ${keySignature(e.key)}${e.expireAfterSeconds !== undefined ? `  TTL=${e.expireAfterSeconds}s` : ''}`
    )
  );

  // 以 key 签名做「有无」判断，以完整签名（key + TTL/稀疏/部分过滤/唯一）做「一致」判断
  const { redundant, missing, needsAction } = diffIndexes(declared, existing);

  console.log('\n=== 差异分析 ===');
  console.log(`冗余索引（将被删除）：${redundant.length} 个`);
  redundant.forEach((r) => console.log(`  - ${r.name.padEnd(34)} ${keySignature(r.key)}`));
  console.log(`缺失索引（将被创建）：${missing.length} 个`);
  missing.forEach((m) => console.log(`  + ${m.signature}`));
  console.log(`选项不一致（需人工处理）：${needsAction.length} 个`);
  needsAction.forEach(({ existing: e, declared: d }) =>
    console.log(
      `  ! ${e.name.padEnd(34)} 数据库=${e.fullSig}\n${' '.repeat(38)}模型  =${d.fullSig}`
    )
  );

  if (!APPLY) {
    console.log(`\n当前差异：${verdictLine({ redundant, missing, needsAction })}`);
    console.log('[演练模式] 未做任何修改。确认无误后追加 --apply 执行。');
    if (needsAction.length > 0) {
      console.log('[注意] 存在选项不一致的索引，--apply 不会自动处理，需按上方差异人工介入。');
    }
    await mongoose.disconnect();
    return;
  }

  console.log('\n=== 执行同步 ===');

  let failedCount = 0;

  for (const m of missing) {
    try {
      await coll.createIndex(m.key, m.options);
      console.log(`  已创建：${m.signature}`);
    } catch (err) {
      failedCount += 1;
      console.error(`  创建失败 ${m.signature}：${err.message}`);
    }
  }

  for (const r of redundant) {
    try {
      await coll.dropIndex(r.name);
      console.log(`  已删除：${r.name}（${keySignature(r.key)}）`);
    } catch (err) {
      failedCount += 1;
      console.error(`  删除失败 ${r.name}：${err.message}`);
    }
  }

  if (needsAction.length > 0) {
    console.warn(
      `  跳过 ${needsAction.length} 个选项不一致的索引（不自动处理，需人工 drop 后重建）：`
    );
    needsAction.forEach(({ existing: e }) => console.warn(`    ! ${e.name}`));
  }

  const after = await coll.indexes();
  console.log(`\n=== 同步后复核：索引数 ${existing.length} → ${after.length} ===`);
  after.forEach((e) =>
    console.log(
      `  ${e.name.padEnd(34)} ${keySignature(e.key)}${e.expireAfterSeconds !== undefined ? `  TTL=${e.expireAfterSeconds}s` : ''}`
    )
  );

  // 用**同一套判据**再算一次残余差异。只看 failedCount 是不够的：
  // createIndex/dropIndex 都可能"没抛错但没改到位"（同名索引已存在、驱动把权限/构建错误咽掉），
  // 而本文件头承诺的是"非零退出码 = 同步未彻底完成"。
  // 演练模式不在此列（它按设计就是只报告，恒 exit 0）。
  const residual = diffIndexes(declared, after);
  console.log(`[同步后] 残余差异：${verdictLine(residual)}`);

  await mongoose.disconnect();

  if (failedCount > 0) {
    console.error(`\n${failedCount} 个操作失败，以退出码 1 结束`);
    process.exit(1);
  }
  const unresolved =
    residual.redundant.length + residual.missing.length + residual.needsAction.length;
  if (unresolved > 0) {
    console.error(
      `\n同步未彻底完成：残余 ${verdictLine(residual)}。` +
        '其中「选项不一致」需人工 drop 后重建（脚本刻意不自动处理 TTL/部分索引）。' +
        '按「非零 = 未彻底完成」的约定以退出码 1 结束。'
    );
    process.exit(1);
  }
  console.log('\n✅ 已完全对齐：冗余 / 缺失 / 选项不一致 均为 0。');
};

/**
 * 致命错误的分类（纯函数，便于真值表断言）。
 *
 * 为什么单独分一格：`NamespaceNotFound`（code 26 / `ns not found`）在本脚本里有三个来源
 * ——`coll.indexes()`（库名写错或目标库还没初始化）、`createIndex`、`dropIndex`。
 * 走通用分支时运维只看到一行 `执行失败：ns not found`，既不知道是"连错了库"
 * 还是"集合被删了"，也无从判断脚本**有没有已经改过索引**。
 * 退出码沿用本脚本既有约定：`2 = 环境/用法问题，未做任何变更`（与 `--apply` 白名单
 * 拒绝同一格），`1 = 执行过但没对齐`。混成 1 会让 CI 把"连错库"和"同步不彻底"
 * 当成同一件事重试，而前者重试一万次也不会好。
 */
const describeFatalError = (err) => {
  const e = err || {};
  const code = e.code !== undefined ? e.code : e.codeName;
  // 三种来源都要吃下：`code`（driver 数字码 26）、`codeName`（服务端符号名），
  // 以及被上层包装后**只剩文案**的形态——文案里既可能是 `ns not found`，
  // 也可能是 CamelCase 的 `NamespaceNotFound`（mongoose/包装层常带类名前缀），
  // 所以空格是可选的。
  const isNamespaceMissing =
    code === 26 ||
    code === 'NamespaceNotFound' ||
    (typeof e.message === 'string' && /ns not found|namespace ?not ?found/i.test(e.message));
  if (isNamespaceMissing) {
    return {
      message:
        `目标命名空间不存在（ns not found / code 26）：请核对 MONGODB_URI 的库名，` +
        `以及审计集合（auditlogs）是否已初始化。` +
        '本脚本刻意不会为"库不存在"隐式建库，未做任何索引变更，退出码 2。',
      exitCode: 2,
    };
  }
  return { message: `执行失败：${e.message || String(err)}`, exitCode: 1 };
};

module.exports = {
  OPTION_KEYS,
  keySignature,
  fullSignature,
  diffIndexes,
  verdictLine,
  describeFatalError,
};

// 仅在被直接执行时才跑；被 require（差集判据与真值表的回归测试）时不得连库、不得退出进程。
// 放在最后：describeFatalError 是 const，前面的位置会依赖"catch 回调必然晚于模块体执行完"这一隐含事实。
if (require.main === module) {
  main().catch((err) => {
    const fatal = describeFatalError(err);
    console.error(fatal.message);
    process.exit(fatal.exitCode);
  });
}
