/**
 * 审计日志索引对账脚本
 *
 * 用途：将 auditlogs 集合的实际索引与 models/AuditLog.js 的声明对齐。
 * 背景：模型层删掉 index 声明后，MongoDB 中已建好的旧索引不会自动消失
 * （Mongoose 的 autoIndex 只负责创建，从不删除），需要显式 dropIndex。
 *
 * 用法：
 *   node scripts/sync-audit-indexes.js          # 只报告差异，不做修改（默认）
 *   node scripts/sync-audit-indexes.js --apply  # 执行创建缺失索引 + 删除冗余索引
 *
 * 安全约束：
 *  - 绝不删除 _id 索引
 *  - 索引一致性按 key + 关键选项（TTL/稀疏/部分过滤）综合判定：
 *    key 相同但选项不一致的索引不会静默跳过，归入 needsAction 提示人工介入
 *    （对 TTL/部分索引执行 drop+create 有风险，不做自动处理）
 *  - 只删除「模型未声明」的索引，逐条打印后再执行
 *  - --apply 缺省时为演练模式，便于先在生产核对
 */

require('dotenv').config();
const mongoose = require('mongoose');

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

(async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('未配置 MONGODB_URI，退出');
    process.exit(1);
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
  // 数据库实际索引同样计算完整签名（选项平铺在索引描述顶层，直接透传即可）
  existing.forEach((e) => {
    e.fullSig = fullSignature(e.key, e);
  });

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

  // 以 key 签名做「有无」判断，以完整签名做「一致」判断
  const declaredByKey = new Map(declared.map((d) => [d.signature, d]));

  // 冗余：数据库有但模型完全未声明该 key（含未声明的 TTL 索引——
  // TTL 豁免已收紧为「key 与关键选项均与声明完全一致才视为正常」）
  const redundant = existing.filter((e) => {
    if (e.name === '_id_') return false;
    return !declaredByKey.has(keySignature(e.key));
  });

  // 缺失：模型声明但数据库没有该 key 的索引
  const missing = declared.filter(
    (d) => !existing.some((e) => keySignature(e.key) === d.signature)
  );

  // 选项不一致：key 相同但 TTL/稀疏/部分过滤等选项不同——
  // 不能自动 drop+create（对 TTL/部分索引有风险），归入 needsAction 提示人工介入
  const needsAction = [];
  for (const e of existing) {
    const d = declaredByKey.get(keySignature(e.key));
    if (!d || d.fullSig === e.fullSig) continue;
    needsAction.push({ existing: e, declared: d });
  }

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
    console.log('\n[演练模式] 未做任何修改。确认无误后追加 --apply 执行。');
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
  console.log(`\n=== 同步完成：索引数 ${existing.length} → ${after.length} ===`);
  after.forEach((e) =>
    console.log(
      `  ${e.name.padEnd(34)} ${keySignature(e.key)}${e.expireAfterSeconds !== undefined ? `  TTL=${e.expireAfterSeconds}s` : ''}`
    )
  );

  await mongoose.disconnect();

  // 部分失败时以非零退出码结束，便于 CI/运维脚本感知同步未彻底完成
  if (failedCount > 0) {
    console.error(`\n${failedCount} 个操作失败，以退出码 1 结束`);
    process.exit(1);
  }
})().catch((err) => {
  console.error(`执行失败：${err.message}`);
  process.exit(1);
});
