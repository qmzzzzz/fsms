/**
 * 修复 tokenblacklists 集合的遗留唯一索引（一次性运维脚本）
 *
 * 症状：refresh 刷新恒返回「刷新令牌已失效」或「密码已修改」，
 *      且每刷一次用户 tokenVersion 就 +1（会话被永久吊销）。
 *
 * 根因：旧 schema 用明文 `token` 字段，改为 `tokenHash` 后 MongoDB 里的
 *      `token_1` 唯一索引没被删除。新文档 token 全为 null，
 *      第二条起插入即 E11000，被 consumeToken 误判为「refresh token 重放」。
 *
 * 幂等：无遗留索引时直接退出，可重复执行。
 * 注：正常启动流程已内置同样的对账（initData.reconcileTokenBlacklistIndexes），
 *    本脚本供无法重启服务、或需要单独确认索引状态的场景使用。
 *
 * 用法：
 *   node scripts/fix-token-blacklist-index.js            # 演练：只报告，不改动
 *   node scripts/fix-token-blacklist-index.js --apply    # 实际执行删除
 *
 * 默认演练与 scripts/sync-audit-indexes.js 保持同一安全约定：
 * 本脚本会 dropIndex + deleteMany 生产集合，绝不能「一条命令就动手」。
 */

require('dotenv').config();
const mongoose = require('mongoose');

const APPLY = process.argv.includes('--apply');

(async () => {
  const uri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/fire_safety_db';
  await mongoose.connect(uri);
  console.log(
    `已连接：${mongoose.connection.host}:${mongoose.connection.port}/${mongoose.connection.name}`
  );
  console.log(
    APPLY ? '模式：APPLY（将实际修改数据）' : '模式：DRY-RUN（仅报告，加 --apply 才执行）'
  );

  const coll = mongoose.connection.collection('tokenblacklists');

  let indexes;
  try {
    indexes = await coll.indexes();
  } catch (e) {
    console.log('tokenblacklists 集合不存在，无需处理');
    await mongoose.disconnect();
    process.exit(0);
  }

  console.log('\n当前索引：');
  indexes.forEach((i) => {
    console.log(`  ${i.name.padEnd(16)} key=${JSON.stringify(i.key)} unique=${!!i.unique}`);
  });

  // 只删「仅含 token 单键」的索引，避免误删复合索引
  const legacy = indexes.filter((idx) => {
    const keys = Object.keys(idx.key || {});
    return keys.length === 1 && keys[0] === 'token';
  });

  const orphan = await coll.countDocuments({ tokenHash: { $exists: false } });

  if (legacy.length === 0 && orphan === 0) {
    console.log('\n未发现遗留的 token 单键索引与无 tokenHash 文档，无需处理');
    await mongoose.disconnect();
    process.exit(0);
  }

  console.log('\n待处理项：');
  legacy.forEach((idx) => console.log(`  [索引] 删除 ${idx.name}`));
  if (orphan > 0)
    console.log(`  [文档] 删除 ${orphan} 条无 tokenHash 的历史记录（旧 schema 残留）`);

  if (!APPLY) {
    console.log('\n演练结束，未做任何修改。确认无误后追加 --apply 重新执行。');
    await mongoose.disconnect();
    process.exit(0);
  }

  for (const idx of legacy) {
    await coll.dropIndex(idx.name);
    console.log(`已删除遗留索引：${idx.name}`);
  }

  if (orphan > 0) {
    await coll.deleteMany({ tokenHash: { $exists: false } });
    console.log(`已清理 ${orphan} 条无 tokenHash 的历史文档`);
  }

  console.log('\n处理完成。建议重启服务以确保 mongoose 索引缓存刷新。');
  await mongoose.disconnect();
  process.exit(0);
})().catch(async (e) => {
  console.error(`执行失败：${e.message}`);
  try {
    await mongoose.disconnect();
  } catch (_) {
    /* 忽略断连异常 */
  }
  process.exit(1);
});
