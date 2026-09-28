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
 *   ALLOWED_SOURCE_DB=<库名> node scripts/fix-token-blacklist-index.js --apply    # 实际执行删除
 *
 * 默认演练与 scripts/sync-audit-indexes.js 保持同一安全约定：
 * 本脚本会 dropIndex + deleteMany 生产集合，绝不能「一条命令就动手」。
 */

require('dotenv').config();
const mongoose = require('mongoose');

// M-08：破坏性操作护栏（fail-closed 库名白名单），与同族脚本共用同一份声明
const { resolveMongoUri, assertApplyAllowed } = require('./destructiveGuard');

const APPLY = process.argv.includes('--apply');

/** 遗留索引判据：只认「仅含 token 一个键」的索引，复合索引一律不动 */
function isLegacyTokenIndex(idx) {
  const keys = Object.keys(idx.key || {});
  return keys.length === 1 && keys[0] === 'token';
}

const ORPHAN_FILTER = { tokenHash: { $exists: false } };

/**
 * 动手之后回库复核，返回未解决项的中文描述（空数组＝通过）。
 * 「已清理 N 条」这类话只能由库来说：dropIndex 静默失败（副本集从库延迟、
 * 同名索引被并发重建）与 deleteMany 一条没删，原先都会得到同一份
 * 「处理完成」+ exit 0。本脚本存在的理由就是消除 refresh 的 E11000 症状，
 * 报告失真的代价是运维带着一个未修复的库离开。
 */
async function verifyApplied(coll) {
  const unresolved = [];
  const remaining = await coll.countDocuments(ORPHAN_FILTER);
  if (remaining > 0) unresolved.push(`仍有 ${remaining} 条无 tokenHash 文档`);
  const stillLegacy = (await coll.indexes()).filter(isLegacyTokenIndex);
  if (stillLegacy.length > 0) {
    unresolved.push(`遗留单键索引仍在：${stillLegacy.map((i) => i.name).join(', ')}`);
  }
  return unresolved;
}

/**
 * 清孤儿，并且**照驱动给的数**报告。
 * 原先打印的是动手之前那次 countDocuments 的结果、deleteMany 的返回值被丢弃，
 * 于是"一条都没删成"与"全删干净"在日志与退出码上完全同形。
 */
async function cleanupOrphans(coll, countedBefore) {
  if (countedBefore === 0) return;
  const res = await coll.deleteMany(ORPHAN_FILTER);
  console.log(
    `已清理 ${res.deletedCount} 条无 tokenHash 的历史文档（动手前清点为 ${countedBefore} 条）`
  );
  if (res.deletedCount !== countedBefore) {
    console.warn('⚠ 删除数与清点数不一致：并发写入或库被其他进程改动过，请以本次复核结果为准');
  }
}

(async () => {
  const { uri, dbName, host, isFallback } = resolveMongoUri({
    scriptName: 'fix-token-blacklist-index.js',
  });
  // M-08：fail-closed——--apply 类操作必须显式声明 ALLOWED_SOURCE_DB。
  // 原先只需单个 --apply 即可删除索引与历史文档，且默认回退本地库。
  //
  // 顺序要求（本次改动修的正是不一致的那一维）：白名单校验必须在 connect **之前**。
  // 原先先 connect 再校验，于是"被拒绝的一次执行"仍然：向目标库（可能正是生产库）
  // 发起 TCP + 鉴权握手；库不可达时脚本卡在 30s serverSelection 超时里，
  // 连"我该被拒绝"都要等连接失败才知道。未获准就一个字节都不该碰那个库。
  if (
    !assertApplyAllowed({
      scriptName: 'fix-token-blacklist-index.js',
      dbName,
      host,
      isFallback,
      apply: APPLY,
    })
  ) {
    process.exit(2);
  }

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
    // 「集合不存在」在本驱动（实测 mongodb 7.5.0）下**会抛错**：`indexes()` 内部走
    // listIndexes，缺 ns 抛 MongoServerError / code=26 / codeName=NamespaceNotFound
    // （不是返回 []）。所以下面那条 NamespaceNotFound 分支**不是死代码**，恰恰是
    // 「集合不存在 ⇒ 无需处理」的唯一通道，删掉它会让全新部署/首次迁移前的正常情形 exit 1。
    // 旧实现的错误在于把这个分支扩成了「任何异常都当良性」并 exit 0，于是真实故障
    // （鉴权失败 / 选主超时 / 网络）也报"无需处理"：遗留 token 单键唯一索引其实还在
    // （刷新令牌 E11000 症状不消失）。现在只放行 NamespaceNotFound，其余一律上抛，
    // 交给最外层 catch 以 exit 1 终止。
    const codeName = e && e.codeName;
    if (codeName === 'NamespaceNotFound' || (e && e.name === 'MongoNamespaceNotFound')) {
      console.log('tokenblacklists 集合不存在，无需处理');
      await mongoose.disconnect();
      process.exit(0);
    }
    throw e;
  }

  console.log('\n当前索引：');
  indexes.forEach((i) => {
    console.log(`  ${i.name.padEnd(16)} key=${JSON.stringify(i.key)} unique=${!!i.unique}`);
  });

  // 只删「仅含 token 单键」的索引，避免误删复合索引
  const legacy = indexes.filter(isLegacyTokenIndex);

  const orphan = await coll.countDocuments(ORPHAN_FILTER);

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

  // 删除条数取自驱动的 deletedCount，而不是动手之前那次 countDocuments 的结果
  await cleanupOrphans(coll, orphan);

  const unresolved = await verifyApplied(coll);
  if (unresolved.length > 0) {
    console.error(`\n✗ 复核未通过：${unresolved.join('；')}`);
    console.error('  症状（refresh 恒报「刷新令牌已失效」）不会消失，请排查后重跑本脚本。');
    await mongoose.disconnect();
    process.exit(1);
  }

  console.log('\n处理完成（结果已按库的读数复核）。建议重启服务以确保 mongoose 索引缓存刷新。');
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
