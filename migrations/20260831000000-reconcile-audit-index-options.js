/**
 * auditlogs 索引选项对齐模型定义（七维终评「AuditLog 索引」项排查结论）
 *
 * 终评疑点「{timestamp:1} 与 TTL {timestamp:-1} 并存写放大」经核实**不成立**：
 * 源码与线上库均无升序 {timestamp:1} 索引。但排查发现真实偏差——
 * 早期版本建的三个索引选项落后于当前模型定义（scripts/sync-audit-indexes.js
 * 演练输出「选项不一致 3 个」）：
 *
 *   1. timestamp_-1  缺 expireAfterSeconds=15552000（TTL 未生效，
 *                    审计留存策略形同虚设，集合只增不减）
 *   2. sessionId_1   缺 sparse:true（大量无 sessionId 的记录产生无效索引项）
 *   3. hash_1        缺 sparse:true（历史/外部记录可能无 hash）
 *
 * 处理：
 *   - TTL 用 collMod 原地生效（MongoDB 支持，无需重建）；
 *   - sparse 无法原地变更，采用「删除重建」（后台构建，低峰执行）。
 * 幂等：逐项先读现有选项，已一致则跳过。
 *
 * 回滚（down）：恢复为无选项索引。注意 TTL 回滚即停止留存策略自动清理；
 * 非必要时不回滚本迁移。
 */

const COLLECTION = 'auditlogs';
const RETENTION_SECONDS = 15552000; // 180 天，与 constants/retention.js 默认口径一致

const getIndex = async (db, name) => {
  const list = await db.collection(COLLECTION).indexes();
  return list.find((i) => i.name === name) || null;
};

module.exports = {
  async up(db) {
    const coll = db.collection(COLLECTION);

    // 1) TTL：优先 collMod 原地生效；索引不存在时按模型定义直接创建
    const tsIdx = await getIndex(db, 'timestamp_-1');
    if (!tsIdx) {
      await coll.createIndex({ timestamp: -1 }, { expireAfterSeconds: RETENTION_SECONDS });
      console.log('timestamp_-1 不存在，已按模型定义创建（含 TTL）');
    } else if (tsIdx.expireAfterSeconds !== RETENTION_SECONDS) {
      await db.command({
        collMod: COLLECTION,
        index: { keyPattern: { timestamp: -1 }, expireAfterSeconds: RETENTION_SECONDS },
      });
      console.log(`timestamp_-1 TTL 已设置为 ${RETENTION_SECONDS}s（留存策略恢复生效）`);
    } else {
      console.log('timestamp_-1 TTL 已一致，跳过');
    }

    // 2/3) sparse 索引：选项无法原地变更，删除重建
    for (const [name, key] of [
      ['sessionId_1', { sessionId: 1 }],
      ['hash_1', { hash: 1 }],
    ]) {
      const idx = await getIndex(db, name);
      if (idx && idx.sparse === true) {
        console.log(`${name} 已含 sparse，跳过`);
        continue;
      }
      if (idx) await coll.dropIndex(name);
      await coll.createIndex(key, { sparse: true, background: true });
      console.log(`${name} 已重建为 sparse 索引`);
    }
  },

  async down(db) {
    const coll = db.collection(COLLECTION);

    // TTL 回滚：collMod 无法移除 TTL，只能删除重建为普通索引
    const tsIdx = await getIndex(db, 'timestamp_-1');
    if (tsIdx && tsIdx.expireAfterSeconds !== undefined) {
      await coll.dropIndex('timestamp_-1');
      await coll.createIndex({ timestamp: -1 }, { background: true });
      console.log('timestamp_-1 已回滚为无 TTL 索引（留存策略停止自动清理）');
    }

    for (const [name, key] of [
      ['sessionId_1', { sessionId: 1 }],
      ['hash_1', { hash: 1 }],
    ]) {
      const idx = await getIndex(db, name);
      if (idx && idx.sparse === true) {
        await coll.dropIndex(name);
        await coll.createIndex(key, { background: true });
        console.log(`${name} 已回滚为普通索引`);
      }
    }
  },
};
