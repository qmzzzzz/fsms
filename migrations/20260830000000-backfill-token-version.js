/**
 * 存量用户补齐 tokenVersion=0（与 schema 默认值对齐）
 *
 * 背景：会话吊销体系要求令牌携带 tokenVersion 并与用户当前版本严格匹配
 * （见 middleware/auth.js 4.7 之前的校验）。User schema 对 tokenVersion
 * 有默认值 0，但仅作用于新写入文档；早期创建的存量用户缺该字段，
 * 认证逻辑以 `?? 0` 兜底参与比对。本迁移把数据对齐到显式值，
 * 消除「字段缺失靠代码兜底」的隐式约定。
 *
 * 幂等：$exists 过滤保证重复执行无副作用。
 * 回滚：移除本次补齐的字段。注意 down 无法区分「本次补的 0」与
 * 「业务推进后仍为 0」的文档——实践中 tokenVersion 只在吊销时递增，
 * 未触发过吊销的用户本就应为 0，故该回滚口径可接受；若需精确回退，
 * 在执行 up 前先用 backup-mongo.sh 留档。
 */

module.exports = {
  async up(db) {
    const result = await db
      .collection('users')
      .updateMany({ tokenVersion: { $exists: false } }, { $set: { tokenVersion: 0 } });
    // migrate-mongo 不打印返回值，写入 _migrations 台账外再留一行日志线索
    console.log(
      `tokenVersion 补齐：匹配 ${result.matchedCount} 条，更新 ${result.modifiedCount} 条`
    );
  },

  async down(db) {
    await db.collection('users').updateMany({ tokenVersion: 0 }, { $unset: { tokenVersion: '' } });
  },
};
