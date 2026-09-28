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
 * 回滚：**有意为空操作**。down 若按 `tokenVersion: 0` 撤字段，射程会远超本迁移的写入范围
 * （schema 有 default: 0，几乎每个未被吊销推进过的用户都是 0），
 * 于是"回滚一次补齐"实际变成"抹掉存量的 tokenVersion"。
 * 需要精确回退时，请在执行 up 前用 backup-mongo.sh 留档，再按 _id 白名单撤字段。
 */

module.exports = {
  async up(db) {
    const result = await db
      .collection('users')
      .updateMany({ tokenVersion: { $exists: false } }, { $set: { tokenVersion: 0 } });
    // migrate-mongo 不打印返回值，写入 _migrations 技术文档外再留一行日志线索
    console.log(
      `tokenVersion 补齐：匹配 ${result.matchedCount} 条，更新 ${result.modifiedCount} 条`
    );
  },

  async down(_db) {
    // 有意无操作（migrate-mongo v14 的 lib/actions/down.js 会无条件调用 down()，函数必须存在）。
    // 原实现 `updateMany({ tokenVersion: 0 }, { $unset: { tokenVersion: '' } })` 的射程
    // 远超本迁移的写入范围 `{ tokenVersion: { $exists: false } }`：User schema 对
    // tokenVersion 有 `default: 0`，因此每一个经 Mongoose 建档、尚未被吊销推进过的用户
    // 都会被一起撤掉字段 —— 回滚从"撤销本次补齐"变成"抹掉存量字段"。
  },
};
