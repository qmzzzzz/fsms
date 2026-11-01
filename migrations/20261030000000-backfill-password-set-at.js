/**
 * 存量用户补齐 passwordSetAt（P1-2，2026-10-30）
 *
 * 背景：新增 mustChangePassword/passwordSetAt 后，新用户在建号/改密时都会写
 * passwordSetAt；存量用户没有这个字段，口令年龄类报表会缺一段。这里用 createdAt
 * 兜底回填（没有更早的口令设置时间证据，createdAt 是保守下界，不虚构历史）。
 *
 * 幂等：只匹配字段不存在的文档；重复执行无副作用。
 * 回滚：仅撤销本迁移写入的字段（保留值为 null 的文档不在此列——它们不是本迁移产生的）。
 */

module.exports = {
  async up(db) {
    const result = await db.collection('users').updateMany({ passwordSetAt: { $exists: false } }, [
      {
        $set: {
          passwordSetAt: { $ifNull: ['$createdAt', '$$NOW'] },
        },
      },
    ]);
    console.log(
      `passwordSetAt 补齐：匹配 ${result.matchedCount} 条，更新 ${result.modifiedCount} 条`
    );
  },

  async down(db) {
    // 仅撤掉本迁移会写入的那类文档（有 passwordSetAt 且没有 mustChangePassword 标记的存量），
    // 新生用户即使 mustChangePassword=false 也已有明确建号时间，不能一刀切抹掉。
    await db
      .collection('users')
      .updateMany(
        { passwordSetAt: { $exists: true }, mustChangePassword: { $exists: false } },
        { $unset: { passwordSetAt: '' } }
      );
  },
};
