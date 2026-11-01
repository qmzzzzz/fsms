/**
 * 批量匿名化（P1-3）：从 userService.js 抽出（其体积已贴 max-lines 棘轮）。单删/批量删除共用
 * 「条件载入 → 匿名化 → 释放指派」，通过传入的 service 复用既有载入点（findUserForUpdate /
 * anonymizeUserDocument / releaseOpenAssignments），避免复制凭证投影载入点。
 */

'use strict';

const User = require('../models/User');
const { withTransaction } = require('../utils/transaction');

/** @param {object} service userService 实例（调用其私有辅助方法）
 *  @param {object} filter 无快照时的过滤条件（有快照时按 expectedByTarget 逐个比对）
 *  @param {Map<string, object>} [expectedByTarget] Map<id, {roles,department,createdBy}>
 *  @returns {Promise<{anonymizedCount: number, acknowledged?: boolean}>} */
async function anonymizeMany(
  service,
  filter,
  expectedByTarget,
  { reason = 'deletion_request' } = {}
) {
  return withTransaction(async (session) => {
    const opts = session ? { session } : {};
    const ids = [];

    if (expectedByTarget) {
      for (const [id, snapshot] of expectedByTarget) {
        const user = await service.findUserForUpdate(id, snapshot, opts);
        // 条件载入为空 == 目标在判定后改过角色/部门/创建人 ⇒ 整批中止（不是静默跳过）
        if (!user) {
          const error = new Error('批量匿名化中止：目标用户状态已变更');
          error.code = 'USER_STATE_CONFLICT';
          throw error;
        }
        await service.anonymizeUserDocument(user, reason, opts);
        ids.push(user._id);
      }
      await service.releaseOpenAssignments(ids, session);
      return { anonymizedCount: ids.length, acknowledged: true };
    }

    // 先取 id：匿名化会改写 email，之后再按原 filter 查就找不到这批人了。逐 id 走 findUserForUpdate
    // （带凭证排除投影的既有载入点，批量上限 100）——多一次轻量 id 查询换"投影清单只留一处"。
    const affected = await User.find(filter, '_id').lean();
    for (const { _id } of affected) {
      const user = await service.findUserForUpdate(_id, undefined, opts);
      if (!user) continue;
      await service.anonymizeUserDocument(user, reason, opts);
      ids.push(user._id);
    }
    // 与删号同一口径：把"进行中的指派"退回池子（见 releaseOpenAssignments 的注释）
    await service.releaseOpenAssignments(ids, session);
    return { anonymizedCount: ids.length };
  });
}

module.exports = { anonymizeMany };
