/**
 * 审计日志数据范围过滤（评价报告 #22 / #13 拆分自 auditQueryService）
 *
 * 职责：把操作者的数据范围（all/self/department）翻译为 AuditLog 查询条件。
 * 拆分动机：体积棘轮——scope 翻译与查询构建/游标分页是两个正交关注点，
 * 同文件混居让 auditQueryService 顶破 max-lines 基线。
 */

const mongoose = require('mongoose');
const User = require('../models/User');

// 评价报告 #22：部门成员集缓存——原实现每次请求都 User.distinct 拉全部门
// 用户 id 进 $in，大部门下查询放大且每请求重复计算。成员变化低频，
// 30s TTL 内复用一份；点查路径（带 userId）根本不需要成员集（见下）。
const DEPT_MEMBERS_CACHE_TTL_MS = 30 * 1000;
const deptMembersCache = new Map(); // department -> { ids, expiresAt }

const getDepartmentMemberIds = async (department) => {
  const hit = deptMembersCache.get(department);
  if (hit && hit.expiresAt > Date.now()) return hit.ids;
  const ids = await User.distinct('_id', { department });
  deptMembersCache.set(department, { ids, expiresAt: Date.now() + DEPT_MEMBERS_CACHE_TTL_MS });
  return ids;
};

/** 无条件拒绝：显式空 $in，语义为「该范围下不可见任何记录」 */
const deniedAuditQuery = (query) => ({ ...query, _id: { $in: [] } });

const applyAuditDataScope = async (query, operatorId) => {
  const { getDataScope } = require('../middleware/rbac');
  const dataScope = await getDataScope(operatorId);
  if (dataScope.type === 'all') return { query, dataScope };

  if (dataScope.type === 'self' && dataScope.userId) {
    const requestedUserId = query.userId ? String(query.userId) : null;
    if (requestedUserId && requestedUserId !== String(dataScope.userId)) {
      return { query: deniedAuditQuery(query), dataScope };
    }
    return {
      query: { ...query, userId: new mongoose.Types.ObjectId(dataScope.userId) },
      dataScope,
    };
  }

  if (dataScope.type === 'department') {
    if (!dataScope.department) {
      return {
        query: { ...query, userId: new mongoose.Types.ObjectId(dataScope.userId) },
        dataScope,
      };
    }
    const requestedUserId = query.userId ? String(query.userId) : null;
    // 点查快路径：只校验目标用户本人是否属于本部门（一次 findById），
    // 不拉全部门成员集——这是审计页最常见的「查某人日志」路径
    if (requestedUserId) {
      const target = await User.findById(requestedUserId)
        .select('department')
        .lean()
        .catch(() => null);
      if (!target || target.department !== dataScope.department) {
        return { query: deniedAuditQuery(query), dataScope };
      }
      return {
        query: { ...query, userId: new mongoose.Types.ObjectId(requestedUserId) },
        dataScope,
      };
    }
    const departmentUserIds = await getDepartmentMemberIds(dataScope.department);
    if (departmentUserIds.length === 0) {
      return { query: deniedAuditQuery(query), dataScope };
    }
    return {
      query: { ...query, userId: { $in: departmentUserIds } },
      dataScope,
    };
  }

  return { query: deniedAuditQuery(query), dataScope };
};

module.exports = { applyAuditDataScope, deniedAuditQuery };
