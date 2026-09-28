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
//
// 与 services/reportDashboardService.js 的 dashboardCache 同一口径：进程内 Map，
// 刻意不做跨模块/跨实例失效广播，只靠 TTL 收敛（真要一致，改法在那里已经写明：
// 走写侧 publishInvalidate，而不是把 TTL 调小——调 TTL 只缩小滞后，不消除不一致）。
// 但两者滞后的**性质**不同，必须说清楚：这里缓存的是数据范围的允许集，
// 所以滞后窗口有方向——成员被调出后 ≤30s 内其日志对该部门管理员仍可见（偏宽），
// 调入者则 ≤30s 内不可见（偏窄）。判为可接受的两条前提：
//   ① 唯一能改 department 的写入口是管理员的 PUT /api/users/:id，且它前面有
//      assertRecordInScope 的域闸（controllers/userController.js）；自助入口的字段
//      白名单不含 department（services/authService.updateUserProfile，H-01）。
//      于是"被调出者"不可能自己触发这个窗口，能触发的只有本来就看得见他的管理员。
//   ② 只影响"看我整个部门"这一条范围查询；点查某个人走下面的 findById，实时准确。
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
    // 部门档却拿不到部门（用户未填/部门被清空）⇒ 必须无条件拒绝，不能"退化为看自己的日志"。
    // 旧实现写的是 `new mongoose.Types.ObjectId(dataScope.userId)`，但 getDataScope 的
    // department 档返回 {type:'department', department}，压根不带 userId（带 userId 的是 self 档，
    // rbac.js:206-215）⇒ 实参恒为 undefined，mongoose 于是生成一个**随机** ObjectId：
    // 查询永久 0 命中、两次请求条件还各不相同（不可复现），而接口按"成功导出 0 条"上报。
    // deny 也与另外两个收敛点同口径（rbac.buildDataScopeFilter 的 `!department → {_id:null}`、
    // applyDataScopeToQuery 返回 false），本文件曾是这条不变量唯一的例外。
    if (!dataScope.department) return { query: deniedAuditQuery(query), dataScope };
    const requestedUserId = query.userId ? String(query.userId) : null;
    // 点查快路径：只校验目标用户本人是否属于本部门（一次 findById），
    // 不拉全部门成员集——这是审计页最常见的「查某人日志」路径
    if (requestedUserId) {
      // 先就地判形状：非法 id 直接 deny，不交给 findById 抛 CastError。
      // 必须在这里挡住，是为了让下面那一次查询**不再需要 catch**（见下）。
      if (!mongoose.Types.ObjectId.isValid(requestedUserId)) {
        return { query: deniedAuditQuery(query), dataScope };
      }
      // 这一句不许加 `.catch(() => null)`：加了就把「基础设施故障」（连接重置/选主/写关注超时）
      // 折成「该用户不在本部门」⇒ deny，于是导出与列表在 DB 抖动期间返回 **200 + 空结果**，
      // 与「确实没有数据」完全不可区分。那正是上面 :46-52 判定为缺陷并已被修掉的同一格，
      // 只是当时载体是随机 ObjectId、这次是 catch。用户不存在时 findById 本就 resolve null
      // （不需要 catch），能 reject 的只剩真故障，必须冒泡给调用方的 AUDIT_*_FAILED。
      const target = await User.findById(requestedUserId).select('department').lean();
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
