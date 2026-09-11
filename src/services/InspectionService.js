/**
 * 巡检业务服务层
 * 封装巡检相关的核心业务逻辑
 */

const Inspection = require('../models/Inspection');
const logger = require('../utils/logger');
const { escapeRegExp, parseDateBoundary } = require('../utils/helpers');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
const { applyDataScopeToQuery } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const ApiError = require('../utils/ApiError');

class InspectionService {
  /**
   * 获取巡检列表（含数据范围过滤和分页）
   *
   * E-2：支持游标分页。传入 cursor 时按 planStartTime 倒序做 keyset seek，
   * 跳过 countDocuments，以 hasMore/nextCursor 表达翻页；
   * 不传 cursor 保持原 page/limit 行为。
   */
  async getInspections({
    page,
    limit,
    cursor,
    status,
    inspectionType,
    assignedTo,
    startDate,
    endDate,
    search,
    dataScope,
  }) {
    const query = {};
    if (status) query.status = status;
    if (inspectionType) query.inspectionType = inspectionType;
    if (assignedTo) query.assignedTo = assignedTo;

    // 日期边界：必须走 parseDateBoundary。直接 new Date('2026-08-25') 按 UTC 解析，
    // 东八区部署下 endDate 实际截止到当天 08:00，当天上午的巡检从列表中消失
    // （AlarmService 已用该工具，此处对齐）
    if (startDate || endDate) {
      query.planStartTime = {};
      if (startDate) query.planStartTime.$gte = parseDateBoundary(startDate, 'start');
      if (endDate) query.planStartTime.$lte = parseDateBoundary(endDate, 'end');
    }

    // 数据范围过滤：统一走 applyDataScopeToQuery（同字段冲突取交集，
    // department 为空时按 deny 处理，消除「三分支全不命中→零过滤」越权）
    // 属主/部门字段取自 DATA_SCOPE_FIELDS 单一声明（P2-20）
    if (!applyDataScopeToQuery(query, dataScope, DATA_SCOPE_FIELDS.inspection)) {
      return { inspections: [], count: 0, hasMore: false, nextCursor: null };
    }

    if (search) {
      const escaped = escapeRegExp(search);
      query.$or = [
        { title: new RegExp(escaped, 'i') },
        { 'locations.building': new RegExp(escaped, 'i') },
      ];
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      const cursorQuery = applyCursorCondition(query, {
        sortField: 'planStartTime',
        sortDir: -1,
        cursor: decoded,
        valueType: 'date',
      });
      const docs = await Inspection.find(cursorQuery)
        .populate({ path: 'assignedTo', select: 'username realName' })
        .populate({ path: 'devices', select: 'deviceCode deviceName deviceType' })
        .populate({ path: 'reviewedBy', select: 'username realName' })
        .sort({ planStartTime: -1 })
        .limit(limit + 1);
      const { items, hasMore, nextCursor } = buildCursorResult(docs, limit, 'planStartTime');
      return { inspections: items, count: null, hasMore, nextCursor };
    }

    const [inspections, count] = await Promise.all([
      Inspection.find(query)
        .populate({ path: 'assignedTo', select: 'username realName' })
        .populate({ path: 'devices', select: 'deviceCode deviceName deviceType' })
        .populate({ path: 'reviewedBy', select: 'username realName' })
        .sort({ planStartTime: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      Inspection.countDocuments(query),
    ]);

    // offset 模式同样下发 nextCursor：客户端可在任意页切换为游标续翻
    const hasNext = page * limit < count;
    const last = inspections[inspections.length - 1];
    const nextCursor =
      hasNext && last ? encodeCursor({ v: last.planStartTime, id: String(last._id) }) : null;

    return { inspections, count, nextCursor };
  }

  /**
   * 根据 ID 获取巡检详情
   */
  async getInspectionById(id) {
    return Inspection.findById(id)
      .populate({ path: 'assignedTo', select: 'username realName' })
      .populate({ path: 'devices', select: 'deviceCode deviceName deviceType location' })
      .populate({ path: 'reviewedBy', select: 'username realName' })
      .populate({ path: 'findings.deviceId', select: 'deviceCode deviceName' })
      .populate({ path: 'executionLog.userId', select: 'username realName' });
  }

  /**
   * 创建巡检计划
   */
  async createInspection(fields) {
    const inspection = await Inspection.create({ ...fields, status: 'pending' });
    logger.info(`巡检计划已创建：${inspection.title}`);
    return inspection;
  }

  /**
   * 更新巡检计划
   */
  async updateInspection(inspection, updates) {
    if (inspection.status !== 'pending') {
      throw ApiError.badRequest('已开始的巡检计划不能修改');
    }
    // P3-14：白名单补齐路由已放行的 description/remark/priority——
    // 原实现三字段被静默丢弃，前端「保存成功」但数据从未落库；
    // 与 deviceRoutes 的 installDate 同类问题（校验了却不在可更新列表）
    const updatableFields = [
      'title',
      'inspectionType',
      'devices',
      'locations',
      'checkItems',
      'assignedTo',
      'planStartTime',
      'planEndTime',
      'description',
      'remark',
      'priority',
    ];
    updatableFields.forEach((field) => {
      if (updates[field] !== undefined) inspection[field] = updates[field];
    });
    await inspection.save();
    logger.info(`巡检计划已更新：${inspection.title}`);
    return inspection;
  }

  /**
   * 开始执行巡检
   * 原子化（参照 AlarmService）：findOneAndUpdate + 状态前置条件，
   * 消除读改写竞态（并发两个 start 请求不再都能成功）；未命中前置条件抛 409 冲突，
   * 控制器侧 err.statusCode 分支会原样返回给调用方。
   * M-2：仅被指派人可开始执行（未指派任何人的计划保持开放，由同权限者代执行）
   */
  async startInspection(inspection, operatorId) {
    const now = new Date();
    // findOneAndUpdate({new:true}) 后链式 .populate 一趟完成，
    // 替代「原子更新后再 getInspectionById 回查」的第二次数据库往返
    const updated = await Inspection.findOneAndUpdate(
      {
        _id: inspection._id,
        status: 'pending',
        $or: [{ assignedTo: operatorId }, { 'assignedTo.0': { $exists: false } }],
      },
      {
        $set: { status: 'in_progress', actualStartTime: now },
        $push: { executionLog: { userId: operatorId, action: 'started', timestamp: now } },
      },
      { new: true }
    )
      .populate({ path: 'assignedTo', select: 'username realName' })
      .populate({ path: 'devices', select: 'deviceCode deviceName deviceType location' })
      .populate({ path: 'reviewedBy', select: 'username realName' })
      .populate({ path: 'findings.deviceId', select: 'deviceCode deviceName' })
      .populate({ path: 'executionLog.userId', select: 'username realName' });
    if (!updated) {
      throw ApiError.conflict('巡检当前状态不允许执行或您不是被指派人');
    }
    logger.info(`巡检开始执行：${updated.title}`);
    return updated;
  }

  /**
   * 提交巡检结果（原子化：仅 in_progress 可提交，防并发重复提交）
   * M-2：仅被指派人可提交结果（未指派任何人的计划保持开放）
   */
  async completeInspection(inspection, { result, findings, location, remark }, operatorId) {
    const now = new Date();
    const setFields = { status: 'completed', actualEndTime: now, result: result || 'normal' };
    if (findings && Array.isArray(findings)) setFields.findings = findings;
    if (remark) setFields.remark = remark;

    // findOneAndUpdate({new:true}) + 链式 populate 一趟完成，避免回查二次往返
    const updated = await Inspection.findOneAndUpdate(
      {
        _id: inspection._id,
        status: 'in_progress',
        $or: [{ assignedTo: operatorId }, { 'assignedTo.0': { $exists: false } }],
      },
      {
        $set: setFields,
        $push: {
          executionLog: {
            userId: operatorId,
            action: 'completed',
            timestamp: now,
            // location 兼容两种形态：字符串（前端地点文字）→ {text}；对象 → {lat,lng}
            location: typeof location === 'string' ? { text: location } : location || undefined,
          },
        },
      },
      { new: true }
    )
      .populate({ path: 'assignedTo', select: 'username realName' })
      .populate({ path: 'devices', select: 'deviceCode deviceName deviceType location' })
      .populate({ path: 'reviewedBy', select: 'username realName' })
      .populate({ path: 'findings.deviceId', select: 'deviceCode deviceName' })
      .populate({ path: 'executionLog.userId', select: 'username realName' });
    if (!updated) {
      throw ApiError.conflict('巡检未开始、已完成或您不是被指派人');
    }
    logger.info(`巡检已完成：${updated.title}`);
    return updated;
  }

  /**
   * 审核巡检结果（原子化：仅已完成且未审核的记录可审核，防并发重复审核）
   * M-2：审核人与被指派人必须分离，禁止自审自批
   */
  async reviewInspection(inspection, { reviewResult, reviewComment }, reviewerId) {
    if (!['approved', 'rejected'].includes(reviewResult)) {
      throw ApiError.badRequest('审核结论必须为 approved（通过）或 rejected（不通过）');
    }

    const now = new Date();
    const setFields = { reviewedBy: reviewerId, reviewedAt: now, reviewResult };
    if (reviewComment) setFields.reviewComment = reviewComment;

    // findOneAndUpdate({new:true}) + 链式 populate 一趟完成，避免回查二次往返
    const updated = await Inspection.findOneAndUpdate(
      // reviewResult: null 同时匹配字段缺失与显式 null（即尚未审核）；
      // assignedTo $ne 审核人 → 被指派人不能审核自己的巡检
      {
        _id: inspection._id,
        status: 'completed',
        reviewResult: null,
        assignedTo: { $ne: reviewerId },
      },
      {
        $set: setFields,
        $push: {
          executionLog: {
            userId: reviewerId,
            action: reviewResult === 'approved' ? 'review_approved' : 'review_rejected',
            timestamp: now,
          },
        },
      },
      { new: true }
    )
      .populate({ path: 'assignedTo', select: 'username realName' })
      .populate({ path: 'devices', select: 'deviceCode deviceName deviceType location' })
      .populate({ path: 'reviewedBy', select: 'username realName' })
      .populate({ path: 'findings.deviceId', select: 'deviceCode deviceName' })
      .populate({ path: 'executionLog.userId', select: 'username realName' });
    if (!updated) {
      throw ApiError.conflict('只能审核已完成且未审核的巡检，且被指派人不能自审');
    }
    logger.info(
      `巡检已审核（${reviewResult === 'approved' ? '通过' : '不通过'}）：${updated.title}`
    );
    return updated;
  }

  /**
   * 取消巡检（原子化：已完成/已取消的记录不允许重复操作）
   */
  async cancelInspection(inspection, reason, operatorId) {
    const now = new Date();
    // 与 start/complete/review 同模式：findOneAndUpdate({new:true}) + 链式 populate 一趟完成
    const updated = await Inspection.findOneAndUpdate(
      { _id: inspection._id, status: { $nin: ['completed', 'cancelled'] } },
      {
        $set: { status: 'cancelled' },
        $push: {
          executionLog: {
            userId: operatorId,
            action: 'cancelled',
            timestamp: now,
            remark: reason || '取消巡检',
          },
        },
      },
      { new: true }
    )
      .populate({ path: 'assignedTo', select: 'username realName' })
      .populate({ path: 'devices', select: 'deviceCode deviceName deviceType location' })
      .populate({ path: 'reviewedBy', select: 'username realName' })
      .populate({ path: 'findings.deviceId', select: 'deviceCode deviceName' })
      .populate({ path: 'executionLog.userId', select: 'username realName' });
    if (!updated) {
      throw ApiError.conflict('已完成或已取消的巡检不能重复操作');
    }
    logger.info(`巡检已取消：${updated.title}`);
    return updated;
  }

  /**
   * 删除巡检（原子删除：状态前置条件并入过滤条件，消除「先读状态再删」的 TOCTOU 竞态）
   */
  async deleteInspection(inspection) {
    const result = await Inspection.deleteOne({
      _id: inspection._id,
      status: { $ne: 'in_progress' },
    });
    if (result.deletedCount === 0) {
      // 未命中时区分两种失败：文档仍在但已被并发置为 in_progress → 400；
      // 文档不存在或已被并发删除 → 404
      const current = await Inspection.findById(inspection._id).select('status').lean();
      if (current && current.status === 'in_progress') {
        throw ApiError.badRequest('正在执行的巡检不能删除');
      }
      throw ApiError.notFound('巡检不存在或已被删除');
    }
    logger.info(`巡检已删除：${inspection.title}`);
  }

  /**
   * 获取巡检统计
   * L2：与列表同口径的数据范围过滤，防止越权看到全组织统计
   */
  async getInspectionStats(startDate, endDate, dataScope = { type: 'all' }) {
    const matchStage = {};
    // 与列表同口径的日期边界（见 getInspections 注释）
    if (startDate || endDate) {
      matchStage.planStartTime = {};
      if (startDate) matchStage.planStartTime.$gte = parseDateBoundary(startDate, 'start');
      if (endDate) matchStage.planStartTime.$lte = parseDateBoundary(endDate, 'end');
    }

    // 数据范围过滤（与 getInspections 相同的口径：同一函数、同一 deny 语义）
    if (!applyDataScopeToQuery(matchStage, dataScope, DATA_SCOPE_FIELDS.inspection)) {
      return { total: 0, byStatus: [], byType: [], byResult: [] };
    }

    const baseMatch = Object.keys(matchStage).length > 0 ? { $match: matchStage } : { $match: {} };

    const [byStatus, byType, byResult, total] = await Promise.all([
      Inspection.aggregate([baseMatch, { $group: { _id: '$status', count: { $sum: 1 } } }]),
      Inspection.aggregate([baseMatch, { $group: { _id: '$inspectionType', count: { $sum: 1 } } }]),
      Inspection.aggregate([
        { $match: { ...matchStage, status: 'completed' } },
        { $group: { _id: '$result', count: { $sum: 1 } } },
      ]),
      Inspection.countDocuments(matchStage),
    ]);

    return { total, byStatus, byType, byResult };
  }
}

module.exports = new InspectionService();
