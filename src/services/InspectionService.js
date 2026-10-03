/**
 * 巡检业务服务层
 * 封装巡检相关的核心业务逻辑
 */

const Inspection = require('../models/Inspection');
const logger = require('../utils/logger');
const { escapeRegExp, parseDateBoundary } = require('../utils/helpers');
const { withListBudget, listCountOptions, listAggregateOptions } = require('../utils/queryBudget');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
const { applyDataScopeToQuery } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
// 审核结论取值与模型 enum、路由 isIn、OpenAPI 同源（F-150）：闸门与白名单各写一遍时，
// 单侧加一个值就会出现"路由放行、这里 400"或反向的静默落库
// 开工/提交/审核三处准入共用巡检域档位表（与 F-137/F-149/F-150 同族：闸门与白名单各写一遍，
// 单侧加值即放行不落库）。可开始/可提交是「开放档位」的两个互补切片，加一档终态时派生式会漂移。
const {
  INSPECTION_REVIEW_RESULTS,
  INSPECTION_OPEN_STATUSES,
  INSPECTION_STARTABLE_STATUSES,
  INSPECTION_SUBMITTABLE_STATUSES,
} = require('../constants/inspection');
const { castScopeObjectIds, applySearchCondition } = require('../utils/scopeCast');
const ApiError = require('../utils/ApiError');
const { readPositiveNumberEnv } = require('../utils/envNumber');

/**
 * executionLog 的写入判据（四处 $push 共用一份，见 pushExecutionLog）
 *
 * 这是一个"每次操作留一条"的追加型数组，而 `overdue` 只是调度器打的时间标记、
 * 不是工作流阶段：一条 planEndTime 已过的计划可以在 startInspection 那里被**反复开始**
 * （`status: {$in:['pending','overdue']}` 放行，`markOverdueInspections` 每轮又把
 * `in_progress` 打回 `overdue`）⇒ 同一个数组无上限增长，而它随详情接口整段返回、
 * 还会 populate executionLog.userId（每条都要再一次 ref 解析）。
 *
 * 封顶取尾部 N 条，同时用 `executionLogCount` 记"总共发生过多少次"：
 * `count > length` 即"有留痕被截断"⇒ 截断这件事可数、不静默
 * （与 xlsx 导出的 X-Export-Truncated 同一口径：宁可声明，不可假装完整）。
 */
const EXECUTION_LOG_CAP = readPositiveNumberEnv('INSPECTION_EXECUTION_LOG_CAP', 200, {
  integer: true,
});
const pushExecutionLog = (entry) => ({
  $push: { executionLog: { $each: [entry], $slice: -EXECUTION_LOG_CAP } },
  $inc: { executionLogCount: 1 },
});

// 详情视图的 populate 规格：getInspectionById 与四个原子写操作返回同一个形状，
// 共用一份常量而不是各抄五遍链式 .populate（抄写期间任何一处增删路径都会让
// 读接口与写接口的响应结构静默分叉）。
const INSPECTION_POPULATE = [
  { path: 'assignedTo', select: 'username realName' },
  { path: 'devices', select: 'deviceCode deviceName deviceType location' },
  { path: 'reviewedBy', select: 'username realName' },
  { path: 'findings.deviceId', select: 'deviceCode deviceName' },
  { path: 'executionLog.userId', select: 'username realName' },
];

class InspectionService {
  /**
   * 查出给定用户 ID 中当前启用（status:active）的子集，返回字符串 id 数组。
   * 供派单/更新前的"执行人可用性"校验使用。模型直连放在服务层：
   * controller 禁直连 models（见 architecture/layeringRatchet 不变式）。
   */
  async findActiveUserIds(ids) {
    if (!Array.isArray(ids) || ids.length === 0) return [];
    const User = require('../models/User');
    const found = await User.find({ _id: { $in: ids }, status: 'active' })
      .select('_id')
      .lean();
    return found.map((doc) => String(doc._id));
  }

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
      // 预防性统一（inspection 当前属主声明是单字段 assignedTo ⇒ 范围条件今天不占 $or，
      // 所以这不是在修一个现网缺陷）：但一旦有人把 ownerField 改成数组（device、alarm 已经是），
      // 直接 `query.$or = [...]` 就会静默吃掉数据范围条件。三处列表口径共用同一个合并器，
      // 新资源就不会再踩第三次（详见 utils/scopeCast.js）。
      applySearchCondition(query, {
        $or: [
          { title: new RegExp(escaped, 'i') },
          { 'locations.building': new RegExp(escaped, 'i') },
        ],
      });
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      const cursorQuery = applyCursorCondition(query, {
        sortField: 'planStartTime',
        sortDir: -1,
        cursor: decoded,
        valueType: 'date',
      });
      const docs = await withListBudget(Inspection.find(cursorQuery))
        .populate({ path: 'assignedTo', select: 'username realName' })
        .populate({ path: 'devices', select: 'deviceCode deviceName deviceType' })
        .populate({ path: 'reviewedBy', select: 'username realName' })
        // `_id` 次级排序键与续翻子句 `{planStartTime:v,_id:{$lt:id}}` 同向，
        // 缺它则等值块跨页漂移（索引见 models/Inspection.js）
        .sort({ planStartTime: -1, _id: -1 })
        .limit(limit + 1);
      const { items, hasMore, nextCursor } = buildCursorResult(docs, limit, 'planStartTime');
      return { inspections: items, count: null, hasMore, nextCursor };
    }

    const [inspections, count] = await Promise.all([
      withListBudget(Inspection.find(query))
        .populate({ path: 'assignedTo', select: 'username realName' })
        .populate({ path: 'devices', select: 'deviceCode deviceName deviceType' })
        .populate({ path: 'reviewedBy', select: 'username realName' })
        // 与游标分支同向：本页末条要拿去 mint nextCursor
        .sort({ planStartTime: -1, _id: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      Inspection.countDocuments(query, listCountOptions()),
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
    return Inspection.findById(id).populate(INSPECTION_POPULATE);
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
   * 更新巡检计划（原子化：仅 pending 可修改，判定与写入同条件，防读改写竞态）
   */
  async updateInspection(inspection, updates) {
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
    const setFields = {};
    updatableFields.forEach((field) => {
      if (updates[field] !== undefined) setFields[field] = updates[field];
    });
    // 状态判定必须与写入同处一条原子操作。原实现是「内存里判 pending → save()」三段式：
    // 控制器 getInspectionById 取文档、服务用上一步读到的 status 把门、save() 按 _id 写回，
    // 中间任何一次并发 startInspection 都不参与判定 ⇒ 已在执行的巡检被静默换掉标题/时间窗/
    // 设备/执行人。本类其余四个写操作早已是 findOneAndUpdate + 状态前置条件，唯独这里漏改。
    //
    // status 一并 $set：值与匹配条件同值（pending），写入是无操作，
    // 但空 body 时不至于发出一个空的 $set（MongoDB 直接报错）；且若日后有人往
    // updatableFields 里加 status，显式的 'pending' 在后面覆盖，闸不会被自身白名单打开。
    const updated = await Inspection.findOneAndUpdate(
      { _id: inspection._id, status: 'pending' },
      { $set: { ...setFields, status: 'pending' } },
      { new: true, runValidators: true }
    ).populate(INSPECTION_POPULATE);
    if (!updated) {
      // 400 而非 409：本仓口径是「状态不允许」400、「状态转移冲突」409
      // （见 tests/controllers/alarmInspectionErrorPaths.test.js:427 的注释与该文件
      // 对"已开始不可更新=400、重复开始=409"的既有断言）。原子化只收紧判定时机，
      // 不改对外契约。
      throw ApiError.badRequest('已开始的巡检计划不能修改');
    }
    logger.info(`巡检计划已更新：${updated.title}`);
    return updated;
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
    //
    // 'overdue' 必须在可开始集合里：调度器（deviceReminder.markOverdueInspections）
    // 会把 planEndTime 已过的 pending 巡检改写成 overdue，若这里只认 pending，
    // 任何"过了计划结束时间才开始"的巡检就再也没有开始入口（唯一出路是 cancel），
    // 而巡检结果/发现项只能挂在 completed 上 ⇒ 真实做过的工作永久无法入库。
    // overdue 是调度器打的时间标记，不是工作流阶段。
    const updated = await Inspection.findOneAndUpdate(
      {
        _id: inspection._id,
        status: { $in: INSPECTION_STARTABLE_STATUSES },
        $or: [{ assignedTo: operatorId }, { 'assignedTo.0': { $exists: false } }],
      },
      {
        // 首次开工时刻只写一次。反复开始是可达路径而非臆想：调度器会把 in_progress
        // 打回 overdue（deviceReminder.markOverdueInspections），而下面的匹配条件又放行
        // overdue ⇒ 同一条计划能被点多次"开始"（本文件 :18-30 为此给 executionLog 封了顶）。
        // 无条件覆盖会把"实际到场"证据改成最后一次点开始的时刻，两处消费方同时失真：
        // reportDashboardService 的今日开始数按 actualStartTime:$gte 统计（几天前的巡检
        // 被算进今天），reportExportService:167 导出的"实际开始"列不再可取证。
        $set: { status: 'in_progress', actualStartTime: inspection.actualStartTime || now },
        ...pushExecutionLog({ userId: operatorId, action: 'started', timestamp: now }),
      },
      { new: true }
    ).populate(INSPECTION_POPULATE);
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
    //
    // 允许从 'overdue' 提交，理由与 startInspection 同源：调度器会把**正在执行**的
    // in_progress 巡检在 planEndTime 过后改写成 overdue，作业人员填到一半回来提交就撞 409，
    // 结果与发现项永久丢失。原子性不受影响——提交成功后 status 变 completed，
    // 重复提交仍匹配不到，"防并发重复提交"这条原始意图完整保留。
    const updated = await Inspection.findOneAndUpdate(
      {
        _id: inspection._id,
        status: { $in: INSPECTION_SUBMITTABLE_STATUSES },
        $or: [{ assignedTo: operatorId }, { 'assignedTo.0': { $exists: false } }],
      },
      {
        $set: setFields,
        ...pushExecutionLog({
          userId: operatorId,
          action: 'completed',
          timestamp: now,
          // location 兼容两种形态：字符串（前端地点文字）→ {text}；对象 → {lat,lng}
          location: typeof location === 'string' ? { text: location } : location || undefined,
        }),
      },
      { new: true }
    ).populate(INSPECTION_POPULATE);
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
    if (!INSPECTION_REVIEW_RESULTS.includes(reviewResult)) {
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
        ...pushExecutionLog({
          userId: reviewerId,
          action: reviewResult === 'approved' ? 'review_approved' : 'review_rejected',
          timestamp: now,
        }),
      },
      { new: true }
    ).populate(INSPECTION_POPULATE);
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
    // 准入写成「$in 开放档位」而不是「$nin 两个终态」：两者今天取值互补，但前者把兜住的
    // 方向说清楚了——越界/未知状态不该从「取消」这条出口被洗成 cancelled（原样 $nin 副本
    // 同时是本域最后一处手抄的档位字面量，见 F-151）。
    const updated = await Inspection.findOneAndUpdate(
      { _id: inspection._id, status: { $in: INSPECTION_OPEN_STATUSES } },
      {
        $set: { status: 'cancelled' },
        ...pushExecutionLog({
          userId: operatorId,
          action: 'cancelled',
          timestamp: now,
          remark: reason || '取消巡检',
        }),
      },
      { new: true }
    ).populate(INSPECTION_POPULATE);
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
  // 缺省值刻意取 none（拒绝）而不是 all：所有现有调用方都会显式传范围，
  // 于是 all 这个默认值今天不产生任何好处，只会在**将来某个调用方漏传**时
  // 静默把全组织统计端出去——漏传的后果必须是零结果，不可能是"看得更多"。
  // （同族的另两处：AlarmService.getAlarmStats 与 DeviceService.getDeviceStats，
  //  已在轮 7 一并按同判据收口。）
  async getInspectionStats(startDate, endDate, dataScope = { type: 'none' }) {
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

    // inspection 的 ownerField 是 assignedTo（ObjectId 数组），self 范围下条件里
    // 是 JWT 带来的 hex 字符串：aggregate 不 cast、countDocuments cast，
    // 不归一化就会出现 total>0 而三个分项维度全空（详见 utils/scopeCast）。
    const scopedMatch = castScopeObjectIds(matchStage);
    const baseMatch = { $match: scopedMatch };

    const [byStatus, byType, byResult, total] = await Promise.all([
      Inspection.aggregate(
        [baseMatch, { $group: { _id: '$status', count: { $sum: 1 } } }],
        listAggregateOptions()
      ),
      Inspection.aggregate(
        [baseMatch, { $group: { _id: '$inspectionType', count: { $sum: 1 } } }],
        listAggregateOptions()
      ),
      Inspection.aggregate(
        [
          { $match: { ...scopedMatch, status: 'completed' } },
          { $group: { _id: '$result', count: { $sum: 1 } } },
        ],
        listAggregateOptions()
      ),
      Inspection.countDocuments(scopedMatch, listCountOptions()),
    ]);

    return { total, byStatus, byType, byResult };
  }
}

module.exports = new InspectionService();
