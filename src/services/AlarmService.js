/**
 * 报警业务服务层
 * 封装报警相关的核心业务逻辑
 */

const FireAlarm = require('../models/FireAlarm');
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

class AlarmService {
  /**
   * 获取报警列表（含数据范围过滤和分页）
   *
   * E-2：支持游标分页。传入 cursor 时按 occurredAt 倒序做 keyset seek，
   * 不做 countDocuments（报警量大时全量 count 与深分页 skip 同为瓶颈），
   * 以 hasMore/nextCursor 表达翻页；不传 cursor 保持原 page/limit 行为。
   */
  async getAlarms({
    page,
    limit,
    cursor,
    status,
    level,
    alarmType,
    startDate,
    endDate,
    search,
    dataScope,
  }) {
    const query = {};
    if (status) query.status = status;
    if (level) query.level = level;
    if (alarmType) query.alarmType = alarmType;

    if (startDate || endDate) {
      query.occurredAt = {};
      if (startDate) query.occurredAt.$gte = parseDateBoundary(startDate, 'start');
      if (endDate) query.occurredAt.$lte = parseDateBoundary(endDate, 'end');
    }

    // 数据范围过滤：统一走 applyDataScopeToQuery
    // （原先手写的三分支在 type==='department' 且 department 为空时全不命中 → 零过滤越权）
    // 属主/部门字段取自 DATA_SCOPE_FIELDS 单一声明（P2-20）
    if (!applyDataScopeToQuery(query, dataScope, DATA_SCOPE_FIELDS.alarm)) {
      return { alarms: [], count: 0, hasMore: false, nextCursor: null };
    }

    if (search) {
      const escaped = escapeRegExp(search);
      query.$or = [
        { alarmCode: new RegExp(escaped, 'i') },
        { description: new RegExp(escaped, 'i') },
        { 'location.building': new RegExp(escaped, 'i') },
      ];
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      const cursorQuery = applyCursorCondition(query, {
        sortField: 'occurredAt',
        sortDir: -1,
        cursor: decoded,
        valueType: 'date',
      });
      const docs = await FireAlarm.find(cursorQuery)
        .populate({ path: 'deviceId', select: 'deviceCode deviceName' })
        .populate({ path: 'handler', select: 'username realName' })
        .sort({ occurredAt: -1 })
        .limit(limit + 1);
      const { items, hasMore, nextCursor } = buildCursorResult(docs, limit, 'occurredAt');
      return { alarms: items, count: null, hasMore, nextCursor };
    }

    const [alarms, count] = await Promise.all([
      FireAlarm.find(query)
        .populate({ path: 'deviceId', select: 'deviceCode deviceName' })
        .populate({ path: 'handler', select: 'username realName' })
        .sort({ occurredAt: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      FireAlarm.countDocuments(query),
    ]);

    // offset 模式同样下发 nextCursor：客户端可在任意页切换为游标续翻
    const hasNext = page * limit < count;
    const last = alarms[alarms.length - 1];
    const nextCursor =
      hasNext && last ? encodeCursor({ v: last.occurredAt, id: String(last._id) }) : null;

    return { alarms, count, nextCursor };
  }

  /**
   * 根据 ID 获取报警详情
   */
  async getAlarmById(id) {
    return FireAlarm.findById(id)
      .populate({ path: 'deviceId', select: 'deviceCode deviceName deviceType' })
      .populate({ path: 'handler', select: 'username realName phone' })
      .populate({ path: 'processLog.operator', select: 'username realName' });
  }

  /**
   * 接收报警（手动上报）
   *
   * P3-15：create 与 processLog 的初始条目必须一次写入。
   * 原实现先 create 再 push+save 两步非原子，第二步失败（写冲突/连接抖动）
   * 会留下一条「没有时间线起点」的火警记录，后续处置节点无从对齐。
   */
  async reportAlarm({
    alarmType,
    level,
    location,
    description,
    deviceId,
    reporterName,
    reporterPhone,
    userId,
    username,
  }) {
    // 存储层保留原文：HTML 转义属于展示层职责，入库前转义会造成永久污染
    // （搜索关键字失配、前端二次转义导致显示乱码）
    // reporter.userId 为 ObjectId ref User，缺失时不写该字段，避免字符串 'unknown' 触发 CastError
    const reporter = { name: reporterName || username || '匿名用户', phone: reporterPhone || '' };
    if (userId) reporter.userId = userId;

    const now = new Date();
    const alarm = await FireAlarm.create({
      alarmType,
      level,
      location,
      description,
      deviceId,
      reporter,
      receivedAt: now,
      processLog: [{ time: now, action: 'alarm_received', remark: '报警已接收，等待处理' }],
    });

    logger.warn(`新火警报警：${alarm.alarmCode} - ${alarm.description}`);
    return alarm;
  }

  /**
   * 受理报警（分配处理人）
   *
   * P2-17：handlerId 必须校验「存在」与「在数据范围内」。
   * 原实现仅路由层 isMongoId() 格式校验即直写：
   * - 指派一个随机 ObjectId → handler 悬空，后续 arriveAtScene/resolveAlarm
   *   因匹配不上处理人而永久卡住工单
   * - 指派其他部门的真实用户 → 绕过数据隔离，把火警派给无权处理的人
   * @param {Object} [options] { dataScope } 传入时按数据范围校验被指派人
   */
  async dispatchAlarm(id, handlerId, operatorId, options = {}) {
    const handler = handlerId || operatorId;

    // 被指派人必须是存在且启用的账户（自派给操作者本人时同样校验，
    // 覆盖「操作者账号刚被停用但令牌未过期」的窗口）
    const User = require('../models/User');
    const handlerDoc = await User.findById(handler).select('status department username').lean();
    if (!handlerDoc) {
      throw ApiError.badRequest('指定的处理人不存在');
    }
    if (handlerDoc.status !== 'active') {
      throw ApiError.badRequest('指定的处理人账户已被禁用或锁定');
    }

    // 数据范围校验：部门级操作者不得跨部门指派
    const { dataScope } = options;
    if (dataScope && dataScope.type === 'department') {
      if (!dataScope.department) {
        throw ApiError.forbidden('当前账户未配置部门，无法指派处理人');
      }
      if (handlerDoc.department !== dataScope.department) {
        throw ApiError.forbidden('无权将报警指派给其他部门的人员');
      }
    }

    const now = new Date();
    const updated = await FireAlarm.findOneAndUpdate(
      { _id: id, status: 'pending' },
      {
        $set: { handler, status: 'processing', dispatchedAt: now },
        $push: {
          processLog: {
            time: now,
            action: 'dispatched',
            operator: operatorId,
            remark: '已指派处理人',
          },
        },
      },
      { new: true }
    );
    if (updated)
      logger.info('报警已指派', { alarmCode: updated.alarmCode, handler: handlerDoc.username });
    return updated;
  }

  /**
   * 到达现场登记（arrivedAt 为 null 或不存在才允许登记，保证幂等）
   * M-1：仅指派的处理人本人可登记，防同范围权限者冒用他人工单
   */
  async arriveAtScene(id, operatorId) {
    const now = new Date();
    const updated = await FireAlarm.findOneAndUpdate(
      { _id: id, status: 'processing', arrivedAt: null, handler: operatorId },
      {
        $set: { arrivedAt: now },
        $push: {
          processLog: { time: now, action: 'arrived', operator: operatorId, remark: '已到达现场' },
        },
      },
      { new: true }
    );
    if (updated) logger.info(`到达现场登记：${updated.alarmCode}`);
    return updated;
  }

  /**
   * 处理完成
   * M-1：仅指派的处理人本人可结单
   */
  async resolveAlarm(id, { handleResult, cause }, operatorId) {
    const now = new Date();
    const updated = await FireAlarm.findOneAndUpdate(
      { _id: id, status: 'processing', handler: operatorId },
      {
        $set: { status: 'resolved', resolvedAt: now, handleResult, cause: cause || 'unknown' },
        $push: {
          processLog: {
            time: now,
            action: 'resolved',
            operator: operatorId,
            remark: `处理完成：${handleResult}`,
          },
        },
      },
      { new: true }
    );
    if (updated) logger.info(`报警处理完成：${updated.alarmCode}`);
    return updated;
  }

  /**
   * 标记为误报
   * M-1：已指派（processing）时仅处理人本人可标记；未指派（pending）任何同权限者可标记
   */
  async markAsFalseAlarm(id, reason, operatorId) {
    const now = new Date();
    const updated = await FireAlarm.findOneAndUpdate(
      {
        _id: id,
        status: { $in: ['pending', 'processing'] },
        $or: [{ handler: operatorId }, { handler: { $exists: false } }, { handler: null }],
      },
      {
        $set: {
          status: 'false_alarm',
          resolvedAt: now,
          cause: 'false_alarm',
          handleResult: reason || '确认为误报',
        },
        $push: {
          processLog: {
            time: now,
            action: 'marked_false_alarm',
            operator: operatorId,
            remark: reason || '标记为误报',
          },
        },
      },
      { new: true }
    );
    if (updated) logger.info(`报警标记为误报：${updated.alarmCode}`);
    return updated;
  }

  /**
   * 取消报警
   * 评价报告 #11：补对象级授权——已指派的工单仅处理人本人可取消，
   * 未指派（pending 且无 handler）任何同数据范围者可取消。
   * 与 markAsFalseAlarm 的 M-1 口径一致，堵住「同范围者取消他人工单」路径。
   */
  async cancelAlarm(id, reason, operatorId) {
    const now = new Date();
    const updated = await FireAlarm.findOneAndUpdate(
      {
        _id: id,
        status: 'pending',
        $or: [{ handler: operatorId }, { handler: { $exists: false } }, { handler: null }],
      },
      {
        $set: { status: 'cancelled' },
        $push: {
          processLog: {
            time: now,
            action: 'cancelled',
            operator: operatorId,
            remark: reason || '取消报警',
          },
        },
      },
      { new: true }
    );
    if (updated) logger.info(`报警已取消：${updated.alarmCode}`);
    return updated;
  }

  /**
   * 检查报警是否存在并返回状态（用于并发冲突检测）
   */
  async getAlarmStatus(id) {
    return FireAlarm.findById(id).select('status');
  }

  /**
   * 获取报警统计（应用与 getAlarms 相同的数据范围口径）
   */
  async getAlarmStats(startDate, endDate, dataScope) {
    const matchStage = {};
    if (startDate || endDate) {
      matchStage.occurredAt = {};
      if (startDate) matchStage.occurredAt.$gte = parseDateBoundary(startDate, 'start');
      if (endDate) matchStage.occurredAt.$lte = parseDateBoundary(endDate, 'end');
    }

    const emptyStats = { total: 0, byStatus: [], byLevel: [], byType: [] };

    // 数据范围过滤（与 getAlarms 列表口径保持一致：同一函数、同一 deny 语义）
    if (dataScope && !applyDataScopeToQuery(matchStage, dataScope, DATA_SCOPE_FIELDS.alarm)) {
      return emptyStats;
    }

    const baseMatch = Object.keys(matchStage).length > 0 ? { $match: matchStage } : { $match: {} };

    const [byStatus, byLevel, byType, total] = await Promise.all([
      FireAlarm.aggregate([baseMatch, { $group: { _id: '$status', count: { $sum: 1 } } }]),
      FireAlarm.aggregate([baseMatch, { $group: { _id: '$level', count: { $sum: 1 } } }]),
      FireAlarm.aggregate([baseMatch, { $group: { _id: '$alarmType', count: { $sum: 1 } } }]),
      FireAlarm.countDocuments(matchStage),
    ]);

    return { total, byStatus, byLevel, byType };
  }
}

module.exports = new AlarmService();
