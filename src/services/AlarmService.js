/**
 * 报警业务服务层
 * 封装报警相关的核心业务逻辑
 */

const FireAlarm = require('../models/FireAlarm');
const logger = require('../utils/logger');
const { escapeRegExp, parseDateBoundary } = require('../utils/helpers');
// 短别名：长名单调用点会超 printWidth 被 prettier 折行，而本文件 max-lines 贴基线
const {
  withListBudget,
  listCountOptions: cntOpts,
  listAggregateOptions: aggOpts,
} = require('../utils/queryBudget');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
const { applyDataScopeToQuery } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const { castScopeObjectIds, applySearchCondition } = require('../utils/scopeCast');
const ApiError = require('../utils/ApiError');

/**
 * 报警**读出**投影（列表两条分支 + 详情共用同一个常量，防止只修一条）。
 *
 * `reporter.phone` 只接受写入、任何读接口都不回传：它是明文存库的第三方手机号
 * （不走 models/User.js 那套 getter 加密），而列表/详情原本没有根文档投影，于是
 * 任何持 `alarm:read` 且落在该条范围内的账号都能整页批量读到它——没有二次验证、
 * 没有 `system:read`、也不写 `view_sensitive_data` 审计，把仓里专为手机号建的合规
 * 通道（POST /api/security/view-sensitive：reauthLimiter + requireReAuthentication +
 * 层级闸）整个架空。同一 model 上的 `handler.phone` 正因同样理由被收窄过
 * （见 tests/services/alarmDetailHandlerPii.test.js）。
 * 全仓消费方实测为零：web-admin 无 reporterPhone/reporter.phone、报表导出只取
 * reporter.name（reportExportService.js:266）、e2e 无引用，故停发不损失任何界面功能。
 * 写回显是唯一例外，且是有意的：`POST /api/alarms/report` 把 create 出来的文档原样回给
 * 提交者，而那个号码正是提交者自己刚写进去的（不构成新的读取）；五个处置接口
 * （dispatch/arrive/resolve/false-alarm/cancel）回的是 updated 文档，所以 projection
 * 必须写进 options——只修列表与详情，同一列就从这五个口漏出去。
 *
 * 如实声明残留缺口：值仍**明文存在库里**（备份转储/密钥轮换的保护缺口不随本改动关闭）。
 * 将来若真要开放"回拨上报人"，正确做法是给它一条与 User PII 同级的揭示通道，
 * 而不是把这一列加回读接口。
 */
const ALARM_READ_SELECT = '-reporter.phone';

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
      // 必须走 applySearchCondition 而不是直接 query.$or = [...]：
      // alarm 的属主声明是数组（reporter.userId ∪ handler），self 范围下
      // applyDataScopeToQuery 已经把 $or 用作范围条件，直接赋值会把它整条覆盖，
      // 等于「带 search 的报警列表不做数据范围过滤」。详见 utils/scopeCast.js。
      applySearchCondition(query, {
        $or: [
          { alarmCode: new RegExp(escaped, 'i') },
          { description: new RegExp(escaped, 'i') },
          { 'location.building': new RegExp(escaped, 'i') },
        ],
      });
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      const cursorQuery = applyCursorCondition(query, {
        sortField: 'occurredAt',
        sortDir: -1,
        cursor: decoded,
        valueType: 'date',
      });
      const docs = await withListBudget(FireAlarm.find(cursorQuery))
        .select(ALARM_READ_SELECT)
        .populate({ path: 'deviceId', select: 'deviceCode deviceName' })
        .populate({ path: 'handler', select: 'username realName' })
        // 次级排序键 `_id` 不是整洁性偏好，而是与续翻子句绑定的方向约束：
        // 条件是 `{occurredAt:v,_id:{$lt:id}}`，而单字段索引的隐式平局序是 _id **升序**，
        // 两者方向相反 ⇒ 等值块（同一毫秒多条）跨页漂移，块内大部分记录永久不可达。
        // 对应的同向复合索引见 models/FireAlarm.js。
        .sort({ occurredAt: -1, _id: -1 })
        .limit(limit + 1);
      const { items, hasMore, nextCursor } = buildCursorResult(docs, limit, 'occurredAt');
      return { alarms: items, count: null, hasMore, nextCursor };
    }

    const [alarms, count] = await Promise.all([
      withListBudget(FireAlarm.find(query))
        .select(ALARM_READ_SELECT)
        .populate({ path: 'deviceId', select: 'deviceCode deviceName' })
        .populate({ path: 'handler', select: 'username realName' })
        // 与上面游标分支同一个排序：offset 页的末条要拿去 mint nextCursor，
        // 方向不一致就会把游标发到等值块中间
        .sort({ occurredAt: -1, _id: -1 })
        .limit(limit)
        .skip((page - 1) * limit),
      FireAlarm.countDocuments(query, cntOpts()),
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
    return (
      FireAlarm.findById(id)
        .select(ALARM_READ_SELECT)
        .populate({ path: 'deviceId', select: 'deviceCode deviceName deviceType' })
        // 与上面两条列表分支同口径：handler 只取 username/realName。
        // 此处原多带一个 `phone`，而 User.phone 的 getter 会把密文解成明文
        // （models/User.js:99），于是 GET /api/alarms/:id 把处置人的完整手机号
        // 直接回给任何持 `alarm:read` 且在该条范围内的账号——没有二次验证、没有
        // `system:read`、也没有 view_sensitive_data 审计。那条合规通道
        // （POST /api/security/view-sensitive）专门挂了 reauthLimiter +
        // requireReAuthentication，被这个多出来的 select 架空了。
        // 前端无 handler.phone 消费者（web-admin 全文 0 处），故收窄即行为对齐，
        // 不损失任何界面功能。
        .populate({ path: 'handler', select: 'username realName' })
        .populate({ path: 'processLog.operator', select: 'username realName' })
    );
  }

  /**
   * 只取"数据范围判定要用的字段"的批量查询（供写路径的对象级范围闸使用）
   *
   * 存在理由同 `DeviceService.findScopeFieldsByIds`：`POST /api/security/report` 的记录型
   * 目标要按 id 反查报警再做 `assertRecordInScope`，而 controllers 层直连 model 违反分层
   * 纪律（判据见 tests/architecture/layeringRatchet）。
   * 投影逐字对齐 DATA_SCOPE_FIELDS.alarm 的三条臂（上报人 / 处置人 / 楼栋）：少投影一列，
   * 命中那一臂的记录就会被判成越权——假 deny 只表现为"报不了"，日志里却写着越权，
   * 比漏判更难发现。新增属主臂时必须同时改这里与那份单一声明。
   * 不用 `getAlarmById`：它带三次 populate（设备/处置人/操作日志），既多打 DB 往返，
   * 又把 handler 变成 populate 后的对象，范围判定的取值口径随之改变。
   */
  async findScopeFieldsByIds(ids) {
    const list = [...new Set((ids || []).map((id) => String(id)))];
    if (list.length === 0) return [];
    return FireAlarm.find({ _id: { $in: list } })
      .select('reporter.userId handler location.building')
      .lean();
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

    // P2-17 数据范围矩阵（2026-09-21 补全）：原先只判 department 一档，
    // 于是 self 档（语义是"仅自己的数据"）可以把报警派给**任意在册用户**——
    // 连同部门都不需要，而 handler 字段正是 handleAlarm/arriveAtScene 的经办人守卫读的，
    // 等于把工单塞进别人的清单。none 档与"调用方根本没传 dataScope"同样曾经放行。
    // 现在每个档位都要有明确判定，认不出来的档位（含 none 与将来新增的档位）一律拒绝：
    // 默认放行会让"新增一种 scope"变成静默的全量授权。
    const { dataScope } = options;
    if (!dataScope || !dataScope.type) {
      throw ApiError.forbidden('缺少数据范围上下文，无法判定可指派人员范围');
    }
    switch (dataScope.type) {
      case 'all':
        break; // 超管/安全总监：不限部门
      case 'department':
        if (!dataScope.department) {
          throw ApiError.forbidden('当前账户未配置部门，无法指派处理人');
        }
        if (handlerDoc.department !== dataScope.department) {
          throw ApiError.forbidden('无权将报警指派给其他部门的人员');
        }
        break;
      case 'self':
        // 只允许自己接单：self 档没有"给别人派活"的授权语义
        if (String(handler) !== String(operatorId)) {
          throw ApiError.forbidden('当前数据范围仅允许处理自己的报警，不能指派给他人');
        }
        break;
      default:
        throw ApiError.forbidden(`数据范围档位 ${dataScope.type} 不允许执行指派`);
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
      { new: true, projection: ALARM_READ_SELECT }
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
      { new: true, projection: ALARM_READ_SELECT }
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
      { new: true, projection: ALARM_READ_SELECT }
    );
    if (updated) logger.info(`报警处理完成：${updated.alarmCode}`);
    return updated;
  }

  /**
   * 标记为误报
   * M-1：已指派（processing）时仅处理人本人可标记；未指派（pending）任何同权限者可标记
   *
   * runValidators：schema 对 handleResult 声明的 maxlength 在 update 路径上默认不生效
   * （Mongoose 只对 save 跑校验），不打开这道开关，路由层一旦漏装就没有第二道闸。
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
      { new: true, runValidators: true, projection: ALARM_READ_SELECT }
    );
    if (updated) logger.info(`报警标记为误报：${updated.alarmCode}`);
    return updated;
  }

  /**
   * 取消报警
   * 评价报告 #11：补对象级授权——已指派的工单仅处理人本人可取消，
   * 未指派（pending 且无 handler）任何同数据范围者可取消。
   * 与 markAsFalseAlarm 的 M-1 口径一致，堵住「同范围者取消他人工单」路径。
   *
   * reason 的长度只由路由层（handleReasonValidation）钉住：这里不开 runValidators，
   * 因为 processLog.remark 在 schema 里本就没有上限，开了也只是自我安慰；
   * 给 remark 补上限会反过来卡住 resolveAlarm（其 remark 为「处理完成：」+ 1000 字描述）。
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
      { new: true, projection: ALARM_READ_SELECT }
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
   *
   * 两处收口：
   *  1. 缺省即 deny：原实现是 `if (dataScope && !apply(...))`，漏传 dataScope 时
   *     整个 deny 分支被短路跳过 ⇒ 统计退化为**全组织**数字，且不报错。
   *     与 InspectionService.getInspectionStats 同判据：漏传只能得到零结果。
   *  2. 聚合前归一化 ObjectId：self/department 范围产出的条件是
   *     `{'reporter.userId':'<24位hex字符串>'}`（userId 来自 JWT）。
   *     countDocuments 会 cast、aggregate 不会 ⇒ total>0 而 byStatus/byLevel/byType
   *     全空，只有非管理员用户能看到这个"说谎的看板"。
   */
  async getAlarmStats(startDate, endDate, dataScope = { type: 'none' }) {
    const matchStage = {};
    if (startDate || endDate) {
      matchStage.occurredAt = {};
      if (startDate) matchStage.occurredAt.$gte = parseDateBoundary(startDate, 'start');
      if (endDate) matchStage.occurredAt.$lte = parseDateBoundary(endDate, 'end');
    }

    const emptyStats = { total: 0, byStatus: [], byLevel: [], byType: [] };

    // 数据范围过滤（与 getAlarms 列表口径保持一致：同一函数、同一 deny 语义）
    if (!applyDataScopeToQuery(matchStage, dataScope, DATA_SCOPE_FIELDS.alarm)) {
      return emptyStats;
    }

    // 同一个条件既进聚合又进 countDocuments，必须归一化后再分发，
    // 否则两条臂对同一范围给出互相矛盾的结论（见上）。
    const scopedMatch = castScopeObjectIds(matchStage);
    const baseMatch = { $match: scopedMatch };

    const [byStatus, byLevel, byType, total] = await Promise.all([
      // 三个 group-by 同构（status/level/alarmType），map 展开成三个 Promise；
      // 各自带列表链预算（listAggregateOptions）
      ...['status', 'level', 'alarmType'].map((field) =>
        FireAlarm.aggregate(
          [baseMatch, { $group: { _id: `$${field}`, count: { $sum: 1 } } }],
          aggOpts()
        )
      ),
      FireAlarm.countDocuments(scopedMatch, cntOpts()),
    ]);

    return { total, byStatus, byLevel, byType };
  }
}

module.exports = new AlarmService();
