/**
 * 设备业务服务层
 * 封装设备相关的核心业务逻辑，控制器仅负责请求解析和响应格式化
 */

const FireDevice = require('../models/FireDevice');
const {
  deviceAlertFilters,
  normalizeExpiringDays,
  EXPIRING_LIST_LIMIT,
} = require('../constants/deviceAlerts');
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');
const logger = require('../utils/logger');
const { withListBudget, listCountOptions, listAggregateOptions } = require('../utils/queryBudget');
const { escapeRegExp, uniqueIdStrings } = require('../utils/helpers');
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
const { DEVICE_STATUS } = require('../utils/constants');
const { withTransaction } = require('../utils/transaction');

const VALID_STATUSES = Object.values(DEVICE_STATUS);

class DeviceService {
  /**
   * 获取设备列表（含数据范围过滤和分页）
   *
   * E-2：支持游标分页。传入 cursor 时按 deviceCode 升序做 keyset seek，
   * 跳过 countDocuments，以 hasMore/nextCursor 表达翻页；
   * 不传 cursor 保持原 page/limit 行为。
   */
  async getDevices({
    page,
    limit,
    cursor,
    deviceType,
    status,
    building,
    floor,
    search,
    dataScope,
  }) {
    const query = {};
    if (deviceType) query.deviceType = deviceType;
    if (status) query.status = status;
    if (building) query['location.building'] = building;
    if (floor) query['location.floor'] = floor;

    // 数据范围过滤：统一走 applyDataScopeToQuery（内部对同字段冲突用 $and 取交集，
    // 且 department 为空时按 deny 处理，不再落入「三分支全不命中→零过滤」）
    // 属主字段取自 DATA_SCOPE_FIELDS 单一声明（P2-20），与详情/统计/导出同口径
    // 同 AlarmService：范围不可用即 403，不回空集（#12）
    applyDataScopeToQuery(query, dataScope, DATA_SCOPE_FIELDS.device);

    if (search) {
      const escaped = escapeRegExp(search);
      // 合并而非赋值：device 的属主声明是数组
      // （createdBy ∪ maintenanceRecord.operator，见 constants/dataScopeFields.js），
      // self 范围下 applyDataScopeToQuery 已把 $or 用作数据范围条件，
      // 直接 `query.$or = [...]` 会把范围条件整条替换掉 ⇒ 越权可见全组织设备。
      // 判据与实现统一收在 utils/scopeCast.js（报警/巡检同族，三处共用一个合并器）。
      applySearchCondition(query, {
        $or: [{ deviceName: new RegExp(escaped, 'i') }, { deviceCode: new RegExp(escaped, 'i') }],
      });
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      const cursorQuery = applyCursorCondition(query, {
        sortField: 'deviceCode',
        sortDir: 1,
        cursor: decoded,
        valueType: 'string',
      });
      const docs = await withListBudget(FireDevice.find(cursorQuery))
        // 这里**不加** `_id` 次级排序键：排序键 deviceCode 是模型 `unique:true` 的
        // 全仓唯一等值不可能重复的键，平局裁决无对象可裁（其余三个列表的排序键是时间，
        // 同一毫秒多条是常态 ⇒ 必须带 `_id`，见 AlarmService/InspectionService/auditQueryService）
        .sort({ deviceCode: 1 })
        .limit(limit + 1);
      const { items, hasMore, nextCursor } = buildCursorResult(docs, limit, 'deviceCode');
      return { devices: items, count: null, hasMore, nextCursor };
    }

    const [devices, count] = await Promise.all([
      withListBudget(FireDevice.find(query))
        .sort({ deviceCode: 1 })
        .limit(limit)
        .skip((page - 1) * limit),
      FireDevice.countDocuments(query, listCountOptions()),
    ]);

    // offset 模式同样下发 nextCursor：客户端可在任意页切换为游标续翻
    const hasNext = page * limit < count;
    const last = devices[devices.length - 1];
    const nextCursor =
      hasNext && last ? encodeCursor({ v: last.deviceCode, id: String(last._id) }) : null;

    return { devices, count, nextCursor };
  }

  /**
   * 根据 ID 获取设备
   */
  async getDeviceById(id) {
    return FireDevice.findById(id);
  }

  /**
   * 只取"数据范围判定要用的字段"的批量查询（供写路径的对象级范围闸使用）
   *
   * 存在理由同 `userService.findScopeFieldsByIds`：alarm/inspection 的写路径要按 id
   * 反查设备做 `assertRecordInScope`，而 controllers 层直连 model 违反分层纪律。
   * 投影含属主两臂（createdBy / maintenanceRecord.operator）+ 部门臂（location.building）。
   * @returns {Promise<Array>} 命中的设备（顺序不保证；调用方按 _id 计数判存在性）
   */
  async findScopeFieldsByIds(ids) {
    const list = uniqueIdStrings(ids);
    if (list.length === 0) return [];
    return FireDevice.find({ _id: { $in: list } })
      .select('createdBy maintenanceRecord.operator location.building')
      .lean();
  }

  /**
   * 创建设备
   */
  async createDevice(fields, createdBy) {
    const device = await FireDevice.create({ ...fields, createdBy });
    logger.info(`消防设备已创建：${device.deviceCode}`);
    return device;
  }

  /**
   * 更新设备信息
   *
   * P2-16：status 从可更新白名单中移除。原实现允许通过通用更新接口直写
   * status='scrapped'，绕过模型层的 transitionTo 迁移表——结果是
   * status 已报废、而 lifecycleStage/scrapDate/scrapReason 全为空，
   * 产生「业务上已报废、生命周期上仍在用」的自相矛盾状态，
   * 且 pre-save 的报废守卫（不再生成检查计划）也不会命中。
   * 状态变更统一走 updateDeviceStatus / scrapDevice。
   */
  async updateDevice(device, updates) {
    // P3-14：installDate 补进白名单——update 路由校验了 ISO8601 格式却
    // 不在可更新列表，合法值被静默丢弃（校验存在暗示可更新，行为必须兑现）
    // deviceType 同理：update 路由 :105 有 `body('deviceType').optional().isIn(...)`，
    // 而前端 DeviceView.vue 的 submitForm 是新建/编辑共用、总会带上 deviceType，
    // 于是"改设备类型"点了保存、看到成功提示，库里却没变——同一类假成功。
    // 注意 deviceCode 的类型前缀（模型 :177 DEVICE_TYPE_PREFIX）不随类型改写：
    // 编码是对外标识与既有单据的引用键，改类型不该让历史标识漂移。
    const updatableFields = [
      'deviceName',
      'deviceType',
      'model',
      'manufacturer',
      'location',
      'installDate',
      'expiryDate',
      'checkCycle',
      'remark',
    ];
    updatableFields.forEach((field) => {
      if (field === 'location') return;
      if (updates[field] !== undefined) device[field] = updates[field];
    });
    // location 按子字段**合并**，不整对象替换。整对象替换的后果：
    // `{location:{floor:'3F'}}` 是能过更新路由校验的合法请求（location 只声明
    // `.optional().isObject()`，子字段各自 optional），却会把 location.building 一起抹掉。
    // 而 building 正是设备的部门数据范围键（DATA_SCOPE_FIELDS.device.departmentField）
    // ⇒ 一次"只改楼层"的编辑让设备从所有按楼栋授权的人的列表/统计/导出里消失，接口还回 200；
    // 表单不维护的 location.coordinates 同理会丢——前端当时用 _locationBase 回传整块
    // location 替服务端兜这个坑，说明该由服务端把它填上（现在前端已不再回传兜底）。
    // 语义收成一句：你发哪个键，就只改哪个键；没发的键保持原值。
    // **空串是这条链上唯一的"清空"指令**：`undefined` 经 JSON.stringify 后键整个消失，
    // 服务端收到的就是"没提这个字段"。所以清空 ⇒ 发 ''，与 PUT /api/auth/profile
    // 的空值分档同一口径（见 tests/routes/profileFieldClearability.test.js）。
    // 顶层 building/floor/room 也在这里兑现：更新路由校验了它们（deviceRoutes.js:142-147）
    // 却没人消费，属 P3-14 明令禁止的「校验存在暗示可更新」；归一方向与创建路径一致
    // （deviceController 的 createDevice 同样是顶层垫底、嵌套值优先）。
    const locationPatch = {};
    for (const part of ['building', 'floor', 'room', 'detail']) {
      if (updates[part] !== undefined) locationPatch[part] = updates[part];
    }
    if (updates.location && typeof updates.location === 'object') {
      // 嵌套键同样把 undefined 当作"未提及"：HTTP 请求经 JSON 后本就没有这种键，
      // 放过它等于让服务内调用方（直接构造对象）多一种"看起来会清空"的写法。
      for (const [key, value] of Object.entries(updates.location)) {
        if (value !== undefined) locationPatch[key] = value;
      }
    }
    if (Object.keys(locationPatch).length > 0) {
      const current =
        device.location && typeof device.location.toObject === 'function'
          ? device.location.toObject()
          : device.location || {};
      device.location = { ...current, ...locationPatch };
    }
    // 显式拒绝而非静默忽略：静默忽略会让调用方以为状态已改（报告 P3-14 同类问题）
    if (updates.status !== undefined && updates.status !== device.status) {
      throw ApiError.badRequest('设备状态不能通过本接口修改，请使用状态变更或报废接口');
    }
    await device.save();
    logger.info(`设备信息已更新：${device.deviceCode}`);
    return device;
  }

  /**
   * 更新设备状态
   *
   * P2-16：status 与 lifecycleStage 是两套并行状态，必须同步推进。
   * - 报废是终态且需要 scrapDate/scrapReason，不允许从本接口进入（改走 scrapDevice）
   * - 已报废设备不接受任何状态变更（报废即生命周期终点）
   * - maintenance 状态需要同步推进 lifecycleStage，否则两套状态永久分叉
   */
  async updateDeviceStatus(device, status) {
    if (!VALID_STATUSES.includes(status)) {
      throw ApiError.badRequest('无效的状态值');
    }
    if (device.status === 'scrapped' || device.lifecycleStage === 'scrapped') {
      throw ApiError.badRequest('设备已报废，不能再变更状态');
    }
    if (status === 'scrapped') {
      throw ApiError.badRequest('报废操作请使用设备报废接口（需提供报废原因）');
    }

    device.status = status;

    // 与生命周期对齐：进入/退出维护态时同步迁移 lifecycleStage。
    // transitionTo 会校验迁移合法性，非法迁移（如 installed → in_use 之外）抛错，
    // 此处只在迁移表允许时推进，避免正常的状态标记被生命周期规则阻断。
    const LIFECYCLE_TRANSITIONS = {
      maintenance: 'maintenance',
      normal: 'in_use',
    };
    const targetStage = LIFECYCLE_TRANSITIONS[status];
    if (targetStage && device.lifecycleStage !== targetStage) {
      try {
        // transitionTo 内部会 save()，无需重复保存
        await device.transitionTo(targetStage);
        logger.info(
          `设备状态已更新：${device.deviceCode} -> ${status}（生命周期 -> ${targetStage}）`
        );
        return device;
      } catch (err) {
        // 只吞"迁移表不允许"这一种（如 installed → maintenance）：业务上的故障标记
        // 不该被生命周期规则阻断，记录告警供运维核对。
        // 其余错误必须原样抛出——此前这里无差别 catch，把并发版本冲突与真实 DB 故障
        // 都降级成一条 warn，然后继续 save() 把设备写回旧世界。
        if (!err.transitionIllegal) throw err;
        logger.warn(
          `设备 ${device.deviceCode} 生命周期迁移跳过（${device.lifecycleStage} → ${targetStage}）：${err.message}`
        );
      }
    }

    await device.save();
    logger.info(`设备状态已更新：${device.deviceCode} -> ${status}`);
    return device;
  }

  /**
   * 添加维护记录
   *
   * P2-16：报废守卫此前只写在模型实例方法 addMaintenanceRecord 里，
   * 而该方法从未被调用（Service 直接 push 数组），守卫形同虚设——
   * 已报废设备可继续添加维护记录，还会被算出一个「未来的下次检查日期」。
   * 此处改为委托模型方法，让守卫与检查周期推进规则成为唯一实现。
   */
  async addMaintenanceRecord(device, content, operatorId, type = 'routine') {
    if (device.status === 'scrapped' || device.lifecycleStage === 'scrapped') {
      throw ApiError.badRequest('设备已报废，不能再添加维护记录');
    }
    // 委托模型方法：内含报废守卫 + 「仅检查类记录推进检查周期」的业务规则
    await device.addMaintenanceRecord({ content, operator: operatorId, type });
    logger.info(`设备维护记录已添加：${device.deviceCode}`);
    return device;
  }

  /**
   * 删除设备（清理关联引用）
   *
   * B-1：四步跨集合写（报警引用清理 → 巡检引用清理×2 → 设备删除）经
   * withTransaction 包裹——副本集环境任一步失败整体回滚，不再残留
   * 「引用已清但设备还在」或「设备已删但引用悬空」的幽灵数据；
   * standalone（开发/测试）自动降级为原顺序执行
   */
  async deleteDevice(device) {
    await withTransaction(async (session) => {
      const opts = session ? { session } : {};
      // 清理报警记录中的 deviceId 引用
      await FireAlarm.updateMany({ deviceId: device._id }, { $unset: { deviceId: 1 } }, opts);
      // 清理巡检记录中的设备引用
      await Inspection.updateMany(
        { devices: device._id },
        { $pull: { devices: device._id } },
        opts
      );
      await Inspection.updateMany(
        { 'findings.deviceId': device._id },
        { $unset: { 'findings.$[elem].deviceId': 1 } },
        { arrayFilters: [{ 'elem.deviceId': device._id }], ...opts }
      );
      await FireDevice.findByIdAndDelete(device._id, opts);
    });
    logger.info(`设备已删除：${device.deviceCode}`);
  }

  /**
   * 设备报废
   *
   * P2-16：委托模型的 transitionTo 状态机，复用其前置状态校验。
   * 原实现直写 status/lifecycleStage/scrapDate，导致已报废设备可被重复报废
   * 并覆盖原始报废日期（审计上等于篡改报废时间）。
   * 迁移表允许 installed/in_use/maintenance/retired → scrapped，
   * scrapped → scrapped 会抛错，天然挡住重复报废。
   */
  async scrapDevice(device, reason, scrapDate) {
    if (device.status === 'scrapped' || device.lifecycleStage === 'scrapped') {
      throw ApiError.badRequest('设备已报废，不能重复报废');
    }

    // B-2：补录日期必须在任何写入之前校验——原实现先报废落库再校验日期，
    // 非法日期返回 400 时设备其实已被报废（响应说失败、状态却变了）
    let parsedScrapDate = null;
    if (scrapDate) {
      parsedScrapDate = new Date(scrapDate);
      if (Number.isNaN(parsedScrapDate.getTime())) {
        throw ApiError.badRequest('报废日期格式无效');
      }
    }

    device.status = 'scrapped';
    // 只把"未提交"当成默认值：路由的 scrapReason 校验是
    // mustBeString + optional().trim().isLength({max:200})，**没有 notEmpty**，
    // 所以 `{"scrapReason": ""}` 是合法的 200 写入。用 `||` 会把它和缺省折叠成
    // 同一句肯定性结论"正常报废"（= 到寿正常处置），而操作者实际声明的是"未填原因"——
    // 台账里凭空多出一条没人说过的合规判定。`??` 只兜 undefined/null。
    device.scrapReason = reason ?? '正常报废';
    try {
      // 单次原子写入：transitionTo 设置 lifecycleStage + scrapDate（补录值优先）并 save，
      // 消除「先迁移后补录」两步写中途失败留下的矛盾记录
      await device.transitionTo('scrapped', { scrapDate: parsedScrapDate });
    } catch (err) {
      // 只有"迁移表不允许"（已 scrapped → scrapped，即重复报废）才翻译成本接口的业务文案；
      // 版本冲突交给 errorHandler 统一映射，真实 DB 故障保持 500——
      // 原实现把两类都包成 400「报废失败：<原文>」，等于把内部错误文本回给客户端。
      if (!err.transitionIllegal) throw err;
      throw ApiError.badRequest(`报废失败：${err.message}`);
    }

    logger.info(`设备已报废：${device.deviceCode}`);
    return device;
  }

  /**
   * 获取设备统计（应用数据范围过滤，口径与列表/详情一致）
   *
   * 两处收口：
   *  1. 漏传即 deny：原缺省 `scopeFilter = {}` 与 type:'all' 返回的 `{}` 无法区分，
   *     于是任何漏传都静默变成"全组织设备统计"。改为无默认值：undefined → 零结果；
   *     真正的 all 由调用方显式传 `{}`（buildDataScopeFilter 对 all 就是返回 `{}`）。
   *  2. 聚合前归一化 ObjectId：device 的 ownerField 是数组
   *     ['createdBy','maintenanceRecord.operator'] ⇒ self 范围产出
   *     `{$or:[{createdBy:'<hex 字符串>'},...]}`。countDocuments 会 cast、
   *     aggregate 不会 ⇒ total>0 而 byType/byStatus 全空。
   */
  async getDeviceStats(scopeFilter) {
    if (!scopeFilter) {
      return {
        total: 0,
        byType: [],
        byStatus: [],
        needMaintenance: 0,
        needSchedule: 0,
        expiringSoon: 0,
        expired: 0,
        expiryUnknown: 0,
      };
    }
    const scoped = castScopeObjectIds(scopeFilter);
    // 判定时刻只取一次：跨秒抖动会让"同一响应里的两个档"用两个now
    const now = new Date();
    const alert = deviceAlertFilters(now);
    const [
      byType,
      byStatus,
      needMaintenance,
      needSchedule,
      expiringSoon,
      expired,
      expiryUnknown,
      total,
    ] = await Promise.all([
      FireDevice.aggregate(
        [
          { $match: scoped },
          { $group: { _id: '$deviceType', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ],
        listAggregateOptions()
      ),
      FireDevice.aggregate(
        [
          { $match: scoped },
          { $group: { _id: '$status', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ],
        listAggregateOptions()
      ),
      FireDevice.countDocuments({ ...scoped, ...alert.needMaintenance }, listCountOptions()),
      // 从未录入过检查日的设备没有排期，$lte 判据永远不命中它——
      // 单列一档而不是并入 needMaintenance，是为了不改变既有指标的含义
      FireDevice.countDocuments({ ...scoped, ...alert.needSchedule }, listCountOptions()),
      FireDevice.countDocuments({ ...scoped, ...alert.expiringSoon }, listCountOptions()),
      FireDevice.countDocuments({ ...scoped, ...alert.expired }, listCountOptions()),
      FireDevice.countDocuments({ ...scoped, ...alert.expiryUnknown }, listCountOptions()),
      FireDevice.countDocuments(scoped, listCountOptions()),
    ]);

    return {
      total,
      byType,
      byStatus,
      needMaintenance,
      needSchedule,
      expiringSoon,
      expired,
      expiryUnknown,
    };
  }

  /**
   * 获取即将到期设备清单（可选带回全集规模）
   * @param {number} days 到期窗口天数
   * @param {Object} scopeFilter 数据范围过滤（H-1：与列表/统计同口径，防止越权枚举全组织设备）
   * @param {Object} [options]
   * @param {boolean} [options.withTotal] 为真时返回 `{devices,total}`；缺省仍返回数组本身
   * @param {number} [options.limit] 覆盖单次返回上限（缺省 EXPIRING_LIST_LIMIT）
   *
   * 缺省即 deny：
   * 原 `scopeFilter = {}` 把"漏传范围"表达成"匹配全表"，而这个接口的返回体是
   * **设备清单本身**（不是计数），漏一次参数就等于把全组织到期设备连编码带位置整表端走。
   * 显式传 `{}` 仍是 all（buildDataScopeFilter 对 type:'all' 就返回 `{}`），
   * 所以窄化只作用于"根本没传"这一种情形，不改变任何现有调用方的行为
   * （唯一 HTTP 调用方 deviceController.getExpiringDevices 总是显式传）。
   *
   * 为什么 total 与清单必须长在同一段代码里（F-174）：
   * 清单按 `.limit(EXPIRING_LIST_LIMIT)` 截断，而"被截断"这一事实如果只体现在
   * `data.length` 上就等于没说——库里 50 台与 512 台的响应完全同形，安全员却会照着
   * 屏幕上这份清单去排巡检、备耗材。所以计数与清单共用同一次过滤器构造、同一个判定
   * 时刻、同一次并发执行：拆成两个方法各算一遍时，两处 `new Date()` 跨秒或两处判据
   * 日后各自漂移，就会出现"被数进去却没列出来"（或反过来）——一个自相矛盾的数比缺
   * 一个数更难排查。钉住：src/tests/controllers/deviceExpiringTruncation.test.js
   */
  async getExpiringDevices(days = 30, scopeFilter, options = {}) {
    const { withTotal = false, limit = EXPIRING_LIST_LIMIT } = options;
    if (!scopeFilter) return withTotal ? { devices: [], total: 0 } : [];
    const filter = {
      ...scopeFilter,
      ...deviceAlertFilters(new Date(), normalizeExpiringDays(days)).expiringSoon,
    };
    const query = withListBudget(FireDevice.find(filter))
      .select('deviceCode deviceName deviceType location expiryDate status')
      .sort({ expiryDate: 1 })
      .limit(limit);
    if (!withTotal) return query;
    const [devices, total] = await Promise.all([
      withListBudget(query),
      FireDevice.countDocuments(filter, listCountOptions()),
    ]);
    return { devices, total };
  }
}

module.exports = new DeviceService();
