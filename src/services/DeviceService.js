/**
 * 设备业务服务层
 * 封装设备相关的核心业务逻辑，控制器仅负责请求解析和响应格式化
 */

const FireDevice = require('../models/FireDevice');
const FireAlarm = require('../models/FireAlarm');
const Inspection = require('../models/Inspection');
const logger = require('../utils/logger');
const { escapeRegExp } = require('../utils/helpers');
const {
  encodeCursor,
  decodeCursor,
  applyCursorCondition,
  buildCursorResult,
} = require('../utils/cursorPagination');
const { applyDataScopeToQuery } = require('../middleware/rbac');
const { DATA_SCOPE_FIELDS } = require('../constants/dataScopeFields');
const ApiError = require('../utils/ApiError');
const { DEVICE_STATUS } = require('../utils/constants');

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
    if (!applyDataScopeToQuery(query, dataScope, DATA_SCOPE_FIELDS.device)) {
      return { devices: [], count: 0, hasMore: false, nextCursor: null };
    }

    if (search) {
      const escaped = escapeRegExp(search);
      query.$or = [
        { deviceName: new RegExp(escaped, 'i') },
        { deviceCode: new RegExp(escaped, 'i') },
      ];
    }

    if (cursor) {
      const decoded = decodeCursor(cursor);
      const cursorQuery = applyCursorCondition(query, {
        sortField: 'deviceCode',
        sortDir: 1,
        cursor: decoded,
        valueType: 'string',
      });
      const docs = await FireDevice.find(cursorQuery)
        .sort({ deviceCode: 1 })
        .limit(limit + 1);
      const { items, hasMore, nextCursor } = buildCursorResult(docs, limit, 'deviceCode');
      return { devices: items, count: null, hasMore, nextCursor };
    }

    const [devices, count] = await Promise.all([
      FireDevice.find(query)
        .sort({ deviceCode: 1 })
        .limit(limit)
        .skip((page - 1) * limit),
      FireDevice.countDocuments(query),
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
    const updatableFields = [
      'deviceName',
      'model',
      'manufacturer',
      'location',
      'installDate',
      'expiryDate',
      'checkCycle',
      'remark',
    ];
    updatableFields.forEach((field) => {
      if (updates[field] !== undefined) device[field] = updates[field];
    });
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
        // 迁移不被允许（如 installed → maintenance）：仅更新 status，
        // 记录告警供运维核对，不阻断业务操作
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
   */
  async deleteDevice(device) {
    // 清理报警记录中的 deviceId 引用
    await FireAlarm.updateMany({ deviceId: device._id }, { $unset: { deviceId: 1 } });
    // 清理巡检记录中的设备引用
    await Inspection.updateMany({ devices: device._id }, { $pull: { devices: device._id } });
    await Inspection.updateMany(
      { 'findings.deviceId': device._id },
      { $unset: { 'findings.$[elem].deviceId': 1 } },
      { arrayFilters: [{ 'elem.deviceId': device._id }] }
    );
    await FireDevice.findByIdAndDelete(device._id);
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

    device.status = 'scrapped';
    device.scrapReason = reason || '正常报废';
    try {
      // transitionTo 内部设置 lifecycleStage + scrapDate 并 save
      await device.transitionTo('scrapped');
    } catch (err) {
      throw ApiError.badRequest(`报废失败：${err.message}`);
    }

    // 允许业务补录历史报废日期（transitionTo 写的是当前时间）
    if (scrapDate) {
      const parsed = new Date(scrapDate);
      if (Number.isNaN(parsed.getTime())) {
        throw ApiError.badRequest('报废日期格式无效');
      }
      device.scrapDate = parsed;
      await device.save();
    }

    logger.info(`设备已报废：${device.deviceCode}`);
    return device;
  }

  /**
   * 获取设备统计（应用数据范围过滤，口径与列表/详情一致）
   */
  async getDeviceStats(scopeFilter = {}) {
    const [byType, byStatus, needMaintenance, expiringSoon, expired, total] = await Promise.all([
      FireDevice.aggregate([
        { $match: scopeFilter },
        { $group: { _id: '$deviceType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      FireDevice.aggregate([
        { $match: scopeFilter },
        { $group: { _id: '$status', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      FireDevice.countDocuments({
        ...scopeFilter,
        nextCheckDate: { $lte: new Date() },
        status: { $ne: 'maintenance' },
      }),
      FireDevice.countDocuments({
        ...scopeFilter,
        expiryDate: {
          $gte: new Date(),
          $lte: (() => {
            const d = new Date();
            d.setDate(d.getDate() + 30);
            return d;
          })(),
        },
        status: { $ne: 'scrapped' },
      }),
      FireDevice.countDocuments({
        ...scopeFilter,
        expiryDate: { $lt: new Date() },
        status: { $ne: 'scrapped' },
      }),
      FireDevice.countDocuments(scopeFilter),
    ]);

    return { total, byType, byStatus, needMaintenance, expiringSoon, expired };
  }

  /**
   * 获取即将到期设备列表
   * @param {number} days 到期窗口天数
   * @param {Object} scopeFilter 数据范围过滤（H-1：与列表/统计同口径，防止越权枚举全组织设备）
   */
  async getExpiringDevices(days = 30, scopeFilter = {}) {
    const daysNum = Math.min(365, Math.max(1, parseInt(days, 10) || 30));
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + daysNum);

    return FireDevice.find({
      ...scopeFilter,
      expiryDate: { $gte: new Date(), $lte: futureDate },
      status: { $ne: 'scrapped' },
    })
      .select('deviceCode deviceName deviceType location expiryDate status')
      .sort({ expiryDate: 1 })
      .limit(50);
  }
}

module.exports = new DeviceService();
