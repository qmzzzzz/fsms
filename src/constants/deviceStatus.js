/**
 * 设备状态「清单视图」的单一来源（值仍来自 utils/constants.js 的 DEVICE_STATUS）
 *
 * 本文件不声明任何新值，只把两处「从 DEVICE_STATUS 算出来的东西」各算一次：
 *   - DEVICE_STATUS_VALUES：全集（Object.values 的结果）。此前 deviceRoutes 的列表
 *     query 校验、update 校验、DeviceService.VALID_STATUSES、文档生成器四处各写一遍；
 *   - DEVICE_STATUS_WRITABLE：PUT /api/devices/{id}/status 的可写子集。
 *
 * 第二样才是本文件存在的理由。它此前是**两份手抄的 5 值清单**（deviceRoutes.js 的
 * updateDeviceStatusValidation、docs/generate.js 的 requestBody enum），抄的是
 * 「全集减去 scrapped」这条规则的**结果**而不是规则本身。后果与 constants/alarm.js
 * 记录的那一族完全同形：给 DEVICE_STATUS 追加第 7 档，模型存得进去，通用状态接口却
 * 400 拒掉新档，而对外文档仍在推荐旧的五档——两份副本还会各自漂，因为它们之间
 * 没有任何东西要求它们相等（文档不是运行时，没人对账就永不红）。
 * 现在加一档只改 DEVICE_STATUS，两个出口跟着动；要再多排除一档，改这一行 filter。
 *
 * scrapped 被排除是设计而非遗漏（P2-16）：报废需要 scrapReason 并推进 lifecycleStage，
 * 只能走 POST /api/devices/{id}/scrap；放行到通用状态接口会绕过 transitionTo 状态机，
 * 造出「status=scrapped 但 lifecycleStage=in_use」的矛盾状态（提醒与报表按 status 排除，
 * 生命周期却仍在推进）。排除的理由集中写在这里，不再依赖两处行注释各说一遍。
 */

const { DEVICE_STATUS } = require('../utils/constants');

// 全部合法状态（顺序即 DEVICE_STATUS 的声明顺序，文档与下拉按此序展示）
const DEVICE_STATUS_VALUES = Object.values(DEVICE_STATUS);

// 通用状态接口可写的子集 = 全集 - scrapped（报废走专门的 /scrap 接口）
const DEVICE_STATUS_WRITABLE = DEVICE_STATUS_VALUES.filter((s) => s !== DEVICE_STATUS.SCRAPPED);

module.exports = { DEVICE_STATUS_VALUES, DEVICE_STATUS_WRITABLE };
