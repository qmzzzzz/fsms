/**
 * 巡检记录模型
 * 管理消防巡检计划和执行记录
 */

const mongoose = require('mongoose');
// 巡检域取值全集的单一事实来源（F-149 起 severity，F-150 起类型/状态/结果/审核结论）。
// 本 schema 的 enum 与巡检路由的 .isIn()、docs/generate.js 的 OpenAPI 枚举必须同源：
// 两处各写一份字面量时，单侧增删就会出现"路由放行、模型 enum 拒"或反向的
// "路由拦了一个模型其实允许的取值"，两边说的都不是同一句话，排查时先怀疑对方。
const {
  INSPECTION_FINDING_SEVERITIES,
  INSPECTION_TYPES,
  INSPECTION_STATUSES,
  INSPECTION_RESULTS,
  INSPECTION_REVIEW_RESULTS,
} = require('../constants/inspection');

const inspectionSchema = new mongoose.Schema(
  {
    // 巡检计划/任务信息
    inspectionType: {
      type: String,
      enum: INSPECTION_TYPES,
      required: true,
    },
    title: {
      type: String,
      required: true,
      maxlength: [200, '巡检标题最多 200 个字符'],
    },
    // P3-14 的白名单补齐要求这两条真正落库：路由（inspectionRoutes）校验、控制器透传、
    // 服务白名单都带了 description/priority，但 schema 从未声明 → strict 模式在 save 时
    // 静默丢弃，PUT 返回 200 而字段消失（同 executionLog.remark 的历史坑，见文件下方）。
    description: {
      type: String,
      trim: true,
      maxlength: [500, '描述最多 500 个字符'],
    },
    priority: {
      type: String,
      maxlength: [20, '优先级最多 20 个字符'],
    },

    // 巡检范围
    devices: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'FireDevice',
      },
    ],
    locations: [
      {
        building: { type: String, maxlength: [100, '楼栋最多 100 个字符'] },
        floor: { type: String, maxlength: [100, '楼层最多 100 个字符'] },
        area: { type: String, maxlength: [100, '区域最多 100 个字符'] },
      },
    ],

    // 检查项目
    checkItems: [
      {
        name: { type: String, maxlength: [100, '检查项目名称最多 100 个字符'] },
        standard: { type: String, maxlength: [200, '检查标准最多 200 个字符'] },
        required: {
          type: Boolean,
          default: true,
        },
      },
    ],

    // 人员安排
    assignedTo: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],

    // 时间计划
    planStartTime: {
      type: Date,
    },
    planEndTime: {
      type: Date,
    },
    actualStartTime: {
      type: Date,
    },
    actualEndTime: {
      type: Date,
    },

    // 状态
    status: {
      type: String,
      enum: INSPECTION_STATUSES,
      default: 'pending',
    },

    // 巡检结果
    result: {
      type: String,
      enum: INSPECTION_RESULTS,
    },
    remark: {
      type: String,
      maxlength: [500, '备注最多 500 个字符'],
    },
    findings: [
      {
        deviceId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'FireDevice',
        },
        issue: { type: String, maxlength: [500, '问题描述最多 500 个字符'] },
        severity: {
          type: String,
          enum: INSPECTION_FINDING_SEVERITIES,
        },
        photo: { type: String, maxlength: [500, '照片地址最多 500 个字符'] },
        suggestion: { type: String, maxlength: [500, '整改建议最多 500 个字符'] },
      },
    ],

    // 审核
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    reviewedAt: {
      type: Date,
    },
    reviewComment: {
      type: String,
      maxlength: [500, '审核意见最多 500 个字符'],
    },
    // 审核结论：approved=通过 / rejected=不通过
    reviewResult: {
      type: String,
      enum: INSPECTION_REVIEW_RESULTS,
    },

    // 执行人记录
    executionLog: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
        },
        action: String,
        timestamp: Date,
        // location 支持两种形态：GPS 结构 {lat,lng} 或文本描述 {text}
        // （前端完成表单提交的是地点文字，直接灌 lat/lng 结构会 CastError）
        location: {
          lat: Number,
          lng: Number,
          text: String,
        },
        // 备注（如取消原因）：此前写入未声明的 remark 字段被 strict 模式静默剥离
        remark: {
          type: String,
          maxlength: 500,
        },
      },
    ],
    // 留痕总条数。executionLog 有尾部封顶（InspectionService.pushExecutionLog），
    // 于是 `executionLogCount > executionLog.length` 就是"有留痕被截断"这一事实的载体——
    // 截断必须可数，不能靠数组长度假装"这就是全部历史"。
    executionLogCount: { type: Number, default: 0, min: 0 },
  },
  {
    timestamps: true,
  }
);

// 索引优化
inspectionSchema.index({ status: 1, planStartTime: -1 });
// 巡检列表游标分页排序 `{ planStartTime: -1, _id: -1 }`（排序键可重复 ⇒ 必须有同向
// 复合索引，否则退化成全表扫描 + 阻塞排序）。原单字段索引被最左前缀整体取代 ⇒ 替换而非新增。
// 带 status 等值筛选的那条走 `{status:1,planStartTime:-1}` 后再做一次子集内排序：
// 正确性优先——旧口径下等值块跨页会漏记录，"快但丢数据"不是可接受的取舍。
inspectionSchema.index({ planStartTime: -1, _id: -1 });
inspectionSchema.index({ assignedTo: 1 });
inspectionSchema.index({ 'locations.building': 1 });

// L-22：设备删除级联（DeviceService.deleteDevice）的两条 updateMany——
// 一条按 devices 数组元素 $pull，一条按 findings.deviceId 数组元素 $unset。
// 此前两者均无索引覆盖 → COLLSCAN。6 万巡检规模实测：
//   { devices: id }        60,000 文档 / 139.44ms → 30 文档 / 1.37ms（101.8x）
//   { 'findings.deviceId': id } 60,000 文档 / 155.47ms → 15 文档 / 1.21ms（128.5x）
// 明细见 deliverables/性能实测基线-2026-09-16.json。
inspectionSchema.index({ devices: 1 });
inspectionSchema.index({ 'findings.deviceId': 1 });

module.exports = mongoose.model('Inspection', inspectionSchema);
