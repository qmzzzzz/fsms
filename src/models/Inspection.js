/**
 * 巡检记录模型
 * 管理消防巡检计划和执行记录
 */

const mongoose = require('mongoose');

const inspectionSchema = new mongoose.Schema(
  {
    // 巡检计划/任务信息
    inspectionType: {
      type: String,
      enum: ['daily', 'weekly', 'monthly', 'quarterly', 'annual', 'special'],
      required: true,
    },
    title: {
      type: String,
      required: true,
      maxlength: [200, '巡检标题最多 200 个字符'],
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
      enum: ['pending', 'in_progress', 'completed', 'overdue', 'cancelled'],
      default: 'pending',
    },

    // 巡检结果
    result: {
      type: String,
      enum: ['normal', 'abnormal', 'partial'],
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
          enum: ['low', 'medium', 'high', 'critical'],
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
      enum: ['approved', 'rejected'],
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
  },
  {
    timestamps: true,
  }
);

// 索引优化
inspectionSchema.index({ status: 1, planStartTime: -1 });
inspectionSchema.index({ planStartTime: -1 });
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
