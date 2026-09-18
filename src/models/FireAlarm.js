/**
 * 火警报警模型
 * 记录和处理火警报警事件
 */

const mongoose = require('mongoose');
const autoIncrement = require('../plugins/autoIncrement');

const fireAlarmSchema = new mongoose.Schema(
  {
    // 报警基本信息
    alarmCode: {
      type: String,
      // L-08：与 FireDevice.deviceCode 口径对齐，补 required。
      // 编号由 plugins/autoIncrement.js 的 pre('save')/pre('validate') 生成，
      // 而 insertMany 不触发文档中间件——当前唯一写入点是 .create()（会触发钩子），
      // 故非现存缺陷；但 unique 索引把缺失值视作 null，一旦未来新增批量导入路径
      // 就会以 E11000 形式暴露。补 required 使失败形态变为显式校验错误。
      required: [true, '报警编号不能为空'],
      unique: true,
    },
    alarmType: {
      type: String,
      enum: [
        'smoke', // 烟雾报警
        'temp_abnormal', // 温度异常
        'manual_button', // 手动按钮
        'phone_report', // 电话报警
        'patrol_find', // 巡检发现
        'other', // 其他
      ],
      required: true,
    },

    // 报警级别
    level: {
      type: String,
      enum: ['info', 'warning', 'critical', 'emergency'],
      default: 'warning',
    },

    // 报警位置
    location: {
      building: { type: String, maxlength: [100, '楼栋最多 100 个字符'] },
      floor: { type: String, maxlength: [50, '楼层最多 50 个字符'] },
      room: { type: String, maxlength: [100, '房间最多 100 个字符'] },
      coordinates: {
        lat: Number,
        lng: Number,
      },
    },

    // 报警内容
    description: {
      type: String,
      required: true,
      maxlength: [500, '报警描述最多 500 个字符'],
    },
    deviceId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'FireDevice',
    },

    // 处理流程
    status: {
      type: String,
      enum: ['pending', 'processing', 'resolved', 'false_alarm', 'cancelled'],
      default: 'pending',
    },
    reporter: {
      name: { type: String, maxlength: [50, '上报人姓名最多 50 个字符'] },
      phone: { type: String, maxlength: [20, '上报人电话最多 20 个字符'] },
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    },
    handler: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },

    // 时间记录
    occurredAt: {
      type: Date,
      default: Date.now,
    },
    receivedAt: {
      type: Date,
      default: Date.now,
    },
    dispatchedAt: {
      type: Date,
    },
    arrivedAt: {
      type: Date,
    },
    resolvedAt: {
      type: Date,
    },

    // 处理结果
    handleResult: {
      type: String,
      maxlength: [1000, '处理结果最多 1000 个字符'],
    },
    cause: {
      type: String,
      enum: ['fire', 'false_alarm', 'equipment_fault', 'test', 'unknown'],
    },

    // 处理过程记录
    processLog: [
      {
        time: {
          type: Date,
          default: Date.now,
        },
        action: String,
        operator: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
        },
        remark: String,
      },
    ],
  },
  {
    timestamps: true,
  }
);

// 自动生成报警编号（使用 autoIncrement 插件，基于 counters 原子计数器）
fireAlarmSchema.plugin(autoIncrement, {
  field: 'alarmCode',
  counterPrefix: 'alarm',
  seqPadding: 4,
  generatePrefix: () => {
    const d = new Date();
    return `ALM${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  },
});

// 索引优化
fireAlarmSchema.index({ occurredAt: -1 });
fireAlarmSchema.index({ status: 1, occurredAt: -1 });
fireAlarmSchema.index({ handler: 1, occurredAt: -1 });
fireAlarmSchema.index({ 'reporter.userId': 1, occurredAt: -1 });
fireAlarmSchema.index({ 'location.building': 1, occurredAt: -1 });
fireAlarmSchema.index({ level: 1 });
fireAlarmSchema.index({ alarmType: 1, occurredAt: -1 });
// L-22：设备删除级联（DeviceService.deleteDevice）按 deviceId 反查并 $unset 引用。
// 此前无索引覆盖 → COLLSCAN。12 万告警规模实测：扫 12 万文档 / 204.54ms，
// 补此索引后扫 30 文档 / 1.07ms（191.2x，见 deliverables/性能实测基线-2026-09-16.json）。
fireAlarmSchema.index({ deviceId: 1 });

module.exports = mongoose.model('FireAlarm', fireAlarmSchema);
