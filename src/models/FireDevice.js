/**
 * 消防设备模型
 * 管理消防设施设备全生命周期
 * 支持安装、维护、检查、报废等环节
 */

const mongoose = require('mongoose');
const autoIncrement = require('../plugins/autoIncrement');

// 设备类型 → 编号前缀映射
const DEVICE_TYPE_PREFIX = {
  fire_alarm: 'FA',
  sprinkler: 'SP',
  hydrant: 'HD',
  extinguisher: 'EX',
  smoke_detector: 'SD',
  heat_detector: 'TD',
  emergency_light: 'EL',
  evacuation_sign: 'ES',
  fire_door: 'FD',
  other: 'OT',
};

const fireDeviceSchema = new mongoose.Schema(
  {
    // 设备基本信息
    deviceCode: {
      type: String,
      required: [true, '设备编号不能为空'],
      unique: true,
      uppercase: true,
      trim: true,
      maxlength: [50, '设备编号最多 50 个字符'],
    },
    deviceName: {
      type: String,
      required: [true, '设备名称不能为空'],
      trim: true,
      maxlength: [100, '设备名称最多 100 个字符'],
    },
    deviceType: {
      type: String,
      enum: [
        'fire_alarm', // 火灾报警器
        'sprinkler', // 喷淋系统
        'hydrant', // 消火栓
        'extinguisher', // 灭火器
        'smoke_detector', // 烟雾探测器
        'heat_detector', // 温度探测器
        'emergency_light', // 应急灯
        'evacuation_sign', // 疏散指示牌
        'fire_door', // 防火门
        'other', // 其他
      ],
      required: [true, '设备类型不能为空'],
    },
    model: {
      type: String,
      trim: true,
      maxlength: [100, '型号最多 100 个字符'],
    },
    manufacturer: {
      type: String,
      trim: true,
      maxlength: [100, '厂商最多 100 个字符'],
    },

    // 位置信息
    location: {
      building: { type: String, maxlength: [100, '楼栋最多 100 个字符'] },
      floor: { type: String, maxlength: [100, '楼层最多 100 个字符'] },
      room: { type: String, maxlength: [100, '房间最多 100 个字符'] },
      detail: { type: String, maxlength: [200, '详细位置最多 200 个字符'] },
      coordinates: {
        lat: Number,
        lng: Number,
      },
    },

    // 状态信息
    status: {
      type: String,
      enum: ['normal', 'warning', 'fault', 'offline', 'maintenance', 'scrapped'],
      default: 'normal',
    },

    // 生命周期管理
    lifecycleStage: {
      type: String,
      enum: ['installed', 'in_use', 'maintenance', 'retired', 'scrapped'],
      default: 'installed',
    },
    installDate: {
      type: Date,
      required: [true, '安装日期不能为空'],
    },
    commissionDate: {
      type: Date, // 投入使用日期
    },
    expiryDate: {
      type: Date,
    },
    scrapDate: {
      type: Date,
    },
    scrapReason: {
      type: String,
      maxlength: [200, '报废原因最多 200 个字符'],
    },

    // 维护信息
    lastCheckDate: {
      type: Date,
    },
    nextCheckDate: {
      type: Date,
    },
    checkCycle: {
      type: Number,
      default: 30, // 默认 30 天检查周期
    },
    maintenanceRecord: [
      {
        date: Date,
        type: {
          type: String,
          enum: ['routine', 'repair', 'replacement', 'inspection'],
          default: 'routine',
        },
        content: String,
        parts: String, // 更换的配件
        cost: Number, // 维护费用
        operator: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
        },
      },
    ],

    // 检查记录
    inspectionRecord: [
      {
        date: Date,
        result: {
          type: String,
          enum: ['pass', 'fail', 'partial'],
        },
        issues: [String],
        inspector: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
        },
      },
    ],

    // QR 代码（用于设备标识）
    qrCode: {
      type: String,
    },

    // 图片
    images: [String],

    // 备注
    remark: {
      type: String,
      maxlength: [500, '备注最多 500 个字符'],
    },

    // 审计字段
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true,
  }
);

// 索引优化
fireDeviceSchema.index({ deviceType: 1, status: 1 });
fireDeviceSchema.index({ createdBy: 1 });
fireDeviceSchema.index({ 'maintenanceRecord.operator': 1 });
fireDeviceSchema.index({ 'location.building': 1, 'location.floor': 1 });
fireDeviceSchema.index({ lifecycleStage: 1, status: 1 });
fireDeviceSchema.index({ expiryDate: 1 });
fireDeviceSchema.index({ nextCheckDate: 1 });

// 自动生成设备编号（使用 autoIncrement 插件，基于 counters 原子计数器）
fireDeviceSchema.plugin(autoIncrement, {
  field: 'deviceCode',
  counterPrefix: 'device',
  seqPadding: 4,
  generatePrefix: (doc) => {
    const typePrefix = DEVICE_TYPE_PREFIX[doc.deviceType] || 'OT';
    const year = new Date().getFullYear();
    return `${typePrefix}-${year}`;
  },
});

// 自动计算下次检查日期：
// - 录入 lastCheckDate 后尚无排期时按现行公式（lastCheckDate + checkCycle）推算
// - checkCycle / lastCheckDate 变更时重算（旧排期基于旧周期或旧检查日，已失真）
// - 已报废设备（status 或 lifecycleStage 为 scrapped）不再生成新的检查计划
fireDeviceSchema.pre('save', function (next) {
  const isScrapped = this.status === 'scrapped' || this.lifecycleStage === 'scrapped';
  const scheduleDirty = this.isModified('checkCycle') || this.isModified('lastCheckDate');
  if (!isScrapped && this.lastCheckDate && (scheduleDirty || !this.nextCheckDate)) {
    this.nextCheckDate = new Date(
      this.lastCheckDate.getTime() + this.checkCycle * 24 * 60 * 60 * 1000
    );
  }
  // 自动设置投入使用日期
  if (this.lifecycleStage === 'in_use' && !this.commissionDate) {
    this.commissionDate = new Date();
  }
  next();
});

// 实例方法：添加维护记录
// 仅检查类记录（routine=例行检查 / inspection=专项检查）推进检查周期；
// repair/replacement 属于维修行为，不代表完成了一次检查，不得顺延 lastCheckDate/nextCheckDate。
// 已报废设备拒绝一切维护记录：报废即生命周期终点，续写"未来待检日期"违背语义
fireDeviceSchema.methods.addMaintenanceRecord = function (record) {
  if (this.status === 'scrapped' || this.lifecycleStage === 'scrapped') {
    return Promise.reject(new Error('设备已报废，不能再添加维护记录'));
  }
  this.maintenanceRecord.push({
    date: new Date(),
    ...record,
  });
  if (record.type === 'routine' || record.type === 'inspection') {
    this.lastCheckDate = new Date();
    this.nextCheckDate = new Date(Date.now() + this.checkCycle * 24 * 60 * 60 * 1000);
  }
  return this.save();
};

// 实例方法：添加检查记录
fireDeviceSchema.methods.addInspectionRecord = function (record) {
  this.inspectionRecord.push({
    date: new Date(),
    ...record,
  });
  return this.save();
};

// 实例方法：报废设备
// 委托 transitionTo 状态机执行迁移，复用其前置状态校验挡住重复报废：
// 迁移表允许 installed/in_use/maintenance/retired → scrapped，已报废（scrapped）再调用会抛错；
// 方法签名保持不变，既有调用方无需改动
fireDeviceSchema.methods.scrapped = function (reason) {
  this.scrapReason = reason || '正常报废';
  this.status = 'scrapped';
  return this.transitionTo('scrapped');
};

// 实例方法：设备状态转换
// B-2：overrides 允许调用方把补录字段（如历史报废日期）并入同一次原子写入——
// 此前 scrapDevice 先 transitionTo 落库再二次 save 补 scrapDate，两步之间失败
// 会留下「状态 scrapped 但报废日期矛盾」的半成品记录
// 评价报告低危项：原为同步方法 + 同步 throw——直调方（不经 DeviceService
// try/catch 的路径）会让非法迁移变成 500。改为 async 方法，throw 自动变成
// rejected Promise：await 调用方语义不变，遗漏 await 也只是 unhandled rejection
// 而非同步崩溃，且错误可被统一错误处理链按 ApiError 映射为 400。
fireDeviceSchema.methods.transitionTo = async function (stage, overrides = {}) {
  const transitions = {
    installed: ['in_use', 'scrapped'],
    in_use: ['maintenance', 'retired', 'scrapped'],
    maintenance: ['in_use', 'retired', 'scrapped'],
    retired: ['scrapped'],
    scrapped: [],
  };

  if (!transitions[this.lifecycleStage]?.includes(stage)) {
    const err = new Error(`无法从 ${this.lifecycleStage} 转换到 ${stage}`);
    err.statusCode = 400;
    throw err;
  }

  this.lifecycleStage = stage;
  if (stage === 'in_use' && !this.commissionDate) {
    this.commissionDate = new Date();
  }
  if (stage === 'scrapped') {
    this.scrapDate = overrides.scrapDate instanceof Date ? overrides.scrapDate : new Date();
  }
  return this.save();
};

module.exports = mongoose.model('FireDevice', fireDeviceSchema);
