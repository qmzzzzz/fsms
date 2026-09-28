/**
 * 消防设备模型
 * 管理消防设施设备全生命周期
 * 支持安装、维护、检查、报废等环节
 */

const mongoose = require('mongoose');
const autoIncrement = require('../plugins/autoIncrement');
// E-05 整改：设备类型与编号前缀此前在本文件各维护一份（与 utils/constants.js
// 的同名声明三处并存）。现统一引用 constants 的单一事实来源，避免新增设备
// 类型时漏改其中一处导致「校验通过但编号前缀取默认 OT」。
const { DEVICE_TYPE, DEVICE_TYPE_PREFIX } = require('../utils/constants');
const { businessDateParts } = require('../constants/timezone');
const DEVICE_TYPE_VALUES = Object.values(DEVICE_TYPE);

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
      // E-05：枚举值引用 utils/constants.js 的 DEVICE_TYPE（单一事实来源）。
      enum: DEVICE_TYPE_VALUES,
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

    // maintenanceRecord 的留痕总条数（截断可数的载体，见文件末尾 pushCapped 的说明）。
    // 只给 maintenanceRecord 配这一个计数：它是唯一有生产写入方的那支数组
    // （POST /api/devices/:id/maintenance → DeviceService.addMaintenanceRecord）；
    // inspectionRecord 的写入方法当前零调用方，对它计数就是给不存在的写入编台账。
    maintenanceRecordCount: { type: Number, default: 0, min: 0 },

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
    // 本模型的三条写路径都是"读快照 → 改内存 → save()"，而 save() 的 filter 默认只有
    // _id ⇒ 后写者无条件覆盖先写者。可观察后果有三个（都实测复现过）：
    //   · 已报废设备被另一路拿着报废前快照的请求改回在用（status 翻回非 scrapped，
    //     而提醒/报表的排除集只看 status ⇒ 报废的灭火器重新出现在待更换五档里）；
    //   · 重复报废覆盖原始 scrapDate/scrapReason（审计上等于篡改报废时间）；
    //   · maintenanceRecordCount 的"+1"是绝对覆盖 ⇒ 计数与数组长度分叉，
    //     而"count > length"恰是数组被截断这一事实的唯一载体。
    // 开版本守卫后 save() 的 filter 带上加载时读到的 __v，冲突方抛 VersionError，
    // 由 errorHandler 统一映射为 400。这与 InspectionService 的"前态条件写"是同一口径，
    // 只是判定交给驱动而不是应用层——好处是所有 pre-save 钩子与校验器照旧生效。
    optimisticConcurrency: true,
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
//
// 年份段与报警编号同一条判据（见 models/FireAlarm.js 的同名注释）：`deviceCode` 直接
// 渲染在设备台账列表里，用服务器本地 getFullYear() 时 UTC 容器会在跨年夜把
// 业务时区已属新年的设备刻成上一年，编号与 createdAt 各行其是。
const buildDeviceCodePrefix = (doc, at) => {
  const typePrefix = DEVICE_TYPE_PREFIX[doc.deviceType] || 'OT';
  return `${typePrefix}-${businessDateParts(at).year}`;
};

fireDeviceSchema.plugin(autoIncrement, {
  field: 'deviceCode',
  counterPrefix: 'device',
  seqPadding: 4,
  generatePrefix: (doc, at) => buildDeviceCodePrefix(doc, at),
});

// 暴露给用例：编号年份段的口径必须能被钉在任意给定时刻上验证（插件内部时刻不可注入）
fireDeviceSchema.statics.buildCodePrefix = buildDeviceCodePrefix;

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

// 两支"每次操作留一条"的追加型子文档数组的尾部封顶（同 Inspection.executionLog 的口径，
// 判据也抄它的理由：这支数组不止被详情接口整段返回——
//   · DeviceService.findScopeFieldsByIds 用 select('maintenanceRecord.operator') 把它
//     读进**报警/巡检写路径的对象级范围闸**，于是一个设备的数组长度会拖慢别人的请求；
//   · reportStatsService 的报表聚合里有 $unwind: '$maintenanceRecord'（无 $limit），
//     代价随总条数线性增长；
//   · 长度无上限 ⇒ 单文档迟早越过 16MB，此后该设备**任何** save() 都失败（含报废、改状态）。
// 取"留最新 N 条 + 计数记总次数"：count > length 就是"有留痕被截断"这一事实的载体，
// 截断必须可数，不能拿数组长度假装"这就是全部历史"。
const RECORD_TAIL_CAP = 200;
const pushCapped = (list, entry) => {
  list.push(entry);
  if (list.length > RECORD_TAIL_CAP) list.splice(0, list.length - RECORD_TAIL_CAP);
};

// 实例方法：添加维护记录
// 仅检查类记录（routine=例行检查 / inspection=专项检查）推进检查周期；
// repair/replacement 属于维修行为，不代表完成了一次检查，不得顺延 lastCheckDate/nextCheckDate。
// 已报废设备拒绝一切维护记录：报废即生命周期终点，续写"未来待检日期"违背语义
fireDeviceSchema.methods.addMaintenanceRecord = function (record) {
  if (this.status === 'scrapped' || this.lifecycleStage === 'scrapped') {
    return Promise.reject(new Error('设备已报废，不能再添加维护记录'));
  }
  pushCapped(this.maintenanceRecord, {
    date: new Date(),
    ...record,
  });
  this.maintenanceRecordCount += 1;
  if (record.type === 'routine' || record.type === 'inspection') {
    this.lastCheckDate = new Date();
    this.nextCheckDate = new Date(Date.now() + this.checkCycle * 24 * 60 * 60 * 1000);
  }
  return this.save();
};

// 实例方法：添加检查记录（当前无生产调用方；封顶是为了"接上调用方时不必再回来补"）
fireDeviceSchema.methods.addInspectionRecord = function (record) {
  pushCapped(this.inspectionRecord, {
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
  // 与 DeviceService.scrapDevice 同口径：空串是"提交了但没填"，不是"未提交"，
  // 不能被 `||` 折成一句没人说过的肯定性结论"正常报废"。
  this.scrapReason = reason ?? '正常报废';
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
    // 给调用方一个**类型判据**而不是靠文案匹配：DeviceService 的 catch 只应吞这一种
    // 错误（非法迁移降级为"仅改 status"），并发版本冲突必须原样抛出去。
    err.transitionIllegal = true;
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
