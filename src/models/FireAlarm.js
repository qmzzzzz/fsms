/**
 * 火警报警模型
 * 记录和处理火警报警事件
 */

const mongoose = require('mongoose');
const autoIncrement = require('../plugins/autoIncrement');
const { ALARM_LEVELS, ALARM_TYPES, ALARM_STATUSES, ALARM_CAUSES } = require('../constants/alarm');
const { businessDateParts } = require('../constants/timezone');

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
      enum: ALARM_TYPES,
      required: true,
    },

    // 报警级别
    level: {
      type: String,
      enum: ALARM_LEVELS,
      default: 'warning',
    },

    // 报警位置
    location: {
      building: { type: String, maxlength: [100, '楼栋最多 100 个字符'] },
      floor: { type: String, maxlength: [50, '楼层最多 50 个字符'] },
      room: { type: String, maxlength: [100, '房间最多 100 个字符'] },
      // detail 与 FireDevice 同形：alarmRoutes 一直在校验它 ≤200，模型缺该子路径时
      // strict 模式会把它静默剥离——接口回 201，而"靠东侧消防箱内"这类信息永久丢失。
      detail: { type: String, maxlength: [200, '详细位置最多 200 个字符'] },
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
      enum: ALARM_STATUSES,
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
      enum: ALARM_CAUSES,
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
//
// 编号里的日期段是"人眼会读的那一日"：报警列表同一行的 occurredAt 按业务时区渲染，
// 编号若改用服务器本地 getter（getFullYear/getMonth/getDate），UTC 容器 + 东八区
// 口径下业务每天前 8 小时产生的记录会被刻成昨天——一天三分之一的记录两个日期互相矛盾，
// 而 deviceCode 是台账列表一等列、报警编号是报修与导出口头引用的键，没人会去核对时区。
// 与全站"今天"同源：只认 constants/timezone.businessDateParts（TZ_BUSINESS 可配）。
const buildAlarmCodePrefix = (at) => {
  const { year, month, day } = businessDateParts(at);
  const pad = (n) => String(n).padStart(2, '0');
  return `ALM${year}${pad(month)}${pad(day)}`;
};

fireAlarmSchema.plugin(autoIncrement, {
  field: 'alarmCode',
  counterPrefix: 'alarm',
  seqPadding: 4,
  generatePrefix: (doc, at) => buildAlarmCodePrefix(at),
});

// 暴露给用例：编号日期段的口径必须能被钉在任意给定时刻上验证（插件内部时刻不可注入）
fireAlarmSchema.statics.buildCodePrefix = buildAlarmCodePrefix;

// 索引优化
// 报警列表的游标分页按 `{ occurredAt: -1, _id: -1 }` 排序，排序键取值可重复
// （同一毫秒多条上报是常态），续翻子句用 `{occurredAt:v,_id:{$lt:id}}` 做平局裁决 ⇒
// 索引必须是**同向复合**形态，否则该排序退化成 COLLSCAN + 阻塞排序（实测 5000 条：
// examined 从 20 涨到 5000，大集合还会撞 32MB 内存排序上限而 500）。
// 原单字段 `{occurredAt:-1}` 被它整体取代：最左前缀仍覆盖"只按时间倒序"的查询与排序，
// 所以这里是**替换**而非新增——写放大只来自每条索引键多 8 字节。
fireAlarmSchema.index({ occurredAt: -1, _id: -1 });
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
