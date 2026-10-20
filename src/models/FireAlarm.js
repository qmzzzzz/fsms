/**
 * 火警报警模型
 * 记录和处理火警报警事件
 */

const mongoose = require('mongoose');
const autoIncrement = require('../plugins/autoIncrement');
const { ALARM_LEVELS, ALARM_TYPES, ALARM_STATUSES, ALARM_CAUSES } = require('../constants/alarm');
const { businessDateParts } = require('../constants/timezone');
// P1（2026-10-16）：reporter.phone at-rest 加密，与 User.phone 同轨
// （读侧 getter 解密 / 写侧 pre('validate') 加密 / v2 AAD 行绑定），
// 判据收口在 utils/piiCrypto.js。加密范围**只覆盖 phone**：reporter.name 是
// 上报人自填的称呼，与 User.realName 的取舍同理（见 utils/piiCrypto.js 头注释）。
const { encryptPii, decryptPii } = require('../utils/piiCrypto');

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
      // P1（2026-10-16）at-rest 加密：原先这里是明文 `{ type: String, maxlength: 20 }`，
      // 值原样落库——拿到备份转储 / DB 文件的人可直读第三方上报人手机号，与
      // 「字段级加密存储」的需求字面要求不符（读侧收窄只挡住接口，挡不住 at-rest）。
      // 现在与 User.phone 同轨：写侧 pre('validate') 钩子加密、读侧 getter 解密。
      //
      // 长度上限**必须从 schema 摘掉**（与 User.phone 的取舍同一理由）：validate 阶段
      // 看到的是 `enc.v2.<iv>.<ct>` 密文（实测 >100 字符），schema 级 maxlength:20 会把
      // 每一行都判非法；20 字符的判据前移到钩子的明文阶段，文案与路由逐字一致。
      //
      // 仍然**任何读接口都不回传**（投影见 services/AlarmService.js 的 ALARM_READ_SELECT）：
      // 加密解决的是 at-rest，不解决"持 alarm:read 的人整页批量读"——那需要一条与
      // User PII 同级的揭示通道（reauth + system:read 层级闸 + view_sensitive_data 审计），
      // 仓里目前没有，故读侧投影保持不变。getter 只在**裸查询/迁移脚本**这类
      // 已越过应用层鉴权的路径上生效（与 User.phone 的 getter 定位一致）。
      //
      // v2 AAD 行绑定需要**父文档**身份（pii:v2:<alarmId>:reporter.phone）：reporter 是
      // 嵌套路径，getter 的 this 指向嵌套 Document，须经 $parent() 上溯到报警文档
      // 取 _id——用嵌套 Document 自己的 _id 会绑定到错误主体（该嵌套对象无 _id，
      // 实测为 undefined ⇒ 退化成无绑定，跨行搬运又成立）。取不到父文档时传 null，
      // 让 decryptPii 的形态校验按 fail-closed 抛错，而不是静默回吐密文。
      phone: {
        type: String,
        get: function (value) {
          const parent = this && typeof this.$parent === 'function' ? this.$parent() : null;
          const subjectId =
            parent && parent._id !== undefined && parent._id !== null ? String(parent._id) : null;
          return decryptPii(value, subjectId ? { subjectId, field: 'reporter.phone' } : null);
        },
      },
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

// P1（2026-10-16）：reporter.phone 写入侧收口（加密 + 明文期长度校验）。
//
// 与 models/User.js 的 PII_ENCRYPTED_FIELDS 同形（同一套 piiCrypto 判据、同一种
// 「只在被修改时动作」纪律）：未修改的行重复 save 不重加密——随机 IV 下重加密会
// 无谓改写密文，让 updatedAt 漂移、审计上出现"没有变更的变更"。
//
// 长度校验为什么在钩子里而不在 schema：validate 阶段看到的是密文（>100 字符），
// schema 级 maxlength:20 会把每一行都判非法（该字段的 schema maxlength 已摘掉）。
//
// 这里**刻意不加** `/^1[3-9]\d{9}$/` 这类移动号码正则（与 User.phone 不同）：
// reporter.phone 是**第三方联系人**电话，路由合同为「≤20 字符自由文本」
// （alarmRoutes.js:68-71 只校验 isLength max 20），现场固话/带分机的号码是合法输入；
// 套用移动号码正则会把这些既有合法值判成非法，属于借加密之名收紧业务合同。
// 本轮只做与路由同口径的长度收口，格式收紧需业务方先确认口径（见交付报告待确认项）。
const REPORTER_PII_FIELDS = [{ path: 'reporter.phone', max: [20, '上报人电话最多 20 个字符'] }];

fireAlarmSchema.pre('validate', function (next) {
  try {
    for (const { path, max } of REPORTER_PII_FIELDS) {
      if (!this.isModified(path)) continue;
      // get() 经字段 getter：赋值期的明文与存量密文都解回明文（透传口径）
      const value = this.get(path);
      if (value) {
        // 长度判据在加密前（明文阶段），文案与明文时代逐字一致
        if (value.length > max[0]) {
          this.invalidate(path, max[1], value);
          continue; // 非法值不加密：失败路径不留任何写入
        }
      }
      // v2：加密必须绑定**父文档** _id（AAD = pii:v2:<alarmId>:reporter.phone）。
      // _id 缺失时拒绝加密而不是落到无绑定密文上——无绑定密文与 v1 同样可跨行搬运。
      if (!this._id) {
        throw new Error(`PII v2 加密需要文档 _id 作 AAD 绑定（字段 ${path}，_id 缺失即拒绝写入）`);
      }
      this.set(
        path,
        value ? encryptPii(value, { subjectId: String(this._id), field: path }) : value
      );
    }
    next();
  } catch (error) {
    next(error);
  }
});

// P1（2026-10-16）：与 models/User.js:251-257 同一条接线不变量——PII 的明文只在
// getter 里（存储侧是密文），而 Mongoose 的 toObject/toJSON **默认不套字段 getter**。
// 不开这两项，res.json / toObject 走到的地方（报警写回显 POST /api/alarms/report
// 把 create 出的文档原样回给提交者、以及任何 toJSON 序列化）都会把 `enc.v2.…`
// 密文当成"电话号码"输出——实测：`doc.reporter.phone` 是明文、`toJSON()` 是密文。
// 迁移到哪条新序列化路径都要带着这两行走。
fireAlarmSchema.set('toJSON', { getters: true });
fireAlarmSchema.set('toObject', { getters: true });

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
// 补此索引后扫 30 文档 / 1.07ms（191.2x，2026-09-16 实测）。
fireAlarmSchema.index({ deviceId: 1 });

// 业务数据保留期（F-07，2026-10-17）：声明与开关分离——口径在
// constants/businessRetention.js（declaredDays=180），开关是
// BUSINESS_RETENTION_DAYS_FIRE_ALARM。**未配置时不建 TTL**（数据永久保留），
// 配置了且通过四道闸才建；TTL 字段取 occurredAt（事件时间）而不是 createdAt，
// 否则"补录的历史报警"会在入库 180 天后被删，而它的事件时间可能更早。
const { resolveTtlIndexPlan } = require('../constants/businessRetention');
const fireAlarmTtl = resolveTtlIndexPlan('FireAlarm');
if (fireAlarmTtl.days !== null) {
  fireAlarmSchema.index(
    { occurredAt: 1 },
    { expireAfterSeconds: fireAlarmTtl.days * 24 * 60 * 60, name: 'ttl_occurredAt' }
  );
}

module.exports = mongoose.model('FireAlarm', fireAlarmSchema);
