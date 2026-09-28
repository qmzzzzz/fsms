/**
 * 系统常量与枚举集中管理
 *
 * 这里只放**事实来源就是本文件**的枚举（设备类型/前缀/状态、用户状态——模型侧的
 * enum 由本文件提供，见 models/FireDevice.js 的 E-05 整改）。
 *
 * 曾经还有 10 个"看起来像集中管理"的枚举（ALARM_STATUS / ALARM_LEVEL /
 * INSPECTION_STATUS / INSPECTION_RESULT / REVIEW_RESULT / RISK_LEVEL /
 * AUDIT_CATEGORY / DATA_SCOPE / PAGINATION / HTTP_STATUS），它们零引用，
 * 且已经和模型侧的真实枚举漂移：
 *   - ALARM_LEVEL 声明 low/medium/high/critical，而 models/FireAlarm.js 的
 *     level 是 info/warning/critical/emergency —— 谁按本文件做校验，
 *     会把 4 个合法值判成非法、把 4 个非法值放行；
 *   - INSPECTION_STATUS 缺 overdue，INSPECTION_RESULT 缺 partial。
 * 副本不会被同步，只会 drift；模型 schema 才是这些业务枚举的唯一事实来源，
 * 需要枚举清单时从对应 model 读（或读 src/docs/generate.js 生成的接口文档）。
 *
 * 【2026-09-25 补：别把这条判据用反】上面否定的是「零引用的伪枚举」，不是
 * 「任何 constants 文件」。区分只看一件事——**model 的 enum 指不指向它**：
 *   - 指向（如 src/constants/audit.js、permission.js、ipList.js、alarm.js）：
 *     schema enum 就是这份常量的一个消费方，全仓只有这一份值，没有副本可 drift；
 *   - 不指向（上面那 10 个）：值在 model 里，本文件再声明一份，两份必然漂。
 * 所以看到 src/constants/*.js 不要按本节历史顺手删掉：删它等于把唯一来源删掉，
 * 消费方会立刻 MODULE_NOT_FOUND。反之，新增常量文件时如果 model 不指它，
 * 就是在重建本节记录过的那类伪枚举。
 */

// 设备状态
const DEVICE_STATUS = Object.freeze({
  NORMAL: 'normal',
  WARNING: 'warning',
  FAULT: 'fault',
  OFFLINE: 'offline',
  MAINTENANCE: 'maintenance',
  SCRAPPED: 'scrapped',
});

// 设备类型
const DEVICE_TYPE = Object.freeze({
  FIRE_ALARM: 'fire_alarm',
  SPRINKLER: 'sprinkler',
  HYDRANT: 'hydrant',
  EXTINGUISHER: 'extinguisher',
  SMOKE_DETECTOR: 'smoke_detector',
  HEAT_DETECTOR: 'heat_detector',
  EMERGENCY_LIGHT: 'emergency_light',
  EVACUATION_SIGN: 'evacuation_sign',
  FIRE_DOOR: 'fire_door',
  OTHER: 'other',
});

// 设备类型 → 编号前缀映射
const DEVICE_TYPE_PREFIX = Object.freeze({
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
});

// 用户状态
const USER_STATUS = Object.freeze({
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  LOCKED: 'locked',
});

module.exports = {
  DEVICE_STATUS,
  DEVICE_TYPE,
  DEVICE_TYPE_PREFIX,
  USER_STATUS,
};
