/**
 * 系统常量与枚举集中管理
 * 所有业务状态码、类型枚举、默认值统一在此定义，避免散落硬编码
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

// 报警状态
const ALARM_STATUS = Object.freeze({
  PENDING: 'pending',
  PROCESSING: 'processing',
  RESOLVED: 'resolved',
  FALSE_ALARM: 'false_alarm',
  CANCELLED: 'cancelled',
});

// 报警级别
const ALARM_LEVEL = Object.freeze({
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

// 巡检状态
const INSPECTION_STATUS = Object.freeze({
  PENDING: 'pending',
  IN_PROGRESS: 'in_progress',
  COMPLETED: 'completed',
  CANCELLED: 'cancelled',
});

// 巡检结果
const INSPECTION_RESULT = Object.freeze({
  NORMAL: 'normal',
  ABNORMAL: 'abnormal',
});

// 审核结果
const REVIEW_RESULT = Object.freeze({
  APPROVED: 'approved',
  REJECTED: 'rejected',
});

// 用户状态
const USER_STATUS = Object.freeze({
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  LOCKED: 'locked',
});

// 审计日志风险等级
const RISK_LEVEL = Object.freeze({
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

// 审计日志分类
const AUDIT_CATEGORY = Object.freeze({
  AUTH: 'auth',
  USER: 'user',
  ROLE: 'role',
  PERMISSION: 'permission',
  DEVICE: 'device',
  ALARM: 'alarm',
  INSPECTION: 'inspection',
  REPORT: 'report',
  SECURITY: 'security',
  SYSTEM: 'system',
});

// 数据范围类型
const DATA_SCOPE = Object.freeze({
  ALL: 'all',
  DEPARTMENT: 'department',
  SELF: 'self',
  NONE: 'none',
});

// 分页默认值
const PAGINATION = Object.freeze({
  DEFAULT_PAGE: 1,
  DEFAULT_LIMIT: 10,
  MAX_LIMIT: 500,
  MAX_PAGE: 10000,
});

// HTTP 状态码
const HTTP_STATUS = Object.freeze({
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_ERROR: 500,
});

module.exports = {
  DEVICE_STATUS,
  DEVICE_TYPE,
  DEVICE_TYPE_PREFIX,
  ALARM_STATUS,
  ALARM_LEVEL,
  INSPECTION_STATUS,
  INSPECTION_RESULT,
  REVIEW_RESULT,
  USER_STATUS,
  RISK_LEVEL,
  AUDIT_CATEGORY,
  DATA_SCOPE,
  PAGINATION,
  HTTP_STATUS,
};
