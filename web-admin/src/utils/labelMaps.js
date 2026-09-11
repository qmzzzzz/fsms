/**
 * 报警类型 / 设备类型 / 报警状态 → i18n 标签映射（前端复审 O-1 抽取，单一事实来源）
 * 调用方传入 t（useI18n 的翻译函数），避免与 i18n 实例组织方式耦合
 */
export const makeAlarmTypeLabels = (t) => ({
  smoke: t('dashboard.smokeAlarm'),
  temp_abnormal: t('dashboard.tempAbnormal'),
  manual_button: t('dashboard.manualAlarm'),
  phone_report: t('dashboard.phoneReport'),
  patrol_find: t('dashboard.patrolFind'),
  other: t('common.all'),
})

export const makeDeviceTypeLabels = (t) => ({
  fire_alarm: t('dashboard.fireAlarm'),
  sprinkler: t('dashboard.sprinkler'),
  hydrant: t('dashboard.hydrant'),
  extinguisher: t('dashboard.extinguisher'),
  smoke_detector: t('dashboard.smokeDetector'),
  heat_detector: t('dashboard.heatDetector'),
  emergency_light: t('dashboard.emergencyLight'),
  evacuation_sign: t('dashboard.evacuationSign'),
})

export const makeAlarmStatusLabels = (t) => ({
  pending: t('alarm.pending'),
  processing: t('alarm.processing'),
  resolved: t('alarm.resolved'),
  false_alarm: t('alarm.falseAlarmTag'),
  cancelled: t('alarm.cancelled'),
})
