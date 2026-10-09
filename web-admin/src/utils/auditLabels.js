/**
 * 审计字段 → 界面文案 的单一映射（O-3 单一事实来源）
 *
 * 原实现内联在 AuditLogView.vue 的 <script setup> 里，属该视图私有。
 * 「我的操作日志」自助面（MyLogsCard）渲染的是**同一份** AuditLog 记录，
 * 若各自维护一份映射，后端新增一个 action 枚举时两处会漂移——一边显示
 * 中文动作名、另一边显示原始 code，而审计文案的漂移只有肉眼能发现。
 * 故提取为纯函数：调用方只负责传入自己的 `t`（vue-i18n 的 t 与 locale 绑定，
 * 不能在此模块顶层 import，否则切语言后不会重算）。
 *
 * 判据与 AuditLogView 原实现逐字一致：
 *  - action 无对应文案时**回退展示原始动作名**（便于识别后端新增枚举），
 *    而不是回退成裸键 `audit.action.xxx`；
 *  - category 无对应文案时回退原始分类名，再退 '-'.
 */

/** 操作类型标签：audit.action.* 文案组与后端 AUDIT_LOG_ACTIONS 枚举一一对应 */
export const actionLabel = (t, action) => {
  if (!action) return '-'
  const key = `audit.action.${action}`
  const label = t(key)
  // 无对应文案时回退展示原始动作名，便于识别新增的枚举值
  return label === key ? action : label
}

/** 分类标签：auditLog.short* 文案组 */
export const categoryLabel = (t, category) => {
  const labels = {
    auth: t('auditLog.shortAuth'),
    user: t('auditLog.shortUser'),
    role: t('auditLog.shortRole'),
    permission: t('auditLog.shortPermission'),
    device: t('auditLog.shortDevice'),
    alarm: t('auditLog.shortAlarm'),
    inspection: t('auditLog.shortInspection'),
    security: t('auditLog.catSecurity'),
    report: t('auditLog.catReport'),
    system: t('auditLog.shortSystem'),
  }
  return labels[category] || category || '-'
}
