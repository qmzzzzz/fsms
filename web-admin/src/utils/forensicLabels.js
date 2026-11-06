/**
 * 取证溯源字段 → 界面文案。
 *
 * 与 utils/auditLabels.actionLabel 同构：无对应文案时回退原始码，不回退成裸 i18n 键。
 * 触发原因是 markForensicTarget 写入的机器码（honeypot_chain 等），而 ForensicCapture
 * 把整份 trigger 对象原样落库；旧界面直接渲染 row.trigger，客户看到的是整段 JSON。
 */

/** 从 trigger（字符串或 { reason, markedAt } 对象）取原因码 */
export const triggerCodeOf = (trigger) => {
  if (!trigger) return ''
  if (typeof trigger === 'string') return trigger
  return String(trigger.reason || '')
}

/** 原因码 → 文案：未知码如实带出，不吞成笼统文案 */
export const triggerReasonLabel = (t, reason) => {
  if (!reason) return '-'
  const key = `forensic.triggerReason.${reason}`
  const label = t(key)
  return label === key ? reason : label
}
