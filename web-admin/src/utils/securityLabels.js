/**
 * 安全建议码 → 界面文案 的单一映射（i18n）
 *
 * 后端 `suggestions` 字段从**成句中文**改为**稳定码**（见
 * src/constants/securitySuggestions.js 文件头）。本模块是那份码表在前端的
 * 唯一对应处：SecurityInfoCard（我的安全信息）与将来的安全概览消费方都走这里，
 * 避免各自维护一份映射。
 *
 * 回退口径与 utils/auditLabels.js 一致：**未知码原样显示**（不是显示裸词条路径、
 * 也不是显示空白）。这样后端新增一码而前端漏翻时，用户至少能看到一个可辨识的
 * 标识串，而不是整条建议凭空消失——后者会把「漏翻」伪装成「没有建议」。
 *
 * 调用方传入自己的 `t`（vue-i18n 的 t 与 locale 绑定，不能在模块顶层 import，
 * 否则切语言后不会重算）。
 */

/** 建议码 → securitySelf.suggestion.* 词条 */
export const securitySuggestionLabel = (t, code) => {
  if (!code) return '-'
  const key = `securitySelf.suggestion.${code}`
  const label = t(key)
  // 无对应文案时回退展示原始码，便于识别后端新增的建议
  return label === key ? code : label
}

/** 批量映射（列表渲染用） */
export const securitySuggestionLabels = (t, codes) =>
  (Array.isArray(codes) ? codes : []).map((code) => securitySuggestionLabel(t, code))
