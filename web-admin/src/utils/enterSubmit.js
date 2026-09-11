/**
 * 回车提交守卫：过滤输入法组词确认时按下的 Enter
 *
 * 之所以用 keydown 而非项目其他页面惯用的 keyup.enter：
 * - 姓名部门为中文输入字段，keyup 在组词确认（compositionend）后仍会带
 *   key='Enter' 触发，导致"输入拼音按回车上屏"被误判为提交
 * - keydown 在 Chrome/Firefox 组词期间 key 报 'Process'，.enter 修饰符天然不匹配；
 *   Safari 报 'Enter' 但 isComposing=true，由本守卫显式排除
 *
 * 模板侧配合 .prevent：拦截原生隐式提交——单输入框表单（MFA 三处）在
 * 无 submit 按钮时按 Enter 会触发原生 form 提交导致整页刷新丢失输入
 *
 * 自 ProfileView 抽出（D-2）：ProfileView / MfaSettingsCard /
 * ChangePasswordCard 三处共用同一判据
 */
export const enterSubmit = (e, fn) => {
  if (e && (e.isComposing || e.keyCode === 229)) return
  fn()
}
