/**
 * 动效偏好与媒体查询的单一事实来源（WF-14，2026-11-02）
 *
 * 背景：`prefers-reduced-motion` 的 JS 侧判定此前散在 3 处
 * （ScrambleText / useCountUp / store/app），且 `safeMatchMedia` 这一
 * 「matchMedia 可能缺失或被策略抛错」的安全包装在 ScrambleText 与
 * usePointerGradient 各复制了一份——同概念多份实现的既有漂移模式。
 * 收口到本模块，与 versionWatcher.isPageHidden 的「全仓统一判据」同纪律。
 *
 * 注意 CSS 侧的 `@media (prefers-reduced-motion: reduce)` 不在此列：
 * 那是样式表中的正常用法，不需要（也不应该）经由 JS 判定。
 */

/**
 * matchMedia 的安全调用：环境缺失（旧 WebView/测试 stub）或策略异常时
 * 按「不匹配」处理——动效照常，不因查询失败而中断调用方逻辑。
 * @param {string} query
 * @returns {{matches: boolean}}
 */
export const safeMatchMedia = (query) => {
  try {
    return window.matchMedia?.(query) ?? { matches: false }
  } catch (_) {
    return { matches: false }
  }
}

/** 用户是否偏好减弱动效；供所有自定义动画（scramble/计数动画/视图过渡）统一判定 */
export const prefersReducedMotion = () => safeMatchMedia('(prefers-reduced-motion: reduce)').matches
