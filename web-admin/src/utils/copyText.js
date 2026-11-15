/**
 * 剪贴板复制（P3-18 收敛）：优先 async Clipboard API；
 * 非安全上下文（HTTP 联调）/权限被拒/不可用时落到隐藏 textarea + execCommand。
 * 返回 true/false 供调用方决定成功/失败提示，不自行弹 toast。
 */
export const copyText = async (text) => {
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch (_) {
    // 非安全上下文 / 权限被拒：落到 textarea 兜底
  }
  let area = null
  try {
    area = document.createElement('textarea')
    area.value = text
    area.setAttribute('readonly', '')
    area.style.position = 'fixed'
    area.style.opacity = '0'
    document.body.appendChild(area)
    area.select()
    return typeof document.execCommand === 'function' && document.execCommand('copy')
  } catch (_) {
    return false
  } finally {
    area?.remove()
  }
}
