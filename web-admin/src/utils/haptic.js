// 移动端触觉反馈：关键动作给一次轻震动，提升操作确认感。
// 仅在支持 Vibration API 的触屏设备上生效；桌面/不支持的环境静默跳过。
// 注意：iOS Safari 不支持 Vibration API，天然静默降级，无需额外判断平台。

export function haptic(pattern = 10) {
  if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
    try {
      navigator.vibrate(pattern)
    } catch (_) {
      // 个别浏览器在权限受限场景会抛错，静默忽略
    }
  }
}

export default haptic
