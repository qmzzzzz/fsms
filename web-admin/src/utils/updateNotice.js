/**
 * 「有新版本」提示的共享状态
 *
 * 两个来源会置位它，语义相同、处置相同：
 *   1. Service Worker 报 onNeedRefresh（前端资源本身有新版）；
 *   2. GET /api/version 的 buildId 与本页构建标识不一致（服务端已换版）。
 *
 * 为什么抽成独立模块而不是塞进组件：注册 SW 的那段代码在 main.js（必须顶层执行），
 * 而提示条在组件树里。两者若各自持有一份 ref，就会出现「SW 说该刷新、界面没反应」
 * 或反过来的哑火。这里同时承载「谁来执行刷新」——SW 的 updateSW(true) 需要先激活
 * 等待中的 SW 再 reload，直接 location.reload() 可能又拿回旧缓存。
 */

import { ref } from 'vue'

/** 是否有待生效的新版本 */
export const updateAvailable = ref(false)

/** 首次置位的原因：'service-worker' | 'version'（仅用于文案/排障，不影响行为） */
export const updateReason = ref('')

/** 真正执行「应用更新」的函数，由 main.js 在注册 SW 后注入 */
let applier = null

export function setUpdateApplier(fn) {
  applier = typeof fn === 'function' ? fn : null
}

/**
 * 标记有新版本。
 *
 * 幂等：只保留**第一次**的原因。若允许覆盖，SW 与版本轮询交替置位会让
 * updateReason 反复跳动，而界面文案并不需要区分到这种程度。
 */
export function markUpdateAvailable(reason) {
  if (updateAvailable.value) return
  updateReason.value = typeof reason === 'string' ? reason : ''
  updateAvailable.value = true
}

/** 仅供测试与「登出后重置」使用 */
export function resetUpdateNotice() {
  updateAvailable.value = false
  updateReason.value = ''
}

/**
 * 应用更新：优先走 SW 的激活路径，没有可用 applier 时退回普通 reload。
 *
 * applier 抛错必须仍能刷新——否则用户点了按钮、界面毫无反应，
 * 而这时页面其实已经处于「新旧混合」状态，比刷一下更危险。
 */
export async function applyUpdate() {
  if (applier) {
    try {
      await applier()
      return
    } catch (_) {
      // 落到下面的兜底 reload
    }
  }
  if (typeof location !== 'undefined' && typeof location.reload === 'function') {
    location.reload()
  }
}
