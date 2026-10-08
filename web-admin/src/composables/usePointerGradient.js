/**
 * 鼠标追踪径向渐变背景
 *
 * 在目标元素上监听 pointermove，将指针相对中心的位置写入 CSS 变量 --posX/--posY，
 * 配合 background-image 中的 radial-gradient + calc() 实现「光斑跟随鼠标」。
 *
 * 仅对精确指针（鼠标/触控板）启用；触屏设备无持续指针位置概念，跳过监听。
 * 注意：不做 prefers-reduced-motion 降级——指针位置跟随是「直接操作映射」，
 * 不是动画（无自动播放、无持续运动），reduced-motion 语义不覆盖它。
 * 全程走 CSS 变量，不直接操作样式，无重排开销。
 *
 * @param {Ref<HTMLElement>} targetRef 需要追踪指针的元素
 */
import { onMounted, onUnmounted } from 'vue'

const safeMatchMedia = (query) => {
  try {
    return window.matchMedia?.(query) ?? { matches: false }
  } catch (_) {
    return { matches: false }
  }
}

export function usePointerGradient(targetRef) {
  let bound = null

  const onPointerMove = (e) => {
    const el = bound
    if (!el) return
    const rect = el.getBoundingClientRect()
    const x = e.clientX - rect.left - rect.width / 2
    const y = e.clientY - rect.top - rect.height / 2
    el.style.setProperty('--posX', x.toFixed(0))
    el.style.setProperty('--posY', y.toFixed(0))
  }

  onMounted(() => {
    if (!safeMatchMedia('(pointer: fine)').matches) return
    bound = targetRef.value
    if (!bound) return
    bound.addEventListener('pointermove', onPointerMove, { passive: true })
  })

  onUnmounted(() => {
    if (!bound) return
    bound.removeEventListener('pointermove', onPointerMove)
    bound = null
  })
}
