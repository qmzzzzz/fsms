/**
 * 鼠标追踪径向渐变背景
 *
 * 在目标元素上监听 pointermove，将指针相对中心的位置写入 CSS 变量 --posX/--posY，
 * 配合 background-image 中的 radial-gradient + calc() 实现「光斑跟随鼠标」。
 *
 * 仅对精确指针（鼠标/触控板）启用；触屏设备无持续指针位置概念，跳过监听。
 * 注意：不做 prefers-reduced-motion 降级——指针位置跟随是「直接操作映射」，
 * 不是动画（无自动播放、无持续运动），reduced-motion 语义不覆盖它。
 * 全程走 CSS 变量，不直接操作样式；getBoundingClientRect 的强制布局读取
 * 只发生在「指针进入 / 窗口 resize / 首次移动兜底」时，pointermove 只读缓存。
 *
 * @param {Ref<HTMLElement>} targetRef 需要追踪指针的元素
 */
import { onMounted, onUnmounted } from 'vue'
// matchMedia 安全包装收口 utils/motion（WF-14）
import { safeMatchMedia } from '@/utils/motion'

export function usePointerGradient(targetRef) {
  let bound = null
  // getBoundingClientRect 每次调用都会强制布局，pointermove 是高频事件，
  // 不能每帧都读。rect 缓存后 move 回调只做算术；尺寸/位置变化由
  // pointerenter（重新悬停）与 window resize 触发重测覆盖绝大多数场景。
  let rect = null
  const measure = () => {
    rect = bound ? bound.getBoundingClientRect() : null
  }

  const onPointerEnter = () => measure()

  const onResize = () => {
    if (bound) measure()
  }

  const onPointerMove = (e) => {
    const el = bound
    if (!el) return
    // 兜底：未经历 pointerenter 的首次移动（如指针已在元素内时才绑定）也拿得到 rect
    if (!rect) measure()
    const x = e.clientX - rect.left - rect.width / 2
    const y = e.clientY - rect.top - rect.height / 2
    el.style.setProperty('--posX', x.toFixed(0))
    el.style.setProperty('--posY', y.toFixed(0))
  }

  onMounted(() => {
    if (!safeMatchMedia('(pointer: fine)').matches) return
    bound = targetRef.value
    if (!bound) return
    bound.addEventListener('pointerenter', onPointerEnter, { passive: true })
    bound.addEventListener('pointermove', onPointerMove, { passive: true })
    window.addEventListener('resize', onResize, { passive: true })
  })

  onUnmounted(() => {
    if (!bound) return
    bound.removeEventListener('pointerenter', onPointerEnter)
    bound.removeEventListener('pointermove', onPointerMove)
    window.removeEventListener('resize', onResize)
    bound = null
    rect = null
  })
}
