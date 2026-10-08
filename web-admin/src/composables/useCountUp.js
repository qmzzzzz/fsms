import { ref, watch, onUnmounted } from 'vue'

// 数字滚动（count-up）：数值型统计在数据到达/刷新时，从当前显示值平滑滚动到新值。
// 设计说明：
// - 非数字值（如 '-' 占位）直接透传，不做动画。
// - 测试环境（vitest 下 import.meta.env.MODE === 'test'）与 reduced-motion 用户
//   直接呈现终值：动画是纯表现层，测试断言应读到确定性文本。
// - 源数组整体重建（语言切换）时同值跳过，不重复滚动。

const REDUCED =
  typeof window !== 'undefined' &&
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches

const SKIP_ANIMATION = import.meta.env.MODE === 'test' || REDUCED

export function useCountUp(statsRef, { duration = 600 } = {}) {
  const display = ref(statsRef.value.map((item) => item.value))
  const rafs = []

  watch(
    statsRef,
    (next) => {
      next.forEach((item, i) => {
        const target = item.value
        if (typeof target !== 'number' || !Number.isFinite(target) || SKIP_ANIMATION) {
          cancelAnimationFrame(rafs[i])
          display.value[i] = target
          return
        }
        const from = typeof display.value[i] === 'number' ? display.value[i] : 0
        if (from === target) return
        cancelAnimationFrame(rafs[i])
        const start = performance.now()
        const tick = (now) => {
          const p = Math.min(1, (now - start) / duration)
          const eased = 1 - Math.pow(1 - p, 3) // easeOutCubic：与苹果弹簧的"先快后稳"同向
          display.value[i] = Math.round(from + (target - from) * eased)
          if (p < 1) rafs[i] = requestAnimationFrame(tick)
        }
        rafs[i] = requestAnimationFrame(tick)
      })
    },
    { deep: true }
  )

  onUnmounted(() => rafs.forEach((id) => cancelAnimationFrame(id)))

  return display
}

export default useCountUp
