/**
 * 移动端下拉刷新手势
 *
 * 仅在页面滚动到顶时触发（主内容区非滚动容器时真实滚动源是 window，
 * 故门槛须同时看 el.scrollTop 与 window.scrollY），
 * 防止与纵向滚动、侧栏滑动手势、浏览器返回手势冲突。
 * 用法：在 layout 主内容区外层调用，返回 { y, refreshing } 给模板渲染指示器。
 */
import { ref, onMounted, onUnmounted } from 'vue'
import { haptic } from '@/utils/haptic'
// 降级上报收口（2026-11-17 审计 D 组）：onRefresh 的同步抛错与异步拒绝此前被
// 双层 catch 静默吞掉，页面只表现成「刷新了但数据没变」，现场无从排查
import { reportDegradation } from '@/utils/errorReporter'

const RESISTANCE = 0.55
const TRIGGER_THRESHOLD = 80
const MAX_PULL = 120

export function usePullToRefresh(targetRef, onRefresh) {
  const y = ref(0)
  const refreshing = ref(false)

  let startY = 0
  let isPulling = false
  // onMounted 记住绑定节点：onUnmounted 时 Vue 已把模板 ref 置 null，
  // 重新解析 targetRef.value 恒拿不到节点，摘监听会被短路
  let bound = null

  const resetPull = () => {
    isPulling = false
    startY = 0
    y.value = 0
  }

  // 页面是否在顶部：主内容区不一定承担滚动（滚动源可能是 window）
  const atTop = (el) => (el ? el.scrollTop : 0) <= 1 && window.scrollY <= 1

  const onTouchStart = (e) => {
    if (refreshing.value) return
    const el = targetRef.value
    if (!el) return
    // 多指/系统手势介入：放弃本轮下拉并清掉原点，
    // 否则下一次单指 move 会按旧 startY 计算 dy，瞬间拽下指示条
    if (e.touches.length !== 1) {
      resetPull()
      return
    }
    if (!atTop(el)) return
    startY = e.touches[0].clientY
    isPulling = true
  }

  const onTouchMove = (e) => {
    if (!isPulling || refreshing.value) return
    const el = targetRef.value
    if (!el) return
    // 滚动中途松手再下拉：一旦页面离开顶部立即停止
    if (!atTop(el)) {
      resetPull()
      return
    }
    const dy = e.touches[0].clientY - startY
    if (dy < 0) {
      resetPull()
      return
    }
    const damped = Math.min(dy * RESISTANCE, MAX_PULL)
    y.value = damped
    e.preventDefault()
  }

  const onTouchEnd = () => {
    if (!isPulling) return
    isPulling = false
    if (y.value >= TRIGGER_THRESHOLD) {
      haptic(15)
      refreshing.value = true
      y.value = TRIGGER_THRESHOLD
      let refreshResult
      try {
        refreshResult = onRefresh?.()
      } catch (error) {
        // 同步抛错：上报留痕后按「无刷新结果」继续收口，指示条照常复位
        reportDegradation('下拉刷新回调执行失败', {
          error: error?.message || String(error),
        })
        refreshResult = undefined
      }
      Promise.resolve(refreshResult)
        .catch((error) => {
          // 异步拒绝：不再静默吞掉，至少进入降级留痕（失败可见）
          reportDegradation('下拉刷新执行失败', {
            error: error?.message || String(error),
          })
        })
        .finally(() => {
          y.value = 0
          refreshing.value = false
        })
    } else {
      y.value = 0
    }
  }

  // 触摸被系统打断（来电/手势接管等）：按取消处理，与 touchend 的"触发刷新"路径隔离
  const onTouchCancel = () => {
    if (refreshing.value) return
    resetPull()
  }

  onMounted(() => {
    bound = targetRef.value
    if (!bound) return
    bound.addEventListener('touchstart', onTouchStart, { passive: true })
    bound.addEventListener('touchmove', onTouchMove, { passive: false })
    bound.addEventListener('touchend', onTouchEnd, { passive: true })
    bound.addEventListener('touchcancel', onTouchCancel, { passive: true })
  })

  onUnmounted(() => {
    if (!bound) return
    bound.removeEventListener('touchstart', onTouchStart)
    bound.removeEventListener('touchmove', onTouchMove)
    bound.removeEventListener('touchend', onTouchEnd)
    bound.removeEventListener('touchcancel', onTouchCancel)
    bound = null
  })

  return { y, refreshing }
}
