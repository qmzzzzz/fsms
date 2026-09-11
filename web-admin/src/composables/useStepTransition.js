/**
 * 分步向导的步骤切换动效（自 RegisterView 拆出，D-2）
 *
 * 职责：方向感知（前进自右、后退自左）、面板高度实测与容器高度过渡、
 * 过渡期间裁切溢出。与表单数据/校验完全无关，是纯视图层过渡状态机。
 *
 * 方向感知取 Apple「来路即去路」原则——若前进向右、后退向下，
 * 用户会失去「我在流程中的位置」的预判。
 * 面板高度用 ResizeObserver 实测：校验错误文案撑高内容时高度会跟着长，
 * 不会把错误提示裁掉。
 */
import { ref, computed, nextTick, onBeforeUnmount } from 'vue'

export function useStepTransition(activeStep) {
  const stepDirection = ref('forward')
  const stepDirClass = computed(() => (stepDirection.value === 'forward' ? 'is-fwd' : 'is-back'))

  const stepPanels = ref([])
  const setPanel = (index, el) => {
    if (el) stepPanels.value[index] = el
  }

  const activeHeight = ref(0)
  const isStepping = ref(false)
  let stepTimer = null
  let panelObserver = null

  const stepsWrapStyle = computed(() => ({
    height: activeHeight.value > 0 ? `${activeHeight.value}px` : 'auto',
  }))

  const measureActivePanel = () => {
    const el = stepPanels.value[activeStep.value]
    if (el && el.offsetHeight > 0) activeHeight.value = el.offsetHeight
  }

  /** 过渡期间才裁切溢出，结束后恢复 visible（错误文案不被长期裁切） */
  const beginStepTransition = () => {
    isStepping.value = true
    clearTimeout(stepTimer)
    stepTimer = setTimeout(() => {
      isStepping.value = false
    }, 380)
    nextTick(measureActivePanel)
  }

  /** 观察三个步骤面板：内容高度变化时（校验错误出现/收起、口令强度规则列表换行）
      容器高度同步跟随，避免卡片内出现滚动或被裁切。须在各面板 ref 就绪后调用 */
  const startObserving = () => {
    if (typeof ResizeObserver !== 'undefined') {
      panelObserver = new ResizeObserver(() => measureActivePanel())
      stepPanels.value.forEach((el) => el && panelObserver.observe(el))
    }
    measureActivePanel()
  }

  const dispose = () => {
    panelObserver?.disconnect()
    panelObserver = null
    clearTimeout(stepTimer)
    stepTimer = null
  }

  onBeforeUnmount(dispose)

  return {
    stepDirection,
    stepDirClass,
    setPanel,
    stepsWrapStyle,
    isStepping,
    beginStepTransition,
    measureActivePanel,
    startObserving,
    dispose,
  }
}
