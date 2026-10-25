<template>
  <div
    ref="trackRef"
    class="glass-segmented"
    :class="{ 'glass-segmented--sm': size === 'sm' }"
    role="tablist"
    aria-orientation="horizontal"
    :aria-label="ariaLabel || undefined"
    @keydown="onKeydown"
  >
    <!-- 透镜滑块：绝对定位，随激活项平滑滑动 -->
    <div ref="thumbRef" class="glass-segmented__thumb" aria-hidden="true" />
    <button
      v-for="(opt, index) in options"
      :key="opt.value"
      type="button"
      class="glass-segmented__item"
      :class="{ 'is-active': modelValue === opt.value }"
      role="tab"
      :aria-selected="modelValue === opt.value"
      :tabindex="index === tabStopIndex ? 0 : -1"
      :data-value="opt.value"
      @click="select(opt.value)"
    >
      <span v-if="opt.count !== undefined && opt.count !== null" class="glass-segmented__count">{{
        opt.count
      }}</span>
      {{ opt.label }}
    </button>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from 'vue'

/**
 * 苹果液态玻璃分段控件（滑动透镜滑块版）
 * options: [{ label, value, count? }]
 * modelValue: 当前激活项 value（v-model）
 */
const props = defineProps({
  options: { type: Array, required: true },
  modelValue: { type: [String, Number], default: '' },
  size: { type: String, default: '' },
  // 无障碍标签由调用方按界面语言传入；未传时不输出 aria-label（避免硬编码中文默认值）
  ariaLabel: { type: String, default: '' },
})

const emit = defineEmits(['update:modelValue', 'change'])

const trackRef = ref(null)
const thumbRef = ref(null)
let resizeObserver = null

// 测量激活项位置并驱动透镜滑块滑动（width + translateX 双过渡，宽度不等时分段也能精确对位）
const moveThumb = () => {
  const track = trackRef.value
  const thumb = thumbRef.value
  if (!track || !thumb) return

  const active = track.querySelector('.glass-segmented__item.is-active')
  if (!active) return

  thumb.style.width = `${active.offsetWidth}px`
  thumb.style.transform = `translateX(${active.offsetLeft}px)`
  if (!thumb.classList.contains('is-ready')) {
    // 首次定位在下一帧显示，避免从 0 位置滑入的跳变
    requestAnimationFrame(() => thumb.classList.add('is-ready'))
  }
}

const select = (value) => {
  if (props.modelValue === value) return
  emit('update:modelValue', value)
  emit('change', value)
}

// roving tabindex：整组分段只占一个 Tab 位；无选中项时落在首项，避免整组无法键盘进入
const tabStopIndex = computed(() => {
  const index = props.options.findIndex((opt) => opt.value === props.modelValue)
  return index === -1 ? 0 : index
})

// 横向 tablist 键盘语义：左右方向键循环切换，Home/End 跳到首/末项。
// 切换即激活（自动激活模式），与点击行为共用 select，事件契约保持一致。
const onKeydown = (event) => {
  const len = props.options.length
  if (!len) return
  let nextIndex
  switch (event.key) {
    case 'ArrowLeft':
      nextIndex = (tabStopIndex.value - 1 + len) % len
      break
    case 'ArrowRight':
      nextIndex = (tabStopIndex.value + 1) % len
      break
    case 'Home':
      nextIndex = 0
      break
    case 'End':
      nextIndex = len - 1
      break
    default:
      return
  }
  event.preventDefault()
  select(props.options[nextIndex].value)
  nextTick(() => {
    trackRef.value?.querySelectorAll('.glass-segmented__item')[nextIndex]?.focus()
  })
}

watch(
  () => props.modelValue,
  () => nextTick(moveThumb)
)

// 选项变化（如计数徽标增删导致宽度变化）后重新对位
watch(
  () => props.options,
  () => nextTick(moveThumb),
  { deep: true }
)

onMounted(() => {
  moveThumb()
  // 容器尺寸变化（响应式/字体加载）时保持滑块贴合
  if (typeof ResizeObserver !== 'undefined' && trackRef.value) {
    resizeObserver = new ResizeObserver(() => moveThumb())
    resizeObserver.observe(trackRef.value)
  } else {
    window.addEventListener('resize', moveThumb)
  }
})

onUnmounted(() => {
  if (resizeObserver) {
    resizeObserver.disconnect()
    resizeObserver = null
  } else {
    window.removeEventListener('resize', moveThumb)
  }
})
</script>
