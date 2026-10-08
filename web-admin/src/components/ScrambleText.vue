<template>
  <span class="scramble-text" @mouseenter="startScramble" @mouseleave="stopScramble">{{
    displayText
  }}</span>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const props = defineProps({
  text: { type: String, required: true },
  // 每轮扰码的帧率（ms），越小越急促
  speed: { type: Number, default: 30 },
  // 每个字符从乱码恢复到原字符所需的帧数（递增式解析）
  resolveStep: { type: Number, default: 1 / 3 },
})

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
const iteration = ref(Infinity) // 初始为已完成态，显示原文
let intervalId = null

const displayText = computed(() => {
  if (iteration.value >= props.text.length) return props.text
  return props.text
    .split('')
    .map((ch, i) => (i < iteration.value ? ch : CHARS[Math.floor(Math.random() * CHARS.length)]))
    .join('')
})

const clear = () => {
  if (intervalId !== null) {
    clearInterval(intervalId)
    intervalId = null
  }
}

const safeMatchMedia = (query) => {
  try {
    return window.matchMedia?.(query) ?? { matches: false }
  } catch (_) {
    return { matches: false }
  }
}

const startScramble = () => {
  if (safeMatchMedia('(prefers-reduced-motion: reduce)').matches) return
  clear()
  iteration.value = 0
  intervalId = setInterval(() => {
    if (iteration.value >= props.text.length) {
      clear()
      return
    }
    iteration.value += props.resolveStep
  }, props.speed)
}

const stopScramble = () => {
  clear()
  iteration.value = Infinity
}

watch(
  () => props.text,
  () => stopScramble()
)
</script>

<style scoped>
.scramble-text {
  display: inline-block;
  font-variant-numeric: tabular-nums;
  letter-spacing: inherit;
}
</style>
