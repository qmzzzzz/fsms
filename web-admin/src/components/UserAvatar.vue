<template>
  <!-- 统一头像展示：有 src 显示图片，加载失败/为空回退姓名首字母 -->
  <el-avatar :size="size" :shape="shape" :src="resolvedSrc" :alt="altText" @error="onError">
    {{ initial }}
  </el-avatar>
</template>

<script setup>
import { computed, ref, watch } from 'vue'

const props = defineProps({
  src: { type: String, default: '' },
  name: { type: String, default: '' },
  // 无姓名时的兜底字符（默认空串：调用方自会决定要不要给占位）
  fallback: { type: String, default: '' },
  size: { type: Number, default: 32 },
  shape: { type: String, default: 'circle' },
})

// 图片加载失败（404/403/CSP 拦截/格式损坏）时回退首字母，且不阻塞页面
const failed = ref(false)
watch(
  () => props.src,
  () => {
    failed.value = false
  }
)

const initial = computed(() => (props.name || props.fallback).slice(0, 1).toUpperCase())
const resolvedSrc = computed(() => (failed.value ? '' : props.src || ''))
const altText = computed(() => props.name || 'avatar')
const onError = () => {
  failed.value = true
}
</script>
