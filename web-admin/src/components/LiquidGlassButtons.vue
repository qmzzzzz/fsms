<template>
  <div class="liquid-glass-buttons" :style="{ height: height + 'px' }">
    <button
      v-for="btn in buttons"
      :key="btn.id"
      type="button"
      class="glass-btn"
      :class="['glass-btn--' + (btn.type || 'default')]"
      :style="{ height: height + 'px' }"
      @click="$emit('press', btn.id)"
    >
      {{ btn.label }}
    </button>
  </div>
</template>

<script setup>
defineProps({
  buttons: {
    type: Array,
    default: () => [],
  },
  height: {
    type: Number,
    default: 40,
  },
})

defineEmits(['press'])
</script>

<style scoped>
/* 仅保留布局/尺寸相关样式，视觉完全继承全局 .glass-btn 体系 */
.liquid-glass-buttons {
  display: flex;
  gap: 12px;
  width: 100%;
}

.glass-btn {
  flex: 1;
}
</style>
