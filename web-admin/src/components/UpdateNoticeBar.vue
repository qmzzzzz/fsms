<template>
  <div v-if="visible" class="update-bar" role="status" aria-live="polite">
    <span class="update-bar__text">{{ t('updateNotice.message') }}</span>
    <button type="button" class="update-bar__action" @click="onRefresh">
      {{ t('updateNotice.refresh') }}
    </button>
    <button
      type="button"
      class="update-bar__dismiss"
      :aria-label="t('updateNotice.dismiss')"
      :title="t('updateNotice.dismiss')"
      @click="dismiss"
    >
      ×
    </button>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { applyUpdate, updateAvailable } from '@/utils/updateNotice'

const { t } = useI18n()

/**
 * 关闭只对本次置位有效（组件内状态，不落 localStorage）。
 *
 * 刻意不持久化：一旦写进本地存储，用户点过一次「稍后」之后，**下一版**的提示
 * 也会被永久吞掉——而那正是这个提示存在的唯一理由。
 */
const dismissed = ref(false)

const visible = computed(() => updateAvailable.value && !dismissed.value)

const dismiss = () => {
  dismissed.value = true
}

const onRefresh = () => {
  // 不 await：applyUpdate 内部会先激活等待中的 SW 再 reload，成功路径不会返回
  applyUpdate()
}
</script>

<style scoped>
.update-bar {
  position: fixed;
  left: 50%;
  bottom: calc(20px + env(safe-area-inset-bottom, 0px));
  transform: translateX(-50%);
  z-index: 3000;
  display: flex;
  align-items: center;
  gap: 12px;
  max-width: min(92vw, 560px);
  padding: 10px 10px 10px 16px;
  border-radius: 12px;
  border: 1px solid var(--el-border-color-light, rgba(0, 0, 0, 0.1));
  background: var(--el-bg-color-overlay, #fff);
  color: var(--el-text-color-primary, #1f2937);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.14);
  font-size: 14px;
  line-height: 1.4;
}

.update-bar__text {
  flex: 1 1 auto;
  min-width: 0;
}

.update-bar__action {
  flex: 0 0 auto;
  padding: 6px 14px;
  border: none;
  border-radius: 8px;
  background: var(--el-color-primary, #c1121f);
  color: #fff;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: filter 0.15s ease;
}

.update-bar__action:hover {
  filter: brightness(1.08);
}

.update-bar__action:focus-visible {
  outline: 2px solid var(--el-color-primary-light-3, #e0555f);
  outline-offset: 2px;
}

.update-bar__dismiss {
  flex: 0 0 auto;
  width: 28px;
  height: 28px;
  padding: 0;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--el-text-color-secondary, #6b7280);
  font-size: 18px;
  line-height: 1;
  cursor: pointer;
}

.update-bar__dismiss:hover {
  background: var(--el-fill-color-light, rgba(0, 0, 0, 0.05));
}

@media (max-width: 480px) {
  .update-bar {
    left: 12px;
    right: 12px;
    max-width: none;
    transform: none;
  }
}
</style>
