<template>
  <!--
    Teleport 到 body：布局层在退出期间给 .app-wrapper 加 inert（下层内容移出可访问性
    树、且不可聚焦），遮罩自身必须留在 inert 子树之外——role="alert" + aria-live 的
    「正在退出」播报依赖它还在可访问性树里。留在原处会被一起 inert 掉，播报静默失效。
  -->
  <Teleport to="body">
    <Transition name="exit-fade">
      <div v-if="visible" class="exit-overlay" role="alert" aria-live="assertive">
        <div class="exit-overlay__brand">
          <div class="exit-overlay__icon">
            <el-icon><SwitchButton /></el-icon>
          </div>
          <span class="exit-overlay__title">{{ t('common.appTitle') }}</span>
        </div>
        <div class="exit-overlay__spinner" aria-hidden="true" />
        <p class="exit-overlay__message">{{ t('auth.signingOut') }}</p>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { SwitchButton } from '@element-plus/icons-vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

defineProps({
  visible: { type: Boolean, default: false },
})
</script>

<style scoped>
.exit-overlay {
  position: fixed;
  inset: 0;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  /* 磨砂玻璃：半透明底 + blur + saturate，叠在页面最上层时
     透过 overlay 能隐约看到下层内容的红色渐变，材质纵深完整 */
  background: rgba(255, 255, 255, 0.82);
  backdrop-filter: blur(28px) saturate(180%);
  -webkit-backdrop-filter: blur(28px) saturate(180%);
}

.exit-overlay__brand {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 32px;
}

.exit-overlay__icon {
  width: 52px;
  height: 52px;
  border-radius: 16px;
  background: linear-gradient(
    135deg,
    var(--xf-primary, #c1121f) 0%,
    var(--xf-primary-strong, #a4161a) 100%
  );
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-size: 26px;
  box-shadow: 0 8px 24px rgba(193, 18, 31, 0.25);
  animation: exit-icon-pulse 2s var(--apple-ease, cubic-bezier(0.32, 0.72, 0, 1)) infinite;
}

.exit-overlay__title {
  font-family: var(--xf-font-display, 'Sora', sans-serif);
  font-size: 22px;
  font-weight: 700;
  color: var(--xf-text-primary, #1e293b);
  letter-spacing: -0.02em;
}

.exit-overlay__spinner {
  width: 32px;
  height: 32px;
  border: 3px solid var(--xf-border-color, #e2e8f0);
  border-top-color: var(--xf-primary, #c1121f);
  border-radius: 50%;
  animation: exit-spin 0.8s linear infinite;
}

.exit-overlay__message {
  margin-top: 20px;
  font-size: 15px;
  color: var(--xf-text-secondary, #475569);
  font-weight: 500;
  letter-spacing: -0.01em;
}

@keyframes exit-spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes exit-icon-pulse {
  0%,
  100% {
    box-shadow: 0 8px 24px rgba(193, 18, 31, 0.25);
  }
  50% {
    box-shadow: 0 8px 32px rgba(193, 18, 31, 0.4);
  }
}

/* 进入/离开过渡 */
.exit-fade-enter-active {
  transition: opacity 0.4s var(--apple-ease, cubic-bezier(0.32, 0.72, 0, 1));
}
.exit-fade-leave-active {
  transition: opacity 0.3s ease;
}
.exit-fade-enter-from,
.exit-fade-leave-to {
  opacity: 0;
}

/* 暗色适配 */
html.dark .exit-overlay {
  background: rgba(10, 15, 26, 0.82);
}

html.dark .exit-overlay__title {
  color: var(--xf-text-primary, #f1f5f9);
}

html.dark .exit-overlay__message {
  color: var(--xf-text-secondary, #cbd5e1);
}

html.dark .exit-overlay__spinner {
  border-color: var(--xf-border-color, #1e293b);
  border-top-color: var(--xf-primary, #c1121f);
}

/* 无障碍降级 */
@media (prefers-reduced-motion: reduce) {
  .exit-overlay__icon {
    animation: none;
  }
  .exit-overlay__spinner {
    animation: none;
    border-top-color: var(--xf-primary);
    border-right-color: var(--xf-primary);
  }
  .exit-fade-enter-active,
  .exit-fade-leave-active {
    transition: none;
  }
}
</style>
