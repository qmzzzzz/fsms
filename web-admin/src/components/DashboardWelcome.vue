<template>
  <!-- 欢迎卡片（D-2 自 DashboardView 拆出）：
       问候语 + 秒级时钟 + 头像，时钟生命周期由本组件自理 -->
  <el-card class="welcome-card" shadow="never">
    <div class="welcome-content">
      <div>
        <h2>{{ greeting }}, {{ currentUser?.realName || currentUser?.username || 'Admin' }}</h2>
        <p>{{ $t('dashboard.welcome') }}</p>
      </div>
      <div class="welcome-right">
        <!-- 系统实时时钟（日期 + 时间，秒级刷新） -->
        <div class="welcome-clock">
          <div class="clock-date">
            {{ currentDate }}
          </div>
          <div class="clock-time">
            {{ currentTime }}
          </div>
        </div>
        <el-avatar :size="64" class="welcome-avatar">
          {{ (currentUser?.username || 'A').slice(0, 1).toUpperCase() }}
        </el-avatar>
      </div>
    </div>
  </el-card>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'

defineProps({
  currentUser: { type: Object, default: null },
})

const { t, locale } = useI18n()

const greeting = computed(() => {
  const h = new Date().getHours()
  if (h < 6) return t('dashboard.greetingLateNight')
  if (h < 12) return t('dashboard.greetingMorning')
  if (h < 14) return t('dashboard.greetingNoon')
  if (h < 18) return t('dashboard.greetingAfternoon')
  return t('dashboard.greetingEvening')
})

// ===== 系统实时时钟 =====
const now = ref(new Date())
let clockTimer = null

const currentDate = computed(() =>
  now.value.toLocaleDateString(locale.value, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    weekday: 'long',
  })
)
const currentTime = computed(() => now.value.toLocaleTimeString(locale.value, { hour12: false }))

const updateClock = () => {
  now.value = new Date()
}
const startClock = () => {
  updateClock()
  clockTimer = setInterval(() => {
    // 页面隐藏时暂停刷新，恢复可见时立即同步
    if (document.visibilityState === 'visible') updateClock()
  }, 1000)
}
const stopClock = () => {
  if (clockTimer) {
    clearInterval(clockTimer)
    clockTimer = null
  }
}

onMounted(startClock)
onUnmounted(stopClock)
</script>

<style scoped>
/* ===== 欢迎卡片 ===== */
.welcome-card {
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  border: none;
  position: relative;
  overflow: hidden;
}

.welcome-card::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image: var(--xf-tech-grid);
  background-size: var(--xf-tech-grid-size) var(--xf-tech-grid-size);
  opacity: 0.5;
  pointer-events: none;
}

.welcome-card::after {
  content: '';
  position: absolute;
  top: 0;
  right: 0;
  width: 40%;
  height: 100%;
  background: radial-gradient(ellipse at right center, rgba(193, 18, 31, 0.15) 0%, transparent 70%);
  pointer-events: none;
}

.welcome-card :deep(.el-card__body) {
  padding: 28px 32px;
  position: relative;
  z-index: 1;
}

.welcome-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: #fff;
}

.welcome-content h2 {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-2xl);
  font-weight: 700;
  margin-bottom: 8px;
  letter-spacing: var(--xf-tracking-tight);
}

.welcome-content p {
  opacity: 0.7;
  font-size: var(--xf-font-size-sm);
  font-family: var(--xf-font-body);
  letter-spacing: var(--xf-tracking-wide);
}

.welcome-avatar {
  background: linear-gradient(135deg, rgba(193, 18, 31, 0.8) 0%, rgba(125, 12, 20, 0.6) 100%);
  color: #fff;
  font-size: 26px;
  font-weight: 700;
  font-family: var(--xf-font-display);
  border: 1px solid rgba(255, 255, 255, 0.15);
  box-shadow: 0 4px 20px rgba(193, 18, 31, 0.3);
}

/* ===== 欢迎卡片系统时钟 ===== */
.welcome-right {
  display: flex;
  align-items: center;
  gap: 28px;
}
.welcome-clock {
  text-align: right;
  font-family: var(--xf-font-mono);
  color: #fff;
}
.clock-date {
  font-size: var(--xf-font-size-sm);
  opacity: 0.75;
  letter-spacing: var(--xf-tracking-wide);
  margin-bottom: 8px;
}
.clock-time {
  font-size: 36px;
  font-weight: 700;
  line-height: 1;
  font-variant-numeric: tabular-nums;
  letter-spacing: var(--xf-tracking-tight);
  text-shadow: 0 0 28px rgba(193, 18, 31, 0.35);
}

/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .welcome-content {
    flex-wrap: wrap;
    gap: 12px;
  }
  .welcome-right {
    gap: 12px;
  }
  .welcome-clock {
    text-align: left;
  }
  .clock-time {
    font-size: 26px;
  }
  .welcome-content h2 {
    font-size: var(--xf-font-size-xl);
  }
}

@media (max-width: 480px) {
  .welcome-card :deep(.el-card__body) {
    padding: 18px 16px;
  }
  .clock-time {
    font-size: 22px;
  }
  .welcome-content h2 {
    font-size: var(--xf-font-size-lg);
  }
}
</style>
