<template>
  <!--
    安全统计（管理员，需 security:stats）：GET /api/security/stats
    后端返回 { overview:{todayLogins,todayFailedLogins,highRiskOperations},
              anomalies:{failedOperationUsers,unusualTimeUsers}, securityLevel }。
    由父视图按权限码门控——无 security:stats 时整卡不渲染也不请求（与 P3-39 同口径）。
  -->
  <el-card shadow="never" class="security-stats-card">
    <template #header>
      <div class="ss-header">
        <span class="card-header">{{ $t('securityStats.title') }}</span>
        <el-tag v-if="!loading && !error" :type="levelType" size="small" effect="plain">
          {{ $t('securityStats.levelLabel') }}·{{ levelText }}
        </el-tag>
      </div>
    </template>

    <!--
      加载态用文本而非 GlassSkeleton：DashboardView 的既有用例断言了页面内
      `.glass-skeleton` 的**精确清单**（骨架期 4 张 + 图表区若干，加载完成后为 0）。
      这里再插一个骨架会把那份清单打破，而该清单守的是"骨架屏必须退出"，
      与本卡无关——用一个不共享类名的轻量文本态即可互不干扰。
    -->
    <p v-if="loading" class="ss-hint">{{ $t('common.loading') }}</p>

    <div v-else-if="error" class="self-error">
      <span>{{ $t('securityStats.loadFailed') }}</span>
      <button type="button" class="glass-btn glass-btn--default glass-btn--sm" @click="load">
        {{ $t('common.refresh') }}
      </button>
    </div>

    <template v-else>
      <div class="ss-grid">
        <div class="ss-item">
          <div class="ss-value">{{ overview.todayLogins }}</div>
          <div class="ss-label">{{ $t('securityStats.todayLogins') }}</div>
        </div>
        <div class="ss-item">
          <div class="ss-value is-bad">{{ overview.todayFailedLogins }}</div>
          <div class="ss-label">{{ $t('securityStats.todayFailedLogins') }}</div>
        </div>
        <div class="ss-item">
          <div class="ss-value is-warn">{{ overview.highRiskOperations }}</div>
          <div class="ss-label">{{ $t('securityStats.highRiskOperations') }}</div>
        </div>
      </div>

      <div class="ss-anomalies">
        <span class="ss-block-label">{{ $t('securityStats.anomalies') }}</span>
        <el-tag
          :type="anomalies.failedOperationUsers.length ? 'warning' : 'info'"
          size="small"
          effect="plain"
        >
          {{ $t('securityStats.failedOperationUsers') }} ·
          {{ anomalies.failedOperationUsers.length }}
        </el-tag>
        <el-tag
          :type="anomalies.unusualTimeUsers.length ? 'warning' : 'info'"
          size="small"
          effect="plain"
        >
          {{ $t('securityStats.unusualTimeUsers') }} ·
          {{ anomalies.unusualTimeUsers.length }}
        </el-tag>
      </div>
    </template>
  </el-card>
</template>

<script setup>
/**
 * 安全统计卡（管理员）
 *
 * 端点在 securityRoutes.js:232-237，挂 checkPermission('security:stats')；
 * 此前前端零引用（api.js 只封装不消费）。落在首页而非个人资料页：它返回的是
 * **全局**今日登录/失败/高危统计与异常用户聚合，不是"本人数据"，与个人资料页
 * 的三张自助卡不同性质。
 *
 * 失败处理：落错误态并清空，不留上一次的读数——统计数字过期比空白更误导
 * （值班界面会把旧值当成当前事实）。
 *
 * 刷新契约（与 DashboardCharts 同型）：本卡自加载，并对外暴露 load()；
 * 首页的 5 分钟定时器 / 可见性恢复 / 语言切换都经 ref 调到这里。若不接，
 * 卡片只在挂载时取一次数，其余数据块都刷新而它停在旧值——同一屏上
 * 「设备数是最新的、登录统计是 5 分钟前的」比整页都旧更难被发现。
 */
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '@/utils/api'
import { useLatestRequest } from '@/composables/useLatestRequest'

const { t } = useI18n()

const EMPTY_OVERVIEW = { todayLogins: 0, todayFailedLogins: 0, highRiskOperations: 0 }
const EMPTY_ANOMALIES = { failedOperationUsers: [], unusualTimeUsers: [] }

const overview = ref({ ...EMPTY_OVERVIEW })
const anomalies = ref({ ...EMPTY_ANOMALIES })
const securityLevel = ref('normal')
const loading = ref(true)
const error = ref(false)

// 请求新鲜度守卫：定时刷新与可见性恢复可能交叠，先发的慢响应若后返回会把
// 新读数覆盖成旧值（与首页 dashGuard / alarmGuard 同口径）。
const statsGuard = useLatestRequest()

const levelText = computed(() =>
  securityLevel.value === 'high' ? t('securityStats.levelHigh') : t('securityStats.levelNormal')
)
const levelType = computed(() => (securityLevel.value === 'high' ? 'danger' : 'success'))

const load = async () => {
  const isCurrent = statsGuard()
  loading.value = true
  error.value = false
  try {
    const { data: resp } = await api.security.getSecurityStats()
    // 过期响应直接丢弃：否则慢的旧请求会覆盖新读数
    if (!isCurrent()) return
    const d = resp.data || {}
    overview.value = { ...EMPTY_OVERVIEW, ...d.overview }
    anomalies.value = { ...EMPTY_ANOMALIES, ...d.anomalies }
    securityLevel.value = d.securityLevel || 'normal'
  } catch (_) {
    // 过期响应的失败不得在新鲜数据上盖错误态
    if (!isCurrent()) return
    // 错误提示已由拦截器统一处理；清空避免展示过期读数
    overview.value = { ...EMPTY_OVERVIEW }
    anomalies.value = { ...EMPTY_ANOMALIES }
    securityLevel.value = 'normal'
    error.value = true
  } finally {
    // 仅最新一次请求可以关掉加载态：过期请求收尾时不能把在途的新请求的
    // 加载态提前关掉（否则会先闪一下旧数据再跳新值）
    if (isCurrent()) loading.value = false
  }
}

onMounted(load)
defineExpose({ load })
</script>

<style scoped>
.ss-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.card-header {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}

.ss-hint,
.self-error {
  margin: 0;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

.self-error {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.ss-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
}

.ss-value {
  font-family: var(--xf-font-display);
  font-size: 28px;
  font-weight: 700;
  line-height: 1.1;
  color: var(--xf-gray-900);
}

/* 分级配色与 el-tag 的 danger/warning 语义同频（涨跌色规范只约束股价类，此处是告警语义） */
.ss-value.is-bad {
  color: var(--xf-danger, #f56c6c);
}
.ss-value.is-warn {
  color: var(--xf-warning, #e6a23c);
}

.ss-label {
  margin-top: 2px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
}

.ss-anomalies {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 16px;
}

.ss-block-label {
  font-size: var(--xf-font-size-sm);
  font-weight: 600;
  color: var(--xf-text-secondary);
}

@media (max-width: 600px) {
  .ss-grid {
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
  }
  .ss-value {
    font-size: 22px;
  }
}
</style>
