<template>
  <div class="page">
    <div class="glass glass-card workbench-bar">
      <div class="card-header">
        <span>{{ $t('nav.securityAnalysis') }}</span>
      </div>
      <el-tabs
        v-model="activeTab"
        class="workbench-tabs"
        data-test="security-analysis-tabs"
        @tab-change="onTabChange"
      >
        <el-tab-pane :label="$t('nav.attackAlerts')" name="alerts" />
        <el-tab-pane :label="$t('nav.attackProfile')" name="attack" />
        <el-tab-pane :label="$t('nav.stuffingProfile')" name="stuffing" />
        <el-tab-pane :label="$t('nav.forensic')" name="forensic" />
      </el-tabs>
    </div>

    <AttackAlertsView
      v-if="mountedTabs.has('alerts')"
      v-show="activeTab === 'alerts'"
      :show-title="false"
    />
    <AttackProfileView
      v-if="mountedTabs.has('attack')"
      v-show="activeTab === 'attack'"
      :show-title="false"
    />
    <StuffingProfileView
      v-if="mountedTabs.has('stuffing')"
      v-show="activeTab === 'stuffing'"
      :show-title="false"
    />
    <ForensicTraceView v-if="mountedTabs.has('forensic')" v-show="activeTab === 'forensic'" />
  </div>
</template>

<script setup>
import { defineAsyncComponent, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

// 四个工具各自成 chunk：工作台首屏只加载当前 tab，访问过再保活（切走不丢查询现场）
const AttackAlertsView = defineAsyncComponent(() => import('@/views/AttackAlertsView.vue'))
const AttackProfileView = defineAsyncComponent(() => import('@/views/AttackProfileView.vue'))
const StuffingProfileView = defineAsyncComponent(() => import('@/views/StuffingProfileView.vue'))
const ForensicTraceView = defineAsyncComponent(() => import('@/views/ForensicTraceView.vue'))

// 攻击告警是工作台的入口（先看告警，再对可疑 IP 深入画像/取证），置于首位为默认 tab
const VALID_TABS = ['alerts', 'attack', 'stuffing', 'forensic']
const DEFAULT_TAB = 'alerts'

const tabOf = (raw) => {
  const value = Array.isArray(raw) ? raw[0] : raw
  return VALID_TABS.includes(value) ? value : DEFAULT_TAB
}

const route = useRoute()
const router = useRouter()
const activeTab = ref(tabOf(route.query.tab))
const mountedTabs = reactive(new Set([activeTab.value]))

watch(activeTab, (tab) => mountedTabs.add(tab))

// 浏览器前进/后退也要跟着 tab 走；route 驱动的变化不回写 URL（保留深链原判据）
watch(
  () => route.query.tab,
  (raw) => {
    activeTab.value = tabOf(raw)
  }
)

const onTabChange = (name) => {
  // 只保留 tab：上一工具的判据留着会被下一工具当成自动查询入口
  router.replace({ query: { tab: name } })
}
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.glass-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}
.card-header {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}
.workbench-tabs :deep(.el-tabs__header) {
  margin-bottom: 0;
}
/* tab 内容区由下方四个视图自身渲染，禁止再套一层空面板 */
.workbench-tabs :deep(.el-tabs__content) {
  display: none;
}
@media (prefers-reduced-motion: reduce) {
  .glass-card {
    animation: none !important;
  }
}
</style>
