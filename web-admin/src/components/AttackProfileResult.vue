<template>
  <div class="profile-result">
    <el-alert
      v-if="profile.truncated"
      :title="$t('attackProfile.truncated', { count: profile.analyzed || 0 })"
      type="warning"
      :closable="false"
      show-icon
      class="load-alert"
    />
    <el-alert
      v-if="profile.scopeLimited"
      :title="$t('attackProfile.scopeLimited')"
      type="info"
      :closable="false"
      show-icon
      class="load-alert"
    />
    <el-alert
      v-if="profile.isPrivate"
      :title="$t('attackProfile.privateIp')"
      type="info"
      :closable="false"
      show-icon
      class="load-alert"
    />
    <el-alert
      v-if="profile.containment && profile.containment.degraded"
      :title="$t('attackProfile.containmentDegraded')"
      type="warning"
      :closable="false"
      show-icon
      class="load-alert"
    />

    <div class="verdict-banner" :class="'verdict--' + profile.verdict" data-test="verdict">
      <div class="verdict-main">
        <div class="verdict-eyebrow">{{ $t('attackProfile.verdictCard') }}</div>
        <div class="verdict-title">
          {{ $t('attackProfile.verdict.' + profile.verdict) }}
        </div>
        <p class="verdict-hint">{{ $t('attackProfile.verdictHint.' + profile.verdict) }}</p>
      </div>
      <div class="verdict-score">
        <div class="score-value">{{ profile.score ?? 0 }}<span class="score-unit">/100</span></div>
        <div class="score-caption">{{ $t('attackProfile.scoreLabel') }}</div>
        <div class="score-caption">
          {{ $t('attackProfile.riskLabel') }}：
          <el-tag :type="tagTypeForLevel(profile.riskLevel)" size="small" effect="dark">
            {{ $t('attackProfile.risk.' + (profile.riskLevel || 'none')) }}
          </el-tag>
        </div>
      </div>
    </div>

    <div class="report-bar">
      <button type="button" class="glass-btn glass-btn--default" @click="$emit('view-audit')">
        {{ $t('attackProfile.viewAuditLogs') }}
      </button>
      <button type="button" class="glass-btn glass-btn--primary" @click="$emit('open-report')">
        {{ $t('attackProfile.reportAction') }}
      </button>
    </div>

    <nav v-if="!isNoData" class="section-nav" data-test="section-nav">
      <button
        v-for="item in sections"
        :key="item.id"
        type="button"
        class="section-nav__item"
        @click="scrollTo(item.id)"
      >
        {{ item.label }}
      </button>
    </nav>

    <template v-if="!isNoData">
      <h3 id="profile-stats" class="section-title">{{ $t('attackProfile.statsTitle') }}</h3>
      <div class="stat-grid">
        <div v-for="cell in statCells" :key="cell.key" class="stat-cell">
          <span class="stat-value">{{ cell.value }}</span>
          <span class="stat-label">{{ $t(cell.labelKey) }}</span>
        </div>
      </div>

      <h3 id="profile-suggestions" class="section-title">
        {{ $t('attackProfile.suggestionsTitle') }}
      </h3>
      <ol class="suggestion-list">
        <li v-for="code in profile.suggestions || []" :key="code" class="suggestion-item">
          {{ $t('attackProfile.suggestion.' + code) }}
        </li>
      </ol>

      <h3 id="profile-categories" class="section-title">
        {{ $t('attackProfile.categoriesTitle') }}
      </h3>
      <p v-if="!categories.length" class="empty-tip">
        {{ $t('attackProfile.categoriesEmpty') }}
      </p>
      <p v-else class="evidence-hint">{{ $t('attackProfile.evidenceHint') }}</p>
      <div
        v-for="cat in categories"
        :key="cat.code"
        class="category-card"
        :data-category="cat.code"
      >
        <div class="category-head">
          <div class="category-title">
            <span class="category-name">{{
              $t('attackProfile.category.' + cat.code + '.label')
            }}</span>
            <el-tag :type="tagTypeForLevel(cat.severity)" size="small" effect="plain">
              {{ $t('attackProfile.severity.' + cat.severity) }}
            </el-tag>
          </div>
          <div class="category-counts">
            <span>{{ $t('attackProfile.categoryCount', { count: cat.count }) }}</span>
            <span class="muted">
              {{ $t('attackProfile.categoryBlocked', { count: cat.blockedCount }) }}
            </span>
            <span class="muted">
              {{ $t('attackProfile.categorySuccess', { count: cat.successCount }) }}
            </span>
          </div>
        </div>
        <p class="category-desc">
          {{ $t('attackProfile.category.' + cat.code + '.description') }}
        </p>
        <AttackEvidenceTable :evidence="cat.evidence || []" @inspect="$emit('inspect', $event)" />
      </div>

      <template v-if="uncategorizedCount > 0">
        <h3 class="section-title">
          {{ $t('attackProfile.uncategorizedTitle', { count: uncategorizedCount }) }}
        </h3>
        <p class="evidence-hint">{{ $t('attackProfile.uncategorizedHint') }}</p>
        <AttackEvidenceTable
          :evidence="uncategorizedEvidence"
          @inspect="$emit('inspect', $event)"
        />
      </template>

      <h3 id="profile-timeline" class="section-title">
        {{ $t('attackProfile.timelineTitle') }}
      </h3>
      <el-table :data="timelineRows" border size="small" style="width: 100%" class="timeline-table">
        <template #empty>
          <div class="empty-tip">{{ $t('attackProfile.timelineEmpty') }}</div>
        </template>
        <el-table-column :label="$t('attackProfile.timelineTime')" width="180">
          <template #default="{ row }">{{ formatTime(row.bucketStart) }}</template>
        </el-table-column>
        <el-table-column prop="total" :label="$t('attackProfile.timelineTotal')" width="110" />
        <el-table-column prop="blocked" :label="$t('attackProfile.timelineBlocked')" width="110" />
        <el-table-column :label="$t('attackProfile.timelineCategories')" min-width="200">
          <template #default="{ row }">
            <span v-if="!row.categories || !row.categories.length">-</span>
            <el-tag
              v-for="code in row.categories"
              :key="code"
              size="small"
              type="info"
              class="category-tag"
            >
              {{ $t('attackProfile.category.' + code + '.label') }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>

      <h3 id="profile-top" class="section-title">{{ $t('attackProfile.topTitle') }}</h3>
      <div class="dist-row">
        <div v-for="list in topLists" :key="list.key" class="dist-col">
          <h4 class="sub-title">{{ $t(list.titleKey) }}</h4>
          <el-table :data="list.items" border size="small" style="width: 100%">
            <template #empty>
              <div class="empty-tip">{{ $t('attackProfile.topEmpty') }}</div>
            </template>
            <el-table-column :label="list.valueLabel" min-width="180" show-overflow-tooltip>
              <template #default="{ row }">
                <span :class="{ mono: list.mono }">{{ row.value || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" :label="$t('attackProfile.countLabel')" width="90" />
          </el-table>
        </div>
      </div>
    </template>

    <h3 id="profile-containment" class="section-title">
      {{ $t('attackProfile.containmentTitle') }}
    </h3>
    <div class="containment-summary">
      <el-tag v-if="containment.blacklisted" type="danger" effect="dark">
        {{ $t('attackProfile.containmentBlacklisted') }}
      </el-tag>
      <el-tag v-else-if="containment.whitelisted" type="success" effect="dark">
        {{ $t('attackProfile.containmentWhitelisted') }}
      </el-tag>
      <el-tag v-else-if="!containment.degraded" type="info">
        {{ $t('attackProfile.containmentNone') }}
      </el-tag>
      <span v-else class="muted">{{ $t('attackProfile.containmentDegraded') }}</span>
    </div>
    <el-table
      v-if="containmentEntries.length"
      :data="containmentEntries"
      border
      size="small"
      style="width: 100%"
    >
      <el-table-column :label="$t('attackProfile.containmentType')" width="110">
        <template #default="{ row }">
          {{
            row.listType === 'black'
              ? $t('attackProfile.containmentTypeBlack')
              : $t('attackProfile.containmentTypeWhite')
          }}
        </template>
      </el-table-column>
      <el-table-column :label="$t('attackProfile.containmentIp')" min-width="150">
        <template #default="{ row }"
          ><span class="mono">{{ row.ip || '-' }}</span></template
        >
      </el-table-column>
      <el-table-column :label="$t('attackProfile.containmentReason')" min-width="180">
        <template #default="{ row }">{{ row.reason || '-' }}</template>
      </el-table-column>
      <el-table-column :label="$t('attackProfile.containmentExpires')" width="180">
        <template #default="{ row }">
          {{ row.expiresAt ? formatTime(row.expiresAt) : '-' }}
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatTime } from '@/utils/datetime'
import { actionLabel as toActionLabel } from '@/utils/auditLabels'
import AttackEvidenceTable from '@/components/AttackEvidenceTable.vue'

const props = defineProps({
  profile: { type: Object, required: true },
})
defineEmits(['inspect', 'view-audit', 'open-report'])

const { t } = useI18n()

const isNoData = computed(() => props.profile.verdict === 'no_data')
const categories = computed(() => props.profile.categories || [])
const uncategorizedCount = computed(() => props.profile.uncategorized?.count || 0)
const uncategorizedEvidence = computed(() => props.profile.uncategorized?.evidence || [])
const timelineRows = computed(() => props.profile.timeline?.buckets || [])
const containment = computed(
  () =>
    props.profile.containment || {
      degraded: true,
      blacklisted: false,
      whitelisted: false,
      entries: [],
    }
)
const containmentEntries = computed(() => containment.value.entries || [])

const sections = computed(() => [
  { id: 'profile-stats', label: t('attackProfile.statsTitle') },
  { id: 'profile-suggestions', label: t('attackProfile.suggestionsTitle') },
  { id: 'profile-categories', label: t('attackProfile.categoriesTitle') },
  { id: 'profile-timeline', label: t('attackProfile.timelineTitle') },
  { id: 'profile-top', label: t('attackProfile.topTitle') },
  { id: 'profile-containment', label: t('attackProfile.containmentTitle') },
])

const statCells = computed(() => {
  const p = props.profile
  const stats = p.stats || {}
  const cells = [
    { key: 'total', labelKey: 'attackProfile.statTotal', value: p.total ?? 0 },
    { key: 'blocked', labelKey: 'attackProfile.statBlocked', value: stats.failedRequests ?? 0 },
    {
      key: 'failedLogins',
      labelKey: 'attackProfile.statFailedLogins',
      value: stats.failedLogins ?? 0,
    },
    {
      key: 'successLogins',
      labelKey: 'attackProfile.statSuccessLogins',
      value: stats.successfulLogins ?? 0,
    },
    {
      key: 'accounts',
      labelKey: 'attackProfile.statAccounts',
      value: stats.distinctAccountsTried ?? 0,
    },
    {
      key: 'agents',
      labelKey: 'attackProfile.statUserAgents',
      value: stats.distinctUserAgents ?? 0,
    },
  ]
  if (stats.peakBucketRequests) {
    const unit =
      p.timeline?.unit === 'hour' ? t('attackProfile.perHour') : t('attackProfile.perDay')
    cells.push({
      key: 'peak',
      labelKey: 'attackProfile.statPeakRequests',
      value: `${stats.peakBucketRequests} ${unit}`,
    })
  }
  if (stats.criticalRows > 0) {
    cells.push({
      key: 'critical',
      labelKey: 'attackProfile.statHighRiskRows',
      value: stats.criticalRows,
    })
  }
  if (stats.suspiciousSuccessAt) {
    cells.push({
      key: 'suspiciousSuccess',
      labelKey: 'attackProfile.statSuspiciousSuccess',
      value: formatTime(stats.suspiciousSuccessAt),
    })
  }
  cells.push(
    {
      key: 'firstSeen',
      labelKey: 'attackProfile.statFirstSeen',
      value: formatTime(stats.firstSeen),
    },
    { key: 'lastSeen', labelKey: 'attackProfile.statLastSeen', value: formatTime(stats.lastSeen) }
  )
  return cells
})

const actionLabel = (code) => toActionLabel(t, code)

const topLists = computed(() => {
  const p = props.profile
  const items = (list, mapper = (value) => value) =>
    (list || []).map((item) => ({ ...item, value: mapper(item.value) }))
  return [
    {
      key: 'paths',
      titleKey: 'attackProfile.topPaths',
      valueLabel: t('attackProfile.topPaths'),
      mono: true,
      items: items(p.topPaths),
    },
    {
      key: 'actions',
      titleKey: 'attackProfile.topActions',
      valueLabel: t('attackProfile.topActions'),
      items: items(p.topActions, actionLabel),
    },
    {
      key: 'accounts',
      titleKey: 'attackProfile.topAccounts',
      valueLabel: t('attackProfile.topAccounts'),
      mono: true,
      items: items(p.topTargetAccounts),
    },
    {
      key: 'agents',
      titleKey: 'attackProfile.topUserAgents',
      valueLabel: t('attackProfile.topUserAgents'),
      items: items(p.topUserAgents),
    },
  ]
})

const tagTypeForLevel = (level) => {
  if (level === 'critical' || level === 'high') return 'danger'
  if (level === 'medium') return 'warning'
  return 'info'
}

const scrollTo = (id) => {
  const el = typeof document === 'undefined' ? null : document.getElementById(id)
  el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}
</script>

<style scoped>
.load-alert {
  margin-bottom: var(--xf-spacing-md);
}
/* ===== 结论横幅：一眼看懂，不要求用户理解分类码 ===== */
.verdict-banner {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  padding: 18px 20px;
  border-radius: 12px;
  border-left: 5px solid var(--el-color-info);
  background: var(--el-fill-color-lighter);
}
.verdict--attack,
.verdict--compromised {
  border-left-color: var(--el-color-danger);
  background: var(--el-color-danger-light-9);
}
.verdict--suspicious,
.verdict--low {
  border-left-color: var(--el-color-warning);
  background: var(--el-color-warning-light-9);
}
.verdict--clean {
  border-left-color: var(--el-color-success);
  background: var(--el-color-success-light-9);
}
.verdict-main {
  min-width: 0;
}
.verdict-eyebrow {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
}
.verdict-title {
  font-family: var(--xf-font-display);
  font-size: 22px;
  font-weight: 700;
  margin: 4px 0 6px;
  color: var(--xf-gray-900);
}
.verdict-hint {
  margin: 0;
  font-size: var(--xf-font-size-sm);
  line-height: 1.7;
  color: var(--xf-gray-600);
}
.verdict-score {
  flex: 0 0 auto;
  text-align: right;
}
.score-value {
  font-family: var(--xf-font-display);
  font-size: 30px;
  font-weight: 700;
  line-height: 1.1;
  color: var(--xf-gray-900);
}
.score-unit {
  font-size: var(--xf-font-size-xs);
  font-weight: 400;
  color: var(--xf-gray-400);
}
.score-caption {
  margin-top: 6px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
}
.report-bar {
  margin-top: var(--xf-spacing-md);
  display: flex;
  justify-content: flex-end;
}
/* ===== 分区导航：长结果页可快速跳转，减少来回滚动 ===== */
.section-nav {
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: var(--xf-spacing-md);
  padding: 8px 0;
  background: var(--el-bg-color);
  border-bottom: 1px solid var(--xf-gray-200);
}
.section-nav__item {
  border: 1px solid var(--xf-gray-200);
  border-radius: 999px;
  background: var(--el-fill-color-lighter);
  color: var(--xf-gray-600);
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  padding: 4px 10px;
  cursor: pointer;
  transition:
    color 0.2s var(--xf-ease-glass),
    border-color 0.2s var(--xf-ease-glass);
}
.section-nav__item:hover {
  color: var(--xf-gray-900);
  border-color: var(--xf-gray-400);
}
.section-nav__item:focus-visible {
  outline: 2px solid var(--el-color-primary);
  outline-offset: 2px;
}
/* ===== 关键数据 ===== */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 10px;
}
.stat-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px 14px;
  border: 1px solid var(--xf-gray-200);
  border-radius: 10px;
  background: var(--el-fill-color-lighter);
}
.stat-value {
  font-family: var(--xf-font-display);
  font-size: 18px;
  font-weight: 600;
  color: var(--xf-gray-900);
}
.stat-label {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
}
/* ===== 建议 ===== */
.suggestion-list {
  margin: 0;
  padding-left: 22px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.suggestion-item {
  font-size: var(--xf-font-size-sm);
  line-height: 1.7;
  color: var(--xf-gray-700);
}
/* ===== 分类卡 ===== */
.category-card {
  border: 1px solid var(--xf-gray-200);
  border-radius: 12px;
  padding: 14px 16px;
  margin-bottom: 12px;
  background: #fff;
}
.category-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.category-title {
  display: flex;
  align-items: center;
  gap: 8px;
}
.category-name {
  font-family: var(--xf-font-display);
  font-weight: 600;
  font-size: var(--xf-font-size-base);
  color: var(--xf-gray-900);
}
.category-counts {
  display: flex;
  gap: 12px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-600);
}
.category-desc {
  margin: 8px 0 0;
  font-size: var(--xf-font-size-sm);
  line-height: 1.7;
  color: var(--xf-gray-700);
}
.evidence-hint {
  margin: 6px 0;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-400);
}
.category-tag {
  margin-right: 4px;
}
.sub-title {
  margin: 6px 0;
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-sm);
  font-weight: 600;
  color: var(--xf-gray-700);
}
.dist-row {
  display: flex;
  gap: var(--xf-spacing-lg);
  flex-wrap: wrap;
}
.dist-col {
  flex: 1 1 320px;
  min-width: 0;
}
.containment-summary {
  margin-bottom: 10px;
}
.section-title {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-base);
  font-weight: 600;
  margin: var(--xf-spacing-lg) 0 var(--xf-spacing-sm);
  color: var(--xf-gray-800);
  letter-spacing: var(--xf-tracking-wide);
  scroll-margin-top: 56px;
}
.mono {
  font-family: var(--xf-font-mono);
}
.muted {
  color: var(--xf-gray-400);
}
.empty-tip {
  font-family: var(--xf-font-body);
  text-align: center;
  padding: 18px 0;
  color: var(--xf-gray-400);
  font-size: var(--xf-font-size-sm);
}
/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .verdict-banner {
    flex-direction: column;
  }
  .verdict-score {
    text-align: left;
  }
  .dist-row {
    flex-direction: column;
  }
}
</style>
