<template>
  <div class="page">
    <div class="glass glass-card">
      <div class="table-toolbar">
        <div class="toolbar-left">
          <!-- 黑白名单切换栏：普通/查询模式均保持可见；查询模式下用于切换查看命中名单类型 -->
          <GlassSegmented
            v-model="listType"
            :options="typeOptions"
            :aria-label="$t('ipList.typeSwitchLabel')"
            @change="onSegmentedChange"
          />

          <span v-if="!queryMode" class="list-desc">
            {{ listType === 'black' ? $t('security.blacklistDesc') : $t('security.whitelistDesc') }}
          </span>
          <!-- 查询模式：表格直接展示该名单类型的命中条目，便于对封禁 IP 直接操作（移除等） -->
          <span v-else class="query-mode-label">
            {{ $t('security.queryMode') }}：{{ queryResult?.ip || '' }}
          </span>
        </div>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          @click="queryMode ? clearQuery() : loadData()"
        >
          {{ $t('common.refresh') }}
        </button>
      </div>

      <!-- IP 命中查询：输入单地址，命中结果直接落入下方地址管理表格，便于对封禁 IP 直接操作 -->
      <div class="query-bar">
        <el-input
          v-model="queryForm.ip"
          :placeholder="$t('security.queryPlaceholder')"
          style="width: 280px"
          clearable
          maxlength="200"
          @keyup.enter="handleQuery"
        />
        <button
          type="button"
          class="glass-btn glass-btn--default"
          :disabled="querying"
          @click="handleQuery"
        >
          {{ querying ? $t('security.querying') : $t('security.queryMatch') }}
        </button>
        <template v-if="queryMode && queryResult">
          <el-tag :type="verdictTagType" size="large" effect="dark">
            {{ verdictText }}
          </el-tag>
          <span class="query-verdict-ip">{{ queryResult.ip }}</span>
          <span
            v-if="queryResult.normalizedIP && queryResult.normalizedIP !== queryResult.ip"
            class="query-verdict-normalized"
          >
            → {{ queryResult.normalizedIP }}
          </span>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--link"
            @click="clearQuery"
          >
            {{ $t('security.clearQuery') }}
          </button>
        </template>
      </div>

      <!-- 添加表单 -->
      <el-form :inline="true" :model="addForm" class="add-form">
        <el-form-item :label="$t('security.ipAddress')">
          <el-input
            v-model="addForm.ip"
            :placeholder="$t('security.ipPlaceholder')"
            style="width: 220px"
            clearable
            maxlength="200"
            @keyup.enter="handleAdd"
          />
        </el-form-item>
        <el-form-item :label="$t('security.duration')">
          <el-select v-model="addForm.durationHours" style="width: 130px">
            <el-option :label="$t('security.durationPermanent')" :value="0" />
            <el-option :label="$t('security.duration1h')" :value="1" />
            <el-option :label="$t('security.duration24h')" :value="24" />
            <el-option :label="$t('security.duration7d')" :value="168" />
            <el-option :label="$t('security.duration30d')" :value="720" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('common.reason')">
          <el-input
            v-model="addForm.reason"
            :placeholder="$t('security.reasonPlaceholder')"
            style="width: 200px"
            clearable
            maxlength="200"
            show-word-limit
          />
        </el-form-item>
        <el-form-item>
          <button
            type="button"
            class="glass-btn glass-btn--primary"
            :class="{ 'glass-btn--danger': listType === 'black' }"
            :disabled="adding"
            @click="handleAdd"
          >
            {{
              adding
                ? $t('common.adding')
                : listType === 'black'
                  ? $t('security.addToBlacklist')
                  : $t('security.addToWhitelist')
            }}
          </button>
        </el-form-item>
      </el-form>

      <!-- 名单表格：首屏骨架占位，数据到达后直接替换（带数据刷新时走表格内 loading） -->
      <GlassSkeleton
        v-if="loading && tableData.length === 0"
        variant="table"
        :rows="6"
        :cols="['16%', '9%', '9%', '16%', '13%', '16%', '10%']"
      />
      <el-table
        v-else
        v-loading="loading"
        :data="queryMode ? queryRows : tableData"
        border
        stripe
        style="width: 100%"
      >
        <el-table-column prop="ip" :label="$t('security.ipAddress')" min-width="160">
          <template #default="{ row }">
            <span class="ip-cell">{{ row.ip }}</span>
            <el-tag
              v-if="row.isPrimary"
              type="primary"
              size="small"
              effect="plain"
              class="primary-tag"
            >
              {{ $t('security.widestMatch') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.type')" width="90">
          <template #default="{ row }">
            <el-tag :type="row.type === 'black' ? 'danger' : 'success'" size="small">
              {{ row.type === 'black' ? $t('security.blacklist') : $t('security.whitelist') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.source')" width="90">
          <template #default="{ row }">
            <el-tag :type="row.source === 'auto' ? 'warning' : 'info'" size="small" effect="plain">
              {{ row.source === 'auto' ? $t('security.autoDetect') : $t('security.manualConfig') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="reason"
          :label="$t('common.reason')"
          min-width="160"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            {{ reasonText(row.reason) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('security.effectiveStatus')" width="130">
          <template #default="{ row }">
            <el-tag v-if="!row.expiresAt" type="success" size="small" effect="light">
              {{ $t('security.permanent') }}
            </el-tag>
            <span v-else class="expire-cell">
              {{ $t('security.until') }} {{ formatTime(row.expiresAt) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.createTime')" width="170">
          <template #default="{ row }">
            {{ formatTime(row.createdAt) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="100" fixed="right">
          <template #default="{ row }">
            <button
              type="button"
              class="glass-btn glass-btn--danger glass-btn--link"
              @click="handleRemove(row)"
            >
              {{ $t('common.remove') }}
            </button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 名单分页（查询模式展示命中条目，无分页意义） -->
      <div v-if="!queryMode" class="pagination">
        <el-pagination
          v-model:current-page="page.current"
          v-model:page-size="page.size"
          :total="page.total"
          :page-sizes="[20, 50, 100, 200]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="loadData"
          @size-change="handleSizeChange"
        />
      </div>

      <div
        v-if="!loading && (queryMode ? queryRows.length === 0 : tableData.length === 0)"
        class="empty-tip"
      >
        {{
          queryMode
            ? $t('security.noMatchFound')
            : listType === 'black'
              ? $t('security.noBlacklist')
              : $t('security.noWhitelist')
        }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
// O-3：时间格式化统一抽取（本地时区、hour12=false 单一口径）
import { formatTime } from '@/utils/datetime'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { apiClient } from '@/utils/api'
import { useLatestRequest } from '@/composables/useLatestRequest'
import GlassSegmented from '@/components/GlassSegmented.vue'

// locale 未使用：本视图的时间展示已统一走 utils/datetime.formatTime
// （固定本地时区 + hour12=false），不再依赖 toLocaleString 的 locale 参数
const { t } = useI18n()

const loading = ref(false)
const adding = ref(false)
const listType = ref('black')
const tableData = ref([])
// 名单分页：后端 /security/ip-list 支持分页，limit=200 一次性拉取会导致超出部分不可见
const page = reactive({ current: 1, size: 20, total: 0 })

// 校验 IPv4/IPv6 地址或 CIDR 网段格式（IPv4 每段 ≤255、前缀 ≤32；IPv6 粗校验、前缀 ≤128）
const validateIpOrCidr = (str) => {
  const s = String(str || '').trim()
  if (!s || /\s/.test(s)) return false
  const cidrMatch = s.match(/^(.+)\/(\d{1,3})$/)
  let addr = s
  let prefix = null
  if (cidrMatch) {
    addr = cidrMatch[1]
    prefix = parseInt(cidrMatch[2], 10)
  }
  const isV6 = addr.includes(':')
  if (isV6) {
    if (prefix !== null && prefix > 128) return false
    return /^[0-9a-fA-F:]+$/.test(addr)
  }
  if (prefix !== null && prefix > 32) return false
  const m = addr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return false
  return m.slice(1).every((part) => Number(part) <= 255)
}

const addForm = reactive({
  ip: '',
  durationHours: 0,
  reason: '',
})

// ===== IP 命中查询 =====
const queryForm = reactive({ ip: '' })
const querying = ref(false)
const queryResult = ref(null)
// 查询模式：true 时下方地址管理表格直接展示命中条目（便于对封禁 IP 直接操作）
const queryMode = ref(false)

const verdictText = computed(() => {
  const v = queryResult.value?.verdict
  if (v === 'whitelisted') return t('security.verdictWhitelisted')
  if (v === 'blocked') return t('security.verdictBlocked')
  return t('security.verdictAllowed')
})

const verdictTagType = computed(() => {
  const v = queryResult.value?.verdict
  if (v === 'whitelisted') return 'success'
  if (v === 'blocked') return 'danger'
  return 'info'
})

// 查询结果合并后按当前黑白名单切换过滤为表格行；
// 各组首位即覆盖面最宽的「主命中」（后端已按宽度优先排序），标记 isPrimary
const queryRows = computed(() => {
  if (!queryResult.value) return []
  const rows = []
  ;(queryResult.value.whiteMatches || []).forEach((entry, i) =>
    rows.push({ ...entry, isPrimary: i === 0 })
  )
  ;(queryResult.value.blackMatches || []).forEach((entry, i) =>
    rows.push({ ...entry, isPrimary: i === 0 })
  )
  return rows.filter((entry) => entry.type === listType.value)
})

const handleQuery = async () => {
  const ip = queryForm.ip.trim()
  if (!ip) {
    ElMessage.warning(t('security.ipRequired'))
    return
  }
  if (!validateIpOrCidr(ip)) {
    ElMessage.warning(t('ipList.invalidFormat'))
    return
  }
  querying.value = true
  try {
    const res = await apiClient.get('/security/ip-list/query', { params: { ip } })
    queryResult.value = res?.data?.data || null
    queryMode.value = true
    // 默认切换到存在命中的名单类型（用户当前选择优先），避免表格误显示空态
    if (queryResult.value) {
      const hasBlack = (queryResult.value.blackMatches || []).length > 0
      const hasWhite = (queryResult.value.whiteMatches || []).length > 0
      if (listType.value === 'black' && !hasBlack && hasWhite) listType.value = 'white'
      else if (listType.value === 'white' && !hasWhite && hasBlack) listType.value = 'black'
    }
  } catch (e) {
    // 错误已在拦截器统一提示
    queryResult.value = null
    queryMode.value = false
  } finally {
    querying.value = false
  }
}

// 黑白名单切换：查询模式下仅切换命中列表的名单类型（computed 自动响应），普通模式重置页码后重新拉取列表
const onSegmentedChange = () => {
  if (!queryMode.value) {
    page.current = 1
    loadData()
  }
}

// 清除查询，恢复名单全量列表
const clearQuery = () => {
  queryMode.value = false
  queryResult.value = null
  queryForm.ip = ''
  page.current = 1
  loadData()
}

// 分段控件计数（黑白各自总数）
const blackCount = ref(0)
const whiteCount = ref(0)

// 分段计数：普通模式显示名单总数；查询模式显示该 IP 在各名单类型的命中数
const typeOptions = computed(() => [
  {
    label: t('security.blacklist'),
    value: 'black',
    count: queryMode.value ? queryResult.value?.blackMatches?.length || 0 : blackCount.value,
  },
  {
    label: t('security.whitelist'),
    value: 'white',
    count: queryMode.value ? queryResult.value?.whiteMatches?.length || 0 : whiteCount.value,
  },
])

// 常见内部原因码转可读文案
const reasonText = (reason) => {
  const map = {
    security_policy: t('security.securityPolicy'),
    brute_force_auto_ban: t('security.bruteForceBan'),
    manual_configuration: t('security.manualConfig'),
    trusted_source: t('security.trustedSource'),
  }
  return map[reason] || reason || '-'
}

// 竞态守卫：快速切换黑白名单时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  try {
    // 后端在同一响应内返回分页列表、分页总数与黑/白名单计数，无需再发一次全量请求
    const res = await apiClient.get('/security/ip-list', {
      params: { type: listType.value, page: page.current, limit: page.size },
    })
    if (!isCurrent()) return
    const payload = res?.data?.data || {}
    tableData.value = payload.list || []
    page.total = payload.pagination?.total || tableData.value.length
    blackCount.value = payload.counts?.black || 0
    whiteCount.value = payload.counts?.white || 0
  } catch (e) {
    if (!isCurrent()) return
    ElMessage.error(t('messages.loadFailed'))
    tableData.value = []
    page.total = 0
  } finally {
    if (isCurrent()) loading.value = false
  }
}

// 分页大小变化：回到第一页再加载，避免停留在超出结果集的页码上
const handleSizeChange = () => {
  page.current = 1
  loadData()
}

const handleAdd = async () => {
  const ip = addForm.ip.trim()
  if (!ip) {
    ElMessage.warning(t('security.ipRequired'))
    return
  }
  if (!validateIpOrCidr(ip)) {
    ElMessage.warning(t('ipList.invalidFormat'))
    return
  }

  adding.value = true
  try {
    await apiClient.post('/security/ip-list', {
      ip,
      type: listType.value,
      reason:
        addForm.reason.trim() ||
        (listType.value === 'black' ? 'manual_configuration' : 'trusted_source'),
      durationHours: Number(addForm.durationHours) || 0,
    })
    ElMessage.success(
      `${t('security.added')} ${ip} ${listType.value === 'black' ? t('security.blacklist') : t('security.whitelist')}`
    )
    addForm.ip = ''
    addForm.reason = ''
    // 新增条目按时间倒序排在第一页，回到首页以便立即看到
    page.current = 1
    loadData()
  } catch (e) {
    // 错误已在拦截器统一提示
  } finally {
    adding.value = false
  }
}

const handleRemove = async (row) => {
  try {
    await ElMessageBox.confirm(
      `${t('messages.deleteConfirm')} ${row.ip}?`,
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
    await apiClient.delete(`/security/ip-list/${row._id}`)
    ElMessage.success(t('messages.deleteSuccess'))
    // 查询模式下保持结果视图，重新查询以同步判定与命中列表
    if (queryMode.value) {
      handleQuery()
    } else {
      loadData()
    }
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') {
      // O-6: 点右上角 X(close) 亦属用户主动放弃，不误报删除失败
      ElMessage.error(t('messages.deleteFailed'))
    }
  }
}

onMounted(() => {
  loadData()
})
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
.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--xf-spacing-lg);
  flex-wrap: wrap;
  gap: 12px;
  font-family: var(--xf-font-body);
  letter-spacing: var(--xf-tracking-wide);
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}
.toolbar-left {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-lg);
  flex-wrap: wrap;
}
.list-desc {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  max-width: 420px;
  letter-spacing: var(--xf-tracking-wide);
}
.add-form {
  margin-bottom: var(--xf-spacing-md);
}
.ip-cell {
  font-family: var(--xf-font-mono);
  font-weight: 600;
  color: var(--xf-gray-800);
}
.expire-cell {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-warning-strong);
}
.empty-tip {
  font-family: var(--xf-font-body);
  text-align: center;
  padding: 32px 0;
  color: var(--xf-gray-400);
  font-size: var(--xf-font-size-base);
}
.query-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: var(--xf-spacing-md);
  flex-wrap: wrap;
}
.query-mode-label {
  font-family: var(--xf-font-body);
  font-weight: 600;
  color: var(--xf-gray-800);
  letter-spacing: var(--xf-tracking-wide);
}
.query-verdict-ip {
  font-family: var(--xf-font-mono);
  font-weight: 600;
  color: var(--xf-gray-800);
}
.query-verdict-normalized {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
}
.primary-tag {
  margin-left: 6px;
}

/* ===== 移动端适配 ===== */
@media (max-width: 768px) {
  .query-bar {
    flex-wrap: wrap;
  }
  .query-bar .el-input {
    flex: 1 1 100%;
    width: 100% !important;
  }
  .query-bar .glass-btn {
    flex: 1;
  }
  .add-form .el-input,
  .add-form .el-select {
    width: 100% !important;
  }
}
.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--xf-spacing-lg);
  font-family: var(--xf-font-mono);
}

/* ===== Apple 风格增量（交互手感层：只叠反馈与过渡，不改布局） ===== */

/* 可交互元素按压即时反馈（pointer-down，非松开） */
.el-button:active {
  transform: scale(0.97);
  transition: transform 100ms ease-out;
}

/* 卡片 hover 轻浮起（可中断阴影过渡，无弹跳，克制） */
.el-card {
  transition: box-shadow 280ms cubic-bezier(0.32, 0.72, 0, 1);
}
.el-card:hover {
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08);
}

/* 表格行背景平滑渐变，避免斑马纹/状态色跳变 */
:deep(.el-table .el-table__row td.el-table__cell) {
  transition: background-color 150ms ease;
}

/* 标签（el-tag）hover 轻微加深，仅提示可读性 */
:deep(.el-tag) {
  transition: opacity 150ms ease;
}

/* 无障碍降级：本页新增动效全部纳入 reduced-motion */
@media (prefers-reduced-motion: reduce) {
  .el-button:active {
    transform: none !important;
  }
  .el-card {
    transition: opacity 150ms ease !important;
  }
  .el-card:hover {
    box-shadow: none !important;
  }
  :deep(.el-table .el-table__row td.el-table__cell) {
    transition: none !important;
  }
}
</style>
