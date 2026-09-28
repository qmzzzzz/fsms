<template>
  <div class="page">
    <!-- 统计卡片：首屏没拿到统计时整排换成失败块，四个数字位不以 0 面孔出现 -->
    <div v-if="statsFailed && !statsLoadedOnce" class="stats-failed">
      <span>{{ $t('messages.loadFailed') }}</span>
      <button type="button" class="glass-btn glass-btn--sm" @click="loadData">
        {{ $t('common.refresh') }}
      </button>
    </div>
    <el-row v-else :gutter="16" class="stat-row">
      <el-col v-for="s in statCards" :key="s.title" :xs="12" :sm="6">
        <el-card shadow="hover" class="mini-stat">
          <div class="mini-stat-body">
            <el-icon :size="32" :color="s.color">
              <component :is="s.icon" />
            </el-icon>
            <div>
              <div class="num">
                {{ s.value }}
              </div>
              <div class="label">
                {{ s.title }}
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 列表 -->
    <div class="glass glass-card">
      <div class="table-toolbar">
        <div class="left glass-btn-group">
          <button
            v-if="hasPerm('inspection:create')"
            type="button"
            class="glass-btn glass-btn--primary"
            @click="handleAdd"
          >
            {{ $t('inspection.createInspection') }}
          </button>
          <button type="button" class="glass-btn glass-btn--default" @click="loadData">
            {{ $t('common.refresh') }}
          </button>
        </div>
        <el-radio-group v-model="filters.status" size="small" @change="handleFilterChange">
          <el-radio-button value="">
            {{ $t('common.all') }}
          </el-radio-button>
          <el-radio-button value="pending">
            {{ $t('inspection.pending') }}
          </el-radio-button>
          <el-radio-button value="in_progress">
            {{ $t('inspection.inProgress') }}
          </el-radio-button>
          <el-radio-button value="completed">
            {{ $t('inspection.completed') }}
          </el-radio-button>
        </el-radio-group>
      </div>
      <!-- 首屏骨架占位；数据到达后直接替换（带数据刷新时走表格内 loading） -->
      <GlassSkeleton
        v-if="loading && tableData.length === 0"
        variant="table"
        :rows="6"
        :cols="['6%', '16%', '10%', '12%', '16%', '10%', '10%', '20%']"
      />
      <el-table v-else v-loading="loading" :data="tableData" border stripe style="width: 100%">
        <el-table-column type="index" label="#" width="60" />
        <el-table-column prop="title" :label="$t('inspection.inspectionTitle')" min-width="160" />
        <el-table-column prop="inspectionType" :label="$t('common.type')" width="100">
          <template #default="{ row }">
            <el-tag size="small">
              {{ typeMap[row.inspectionType] }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('inspection.assignedTo')" width="120">
          <template #default="{ row }">
            <span v-if="row.assignedTo?.length">{{
              row.assignedTo.map((u) => u.realName || u.username).join(', ')
            }}</span>
            <span v-else class="muted">{{ $t('common.noData') }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('inspection.planStartTime')" width="170">
          <template #default="{ row }">
            <!-- 直接 prop 会把 ISO UTC 串原样渲染（东八区 09:00 显示成 01:00）；
                 走 utils/datetime 的本地时区口径（O-3 单一事实来源） -->
            {{ formatTime(row.planStartTime) }}
          </template>
        </el-table-column>
        <el-table-column prop="result" :label="$t('inspection.result')" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.result" :type="resultType(row.result)" size="small">
              {{ resultMap[row.result] }}
            </el-tag>
            <span v-else class="muted">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="$t('common.status')" width="110">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" effect="light">
              {{ statusMap[row.status] }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="280" fixed="right">
          <template #default="{ row }">
            <button
              v-if="hasPerm('inspection:execute') && STARTABLE.includes(row.status)"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              @click="handleStart(row)"
            >
              {{ $t('inspection.start') }}
            </button>
            <button
              v-if="hasPerm('inspection:execute') && SUBMITTABLE.includes(row.status)"
              type="button"
              class="glass-btn glass-btn--success glass-btn--link"
              @click="handleComplete(row)"
            >
              {{ $t('inspection.complete') }}
            </button>
            <button
              v-if="hasPerm('inspection:review') && row.status === 'completed'"
              type="button"
              class="glass-btn glass-btn--warning glass-btn--link"
              @click="handleReview(row)"
            >
              {{ $t('inspection.review') }}
            </button>
            <button
              type="button"
              class="glass-btn glass-btn--default glass-btn--link"
              @click="detail(row)"
            >
              {{ $t('common.detail') }}
            </button>
            <button
              v-if="hasPerm('inspection:delete') && row.status !== 'in_progress'"
              type="button"
              class="glass-btn glass-btn--danger glass-btn--link"
              @click="handleDelete(row)"
            >
              {{ $t('common.delete') }}
            </button>
          </template>
        </el-table-column>
      </el-table>
      <div class="pagination">
        <el-pagination
          v-model:current-page="page.current"
          v-model:page-size="page.size"
          :total="page.total"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="loadData"
          @size-change="
            () => {
              page.current = 1
              loadData()
            }
          "
        />
      </div>
    </div>

    <!-- 巡检表单对话框 -->
    <InspectionForm
      v-model="visible"
      :edit-data="editData"
      :disabled="formReadonly"
      @success="loadData"
    />

    <!-- 完成巡检对话框 -->
    <InspectionCompleteForm
      v-model="completeVisible"
      :inspection-id="currentInspection?._id || ''"
      :inspection-title="currentInspection?.title"
      @success="loadData"
    />

    <!-- 审核巡检对话框 -->
    <InspectionReviewForm
      v-model="reviewVisible"
      :inspection-id="currentInspection?._id || ''"
      @success="loadData"
    />
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed, shallowRef } from 'vue'
import { useI18n } from 'vue-i18n'
import { CircleCheckFilled, Tools, Bell, Calendar } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { api, isCanceledError } from '@/utils/api'
import { formatTime } from '@/utils/datetime'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'
import InspectionForm from '@/components/InspectionForm.vue'
import InspectionCompleteForm from '@/components/InspectionCompleteForm.vue'
import InspectionReviewForm from '@/components/InspectionReviewForm.vue'

const { hasPerm } = usePermission()
const { t } = useI18n()

const loading = ref(false)
const filters = reactive({ status: '' })
const page = reactive({ current: 1, size: 10, total: 0 })
const tableData = ref([])

const typeMap = computed(() => ({
  daily: t('inspection.typeDaily'),
  weekly: t('inspection.typeWeekly'),
  monthly: t('inspection.typeMonthly'),
  quarterly: t('inspection.typeQuarterly'),
  annual: t('inspection.typeAnnual'),
  special: t('inspection.typeSpecial'),
}))
const statusMap = computed(() => ({
  pending: t('inspection.pending'),
  in_progress: t('inspection.inProgress'),
  completed: t('inspection.completed'),
  overdue: t('common.warning'),
  cancelled: t('common.cancel'),
}))
const resultMap = computed(() => ({
  normal: t('inspection.normal'),
  abnormal: t('inspection.abnormal'),
  partial: t('inspection.partial'),
}))
const statusType = (s) =>
  ({
    pending: 'info',
    in_progress: 'warning',
    completed: 'success',
    overdue: 'danger',
    cancelled: 'info',
  })[s]
const resultType = (r) => ({ normal: 'success', abnormal: 'danger', partial: 'warning' })[r]

const statCards = shallowRef([
  { title: t('inspection.pending'), value: 0, color: '#64748b', icon: Calendar },
  { title: t('inspection.inProgress'), value: 0, color: '#d97706', icon: Tools },
  { title: t('inspection.completed'), value: 0, color: '#16a34a', icon: CircleCheckFilled },
  { title: t('common.warning'), value: 0, color: '#e63946', icon: Bell },
])

// 「开始 / 提交结果」的可进入档位，与后端 src/constants/inspection.js 的
// INSPECTION_STARTABLE_STATUSES / INSPECTION_SUBMITTABLE_STATUSES 同口径（两边都含 overdue）。
// overdue 是调度器打的时间标记、不是工作流阶段：只按 pending / in_progress 亮按钮时，
// 过了计划结束时间的巡检在界面上没有任何入口开工或补录结果，
// 而巡检结果与发现项只能挂在 completed 上 ⇒ 真实做过的工作永久无法入库（后端明确接受这两条路径）。
// 同一条 overdue 行两个按钮都在是对的：未开工的人点「开始」、已填一半的人直接「提交结果」，
// 后端对两种跳转都放行且 actualStartTime 只记首次开工时刻。
const STARTABLE = ['pending', 'overdue']
const SUBMITTABLE = ['in_progress', 'overdue']

// 统计是否拿到过：首屏失败（含列表本身失败导致统计没发出去）时整排换成失败块，
// 已经显示过真实计数后再刷新失败则保留上一次已知数字（与 AlarmView 同口径）。
const statsFailed = ref(false)
const statsLoadedOnce = ref(false)

// 竞态守卫：快速筛选/翻页时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()

// 换筛选条件必须回到第 1 页：筛选后的结果集一般比「全部」小，
// 停在第 N 页发出去的是 page=N + 新条件 ⇒ 表格空白而 total 仍显示有数据。
// AlarmView / DeviceView / AuditLogView 都是这个口径。
const handleFilterChange = () => {
  page.current = 1
  loadData()
}

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  try {
    const res = await api.inspections.getList({
      page: page.current,
      limit: page.size,
      status: filters.status,
    })
    if (!isCurrent()) return
    // 后端 ApiResponse.paginated 返回 { success, message, data, pagination }
    const payload = res?.data?.data
    const list = Array.isArray(payload) ? payload : payload?.list || payload?.items || []
    tableData.value = list
    // 使用后端返回的分页总数，而非当前页数据长度
    page.total = res?.data?.pagination?.total || list.length

    // 统计
    try {
      const statsRes = await api.inspections.getStats()
      // 列表侧有 isCurrent 守卫、统计侧此前没有：被新筛选条件取代的旧统计后到时
      // 会把新条件下的计数覆盖成上一条件的（页面上表现为「数字与表格对不上」且无声）。
      if (!isCurrent()) return
      // statsRes.data 缺失（畸形/被中间层改写）时读 .success 会抛，被下面的 catch 吞掉，
      // 四张卡就以 0 面孔出现——与「真的没有巡检」无法区分。
      if (statsRes?.data?.success) {
        const s = statsRes.data.data
        // 后端 /api/inspections/stats 返回 { total, byStatus:[{_id,count}], byType, byResult }，
        // 状态计数是 $group 后的 [{_id:status,count}] 数组，而非 pending/inProgress 平铺字段。
        // 直接读 s.pending 恒为 undefined → 四张统计卡永远是 0（谎报「无巡检」）。_id 取模型
        // 枚举原值：pending / in_progress / completed / overdue。
        const by = (k) => (s.byStatus || []).find((x) => x._id === k)?.count || 0
        statCards.value = [
          {
            title: t('inspection.pending'),
            value: by('pending'),
            color: '#64748b',
            icon: Calendar,
          },
          {
            title: t('inspection.inProgress'),
            value: by('in_progress'),
            color: '#d97706',
            icon: Tools,
          },
          {
            title: t('inspection.completed'),
            value: by('completed'),
            color: '#16a34a',
            icon: CircleCheckFilled,
          },
          { title: t('common.warning'), value: by('overdue'), color: '#e63946', icon: Bell },
        ]
        statsLoadedOnce.value = true
        statsFailed.value = false
      } else {
        statsFailed.value = true
      }
    } catch (e) {
      // FE-L1：路由切换 abort 的在途统计不记账为失败（用户已离开本页）
      if (isCanceledError(e) || !isCurrent()) return
      // 旧口径是 catch (_) { /* 忽略统计失败 */ }：首屏统计失败后四张卡恒为 0/0/0/0，
      // 值班员读作「无巡检」，而真实情况是「没拿到数据」。
      statsFailed.value = true
    }
  } catch (e) {
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    // API 失败时展示空列表而非假数据，防止误导用户
    tableData.value = []
    page.total = 0
    ElMessage.warning(t('messages.loadFailed'))
    // 统计请求只在上面的列表成功分支里发出：首屏列表就失败 ⇒ 统计也从没拿到过，
    // 那四个数字位同样不能以 0 面孔出现（读作「无巡检」）。
    // 已经显示过真实计数时不动它——保留上一次已知值，别把「刷新失败」伪装成「数据归零」。
    if (!statsLoadedOnce.value) statsFailed.value = true
  } finally {
    if (isCurrent()) loading.value = false
  }
}

const visible = ref(false)
const editData = ref(null)
// 详情打开的表单为只读模式（隐藏保存按钮），新建时恢复可编辑
const formReadonly = ref(false)
const completeVisible = ref(false)
const reviewVisible = ref(false)
const currentInspection = ref(null)

const handleAdd = () => {
  editData.value = null
  formReadonly.value = false
  visible.value = true
}
const handleStart = async (row) => {
  try {
    await ElMessageBox.confirm(
      `${t('messages.startConfirm')}「${row.title}」?`,
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
    await api.inspections.start(row._id)
    ElMessage.success(t('messages.updateSuccess'))
    loadData()
  } catch (error) {
    // 'cancel'/'close' 均为用户主动关闭确认框，不视为操作失败；
    // 其余错误已在拦截器统一提示（2026-09-26 审计：泛化 toast 会双提示并覆盖具体语义）
    if (error !== 'cancel' && error !== 'close') {
      // 已由拦截器提示
    }
  }
}
const handleComplete = (row) => {
  currentInspection.value = row
  completeVisible.value = true
}
const handleReview = (row) => {
  currentInspection.value = row
  reviewVisible.value = true
}
const detail = (row) => {
  editData.value = row
  formReadonly.value = true
  visible.value = true
}
const handleDelete = (row) => {
  ElMessageBox.confirm(
    `${t('messages.deleteConfirm')}「${row.title}」?`,
    t('messages.confirmTitle'),
    { type: 'warning' }
  )
    .then(async () => {
      try {
        await api.inspections.delete(row._id)
        ElMessage.success(t('messages.deleteSuccess'))
        loadData()
      } catch (error) {
        // 错误已在拦截器统一提示（2026-09-26 审计：泛化 toast 会双提示并覆盖具体语义）
      }
    })
    .catch(() => {})
}

onMounted(loadData)
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.stat-row {
  margin-bottom: 4px;
}

/* 统计失败块：与 AlarmView 同形（文案 + 刷新），替换整排数字卡而不是把它们写成 0 */
.stats-failed {
  display: flex;
  gap: var(--xf-spacing-md);
  align-items: center;
  margin-bottom: var(--xf-spacing-md);
}

.mini-stat {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}
.stat-row :deep(.el-col:nth-child(1)) .mini-stat {
  animation-delay: 0.05s;
}
.stat-row :deep(.el-col:nth-child(2)) .mini-stat {
  animation-delay: 0.1s;
}
.stat-row :deep(.el-col:nth-child(3)) .mini-stat {
  animation-delay: 0.15s;
}
.stat-row :deep(.el-col:nth-child(4)) .mini-stat {
  animation-delay: 0.2s;
}

.mini-stat :deep(.el-card__body) {
  padding: 16px;
}
.mini-stat-body {
  display: flex;
  align-items: center;
  gap: 16px;
}
.mini-stat-body .num {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-xl);
  font-weight: 700;
  letter-spacing: var(--xf-tracking-tight);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
  color: var(--xf-gray-900);
}
.mini-stat-body .label {
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  letter-spacing: var(--xf-tracking-wide);
  text-transform: uppercase;
}
.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--xf-spacing-lg);
  font-family: var(--xf-font-body);
  letter-spacing: var(--xf-tracking-wide);
}
.muted {
  color: var(--xf-gray-400);
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-sm);
  letter-spacing: var(--xf-tracking-wide);
}
.glass-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.25s;
}
.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--xf-spacing-lg);
  font-family: var(--xf-font-body);
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
