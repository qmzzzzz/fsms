<template>
  <div class="page">
    <!-- 统计卡片 -->
    <el-row :gutter="16" class="stat-row">
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
        <el-radio-group v-model="filters.status" size="small" @change="loadData">
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
        <el-table-column prop="planStartTime" :label="$t('inspection.planStartTime')" width="170" />
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
              v-if="hasPerm('inspection:execute') && row.status === 'pending'"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              @click="handleStart(row)"
            >
              {{ $t('inspection.start') }}
            </button>
            <button
              v-if="hasPerm('inspection:execute') && row.status === 'in_progress'"
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
              {{ $t('common.operation') }}
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
import { api } from '@/utils/api'
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

// 竞态守卫：快速筛选/翻页时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()

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
      if (statsRes.data.success) {
        const s = statsRes.data.data
        statCards.value = [
          {
            title: t('inspection.pending'),
            value: s.pending || 0,
            color: '#64748b',
            icon: Calendar,
          },
          {
            title: t('inspection.inProgress'),
            value: s.inProgress || 0,
            color: '#d97706',
            icon: Tools,
          },
          {
            title: t('inspection.completed'),
            value: s.completed || 0,
            color: '#16a34a',
            icon: CircleCheckFilled,
          },
          { title: t('common.warning'), value: s.overdue || 0, color: '#e63946', icon: Bell },
        ]
      }
    } catch (_) {
      /* 忽略统计失败 */
    }
  } catch (e) {
    if (!isCurrent()) return
    // API 失败时展示空列表而非假数据，防止误导用户
    tableData.value = []
    page.total = 0
    ElMessage.warning(t('messages.loadFailed'))
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
    // 'cancel'/'close' 均为用户主动关闭确认框，不视为操作失败
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(t('messages.updateFailed'))
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
        ElMessage.error(t('messages.deleteFailed'))
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
