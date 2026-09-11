<template>
  <div class="page">
    <el-row :gutter="16">
      <!-- 左侧：角色列表 -->
      <el-col :xs="24" :md="8">
        <div class="glass-panel glass-panel--role">
          <div class="panel-header">
            <span class="panel-title">{{ $t('role.title') }}</span>
            <button
              type="button"
              class="glass-btn glass-btn--primary glass-btn--sm"
              @click="handleAdd"
            >
              <span class="role-add-icon">+</span>
              <span>{{ $t('common.add') }}</span>
            </button>
          </div>
          <!-- 角色列表（D-2 拆为 RoleListPanel 组件） -->
          <RoleListPanel
            :roles="roles"
            :current-role="currentRole"
            :loading="loadingRoleList"
            @select="handleCurrentChange"
            @delete="handleDelete"
          />
        </div>
      </el-col>

      <!-- 右侧：权限模块 -->
      <el-col :xs="24" :md="16">
        <div class="glass-panel glass-panel--permission">
          <div class="panel-header">
            <div class="panel-title-group">
              <span class="panel-title">{{ $t('role.permissions') }}</span>
              <span v-if="currentRole" class="panel-subtitle">
                <span class="role-tag">{{ currentRole.name }}</span>
                <span v-if="currentRole.isBuiltIn" class="role-tag role-tag--builtin">{{
                  $t('role.builtIn')
                }}</span>
              </span>
            </div>
            <div v-if="currentRole" class="header-actions">
              <span v-if="hasUnsavedChanges" class="unsaved-hint">{{
                $t('messages.unsavedChanges')
              }}</span>
              <button
                type="button"
                class="glass-btn glass-btn--default glass-btn--sm"
                @click="resetChecked"
              >
                {{ $t('common.reset') }}
              </button>
              <button
                type="button"
                class="glass-btn glass-btn--primary glass-btn--sm"
                :disabled="savingPermissions"
                @click="savePermissions"
              >
                {{ savingPermissions ? $t('common.adding') : $t('role.assignPermissions') }}
              </button>
            </div>
          </div>

          <!-- 空状态 -->
          <div v-if="!currentRole" class="empty-state">
            <div class="empty-state__icon">🔐</div>
            <p>{{ $t('role.selectRole') }}</p>
          </div>

          <template v-else>
            <!-- 统计摘要 + 权限搜索 -->
            <div class="perm-toolbar">
              <div class="perm-summary">
                <span class="perm-summary__item">
                  {{ $t('role.permTotal') }} <b>{{ totalPermCount }}</b>
                </span>
                <span class="perm-summary__item is-on">
                  {{ $t('role.permEnabled') }} <b>{{ checkedCount }}</b>
                </span>
                <span v-if="addedCount > 0" class="perm-summary__item is-added">
                  {{ $t('role.permAdded') }} <b>+{{ addedCount }}</b>
                </span>
                <span v-if="removedCount > 0" class="perm-summary__item is-removed">
                  {{ $t('role.permRemoved') }} <b>-{{ removedCount }}</b>
                </span>
              </div>
              <el-input
                v-model="permSearch"
                :placeholder="$t('role.searchPerm')"
                maxlength="50"
                clearable
                size="small"
                class="perm-search"
              >
                <template #prefix>
                  <el-icon><Search /></el-icon>
                </template>
              </el-input>
            </div>

            <!-- 权限模块网格 -->
            <div v-if="loadingTree && moduleList.length === 0" class="module-grid">
              <GlassSkeleton
                v-for="i in 4"
                :key="i"
                variant="table"
                :rows="3"
                :cols="['55%', '45%']"
                style="height: 100%"
              />
            </div>
            <div v-loading="loadingTree" class="module-grid">
              <!-- 权限模块卡片（D-2 拆为 PermissionModuleCard 组件，
                   useRolePermissions 状态机经 ui 属性传入） -->
              <PermissionModuleCard
                v-for="module in filteredModules"
                :key="module.module"
                :module="module"
                :ui="rolePermUi"
              />

              <!-- 搜索无结果 -->
              <div v-if="filteredModules.length === 0 && !loadingTree" class="perm-empty-search">
                {{ $t('role.noPermFound') }}「{{ permSearch }}」
              </div>
            </div>
          </template>
        </div>
      </el-col>
    </el-row>

    <!-- 新增角色对话框（组件化，提交成功回调 created） -->
    <RoleFormDialog v-model:visible="dialogVisible" @created="onRoleCreated" />
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { ElNotification } from 'element-plus/es/components/notification/index.mjs'
import { Search } from '@element-plus/icons-vue'
import { api } from '@/utils/api'
import { acquireWebSocket, releaseWebSocket } from '@/utils/websocket'
import { useRolePermissions } from '@/composables/useRolePermissions'
import { useLatestRequest } from '@/composables/useLatestRequest'
import RoleFormDialog from '@/components/RoleFormDialog.vue'
// D-2：角色列表与权限模块卡片拆为子组件
import RoleListPanel from '@/components/RoleListPanel.vue'
import PermissionModuleCard from '@/components/PermissionModuleCard.vue'

const { t } = useI18n()

const roles = ref([])
const currentRole = ref(null)
const savingPermissions = ref(false)
const loadingTree = ref(false)
const loadingRoleList = ref(false)
const dialogVisible = ref(false)

// ===== 权限编辑状态机（自本视图拆出，含勾选集合/模块列表/搜索/统计/差异显示） =====
// D-2：完整对象同时传给 PermissionModuleCard 作渲染层状态机
const rolePermUi = useRolePermissions()
const {
  hasUnsavedChanges,
  permSearch,
  checkedPermIds,
  setTree,
  setChecked,
  clearChecked,
  resetChecked,
  totalPermCount,
  checkedCount,
  addedCount,
  removedCount,
  filteredModules,
  moduleList,
} = rolePermUi

const handleAdd = () => {
  dialogVisible.value = true
}

// 加载角色列表
const loadRoles = async (forceSelect = false) => {
  loadingRoleList.value = true
  try {
    const res = await api.roles.getList()
    const payload = res?.data?.data
    roles.value = Array.isArray(payload) ? payload : []
    if (forceSelect && roles.value.length > 0) {
      currentRole.value = roles.value[0]
      await loadRolePermissions(currentRole.value._id)
    } else if (!currentRole.value && roles.value.length > 0) {
      currentRole.value = roles.value[0]
      await loadRolePermissions(currentRole.value._id)
    }
  } catch (e) {
    // 失败原因已在拦截器统一提示
    roles.value = []
  } finally {
    loadingRoleList.value = false
  }
}

// 加载权限树
const loadPermissionTree = async () => {
  loadingTree.value = true
  try {
    const res = await api.roles.getPermissionTree()
    setTree(res?.data?.data)
  } catch (e) {
    // 失败原因已在拦截器统一提示
    setTree([])
  } finally {
    loadingTree.value = false
  }
}

// 角色切换竞态守卫：快速连点角色时，过期的 getById 响应在写回前被丢弃
const roleGuard = useLatestRequest()

// 加载角色的权限
const loadRolePermissions = async (roleId) => {
  if (!roleId) return
  const isCurrent = roleGuard()
  try {
    if (filteredModules.value.length === 0) {
      await loadPermissionTree()
    }
    const res = await api.roles.getById(roleId)
    if (!isCurrent()) return
    const roleData = res?.data?.data
    const permissions = roleData?.permissions || []
    setChecked(permissions.map((p) => p._id || p.id).filter(Boolean))
  } catch (e) {
    if (!isCurrent()) return
    setChecked([])
  }
}

// 切换角色
const handleCurrentChange = async (row) => {
  if (!row) return
  if (hasUnsavedChanges.value) {
    try {
      await ElMessageBox.confirm(t('role.unsavedConfirm'), t('messages.confirmTitle'), {
        confirmButtonText: t('role.discardChanges'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      })
    } catch {
      // 用户取消：停留在当前角色，无需重拉列表
      return
    }
  }
  currentRole.value = row
  await loadPermissionTree()
  await loadRolePermissions(row._id)
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      `${t('messages.deleteConfirm')}「${row.name}」?`,
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
    await api.roles.delete(row._id)
    ElMessage.success(t('messages.deleteSuccess'))
    const wasCurrent = currentRole.value?._id === row._id
    if (wasCurrent) {
      currentRole.value = null
      clearChecked()
      await loadRoles(true)
    } else {
      await loadRoles()
    }
  } catch (e) {
    // 取消删除或失败原因已在拦截器统一提示
  }
}

// 新建角色成功：刷新列表并选中新角色
const onRoleCreated = async (newRole) => {
  await loadRoles()
  if (newRole) {
    currentRole.value = newRole
    await loadRolePermissions(newRole._id)
  }
}

// 保存权限
const savePermissions = async () => {
  if (!currentRole.value) {
    ElMessage.warning(t('role.selectRole'))
    return
  }
  savingPermissions.value = true
  try {
    const permIds = Array.from(checkedPermIds.value)

    // P3-43：空权限集是合法操作，不再直接拒绝。
    // 原实现把「清空权限」当成「忘选权限」拦下，导致无法「临时冻结角色」——
    // 而这恰恰是应急场景最需要的动作：某角色被发现权限配置有误时，
    // 运维希望先摘掉全部权限止损、再慢慢重配，而不是逐个取消勾选后发现存不了，
    // 只能改为删除角色（连带解绑所有持有者，且不可逆）。
    // 后端 assignPermissions 接受空数组，此处只需二次确认防误触。
    if (permIds.length === 0) {
      try {
        await ElMessageBox.confirm(t('role.clearPermConfirm'), t('role.clearPermTitle'), {
          confirmButtonText: t('common.confirm'),
          cancelButtonText: t('common.cancel'),
          type: 'warning',
        })
      } catch {
        savingPermissions.value = false
        return
      }
    }

    const payload = { permissions: permIds }

    // 内置角色全局修改风险提示：文案与实际行为一致（当前走全局修改，影响所有持有者）
    if (currentRole.value.isBuiltIn) {
      try {
        await ElMessageBox.confirm(t('role.builtinConfirm'), t('role.builtinTitle'), {
          confirmButtonText: t('common.confirm'),
          cancelButtonText: t('common.cancel'),
          type: 'warning',
        })
      } catch {
        savingPermissions.value = false
        return
      }
    }

    await api.roles.assignPermissions(currentRole.value._id, payload)
    ElMessage.success(t('messages.saveSuccess'))
    await loadRolePermissions(currentRole.value._id)
    await loadRoles()
  } catch (e) {
    // 失败原因已在拦截器统一提示
  } finally {
    savingPermissions.value = false
  }
}

// WebSocket
// 持有本页取得的连接引用：卸载时据此精确解绑自己注册的监听
let wsRef = null

const initWebSocket = () => {
  try {
    // acquire 而非 connect：引用计数机制下，本页卸载时只释放自己的引用，
    // 布局层的权限同步订阅不会被连带拆掉
    const ws = acquireWebSocket()
    wsRef = ws
    // 角色管理页需要房间广播（role-updated / permissions-updated）。
    // 该房间要求 SUPER_ADMIN/SECURITY_ADMIN —— 能进本页说明已有 role:read，
    // 但两者并非等价，后端拒绝时只回一条 error 事件，不影响其余功能
    ws.joinRoom('role-management')
    // P3-43：重连耗尽后必须明确告知用户。此前连接静默死亡，页面照常显示
    // 旧数据——用户会以为「没人改过角色」，实际是推送早就断了。
    // 用 ElNotification 且 duration=0（不自动消失）：这条信息决定了
    // 用户是否该信任眼前的数据，不能一闪而过。
    ws.onGiveUp(() => {
      ElNotification({
        title: t('common.warning'),
        message: t('role.wsDisconnected'),
        type: 'warning',
        duration: 0,
      })
    })
    ws.on('role-updated', handleRoleUpdated)
    ws.on('permissions-updated', handlePermissionsUpdated)
  } catch (error) {
    // 静默处理
  }
}

/** 角色本身变更（新建/删除/改名）：只需刷新列表 */
const handleRoleUpdated = () => {
  loadRoles()
}

/**
 * 角色权限集变更：刷新管理界面上的权限树与当前选中角色的已选项
 *
 * 注意这里**不**刷新 authStore —— 那由布局层的 usePermissionSync 统一处理。
 * 本事件是房间广播（发给所有管理员），而管理员自己的权限未必受影响；
 * 「我的权限变了」由后端定向下发的 permission-sync 负责，两者职责不同。
 */
const handlePermissionsUpdated = () => {
  loadPermissionTree()
  if (currentRole.value) {
    loadRolePermissions(currentRole.value._id)
  }
}

// 路由离开拦截：有未保存的权限变更时先确认，确认后放行并清状态
onBeforeRouteLeave(async () => {
  if (!hasUnsavedChanges.value) return true
  try {
    await ElMessageBox.confirm(t('messages.unsavedChanges'), t('messages.confirmTitle'), {
      type: 'warning',
    })
    hasUnsavedChanges.value = false
    return true
  } catch (_) {
    return false
  }
})

// 浏览器级离开拦截：刷新/关闭页签前提醒未保存的变更（仅提示，无法阻止）
const handleBeforeUnload = (e) => {
  if (!hasUnsavedChanges.value) return
  e.preventDefault()
  e.returnValue = ''
}

onMounted(async () => {
  window.addEventListener('beforeunload', handleBeforeUnload)
  initWebSocket()
  // 两者内部均已自行捕获异常，无依赖关系，并行加载加快首屏渲染
  await Promise.all([loadPermissionTree(), loadRoles()])
})

onUnmounted(() => {
  window.removeEventListener('beforeunload', handleBeforeUnload)
  // 只解绑本页的监听并释放一次引用；布局层的权限同步仍持有引用，连接保持。
  // wsRef 为 null 说明 initWebSocket 建连失败，此时未 acquire 也不应 release
  if (!wsRef) return
  wsRef.off('role-updated', handleRoleUpdated)
  wsRef.off('permissions-updated', handlePermissionsUpdated)
  releaseWebSocket()
  wsRef = null
})
</script>

<style scoped>
/* ==========================================================================
   说明：按钮样式完全复用全局 .glass-btn 体系（global.css 设计令牌驱动），
   本组件不再定义任何与全局冲突的按钮样式，仅保留布局与组件特有视觉。
   ========================================================================== */

/* ========== 基础布局 ========== */
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 8px 0;
}

/* ========== 液态玻璃面板 ========== */
.glass-panel {
  background: var(--xf-bg-glass-strong);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid var(--xf-border-glass);
  border-radius: var(--xf-radius-xl);
  box-shadow: var(--xf-glass-edge), var(--xf-shadow-lg);
  padding: var(--xf-spacing-xl);
  height: 100%;
  transition: box-shadow var(--xf-duration-base) var(--xf-ease-standard);
}

.glass-panel:hover {
  box-shadow: var(--xf-glass-edge-hover), var(--xf-shadow-xl);
}

/* ========== 面板头部 ========== */
.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--xf-spacing-lg);
  padding-bottom: 12px;
  border-bottom: 1px solid var(--xf-border-color);
}

.panel-title-group {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-md);
}

.panel-title {
  font-size: var(--xf-font-size-md);
  font-weight: 700;
  color: var(--xf-gray-800);
  letter-spacing: 0.3px;
}

.panel-subtitle {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-sm);
}

.role-tag {
  display: inline-block;
  padding: 2px 10px;
  font-size: var(--xf-font-size-xs);
  font-weight: 600;
  color: var(--xf-gray-600);
  background: var(--xf-gray-50);
  border-radius: 12px;
  border: 1px solid var(--xf-border-color);
}

.role-tag--builtin {
  color: var(--xf-warning-strong);
  background: var(--xf-warning-alpha-8);
  border-color: var(--xf-warning-alpha-15);
}

.header-actions {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-sm);
}

.unsaved-hint {
  font-size: var(--xf-font-size-xs);
  color: var(--xf-warning);
  font-weight: 500;
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
}

/* 角色列表样式已随组件迁入 RoleListPanel.vue（D-2） */

.module-grid::-webkit-scrollbar {
  width: 5px;
}

.module-grid::-webkit-scrollbar-thumb {
  background: var(--xf-border-color-strong);
  border-radius: 5px;
}

.role-add-icon {
  font-size: 14px;
  font-weight: 700;
  line-height: 1;
}

/* ========== 空状态 ========== */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 80px 20px;
  color: var(--xf-gray-400);
}

.empty-state__icon {
  font-size: 56px;
  margin-bottom: var(--xf-spacing-lg);
  filter: grayscale(0.3);
}

.empty-state p {
  font-size: var(--xf-font-size-base);
  margin: 0;
}

/* ========== 统计摘要 + 搜索工具条 ========== */
.perm-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--xf-spacing-lg);
  flex-wrap: wrap;
  margin-bottom: var(--xf-spacing-lg);
}

.perm-summary {
  display: flex;
  align-items: center;
  gap: var(--xf-spacing-md);
  flex-wrap: wrap;
}

.perm-summary__item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 12px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
  background: var(--xf-gray-50);
  border: 1px solid var(--xf-border-color);
  border-radius: 999px;
  white-space: nowrap;
}

.perm-summary__item b {
  font-weight: 700;
  color: var(--xf-gray-800);
}

.perm-summary__item.is-on {
  background: var(--xf-primary-alpha-8);
  border-color: var(--xf-primary-alpha-15);
}

.perm-summary__item.is-on b {
  color: var(--xf-primary-strong);
}

.perm-summary__item.is-added {
  background: var(--xf-success-alpha-8);
  border-color: var(--xf-success-alpha-15);
}

.perm-summary__item.is-added b {
  color: var(--xf-success-strong);
}

.perm-summary__item.is-removed {
  background: var(--xf-warning-alpha-8);
  border-color: var(--xf-warning-alpha-15);
}

.perm-summary__item.is-removed b {
  color: var(--xf-warning-strong);
}

.perm-search {
  width: 220px;
  flex-shrink: 0;
}

/* ========== 权限模块网格 ========== */
.module-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: var(--xf-spacing-lg);
  max-height: 620px;
  overflow-y: auto;
  padding-right: 6px;
  padding-top: 4px;
}

.perm-empty-search {
  grid-column: 1 / -1;
  text-align: center;
  padding: 48px 20px;
  color: var(--xf-gray-400);
  font-size: var(--xf-font-size-base);
}

/* 权限模块卡片与权限项按钮样式已随组件迁入 PermissionModuleCard.vue（D-2） */

/* ========== 触屏与减动效兼容 ========== */
@media (prefers-reduced-motion: reduce) {
  .unsaved-hint {
    transition: none;
    animation: none;
  }
}

/* ========== 响应式 ========== */
@media (max-width: 768px) {
  .module-grid {
    grid-template-columns: 1fr;
  }

  .glass-panel {
    padding: 14px;
    border-radius: var(--xf-radius-lg);
  }

  .perm-toolbar {
    flex-direction: column;
    align-items: stretch;
  }

  .perm-search {
    width: 100%;
  }

  .panel-header {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--xf-spacing-sm);
  }
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
