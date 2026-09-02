<template>
  <div class="page">
    <div class="glass glass-card">
      <div class="table-toolbar">
        <div class="left glass-btn-group">
          <button
            v-if="hasPerm('user:create')"
            type="button"
            class="glass-btn glass-btn--primary"
            @click="handleAdd"
          >
            {{ $t('user.addUser') }}
          </button>
          <button type="button" class="glass-btn glass-btn--default" @click="loadData">
            {{ $t('common.refresh') }}
          </button>
          <div v-if="hasPerm('security:config')" class="config-switches">
            <div class="switch-item">
              <div
                class="glass-switch"
                :class="{
                  'glass-switch--checked': registrationEnabled,
                  'glass-switch--loading': registrationLoading,
                }"
                @click="!registrationLoading && handleRegistrationToggle(!registrationEnabled)"
              >
                <div class="glass-switch__handle" />
              </div>
              <span class="glass-switch__label">{{
                registrationEnabled ? $t('security.allowPublicRegistration') : $t('common.disabled')
              }}</span>
              <el-tooltip :content="$t('security.registrationTip')" placement="bottom">
                <el-icon class="switch-tip">
                  <QuestionFilled />
                </el-icon>
              </el-tooltip>
            </div>
            <div class="switch-item">
              <div
                class="glass-switch"
                :class="{
                  'glass-switch--checked': loginCaptchaEnabled,
                  'glass-switch--loading': loginCaptchaLoading,
                }"
                @click="!loginCaptchaLoading && handleLoginCaptchaToggle(!loginCaptchaEnabled)"
              >
                <div class="glass-switch__handle" />
              </div>
              <span class="glass-switch__label">{{
                loginCaptchaEnabled
                  ? $t('security.loginCaptcha') + ' ON'
                  : $t('security.loginCaptcha') + ' OFF'
              }}</span>
              <el-tooltip :content="$t('security.loginCaptchaTip')" placement="bottom">
                <el-icon class="switch-tip">
                  <QuestionFilled />
                </el-icon>
              </el-tooltip>
            </div>
            <div class="switch-item">
              <div
                class="glass-switch"
                :class="{
                  'glass-switch--checked': registerCaptchaEnabled,
                  'glass-switch--loading': registerCaptchaLoading,
                }"
                @click="
                  !registerCaptchaLoading && handleRegisterCaptchaToggle(!registerCaptchaEnabled)
                "
              >
                <div class="glass-switch__handle" />
              </div>
              <span class="glass-switch__label">{{
                registerCaptchaEnabled
                  ? $t('security.registerCaptcha') + ' ON'
                  : $t('security.registerCaptcha') + ' OFF'
              }}</span>
              <el-tooltip :content="$t('security.registerCaptchaTip')" placement="bottom">
                <el-icon class="switch-tip">
                  <QuestionFilled />
                </el-icon>
              </el-tooltip>
            </div>
          </div>
        </div>
        <el-input
          v-model="filters.keyword"
          :placeholder="$t('user.username') + '/' + $t('auth.email')"
          maxlength="100"
          clearable
          style="width: 240px"
          @update:model-value="debouncedSearch"
          @keyup.enter="handleSearch"
          @clear="handleSearch"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
      </div>
      <!-- 首屏骨架占位；数据到达后直接替换（带数据刷新时走表格内 loading） -->
      <GlassSkeleton
        v-if="loading && tableData.length === 0"
        variant="table"
        :rows="6"
        :cols="['6%', '18%', '11%', '13%', '13%', '14%', '9%', '16%']"
      />
      <el-table v-else v-loading="loading" :data="tableData" border stripe style="width: 100%">
        <el-table-column type="index" label="#" width="60" />
        <el-table-column :label="$t('user.title')" min-width="180">
          <template #default="{ row }">
            <div class="user-cell">
              <el-avatar :size="32" class="user-avatar">
                {{ (row.username || 'U').slice(0, 1).toUpperCase() }}
              </el-avatar>
              <div class="user-meta">
                <div class="uname">
                  {{ row.username }}
                </div>
                <div class="uemail" :title="row.email">
                  {{ row.email }}
                </div>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="realName" :label="$t('user.realName')" width="120" />
        <el-table-column prop="department" :label="$t('user.department')" width="140" />
        <el-table-column prop="phone" :label="$t('user.phone')" width="140" />
        <el-table-column :label="$t('user.roles')" width="160">
          <template #default="{ row }">
            <el-tag
              v-for="r in (row.roles || []).slice(0, 2)"
              :key="r.code || r._id || r"
              size="small"
              style="margin-right: 4px"
            >
              {{ r.name || r.code || r }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="$t('common.status')" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'info'" effect="light">
              {{ row.status === 'active' ? $t('user.active') : $t('user.inactive') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('user.mfa')" width="90">
          <template #default="{ row }">
            <el-tag :type="row.mfaEnabled ? 'success' : 'info'" effect="plain" size="small">
              {{ row.mfaEnabled ? $t('user.mfaOn') : $t('user.mfaOff') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="300" fixed="right">
          <template #default="{ row }">
            <button
              v-if="hasPerm('user:update')"
              type="button"
              class="glass-btn glass-btn--primary glass-btn--link"
              @click="handleEdit(row)"
            >
              {{ $t('common.edit') }}
            </button>
            <button
              v-if="hasPerm('role:assign')"
              type="button"
              class="glass-btn glass-btn--warning glass-btn--link"
              @click="handleRole(row)"
            >
              {{ $t('user.assignRoles') }}
            </button>
            <button
              v-if="hasPerm('user:reset_password') && row.mfaEnabled && !authStore.isSelf(row._id)"
              type="button"
              class="glass-btn glass-btn--warning glass-btn--link"
              @click="handleResetMfa(row)"
            >
              {{ $t('user.resetMfa') }}
            </button>
            <button
              v-if="hasPerm('user:delete') && !authStore.isSelf(row._id)"
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
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="loadData"
          @size-change="handleSearch"
        />
      </div>
    </div>

    <!-- 新增/编辑用户对话框 -->
    <el-dialog
      v-model="dialog.visible"
      :title="dialog.isEdit ? $t('user.editUser') : $t('user.addUser')"
      width="560px"
      @close="resetForm"
    >
      <el-form ref="formRef" :model="dialog.form" :rules="dialog.rules" label-width="100px">
        <el-form-item :label="$t('auth.username')" prop="username">
          <el-input
            v-model="dialog.form.username"
            :placeholder="$t('validation.usernameLen')"
            maxlength="30"
            :disabled="dialog.isEdit"
          />
        </el-form-item>
        <el-form-item :label="$t('auth.email')" prop="email">
          <el-input
            v-model="dialog.form.email"
            :placeholder="$t('register.emailPlaceholder')"
            maxlength="254"
          />
        </el-form-item>
        <el-form-item v-if="!dialog.isEdit" :label="$t('auth.password')" prop="password">
          <el-input
            id="newUserPassword"
            v-model="dialog.form.password"
            name="password"
            type="password"
            :placeholder="$t('validation.passwordMin')"
            maxlength="64"
            show-password
            autocomplete="new-password"
          />
        </el-form-item>
        <el-form-item :label="$t('user.realName')" prop="realName">
          <el-input
            v-model="dialog.form.realName"
            :placeholder="$t('validation.realNameRequired')"
            maxlength="50"
          />
        </el-form-item>
        <el-form-item :label="$t('user.department')" prop="department">
          <el-input
            v-model="dialog.form.department"
            :placeholder="$t('register.departmentPlaceholder')"
            maxlength="100"
          />
        </el-form-item>
        <el-form-item :label="$t('user.phone')" prop="phone">
          <el-input
            v-model="dialog.form.phone"
            :placeholder="$t('register.phonePlaceholder')"
            maxlength="20"
          />
        </el-form-item>
        <el-form-item :label="$t('common.status')" prop="status">
          <el-select
            v-model="dialog.form.status"
            :placeholder="$t('messages.selectRequired')"
            style="width: 100%"
          >
            <el-option :label="$t('user.active')" value="active" />
            <el-option :label="$t('user.inactive')" value="inactive" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('user.allowedIPs')" prop="allowedIPs">
          <el-input
            v-model="dialog.form.allowedIPs"
            type="textarea"
            :rows="4"
            maxlength="8192"
            show-word-limit
            :placeholder="$t('user.allowedIPsPlaceholder')"
          />
          <div class="ip-range-hint">
            <div class="ip-range-hint__title">
              {{ $t('user.allowedIPsHint') }}
            </div>
            <pre class="ip-range-hint__samples">{{ IP_RANGE_SAMPLES }}</pre>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <button type="button" class="glass-btn glass-btn--default" @click="dialog.visible = false">
          {{ $t('common.cancel') }}
        </button>
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="dialog.submitting"
          @click="submitForm"
        >
          {{ dialog.isEdit ? $t('common.save') : $t('common.add') }}
        </button>
      </template>
    </el-dialog>

    <!-- 分配角色对话框 -->
    <el-dialog v-model="roleDialog.visible" :title="$t('user.assignRoles')" width="400px">
      <el-form label-width="80px">
        <el-form-item :label="$t('user.title')">
          <span>{{ roleDialog.username }}</span>
        </el-form-item>
        <el-form-item :label="$t('user.roles')">
          <el-select
            v-model="roleDialog.selectedRoles"
            multiple
            :placeholder="$t('messages.selectRequired')"
            style="width: 100%"
          >
            <el-option
              v-for="role in availableRoles"
              :key="role._id || role.id"
              :label="role.name"
              :value="role._id || role.id"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          @click="roleDialog.visible = false"
        >
          {{ $t('common.cancel') }}
        </button>
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="roleDialog.submitting"
          @click="submitRoleAssignment"
        >
          {{ $t('common.save') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Search, QuestionFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { api } from '@/utils/api'
import { passwordStrengthRule } from '@/utils/password'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { useAuthStore } from '@/store'

const { hasPerm } = usePermission()
const { t } = useI18n()
const authStore = useAuthStore()

const loading = ref(false)
const filters = reactive({ keyword: '' })
const formRef = ref(null)

// 注册开关
const registrationEnabled = ref(false)
const registrationLoading = ref(false)

const tableData = ref([])
const availableRoles = ref([])

const page = reactive({ current: 1, size: 10, total: 0 })

// IP 范围格式示例（与后端 utils/ipRange 支持的语法一一对应）
const IP_RANGE_SAMPLES = [
  '192.168.1.1',
  '192.168.1.1-254',
  '192.168.1.1/24',
  '192.168.1.*',
  '192.168.1-10.*',
  '!192.168.1.1',
  '2001::db8:2003',
  '2001::db8:2003/96',
  '!2001::db8:2003',
].join('\n')

const dialog = reactive({
  visible: false,
  isEdit: false,
  submitting: false,
  form: {
    _id: null,
    username: '',
    email: '',
    password: '',
    realName: '',
    department: '',
    phone: '',
    status: 'active',
    allowedIPs: '',
  },
  rules: {
    username: [
      { required: true, message: t('validation.usernameRequired'), trigger: 'blur' },
      { min: 3, max: 30, message: t('validation.usernameLen'), trigger: 'blur' },
      { pattern: /^[a-zA-Z0-9_]+$/, message: t('validation.usernamePattern'), trigger: 'blur' },
    ],
    email: [
      { required: true, message: t('validation.emailRequired'), trigger: 'blur' },
      { type: 'email', message: t('validation.emailInvalid'), trigger: 'blur' },
    ],
    password: [
      { required: true, message: t('validation.passwordRequired'), trigger: 'blur' },
      passwordStrengthRule(t('validation.passwordMin')),
    ],
    realName: [{ required: true, message: t('validation.realNameRequired'), trigger: 'blur' }],
    status: [{ required: true, message: t('messages.selectRequired'), trigger: 'change' }],
  },
})

const roleDialog = reactive({
  visible: false,
  username: '',
  userId: null,
  selectedRoles: [],
  submitting: false,
})

// 关键词防抖定时器
let searchTimer = null

// 搜索条件变更时回到第一页，避免停留在超出结果集的页码上看到空列表；
// 同时清掉未触发的防抖定时器，防止回车/清空后再补发一次重复请求
const handleSearch = () => {
  if (searchTimer) {
    clearTimeout(searchTimer)
    searchTimer = null
  }
  page.current = 1
  loadData()
}

// 关键词防抖：停止输入 300ms 后自动搜索（含页码重置），回车仍可立即触发
const debouncedSearch = () => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    searchTimer = null
    handleSearch()
  }, 300)
}

// 竞态守卫：快速搜索/翻页时丢弃过期的旧响应，防止旧数据覆盖新结果
const listGuard = useLatestRequest()

const loadData = async () => {
  const isCurrent = listGuard()
  loading.value = true
  try {
    const res = await api.users.getList({
      page: page.current,
      limit: page.size,
      search: filters.keyword,
    })
    if (!isCurrent()) return
    const payload = res?.data?.data
    const list = Array.isArray(payload) ? payload : []
    tableData.value = list
    page.total = res?.data?.pagination?.total || list.length
  } catch (e) {
    if (!isCurrent()) return
    ElMessage.error(t('messages.loadFailed'))
    tableData.value = []
    page.total = 0
  } finally {
    if (isCurrent()) loading.value = false
  }
}

// 加载注册开关状态
const loadRegistrationConfig = async () => {
  try {
    const res = await api.security.getRegistrationConfig()
    registrationEnabled.value = res?.data?.data?.allowPublicRegistration || false
  } catch (e) {
    // 接口不存在或权限不足时静默忽略
  }
}

// 切换注册开关
const handleRegistrationToggle = async (val) => {
  const prev = registrationEnabled.value
  registrationEnabled.value = val
  registrationLoading.value = true
  try {
    await api.security.setRegistrationConfig({ allowPublicRegistration: val })
    ElMessage.success(
      `${val ? t('common.enabled') : t('common.disabled')} ${t('security.allowPublicRegistration')}`
    )
  } catch (e) {
    // 失败时回滚开关状态
    registrationEnabled.value = prev
    ElMessage.error(e?.response?.data?.message || t('common.failed'))
  } finally {
    registrationLoading.value = false
  }
}

// 登录验证码开关
const loginCaptchaEnabled = ref(false)
const loginCaptchaLoading = ref(false)

// 加载登录验证码开关状态
const loadLoginCaptchaConfig = async () => {
  try {
    const res = await api.security.getLoginCaptchaConfig()
    loginCaptchaEnabled.value = res?.data?.data?.loginCaptchaEnabled || false
  } catch (e) {
    // 接口不存在或权限不足时静默忽略
  }
}

// 切换登录验证码开关
const handleLoginCaptchaToggle = async (val) => {
  const prev = loginCaptchaEnabled.value
  loginCaptchaEnabled.value = val
  loginCaptchaLoading.value = true
  try {
    await api.security.setLoginCaptchaConfig({ loginCaptchaEnabled: val })
    ElMessage.success(
      `${val ? t('common.enabled') : t('common.disabled')} ${t('security.loginCaptcha')}`
    )
  } catch (e) {
    // 失败时回滚开关状态
    loginCaptchaEnabled.value = prev
    ElMessage.error(e?.response?.data?.message || t('common.failed'))
  } finally {
    loginCaptchaLoading.value = false
  }
}

// 注册验证码开关
const registerCaptchaEnabled = ref(true)
const registerCaptchaLoading = ref(false)

// 加载注册验证码开关状态
const loadRegisterCaptchaConfig = async () => {
  try {
    const res = await api.security.getRegisterCaptchaConfig()
    registerCaptchaEnabled.value = res?.data?.data?.registerCaptchaEnabled ?? true
  } catch (e) {
    // 接口不存在或权限不足时保持默认开启
  }
}

// 切换注册验证码开关
const handleRegisterCaptchaToggle = async (val) => {
  const prev = registerCaptchaEnabled.value
  registerCaptchaEnabled.value = val
  registerCaptchaLoading.value = true
  try {
    await api.security.setRegisterCaptchaConfig({ registerCaptchaEnabled: val })
    ElMessage.success(
      `${val ? t('common.enabled') : t('common.disabled')} ${t('security.registerCaptcha')}`
    )
  } catch (e) {
    registerCaptchaEnabled.value = prev
    ElMessage.error(e?.response?.data?.message || t('common.failed'))
  } finally {
    registerCaptchaLoading.value = false
  }
}

const loadAvailableRoles = async () => {
  try {
    const res = await api.roles.getAll()
    availableRoles.value = res?.data?.data || []
  } catch (e) {
    availableRoles.value = []
    ElMessage.error(t('messages.loadFailed'))
  }
}

const handleAdd = () => {
  dialog.isEdit = false
  dialog.form._id = null
  dialog.form.username = ''
  dialog.form.email = ''
  dialog.form.password = ''
  dialog.form.realName = ''
  dialog.form.department = ''
  dialog.form.phone = ''
  dialog.form.status = 'active'
  dialog.form.allowedIPs = ''
  dialog.visible = true
}

const handleEdit = (row) => {
  dialog.isEdit = true
  dialog.form._id = row._id
  dialog.form.username = row.username
  dialog.form.email = row.email
  dialog.form.realName = row.realName || ''
  dialog.form.department = row.department || ''
  dialog.form.phone = row.phone || ''
  dialog.form.status = row.status || 'active'
  dialog.form.allowedIPs = row.allowedIPs || ''
  dialog.visible = true
}

const handleRole = async (row) => {
  roleDialog.username = row.username
  roleDialog.userId = row._id
  roleDialog.selectedRoles = (row.roles || []).map((r) => r._id || r.id)
  await loadAvailableRoles()
  roleDialog.visible = true
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      `${t('messages.deleteConfirm')}「${row.username}」?`,
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
    await api.users.delete(row._id || row.id)
    ElMessage.success(t('messages.deleteSuccess'))
    loadData()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(t('messages.deleteFailed'))
    }
  }
}

/** 管理员重置用户两步验证（丢失认证器时的救济操作，成功后该用户被强制下线） */
const handleResetMfa = async (row) => {
  try {
    await ElMessageBox.confirm(
      `${t('user.resetMfaConfirm')}「${row.username}」?`,
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
    await api.security.resetUserMfa(row._id || row.id)
    ElMessage.success(t('user.resetMfaSuccess'))
    loadData()
  } catch (_) {
    // 取消确认或失败原因已在拦截器提示
  }
}

const submitForm = async () => {
  if (!formRef.value) return
  try {
    const valid = await formRef.value.validate()
    if (!valid) return
  } catch (e) {
    return
  }
  dialog.submitting = true
  try {
    const payload = {
      username: dialog.form.username,
      email: dialog.form.email,
      realName: dialog.form.realName,
      department: dialog.form.department,
      phone: dialog.form.phone,
      status: dialog.form.status,
      allowedIPs: dialog.form.allowedIPs,
    }
    if (!dialog.isEdit) {
      payload.password = dialog.form.password
      await api.users.create(payload)
      ElMessage.success(t('messages.createSuccess'))
    } else {
      await api.users.update(dialog.form._id, payload)
      ElMessage.success(t('messages.updateSuccess'))
    }
    dialog.visible = false
    loadData()
  } catch (e) {
    ElMessage.error(dialog.isEdit ? t('messages.updateFailed') : t('messages.createFailed'))
  } finally {
    dialog.submitting = false
  }
}

const submitRoleAssignment = async () => {
  roleDialog.submitting = true
  try {
    await api.users.assignRoles(roleDialog.userId, {
      roles: roleDialog.selectedRoles,
    })
    ElMessage.success(t('messages.saveSuccess'))
    roleDialog.visible = false
    loadData()
  } catch (e) {
    ElMessage.error(t('messages.saveFailed'))
  } finally {
    roleDialog.submitting = false
  }
}

const resetForm = () => {
  dialog.form = {
    _id: null,
    username: '',
    email: '',
    password: '',
    realName: '',
    department: '',
    phone: '',
    status: 'active',
    allowedIPs: '',
  }
  if (formRef.value) {
    formRef.value.clearValidate()
  }
}

onMounted(() => {
  loadData()
  // P3-37：两个开关的读写接口都要求 security:config。无该权限时不能发请求——
  // 原实现无条件调用，虽然本地 catch 是静默的，但 api.js 的响应拦截器
  // 对所有 403 统一弹红框，结果是「有 stats 无 config」的用户一进页面就吃两个 403 toast。
  // 与开关的显隐条件用同一个权限码，保证「看得到就点得动、点不动就看不到」。
  if (hasPerm('security:config')) {
    loadRegistrationConfig()
    loadLoginCaptchaConfig()
    loadRegisterCaptchaConfig()
  }
})

onUnmounted(() => {
  // 清理搜索防抖定时器，防止组件卸载后仍触发请求
  if (searchTimer) {
    clearTimeout(searchTimer)
    searchTimer = null
  }
})
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.ip-range-hint {
  margin-top: 6px;
  padding: 8px 10px;
  border-radius: var(--xf-radius-sm, 6px);
  background: var(--xf-gray-50, rgba(0, 0, 0, 0.03));
  font-size: var(--xf-font-size-xs, 12px);
  line-height: 1.6;
  color: var(--xf-gray-600, #6b7280);
  width: 100%;
}
.ip-range-hint__title {
  margin-bottom: 4px;
}
.ip-range-hint__samples {
  margin: 0;
  font-family: var(--xf-font-mono, monospace);
  white-space: pre;
  color: var(--xf-gray-700, #374151);
}
.glass-card {
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}
.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--xf-spacing-lg);
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
.config-switches {
  display: flex;
  align-items: center;
  gap: 24px;
  margin-left: 16px;
  padding-left: 16px;
  border-left: 1px solid var(--xf-border-color);
}
.switch-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.switch-tip {
  color: var(--xf-gray-400);
  cursor: help;
  font-size: var(--xf-font-size-base);
}
.user-cell {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.user-avatar {
  flex-shrink: 0;
}
.user-meta {
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.uname {
  font-family: var(--xf-font-body);
  font-weight: 600;
  color: var(--xf-gray-900);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.uemail {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  color: var(--xf-gray-500);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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
