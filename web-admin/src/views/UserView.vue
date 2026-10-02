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
        <el-table-column type="index" label="#" width="50" />
        <el-table-column :label="$t('user.userColumn')" min-width="160">
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
        <el-table-column prop="realName" :label="$t('user.realName')" width="110" />
        <el-table-column prop="department" :label="$t('user.department')" width="120" />
        <!-- 手机号读的是服务端下发的 phoneMasked（脱敏在 services/userService.js
             的 toMaskedAdminUser 完成）。前端不再打码：maskPhone 不幂等，
             对 `138****5678` 再打一次会得到 `****`；要看明文走编辑框里的「查看完整号码」。 -->
        <el-table-column prop="phoneMasked" :label="$t('user.phone')" width="130">
          <template #default="{ row }">
            {{ row.phoneMasked || '-' }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('user.roles')" width="150">
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
        <el-table-column prop="status" :label="$t('common.status')" width="90">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)" effect="light">
              {{ statusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('user.mfa')" width="80">
          <template #default="{ row }">
            <el-tag :type="row.mfaEnabled ? 'success' : 'info'" effect="plain" size="small">
              {{ row.mfaEnabled ? $t('user.mfaOn') : $t('user.mfaOff') }}
            </el-tag>
          </template>
        </el-table-column>
        <!-- 列宽预算：主内容区 1440-220(侧栏)-48(边距)=1172px，
             全列合计须 ≤1172，否则固定列被推出视口（实测曾溢出 115px） -->
        <el-table-column :label="$t('common.operation')" width="230" fixed="right">
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
          <div class="phone-field">
            <el-input
              v-model="dialog.form.phone"
              :placeholder="dialog.isEdit ? '' : $t('register.phonePlaceholder')"
              maxlength="20"
            />
            <button
              v-if="dialog.isEdit"
              type="button"
              class="glass-btn glass-btn--link glass-btn--primary phone-field__reveal"
              @click="openReveal"
            >
              {{ $t('user.revealPhone') }}
            </button>
          </div>
          <!-- 两种状态要说两句不同的话：没揭示过="留空即不修改"，
               揭示过="现在框里是真值，删掉保存就是清空"。 -->
          <div v-if="dialog.isEdit" class="phone-field__hint">
            {{
              dialog.phoneBaseline === null
                ? $t('user.phoneKeepBlank')
                : $t('user.phoneAfterReveal')
            }}
          </div>
        </el-form-item>
        <el-form-item :label="$t('common.status')" prop="status">
          <el-select
            v-model="dialog.form.status"
            :placeholder="$t('messages.selectRequired')"
            style="width: 100%"
          >
            <el-option
              v-for="opt in statusOptions"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
              :disabled="opt.disabled"
            />
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
        <!--
          后端 assignRoles 校验 roles 为 isArray({min:1})：清空全部角色会 400。
          与其让用户点了才知道，不如按同一条业务规则（至少保留一个角色）禁用保存按钮。
        -->
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="roleDialog.submitting || roleDialog.selectedRoles.length === 0"
          @click="submitRoleAssignment"
        >
          {{ $t('common.save') }}
        </button>
      </template>
    </el-dialog>
    <!-- 手机号按需揭示（step-up）：明文唯一的出口是 POST /api/security/view-sensitive
         （服务端做口令复检 + 写 view_sensitive_data 审计，审计写失败即不返回明文）。
         揭示结果只进组件内存与下面的编辑框，不写任何 storage。 -->
    <el-dialog
      v-model="reveal.visible"
      :title="$t('user.revealPhoneTitle')"
      width="420px"
      append-to-body
      :close-on-click-modal="false"
      @closed="resetReveal"
    >
      <p class="reveal-hint">{{ $t('user.revealPhoneHint') }}</p>
      <el-form @submit.prevent>
        <el-form-item>
          <el-input
            v-model="reveal.password"
            type="password"
            show-password
            autocomplete="current-password"
            :placeholder="$t('auth.currentPassword')"
            @keydown.enter.prevent="enterSubmit($event, doReveal)"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <button type="button" class="glass-btn glass-btn--default" @click="reveal.visible = false">
          {{ $t('common.cancel') }}
        </button>
        <!-- 空口令不发请求：服务端必定 REAUTH_REQUIRED，白占一次 reauth 限流配额 -->
        <button
          type="button"
          class="glass-btn glass-btn--primary"
          :disabled="reveal.submitting || !reveal.password"
          @click="doReveal"
        >
          {{ $t('user.revealPhone') }}
        </button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, ref, reactive, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Search, QuestionFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { api, isCanceledError } from '@/utils/api'
import { encryptPassword } from '@/utils/loginCipher'
import { passwordStrengthRule } from '@/utils/password'
import { enterSubmit } from '@/utils/enterSubmit'
import { usePermission } from '@/composables/usePermission'
import { useLatestRequest } from '@/composables/useLatestRequest'
import { useAuthStore } from '@/store'

const { hasPerm } = usePermission()
const { t } = useI18n()
const authStore = useAuthStore()

/**
 * 账户状态的唯一呈现口径：列表标签与编辑下拉共用这一份。
 *
 * 后端 User.status 是三值枚举（models/User.js 的 enum: active/inactive/locked），
 * 而原先两处各自硬编码成两值：表格写 `status === 'active' ? 正常 : 禁用`，
 * 编辑框只列 active/inactive 两个选项。后果是**被管理员锁定的账户在列表里显示成"禁用"**——
 * 管理员锁定与管理员禁用是两回事（锁定可由专用接口解除、并会连带清 lockUntil 与失效权限缓存；
 * 禁用改的是登录语义），看错状态会直接导致错误的处置。
 *
 * 这里只统一"怎么显示"，不新增"能改成什么"：locked 在选项里置灰不可选
 * （锁定/解锁走专用接口，见 services/authService 的 lock/unlock 与审计动作 user_locked），
 * 但选项本身仍在，于是当前值 locked 能被显出来——原先下拉没有对应项，
 * 表单里 status 实际是 locked 却显示成空白，管理员改别的字段保存时看不见这个隐值。
 * 跨账户改状态服务端另需 user:lock 权限（controllers/userController 的三道闸门）。
 */
const USER_STATUS_META = {
  active: { type: 'success', key: 'user.active' },
  inactive: { type: 'info', key: 'user.inactive' },
  locked: { type: 'warning', key: 'user.locked' },
}
// 未知取值（后端枚举将来加了新值）原样显示，不塌缩成"禁用"
const statusLabel = (status) => {
  const meta = USER_STATUS_META[status]
  return meta ? t(meta.key) : String(status ?? '-')
}
const statusTagType = (status) => (USER_STATUS_META[status] || {}).type || 'info'
// 下拉选项同样从那张表推导，locked 置灰不可选：锁定/解锁走 PUT /api/security/users/:userId/lock
// （服务层会连带清 lockUntil 并写 user_locked 审计），让它可选等于开一条绕过该接口的旁路。
const statusOptions = computed(() =>
  Object.entries(USER_STATUS_META).map(([value, meta]) => ({
    value,
    label: t(meta.key),
    disabled: value === 'locked',
  }))
)

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
  // 手机号脏判定基线：null=本次编辑从未揭示过明文（列表只给 phoneMasked，
  // 回填它就是拿展示值去撞服务端的号码正则），string=已通过 step-up 揭示并把
  // 明文交给输入框，此时的值才是"可提交的现值"。提交时只有与基线不同才带 phone 键，
  // 理由见 submitForm 的注释。
  phoneBaseline: null,
  // 校验文案必须随语言切换重建：在 setup 顶层用 t(...) 求值一次只会得到
  // 一串**固化字符串**，用户在页内切语言后标签变了、错误提示还是旧语言。
  // 放进 reactive 的 computed 后，模板 :rules="dialog.rules" 无需改动
  // （reactive 会自动解包 ref）。
  rules: computed(() => ({
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
    // 与 userRoutes.js 的 /^1[3-9]\d{9}$/ 同一条正则（此前只有服务端判，
    // 用户要等一次往返才知道号码打错了）。留空不触发：空=不修改，见 phoneBaseline。
    phone: [{ pattern: /^1[3-9]\d{9}$/, message: t('validation.phonePattern'), trigger: 'blur' }],
    status: [{ required: true, message: t('messages.selectRequired'), trigger: 'change' }],
  })),
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
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    // P2-3：加载失败只清态，**提示由 api.js 响应拦截器统一负责**（与 alarmView 同契约）。
    // 报告 P2-3 的清单只列了 Device/Inspection/AuditLog/ipList 四处，本文件是**同型漏列**：
    // 组件这里再弹一条，同一次失败会弹两条（拦截器具体文案 + 组件泛化文案）。
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
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
    // P2-3：清态即可，提示由 api.js 响应拦截器统一负责（与 alarmView 同契约）。
    // 这是审计清单「四处视图」之外的同型漏列——同一次失败原本会弹两条。
    availableRoles.value = []
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
  dialog.phoneBaseline = null
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
  // 手机号**不回填**：列表给的是脱敏展示值（phoneMasked），把它当可写字段塞进表单
  // 会让一次"什么都没改"的保存拿 `138****5678` 去撞服务端的号码正则。
  // 要看/要改现值，走输入框旁边的「查看完整号码」（step-up + 审计）。
  dialog.form.phone = ''
  dialog.phoneBaseline = null
  dialog.form.status = row.status || 'active'
  dialog.form.allowedIPs = row.allowedIPs || ''
  dialog.visible = true
}

// 手机号按需揭示（step-up）的独立弹层状态。
// 明文在管理端只有一个出口：POST /api/security/view-sensitive——服务端先做当前口令
// （或 TOTP）复检，再写一条 view_sensitive_data 审计，且审计写入失败就不返回明文。
// 所以这里只传口令，不在本地做任何"能不能看"的判断。
const reveal = reactive({
  visible: false,
  submitting: false,
  password: '',
  userId: null,
})

// 口令的唯一清理点是下面 el-dialog 的 @closed，openReveal 只负责带入目标用户：
// 两处都清是冗余，且冗余的那处永远测不到（清理逻辑被改坏时测试照样绿）。
const openReveal = () => {
  reveal.userId = dialog.form._id
  reveal.visible = true
}

// 绑 el-dialog 的 @closed（动画结束、已离开 DOM）而不是 @close：
// 口令在请求还在飞的瞬间被清掉会让 doReveal 的守卫提前失败。
const resetReveal = () => {
  reveal.password = ''
  reveal.userId = null
  reveal.submitting = false
}

const doReveal = async () => {
  if (!reveal.password) return
  // 目标在发请求前定稿：step-up 弹层一关，下面的 resetReveal 就会把 reveal.userId 清空，
  // 那时再读它已经认不出"这份明文属于哪一行"。
  const targetUserId = reveal.userId
  reveal.submitting = true
  try {
    const res = await api.security.viewSensitive({
      dataType: 'phone',
      targetUserId,
      currentPassword: reveal.password,
    })
    // 迟到写入守卫：请求飞行期间用户可能已经 ESC 掉 step-up、关掉编辑框、
    // 甚至点了另一行的「编辑」。少这一道判断，A 的明文就会写进 B 的表单，
    // 基线（phoneBaseline）也一起变成 A 的号码 —— 用户照着"清空即删除"的提示
    // 删空再保存，抹掉的就是 B 的真实号码。
    // 只比 _id 就够：关掉编辑框会走 resetForm（_id 归 null），新增框同样是 null，
    // 所以"还开着、还是这一行"是唯一能放行写入的状态。
    if (dialog.form._id !== targetUserId) {
      reveal.visible = false
      return
    }
    // full 可能为空串（该用户从未填过号码）：此时基线也是空串，
    // 与"没揭示过"的 null 区分开，下面的提示文案据此切换。
    const full = res?.data?.data?.full ?? ''
    dialog.form.phone = full
    dialog.phoneBaseline = full
    reveal.visible = false
  } catch (_) {
    // 口令错 / 权限不足 / 限流 / 需要 MFA 都由 api.js 拦截器按 errorCode 弹一次，
    // 组件不再重复提示；失败时输入框保持原样（空），不会写入半截值。
  } finally {
    reveal.submitting = false
  }
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
      status: dialog.form.status,
      allowedIPs: dialog.form.allowedIPs,
    }
    // 手机号**只在动过时才发**：userController.js 落库用的是 `if (phone !== undefined)`，
    // 键缺失才是 no-op，传空串等于清空号码；而编辑框已不再回填明文（列表只给 phoneMasked）。
    // 所以"打开编辑框什么都没碰"必须不发这个键，否则一次普通保存就会抹掉用户手机号。
    // 基线 null 归一到 ''（未揭示=框本来就是空）；揭示过则基线就是明文现值，
    // 看完不改 → 不发，删空再保存 → 真的清空。
    if (!dialog.isEdit || dialog.form.phone !== (dialog.phoneBaseline ?? '')) {
      payload.phone = dialog.form.phone
    }
    if (!dialog.isEdit) {
      // FE-M3：管理员代设口令走密文轨——「可用但失败」阻断提交（用户重试成本为零）
      const enc = await encryptPassword(dialog.form.password).catch((e) => {
        console.warn('[loginCipher] 建号口令加密失败：', e?.message)
        ElMessage.error(t('login.encryptionFailed'))
        return 'BLOCKED'
      })
      if (enc === 'BLOCKED') return
      if (enc) payload.encPassword = enc
      else payload.password = dialog.form.password
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
  dialog.phoneBaseline = null
  // 编辑对话框被关掉时，挂在它下面的 step-up 弹层（append-to-body，独立渲染）
  // 不会跟着消失——不主动收就会留一个悬空的密码框。
  reveal.visible = false
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
/* 手机号输入 + 揭示按钮同一行，按钮不能把输入框挤窄到截断 11 位号码 */
.phone-field {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
}
.phone-field :deep(.el-input) {
  flex: 1;
  min-width: 0;
}
.phone-field__reveal {
  flex: none;
}
.phone-field__hint {
  margin-top: 4px;
  font-size: var(--xf-font-size-xs, 12px);
  line-height: 1.5;
  color: var(--xf-gray-600, #6b7280);
  width: 100%;
}
.reveal-hint {
  margin: 0 0 12px;
  font-size: var(--xf-font-size-sm, 13px);
  line-height: 1.6;
  color: var(--xf-gray-600, #6b7280);
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
