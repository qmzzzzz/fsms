<template>
  <div class="page">
    <el-row :gutter="16">
      <!--
        左栏「基本信息」：身份卡 + 资料编辑
        栅格取 md=10 / lg=9 而非更窄的 8：左栏内含 label-width=100px 的表单，
        再窄下去输入框会被压到 200px 出头，长邮箱看不全。
      -->
      <el-col :xs="24" :md="10" :lg="9">
        <h2 class="profile-section-title">
          {{ $t('profile.basicInfo') }}
        </h2>
        <el-card shadow="never" class="profile-card">
          <!-- 骨架屏：头像/标题/正文灰块占位，数据到达后直接替换 -->
          <GlassSkeleton v-if="profileLoading" variant="detail" :avatar-size="100" :rows="5" />
          <template v-else>
            <div class="profile-avatar">
              <el-avatar :size="100">
                {{ avatarText }}
              </el-avatar>
            </div>
            <h3 class="profile-name">
              {{ user.realName || user.username }}
            </h3>
            <p class="profile-role">
              {{ roleText }}
            </p>
            <el-divider />
            <ul class="profile-meta">
              <li>
                <el-icon><User /></el-icon><span>{{ $t('profile.username') }}：</span
                >{{ user.username }}
              </li>
              <li>
                <el-icon><Message /></el-icon><span>{{ $t('profile.email') }}：</span
                >{{ user.email }}
              </li>
              <li>
                <el-icon><Phone /></el-icon><span>{{ $t('profile.phone') }}：</span
                >{{ user.phone || $t('profile.notSet') }}
              </li>
              <li>
                <el-icon><OfficeBuilding /></el-icon><span>{{ $t('profile.department') }}：</span
                >{{ user.department || $t('profile.notSet') }}
              </li>
              <li v-if="user.lastLoginAt">
                <el-icon><Clock /></el-icon><span>{{ $t('profile.lastLogin') }}：</span
                >{{ formatDate(user.lastLoginAt) }}
              </li>
            </ul>
          </template>
        </el-card>

        <!--
          资料编辑与身份卡同属「基本信息」，因此留在左栏：
          两者数据同源（同一个 user 对象），拆到两栏会让用户改完右栏
          还要回头去左栏确认结果。
        -->
        <el-card shadow="never" class="profile-block">
          <template #header>
            <span class="card-header">{{ $t('profile.editProfile') }}</span>
          </template>
          <el-form
            ref="profileFormRef"
            :model="form"
            :rules="formRules"
            label-width="100px"
            class="profile-form"
            @submit.prevent
          >
            <el-form-item :label="$t('profile.username')">
              <el-input v-model="form.username" disabled maxlength="30" />
            </el-form-item>
            <el-form-item :label="$t('profile.realName')">
              <el-input
                v-model="form.realName"
                :placeholder="$t('validation.realNameRequired')"
                maxlength="50"
                @keydown.enter.prevent="enterSubmit($event, save)"
              />
            </el-form-item>
            <el-form-item :label="$t('profile.email')" prop="email">
              <el-input
                id="profileEmail"
                v-model="form.email"
                name="email"
                :placeholder="$t('register.emailPlaceholder')"
                maxlength="254"
                autocomplete="email"
                @keydown.enter.prevent="enterSubmit($event, save)"
              />
            </el-form-item>
            <el-form-item :label="$t('profile.phone')" prop="phone">
              <el-input
                v-model="form.phone"
                :placeholder="$t('register.phonePlaceholder')"
                maxlength="20"
                @keydown.enter.prevent="enterSubmit($event, save)"
              />
            </el-form-item>
            <el-form-item :label="$t('profile.department')">
              <el-input
                v-model="form.department"
                :placeholder="$t('register.departmentPlaceholder')"
                maxlength="100"
                @keydown.enter.prevent="enterSubmit($event, save)"
              />
            </el-form-item>
            <el-form-item>
              <button type="button" class="glass-btn glass-btn--primary" @click="save">
                {{ $t('common.save') }}
              </button>
              <button type="button" class="glass-btn glass-btn--default" @click="reset">
                {{ $t('common.reset') }}
              </button>
            </el-form-item>
          </el-form>
        </el-card>
      </el-col>

      <!--
        右栏「安全设置」：改密 / 登录会话 / 两步验证
        三块都是账号安全操作，聚在一栏后用户在一处就能看完「我的账号
        安全到什么程度」，不必在四张平铺卡片间上下找。
      -->
      <el-col :xs="24" :md="14" :lg="15">
        <h2 class="profile-section-title">
          {{ $t('profile.security') }}
        </h2>
        <!-- 修改口令（D-2 拆为 ChangePasswordCard 组件） -->
        <ChangePasswordCard />

        <!-- 设备级登录会话：查看并管理正在使用本账号的设备 -->
        <el-card shadow="never" class="profile-block">
          <template #header>
            <span class="card-header">{{ $t('session.title') }}</span>
          </template>
          <p class="session-intro">
            {{ $t('session.intro') }}
          </p>
          <SessionManager />
        </el-card>

        <!-- MFA 两步验证（I-06，D-2 拆为 MfaSettingsCard 组件） -->
        <MfaSettingsCard />
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { User, Message, Phone, OfficeBuilding, Clock } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useAuthStore } from '@/store'
import { api } from '@/utils/api'
import { enterSubmit } from '@/utils/enterSubmit'
import SessionManager from '@/components/SessionManager.vue'
// D-2：修改口令与两步验证拆为独立组件
import ChangePasswordCard from '@/components/ChangePasswordCard.vue'
import MfaSettingsCard from '@/components/MfaSettingsCard.vue'

const { t, locale } = useI18n()
const authStore = useAuthStore()
const user = ref(authStore.currentUser || {})
const profileFormRef = ref(null)
// 手机号格式规则与后端 authRoutes 一致；非必填，留空不校验
// 无缓存用户（如会话恢复边缘场景）时先用骨架屏占位，拉取完成后直换
const profileLoading = ref(!authStore.currentUser)

const avatarText = ref((user.value.username || 'U').slice(0, 1).toUpperCase())
const roleText = ref('')

const updateRoleText = (roles) => {
  if (!roles || roles.length === 0) {
    roleText.value = t('profile.normalUser')
    return
  }
  if (typeof roles[0] === 'string') {
    roleText.value = roles.join(', ')
    return
  }
  roleText.value = roles.map((r) => r.name || r.code || t('profile.unknownRole')).join(', ')
}
updateRoleText(user.value.roles)

const form = reactive({
  username: user.value.username || '',
  realName: user.value.realName || '',
  email: user.value.email || '',
  phone: user.value.phone || '',
  department: user.value.department || '',
})

const formRules = {
  email: [
    // 与后端 updateProfileValidation（express-validator isEmail）同口径，
    // 非必填：留空不校验（clean 规则自带空值跳过）
    { type: 'email', message: t('validation.emailInvalid'), trigger: 'blur' },
  ],
  phone: [{ pattern: /^1[3-9]\d{9}$/, message: t('validation.phonePattern'), trigger: 'blur' }],
}

// 修改口令（pwdForm/changePwd）与两步验证（MFA 状态机/二维码/恢复码对话框）
// 已分别迁入 ChangePasswordCard.vue 与 MfaSettingsCard.vue（D-2）

// 监听用户数据变化，同步更新表单
watch(
  user,
  (newUser) => {
    form.username = newUser.username || ''
    form.realName = newUser.realName || ''
    form.email = newUser.email || ''
    form.phone = newUser.phone || ''
    form.department = newUser.department || ''
    avatarText.value = (newUser.username || 'U').slice(0, 1).toUpperCase()
    updateRoleText(newUser.roles)
  },
  { deep: true }
)

const formatDate = (dateStr) => {
  if (!dateStr) return '—'
  const d = new Date(dateStr)
  return d.toLocaleString(locale.value, { hour12: false })
}

/** 回车提交守卫已抽至 utils/enterSubmit.js，三处表单共用同一判据（D-2） */

const save = async () => {
  try {
    await profileFormRef.value.validate()
  } catch (_) {
    // 表单校验未通过，不提交
    return
  }
  try {
    const updateData = {
      realName: form.realName,
      email: form.email || undefined,
      phone: form.phone || undefined,
      department: form.department || undefined,
    }

    await api.auth.updateProfile(updateData)

    // 同步更新本地 user 与 store：user.value 是独立于 store 状态的对象，
    // 只更新 store 的话左侧卡片与 reset() 仍读取挂载时的旧值
    const updated = {
      ...user.value,
      realName: form.realName,
      email: form.email,
      phone: form.phone,
      department: form.department,
    }
    user.value = updated
    authStore.setCurrentUser(updated)

    ElMessage.success(t('profile.saved'))
  } catch (e) {
    // 错误已在拦截器处理
  }
}

const reset = () => {
  form.realName = user.value.realName || ''
  form.email = user.value.email || ''
  form.phone = user.value.phone || ''
  form.department = user.value.department || ''
}

// changePwd 已迁入 ChangePasswordCard.vue（含改密后延时登出与定时器清理，D-2）

// 加载最新用户信息（MFA 状态查询已随 MfaSettingsCard 自行挂载时执行）
onMounted(async () => {
  try {
    const res = await api.auth.getMe()
    if (res.data.success) {
      const u = res.data.data.user
      authStore.setCurrentUser({ ...u })
      user.value = { ...u }
    }
  } catch (e) {
    // 静默失败，使用缓存数据
  } finally {
    profileLoading.value = false
  }
})
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
}

/*
  两栏分区标题（基本信息 / 安全设置）

  为什么需要它：改成两栏后，右栏三张卡片（改密/登录会话/两步验证）在视觉上
  仍是彼此独立的块，用户看不出「这一栏讲的是同一件事」。加一行分区标题把
  两栏各自的语义说清楚，比单纯调间距更能减少找东西的成本。

  用 h2 而非 div：两栏是页面的两个主分区，标题层级应当真实存在于文档结构里，
  屏幕阅读器才能按标题导航。视觉尺寸靠 font-size 压到与正文接近，不因语义
  层级而变得突兀。
*/
.profile-section-title {
  margin: 0 0 12px;
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-base);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
  color: var(--xf-text-secondary);
}

/*
  栏内卡片间距

  原实现是逐张卡片写 style="margin-top: 16px"（共四处）。改为统一的类有两个
  好处：间距值只存在一处，不会日后改了三处漏一处；且首张卡片天然没有多余
  上边距，不必靠「第一张不写、其余都写」这种约定来维持。
*/
.profile-block {
  margin-top: 16px;
}

/*
  表单宽度约束

  原为逐个表单写 style="max-width: 500px|560px"（同一页面混用两个数值）。
  统一成一个类并改为「宽度 100% + 上限 520px」：窄屏交给百分比自适应，
  宽屏才受上限约束。只写 max-width 不写 width 在窄屏下不会溢出，
  但 el-form 是块级元素、配合 100px 的 label-width，输入框会先被挤扁。
*/
.profile-form {
  width: 100%;
  max-width: 520px;
}

/* 登录会话说明文案：与卡片标题同一视觉层级下的辅助说明 */
.session-intro {
  margin: 0 0 12px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

/*
  栅格折叠为单栏时的分区间隔

  断点取 991px 而非 768px：本页只声明了 xs / md / lg 三档，而 Element Plus 的
  md 类从 ≥992px 才生效，因此 768~991px 区间实际仍按 xs=24 渲染为单栏。
  若按 768px 写，这段区间的两个分区之间就会只剩栅格自带的 12px 间距，
  「基本信息结束、安全设置开始」的边界被吃掉。
*/
@media (max-width: 991px) {
  .el-col + .el-col .profile-section-title {
    margin-top: 20px;
  }
}

/* MFA 密钥/URI 展示与恢复码网格样式已随组件迁入 MfaSettingsCard.vue（D-2） */

.profile-card {
  text-align: center;
  animation: page-enter 0.4s var(--xf-ease-glass) both;
  animation-delay: 0.1s;
}

.profile-avatar {
  display: flex;
  justify-content: center;
  margin: 10px 0;
}

.profile-avatar :deep(.el-avatar) {
  background: var(--xf-gradient-primary);
  color: #fff;
  font-family: var(--xf-font-display);
  font-size: 36px;
  font-weight: 600;
}

.profile-name {
  font-family: var(--xf-font-display);
  font-size: var(--xf-font-size-xl);
  font-weight: 700;
  letter-spacing: var(--xf-tracking-tight);
  color: var(--xf-gray-900);
  margin: 8px 0 4px;
}

.profile-role {
  font-family: var(--xf-font-mono);
  font-size: var(--xf-font-size-xs);
  letter-spacing: var(--xf-tracking-wide);
  background-color: var(--xf-gray-100);
  border-radius: 999px;
  padding: 4px 12px;
  color: var(--xf-gray-600);
  margin-bottom: 0;
}

.profile-meta {
  list-style: none;
  padding: 0;
  text-align: left;
}

.profile-meta li {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: var(--xf-spacing-md) 0;
  color: var(--xf-gray-700);
  font-family: var(--xf-font-body);
  font-size: var(--xf-font-size-sm);
  border-bottom: 1px solid var(--xf-border-color);
}

.profile-meta li:last-child {
  border-bottom: none;
}

.profile-meta li span {
  font-family: var(--xf-font-body);
  color: var(--xf-gray-500);
  font-size: var(--xf-font-size-sm);
}

.card-header {
  font-family: var(--xf-font-display);
  font-weight: 600;
  letter-spacing: var(--xf-tracking-wide);
}

/* 第二组 MFA 样式（密钥/URI/二维码）已随组件迁入 MfaSettingsCard.vue（D-2） */

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
