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
                >{{ formatProfileTime(user.lastLoginAt) }}
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
            <!-- 部门非自助可改字段：它是数据范围的判定依据（H-01），仅管理员经用户管理可改，
                 后端 updateUserProfile 刻意不白名单该字段。此前放一个可编辑输入会造成
                 "改了就报保存成功、刷新又回退旧值"，且本地 store 与库中授权归属长期不一致，
                 故改为只读展示（见上方信息卡片的 department）。 -->
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
import { computed, ref, reactive, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { User, Message, Phone, OfficeBuilding, Clock } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useAuthStore } from '@/store'
import { api } from '@/utils/api'
import { enterSubmit } from '@/utils/enterSubmit'
import { formatTime } from '@/utils/datetime'
import SessionManager from '@/components/SessionManager.vue'
// D-2：修改口令与两步验证拆为独立组件
import ChangePasswordCard from '@/components/ChangePasswordCard.vue'
import MfaSettingsCard from '@/components/MfaSettingsCard.vue'

const { t } = useI18n()
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

/**
 * 服务端值灌入表单前问一句"用户动过没有"
 *
 * onMounted 的 `/auth/me` 是一次迟到刷新：它完全可能在用户已经开始输入之后才回来
 * （实测窗口：进页面即在"真实姓名"里打字，慢网络下这次输入被静默还原成服务端值，
 * 而且没有任何提示——用户只知道"我刚才打的字没了"）。
 * 下面的 `watch(user)` 本来是为了把权威值同步进表单（保存后的规范化结果、
 * 迟到刷新的最新资料都靠它），但它是**无条件覆盖**，于是把这条同步通道
 * 同时变成了丢输入的通道。
 *
 * 判据选"表单是否被动过"而不是请求序号：本页只发一次 getMe，
 * 用来去重并发请求的 `useLatestRequest` 解决不了"回包晚于用户输入"这件事。
 *
 * `flush: 'sync'` 是必需的，不是优化：服务端赋值走的是同步代码，而默认的
 * pre-flush 回调要等到下一个微任务才跑——那时 `syncingFromServer` 已经被 finally
 * 复原成 false，赋值自己就被记成"用户动过"。保存路径每次都显式撤销脏标记，所以那条
 * 通道看不出问题；但「重置」之后迟到的 `/auth/me` 会被这个误标挡掉，表单停在重置
 * 那一刻的旧值上——用户以为"重置后再刷新会拿到最新值"（实测：改成 pre-flush 后
 * 该用例转红，源文件里那行 `flush: 'sync'` 是有牙齿的）。
 *
 * 源是 reactive 对象，Vue 本就隐式深比，所以选项里没有 `deep: true`
 * （实测：加上它 18 条用例零差异，属于装饰）。
 *
 * 另需说明：`syncingFromServer` 这一层抑制目前测不到。两个方向都试过——让它恒为
 * false（服务端赋值一律标脏）和让它不复原（此后用户输入一律不标脏），18 条用例都全绿。
 * 原因是本页只有一次非请求式同步（onMounted 的 getMe），而 save()/reset() 各自都在
 * 末尾显式撤销脏标记，把后果盖住了。留着的理由是它让"服务端写入不算用户输入"成为
 * 局部不变式，将来多一个同步入口（比如聚焦重取）不会一踩就中；别把它当成有测试兜着的机制。
 */
const formDirty = ref(false)
let syncingFromServer = false
const applyFromServer = (assign) => {
  syncingFromServer = true
  try {
    assign()
  } finally {
    syncingFromServer = false
  }
}
watch(
  form,
  () => {
    if (!syncingFromServer) formDirty.value = true
  },
  { flush: 'sync' }
)

const formRules = computed(() => ({
  email: [
    // User.email 在 schema 上是 required + unique ⇒ 库里永远非空，邮箱不是能清空的字段。
    // 原先"留空不校验"配上提交时 `email: form.email || undefined`，让清空动作既拦不住
    // 也不生效：表单显示为空、后端按"未提供"保持旧值、刷新后旧邮箱又冒出来。
    // 必填之后，这个不可表达的操作以一条红字呈现，而不是以一次假保存呈现。
    { required: true, message: t('validation.emailRequired'), trigger: 'blur' },
    { type: 'email', message: t('validation.emailInvalid'), trigger: 'blur' },
  ],
  // 手机号非必填，留空即清空：User.phone 的校验器明确允许 ''，
  // 路由侧 body('phone').optional({ values: 'falsy' }) 放行空串（两者缺一都会 400）
  phone: [{ pattern: /^1[3-9]\d{9}$/, message: t('validation.phonePattern'), trigger: 'blur' }],
}))

// 修改口令（pwdForm/changePwd）与两步验证（MFA 状态机/二维码/恢复码对话框）
// 已分别迁入 ChangePasswordCard.vue 与 MfaSettingsCard.vue（D-2）

// 监听用户数据变化，同步更新表单；用户已经动过表单时不覆盖其输入
watch(
  user,
  (newUser) => {
    if (!formDirty.value) {
      applyFromServer(() => {
        form.username = newUser.username || ''
        form.realName = newUser.realName || ''
        form.email = newUser.email || ''
        form.phone = newUser.phone || ''
        form.department = newUser.department || ''
      })
    }
    // 只读展示位与脏标记无关：它们显示的就是服务端权威值，盖掉不会丢用户输入
    avatarText.value = (newUser.username || 'U').slice(0, 1).toUpperCase()
    updateRoleText(newUser.roles)
  },
  { deep: true }
)

/**
 * 资料页时间展示：统一走 utils/datetime.formatTime（O-3 单一事实来源——本地时区、
 * 固定 YYYY-MM-DD HH:mm:ss、各段补零、非法值兜底，且不随界面语言漂移）。
 *
 * 为什么保留 em dash 而不直接用 formatTime 的半角 '-'：'—' 是本页既有空值占位符，
 * 换符号属于用户可见的文案变更，与「统一时间格式」目标无关，故仅在 formatTime
 * 判定为空/非法（返回 '-'）时映射成本页占位符。
 */
const formatProfileTime = (value) => {
  const text = formatTime(value)
  return text === '-' ? '—' : text
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
    // 原样提交表单值：空串就是"清空"这一合法操作（手机号），不再用 `|| undefined`
    // 把它伪装成"未提供"。邮箱由上面的必填规则保证非空。
    const updateData = {
      realName: form.realName,
      email: form.email,
      phone: form.phone,
    }

    const res = await api.auth.updateProfile(updateData)

    // 同步更新本地 user 与 store：user.value 是独立于 store 状态的对象，
    // 只更新 store 的话左侧卡片与 reset() 仍读取挂载时的旧值。
    // 取服务端回包里的权威 profile 而不是表单值——后端会对提交值做规范化
    // （邮箱小写化落库），也可能根本不采纳（字段被白名单挡下）；
    // 把表单值写进本地态就是"界面显示一个数据库里没有的值"，
    // 下一次 /auth/me 又把它改回去，用户看到的是"保存成功了但没生效"。
    const updated = { ...user.value, ...(res?.data?.data || {}) }
    // 保存成功后必须让权威值落回表单：后端的规范化结果（邮箱小写化）与"白名单挡下的
    // 字段保持原值"都靠这一步显示。脏标记是为"迟到的 getMe"设的，不能反过来把
    // 刚保存成功的规范化值也一起挡掉，所以这里先撤销脏标记再赋值。
    formDirty.value = false
    user.value = updated
    authStore.setCurrentUser(updated)

    ElMessage.success(t('profile.saved'))
  } catch (e) {
    // 错误已在拦截器处理
  }
}

/** 「重置」是用户主动要求丢弃输入，因此赋值前后都要让脏标记归位 */
const reset = () => {
  applyFromServer(() => {
    form.realName = user.value.realName || ''
    form.email = user.value.email || ''
    form.phone = user.value.phone || ''
    form.department = user.value.department || ''
  })
  formDirty.value = false
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
