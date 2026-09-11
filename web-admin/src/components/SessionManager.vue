<template>
  <div class="session-manager">
    <div class="session-toolbar">
      <span class="session-summary">
        {{ t('session.activeCount', { count: sessions.length }) }}
      </span>
      <div class="session-actions">
        <button
          type="button"
          class="glass-btn glass-btn--default glass-btn--sm"
          :disabled="loading"
          @click="load"
        >
          {{ t('common.refresh') }}
        </button>
        <button
          type="button"
          class="glass-btn glass-btn--danger glass-btn--sm"
          :disabled="loading || otherCount === 0"
          @click="revokeOthers"
        >
          {{ t('session.revokeOthers') }}
        </button>
      </div>
    </div>

    <!--
      当前令牌不含 sid 时的提示：功能上线前签发的令牌没有 sid，
      列表里不会有任何一条标为「本设备」。不提示的话用户会以为
      自己这台设备没被记录、怀疑功能失效。
    -->
    <el-alert
      v-if="!loading && !currentSidPresent && sessions.length > 0"
      :title="t('session.noCurrentSidHint')"
      type="info"
      :closable="false"
      class="session-alert"
    />

    <GlassSkeleton v-if="loading" variant="table" :rows="3" />
    <el-empty v-else-if="sessions.length === 0" :description="t('session.empty')" />
    <ul v-else class="session-list">
      <li
        v-for="item in sessions"
        :key="item.sid"
        class="session-item"
        :class="{ 'session-item--current': item.current }"
      >
        <el-icon class="session-icon">
          <component :is="deviceIcon(item.deviceType)" />
        </el-icon>
        <div class="session-info">
          <div class="session-title">
            <!-- 主标题给最具辨识度的名称：有型号就用型号（iPhone / Pixel 8），
                 否则退回浏览器+系统。用户扫一眼要能认出「这台是不是我的」 -->
            <span class="session-device">{{ deviceName(item) }}</span>
            <el-tag v-if="item.current" type="success" size="small" effect="plain">
              {{ t('session.currentDevice') }}
            </el-tag>
            <el-tag v-if="item.deviceType === 'bot'" type="warning" size="small" effect="plain">
              {{ t('session.botDevice') }}
            </el-tag>
          </div>
          <!-- 次行放软件环境：与主标题不重复（主标题已用掉型号或浏览器之一） -->
          <div v-if="softwareLine(item)" class="session-software">
            {{ softwareLine(item) }}
          </div>
          <div class="session-meta">
            <span>{{ t('session.ip') }}：{{ item.lastIp || item.ip || '—' }}</span>
            <span>{{ t('session.lastSeen') }}：{{ formatTime(item.lastSeenAt) }}</span>
            <span>{{ t('session.loginAt') }}：{{ formatTime(item.createdAt) }}</span>
          </div>

          <!--
            技术细节默认折叠：引擎/架构/原始 UA 对多数用户是噪音，但在核查
            可疑登录时是关键依据（伪造的 UA 常出现「自称 Chrome 却是 Gecko
            引擎」这类内部矛盾）。默认展开会把真正要看的时间与 IP 挤下去。
          -->
          <button
            type="button"
            class="session-detail-toggle"
            :aria-expanded="String(expanded.has(item.sid))"
            @click="toggleDetail(item.sid)"
          >
            {{ expanded.has(item.sid) ? t('session.hideDetail') : t('session.showDetail') }}
          </button>
          <dl v-if="expanded.has(item.sid)" class="session-detail">
            <template v-if="item.engine">
              <dt>{{ t('session.engine') }}</dt>
              <dd>{{ item.engine }}</dd>
            </template>
            <template v-if="item.cpu">
              <dt>{{ t('session.cpu') }}</dt>
              <dd>{{ item.cpu }}</dd>
            </template>
            <template v-if="item.ip && item.lastIp && item.ip !== item.lastIp">
              <!-- 仅在两者不同时展示登录 IP：会话期间换网络是「令牌被挪到
                   别处使用」的关键线索，相同时展示只是重复噪音 -->
              <dt>{{ t('session.loginIp') }}</dt>
              <dd>{{ item.ip }}</dd>
            </template>
            <dt>{{ t('session.expiresAt') }}</dt>
            <dd>{{ formatTime(item.expiresAt) }}</dd>
            <template v-if="item.userAgent">
              <dt>{{ t('session.rawUa') }}</dt>
              <dd class="session-ua">
                {{ item.userAgent }}
              </dd>
            </template>
          </dl>
        </div>
        <button
          type="button"
          class="glass-btn glass-btn--danger glass-btn--sm session-revoke"
          :disabled="item.current || revoking === item.sid"
          :title="item.current ? t('session.cannotRevokeCurrent') : ''"
          @click="revokeOne(item)"
        >
          {{ t('session.revoke') }}
        </button>
      </li>
    </ul>
  </div>
</template>

<script setup>
/**
 * 设备级会话管理（登录会话）
 *
 * 解决的问题：此前系统只有 tokenVersion 一种吊销手段，而它是全局的 ——
 * 用户既看不到「账号正在哪些设备上登录」，想踢掉一台可疑设备也只能改密码
 * 把自己所有设备一起踢下线。
 *
 * 独立成组件而非直接写在 ProfileView 里：ProfileView 已有资料/改密/MFA
 * 三大块近 800 行，再加一块会话管理会让该文件难以维护；且会话列表将来
 * 也可能被安全中心复用。
 */
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { Monitor, Cellphone, Platform, Help } from '@element-plus/icons-vue'
import { api } from '@/utils/api'
import GlassSkeleton from '@/components/GlassSkeleton.vue'

const { t, locale } = useI18n()

const sessions = ref([])
const loading = ref(true)
const revoking = ref('')
const currentSidPresent = ref(true)
/**
 * 已展开技术详情的 sid 集合
 *
 * 用 Set 而非给每条数据加 expanded 字段：load() 会整体替换 sessions，
 * 挂在数据上的展开状态会随刷新丢失，用户点开详情、按下刷新就白点了。
 * 用 shallowRef 之外的普通 ref 包 Set 需要重新赋值才触发更新，
 * 因此下方 toggleDetail 里刻意重建 Set 而非原地 add/delete。
 */
const expanded = ref(new Set())

/** 可踢除的会话数（当前设备不计入：它只能通过退出登录结束） */
const otherCount = computed(() => sessions.value.filter((s) => !s.current).length)

/** 设备类型 → 图标。unknown/bot 落到 Help，避免图标与实际不符造成误认 */
const deviceIcon = (type) => {
  switch (type) {
    case 'mobile':
      return Cellphone
    case 'tablet':
      return Platform
    case 'desktop':
      return Monitor
    default:
      return Help
  }
}

/**
 * 主标题：优先用设备型号，其次浏览器+系统
 *
 * 为什么型号优先：账号在多台安卓上登录时，三条「Chrome · Android」并排
 * 毫无区分度，而「Xiaomi 13」「Samsung SM-G991B」用户一眼就知道哪台不是
 * 自己的。桌面浏览器解析不出型号，退回浏览器+系统仍是可读的。
 */
const deviceName = (item) => {
  const model = [item.deviceVendor, item.deviceModel].filter(Boolean).join(' ')
  if (model) return model
  const fallback = [item.browser, item.os].filter(Boolean).join(' · ')
  // 两者都缺失时给「未知设备」而非空串 —— 空行会让用户以为列表渲染坏了
  return fallback || t('session.unknownDevice')
}

/**
 * 次行：软件环境（浏览器 版本 · 系统 版本）
 *
 * 主标题用了型号时，这一行补上浏览器与系统；主标题已经是「浏览器 · 系统」
 * 时返回空串，由模板的 v-if 省掉该行，避免同一信息出现两遍。
 */
const softwareLine = (item) => {
  const model = [item.deviceVendor, item.deviceModel].filter(Boolean).join(' ')
  const browser = [item.browser, item.browserVersion].filter(Boolean).join(' ')
  const os = [item.os, item.osVersion].filter(Boolean).join(' ')
  const parts = [browser, os].filter(Boolean)
  if (parts.length === 0) return ''
  // 主标题是型号时，这一行完整展示软件环境
  if (model) return parts.join(' · ')
  // 主标题已是「浏览器 · 系统」（无版本号），此处补上带版本号的完整信息才有增量
  const withVersion = item.browserVersion || item.osVersion ? parts.join(' · ') : ''
  return withVersion
}

const formatTime = (value) => {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(locale.value, { hour12: false })
}

/** 展开/收起某条会话的技术详情（重建 Set 以触发响应式更新） */
const toggleDetail = (sid) => {
  const next = new Set(expanded.value)
  if (next.has(sid)) next.delete(sid)
  else next.add(sid)
  expanded.value = next
}

const load = async () => {
  loading.value = true
  try {
    const { data: resp } = await api.auth.listSessions()
    sessions.value = Array.isArray(resp.data?.sessions) ? resp.data.sessions : []
    // 显式判断 === false：字段缺失（旧后端）时不应触发提示，
    // 用 `!resp.data?.currentSidPresent` 会把 undefined 也当成「不含 sid」
    currentSidPresent.value = resp.data?.currentSidPresent !== false
  } catch (_) {
    // 错误提示已由拦截器统一处理；此处清空避免展示上一次的过期数据
    sessions.value = []
  } finally {
    loading.value = false
  }
}

const revokeOne = async (item) => {
  if (item.current) return
  try {
    await ElMessageBox.confirm(
      t('session.revokeConfirm', { device: deviceName(item) }),
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
  } catch (_) {
    return
  }

  revoking.value = item.sid
  try {
    await api.auth.revokeSession(item.sid)
    ElMessage.success(t('session.revoked'))
    // 重新拉取而非本地剔除：期间可能有新登录，本地删一条会让列表
    // 与服务端状态不一致，而这个列表的全部价值就在于「反映真实情况」
    await load()
  } catch (_) {
    // 错误已在拦截器处理
  } finally {
    revoking.value = ''
  }
}

const revokeOthers = async () => {
  try {
    await ElMessageBox.confirm(
      t('session.revokeOthersConfirm', { count: otherCount.value }),
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
  } catch (_) {
    return
  }

  try {
    const { data: resp } = await api.auth.revokeOtherSessions()
    ElMessage.success(t('session.revokedOthers', { count: resp.data?.revokedCount ?? 0 }))
    await load()
  } catch (_) {
    // 错误已在拦截器处理
  }
}

onMounted(load)

defineExpose({ load })
</script>

<style scoped>
.session-manager {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.session-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
}

.session-summary {
  font-size: var(--xf-font-size-sm);
  color: var(--xf-text-secondary);
}

.session-actions {
  display: flex;
  gap: 8px;
}

.session-alert {
  margin: 0;
}

.session-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

/* 色值一律走 --xf-* 变量：html.dark 会整体翻转这些变量，
   写死 #fff 会在暗色下变成刺眼白块（注册页踩过同样的坑） */
.session-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 14px;
  border: 1px solid var(--xf-border-color);
  border-radius: 10px;
  background: var(--xf-gray-50);
}

.session-item--current {
  border-color: var(--xf-primary);
  background: var(--xf-primary-alpha-15);
}

.session-icon {
  font-size: 22px;
  color: var(--xf-text-secondary);
  flex-shrink: 0;
}

.session-info {
  flex: 1;
  min-width: 0;
}

.session-title {
  display: flex;
  align-items: center;
  gap: 8px;
}

.session-device {
  font-weight: 600;
  color: var(--xf-gray-900);
}

/* 软件环境行：比主标题弱、比元信息强，形成三级信息层次 */
.session-software {
  margin-top: 2px;
  font-size: var(--xf-font-size-sm);
  color: var(--xf-gray-700);
}

.session-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 14px;
  margin-top: 4px;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-text-secondary);
}

/*
  详情开关做成文字链而非按钮：它是次要操作，做成实体按钮会与右侧的
  「终止登录」抢注意力，而后者才是这个列表的主操作。
*/
.session-detail-toggle {
  margin-top: 6px;
  padding: 0;
  border: none;
  background: none;
  cursor: pointer;
  font-size: var(--xf-font-size-xs);
  color: var(--xf-primary);
}
.session-detail-toggle:hover {
  text-decoration: underline;
}

/*
  详情用 dl/dt/dd：这是「字段名—值」的语义结构，屏幕阅读器能把两者关联起来。
  用 grid 摆成两列，dt 定宽保证多行对齐。
*/
.session-detail {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 4px 12px;
  margin: 8px 0 0;
  padding: 8px 10px;
  border-radius: 8px;
  background: var(--xf-gray-100);
  font-size: var(--xf-font-size-xs);
}
.session-detail dt {
  color: var(--xf-text-secondary);
  white-space: nowrap;
}
.session-detail dd {
  margin: 0;
  color: var(--xf-gray-700);
  min-width: 0;
}

/* 原始 UA 必须允许断行：不换行会把整条列表撑出横向滚动条 */
.session-ua {
  font-family: var(--xf-font-mono, monospace);
  word-break: break-all;
  line-height: 1.5;
}

.session-revoke {
  flex-shrink: 0;
}

@media (max-width: 600px) {
  .session-item {
    align-items: flex-start;
    flex-wrap: wrap;
  }
  .session-revoke {
    margin-left: 34px;
  }
}
</style>
