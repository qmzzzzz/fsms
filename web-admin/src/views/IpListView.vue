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
            {{ $t('security.queryMode') }}{{ $t('common.labelColon') }}{{ queryResult?.ip || '' }}
          </span>
        </div>
        <button
          type="button"
          class="glass-btn glass-btn--default"
          :disabled="loading"
          @click="queryMode ? clearQuery() : loadData()"
        >
          {{ $t('common.refresh') }}
        </button>
      </div>

      <!-- 加载失败必须显式可见：此前失败只清空数据，界面与「名单确实为空」完全一样，
           用户会误以为封禁/白名单被清空。已有数据时保留并标注为上次数据。 -->
      <el-alert
        v-if="loadError"
        :title="tableData.length > 0 ? $t('ipList.staleData') : $t('ipList.loadError')"
        type="warning"
        :closable="false"
        show-icon
        class="load-error"
      >
        <template #default>
          <button
            type="button"
            class="glass-btn glass-btn--default glass-btn--sm"
            :disabled="loading"
            @click="queryMode ? handleQuery() : loadData()"
          >
            {{ $t('common.retry') }}
          </button>
        </template>
      </el-alert>

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
        <el-form-item v-if="typedConfirmTarget" :label="$t('ipList.typedConfirmLabel')">
          <el-input
            v-model="typedConfirmText"
            class="ip-typed-confirm"
            :placeholder="typedConfirmExpected || $t('ipList.typedConfirmPlaceholder')"
            style="width: 220px"
            maxlength="200"
            @keyup.enter="handleAdd"
          />
        </el-form-item>
        <el-form-item>
          <!-- 权限门控与路由 meta / 后端 POST 同一权限码：会话期内权限被热回收时
               按钮随之消失，而不是留着让用户点一次 403（下方「移除」同此门控） -->
          <button
            v-if="hasPerm('security:config')"
            type="button"
            class="glass-btn glass-btn--primary"
            :class="{ 'glass-btn--danger': listType === 'black' }"
            :disabled="adding || switchingId !== null"
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
        <!-- 空态文案收进表格 empty 插槽：替代 EP 默认「暂无数据」，
             此前独立 div 挂在分页下方，与默认文案重复且位置错位 -->
        <template #empty>
          <div v-if="!loading" class="empty-tip">
            {{
              loadError
                ? $t('ipList.loadError')
                : queryMode
                  ? $t('security.noMatchFound')
                  : listType === 'black'
                    ? $t('security.noBlacklist')
                    : $t('security.noWhitelist')
            }}
          </div>
        </template>
        <el-table-column prop="ip" :label="$t('security.ipAddress')" min-width="160">
          <template #default="{ row }">
            <span class="ip-cell">{{ row.ip }}</span>
            <!-- 归属地：后端可选增强（CIDR 网段/检索不可用时缺字段），必须省略而非渲染空串 -->
            <span v-if="row.location" class="ip-location">
              · {{ ipLocationLabel(t, row.location) }}</span
            >
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
        <!-- 权限门控与路由 meta / 后端 DELETE 同一权限码：会话期内权限被热回收时，
             按钮随之消失，而不是留着让用户点一次 403（上方「加入名单」同此门控） -->
        <el-table-column :label="$t('common.operation')" width="210" fixed="right">
          <template #default="{ row }">
            <button
              v-if="hasPerm('security:config')"
              type="button"
              class="glass-btn glass-btn--primary switch-btn"
              :disabled="switchingId !== null"
              @click="handleSwitchList(row)"
            >
              {{
                row.type === 'black' ? $t('security.addToWhitelist') : $t('security.addToBlacklist')
              }}
            </button>
            <button
              v-if="hasPerm('security:config')"
              type="button"
              class="glass-btn glass-btn--danger glass-btn--link"
              :disabled="switchingId !== null"
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
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
// O-3：时间格式化统一抽取（本地时区、hour12=false 单一口径）
import { formatTime } from '@/utils/datetime'
// IP 归属地：后端只出稳定码，中文「内网」/ 英文 "Internal network" 的本地化在这一个模块
import { ipLocationLabel } from '@/utils/ipLocationLabels'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import { usePermission } from '@/composables/usePermission'
import { apiClient, isCanceledError, isHandledApiError } from '@/utils/api'
import { useLatestRequest } from '@/composables/useLatestRequest'
import GlassSegmented from '@/components/GlassSegmented.vue'

// locale 未使用：本视图的时间展示已统一走 utils/datetime.formatTime
// （固定本地时区 + hour12=false），不再依赖 toLocaleString 的 locale 参数
const { t } = useI18n()
const { hasPerm } = usePermission()

const loading = ref(false)
// 名单加载失败标记：区分「加载失败」与「名单为空」，失败时保留上次数据并提示可重试
const loadError = ref(false)
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

// 查询重入锁：与 querying 分开，**同步**置位。querying 要等 DOM 重渲染才让按钮
// disabled 生效，同一 tick 连点时后面的点击会全部进入 handler（实测三次连点
// 发出 3 个查询请求），用独立 ref 在函数首行同步拦截。
const querySubmitting = ref(false)

const handleQuery = async () => {
  if (querySubmitting.value) return
  const ip = queryForm.ip.trim()
  if (!ip) {
    ElMessage.warning(t('security.ipRequired'))
    return
  }
  if (!validateIpOrCidr(ip)) {
    ElMessage.warning(t('ipList.invalidFormat'))
    return
  }
  querySubmitting.value = true
  querying.value = true
  try {
    const res = await apiClient.get('/security/ip-list/query', { params: { ip } })
    queryResult.value = res?.data?.data || null
    queryMode.value = true
    loadError.value = false
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
    querySubmitting.value = false
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
  // 用 hasOwnProperty 而非裸 map[reason]：新增表单的 reason 是管理员自由文本，
  // 直接下标会命中 Object.prototype（如 'constructor'/'toString'）而渲染出函数源码。
  if (typeof reason === 'string' && Object.prototype.hasOwnProperty.call(map, reason)) {
    return map[reason]
  }
  // 后端渐进式封禁写入的是 brute_force_auto_ban_tier{1..4}（见 src/services/securityAlert.js
  // ESCALATION_TIERS），裸键 brute_force_auto_ban 从不出现 → 按前缀归一，否则界面直出原始码。
  if (typeof reason === 'string' && reason.startsWith('brute_force_auto_ban')) {
    return map.brute_force_auto_ban
  }
  return reason || '-'
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
    loadError.value = false
  } catch (e) {
    // FE-L1：路由切换 abort 的在途请求不提示（用户已到达新页面）
    if (isCanceledError(e)) return
    if (!isCurrent()) return
    // P2-3：加载失败只清态，**提示由 api.js 响应拦截器统一负责**（与 alarmView 同契约）。
    // 此前组件这里再弹一条 messages.loadFailed，同一次失败会弹两条：
    // 拦截器的具体文案（400/403/404/429/5xx/网络错误）+ 组件的泛化文案。
    //
    // 但「只清态」不能把失败伪装成空表：保留上次数据并标记 loadError，
    // 由页头警示条明确告知是「刷新失败/加载失败」。首次加载失败时表为空，
    // 空态文案也改为错误提示，不再显示「暂无名单」。
    loadError.value = true
    if (tableData.value.length === 0) page.total = 0
  } finally {
    if (isCurrent()) loading.value = false
  }
}

// 分页大小变化：回到第一页再加载，避免停留在超出结果集的页码上
const handleSizeChange = () => {
  page.current = 1
  loadData()
}

// 新增重入锁：同 handleQuery，adding 要等 DOM 重渲染才对按钮生效
// （实测同一 tick 三次连点发出 3 个 POST，名单会被重复写入三次）
const addSubmitting = ref(false)
/**
 * 打字确认的**两阶段**：第一次提交被拒（typed_confirmation_required）后，
 * 后端把"这个网段需要逐字敲一遍"说出来，本视图据此亮出输入框；第二次提交带上 typedConfirm。
 * 不做成"永远显示输入框"：低危条目（单地址）不需要，多一个必填项只会让人乱填。
 */
const typedConfirmTarget = ref('')
const typedConfirmText = ref('')
// 后端回带的归一化形态，仅用于提示（不自动回填——回填等于替用户签字）
const typedConfirmExpected = ref('')
// 名单切换重入锁：跨名单操作包含多个写请求，整个流程期间禁用所有行操作。
const switchingId = ref(null)

/** 读网段护栏的原因码：只在被拒时存在，命中不了就当"没有这回事"（不吞成笼统文案） */
const refusalReasonOf = (e) => {
  const err = e?.response?.data?.errors
  if (!err || err.errorCode !== 'IP_SEGMENT_WRITE_REFUSED') return ''
  return typeof err.reason === 'string' ? err.reason : ''
}

/** 后端回带的**归一化形态**（errors.expected）：确认串比对的就是它，取不到返回空串 */
const expectedOf = (e) => {
  const err = e?.response?.data?.errors
  return typeof err?.expected === 'string' && err.expected ? err.expected : ''
}

/**
 * 逐字确认的**期望值唯一来源**：后端 errors.expected（归一化形态）优先，缺失才回退给定原文。
 *
 * 新增路径与切换路径**都必须**经这里取期望值。两条路径各写一套（一条用 expected、一条用
 * 原始 row.ip）就是判据分叉：非规范写法（2001:DB8::/64、::ffff:10.0.0.0/104）下，用原文的
 * 那条会把用户钉在后端永不接受的字符串上——他敲对了也 400，且提示还在让他"再敲一遍"。
 * 回退层（fallback）由调用方按「这个界面有没有别处显示该值」决定，不由判据决定：
 * 切换路径行内无输入框 ⇒ 传 row.ip；新增路径上方已显示输入框内容 ⇒ 传空串落回 i18n 通用提示。
 * **优先级本身（expected 优先）只有这一处**，不随界面变。
 * @param {object} e 后端拒绝响应
 * @param {string} fallback 老后端未回带 expected 时的原文兜底
 */
const typedConfirmExpectationOf = (e, fallback) => expectedOf(e) || String(fallback || '')

const handleAdd = async () => {
  if (addSubmitting.value) return
  const ip = addForm.ip.trim()
  if (!ip) {
    ElMessage.warning(t('security.ipRequired'))
    return
  }
  if (!validateIpOrCidr(ip)) {
    ElMessage.warning(t('ipList.invalidFormat'))
    return
  }

  // 换了网段：上一个网段的确认态（含 expected 提示）不能跟着走——否则输入框会继续
  // 拿旧网段的归一化形态当占位符，指向一个与本表单无关的值
  if (typedConfirmTarget.value && typedConfirmTarget.value !== ip) {
    typedConfirmTarget.value = ''
    typedConfirmText.value = ''
    typedConfirmExpected.value = ''
  }

  addSubmitting.value = true
  adding.value = true
  try {
    // 后端可能回带归一化形态（见 expectedOf）：敲错的根因往往是用户不知道规范写法，
    // 故记下来给输入框当占位/提示，而不是让他反复试
    const body = {
      ip,
      type: listType.value,
      reason:
        addForm.reason.trim() ||
        (listType.value === 'black' ? 'manual_configuration' : 'trusted_source'),
      durationHours: Number(addForm.durationHours) || 0,
    }
    // 同一网段的第二次提交才带确认串：第一次被拒本身就说明了"这段是高危段"
    if (typedConfirmTarget.value === ip && typedConfirmText.value.trim()) {
      body.typedConfirm = typedConfirmText.value.trim()
    }
    await apiClient.post('/security/ip-list', body)
    ElMessage.success(
      `${t('security.added')} ${ip} ${listType.value === 'black' ? t('security.blacklist') : t('security.whitelist')}`
    )
    addForm.ip = ''
    addForm.reason = ''
    // 确认串只对"那一次、那个网段"有效：不清掉下次换网段会被判成敲错
    typedConfirmTarget.value = ''
    typedConfirmText.value = ''
    typedConfirmExpected.value = ''
    // 新增条目按时间倒序排在第一页，回到首页以便立即看到
    page.current = 1
    loadData()
  } catch (e) {
    // 网段护栏的拒绝要给**可执行的下一步**，不是一个笼统的"操作失败"：
    // typed_confirmation_required 能靠再点一次满足（亮出输入框），另两条只能换更小的网段。
    const refusal = refusalReasonOf(e)
    if (refusal === 'typed_confirmation_required') {
      typedConfirmTarget.value = ip
      // 回退参数给空串：新增表单上方已经显示着用户输入的 ip，占位符再抄一遍没有增量信息；
      // 留空则落到 i18n 的通用提示（「逐字照抄上面的网段」）。切换路径相反——行内没有输入框，
      // 提示里必须出现那个值，故那里回退 row.ip。**期望值的优先级两边同一个函数**，
      // 差的只是「没有 expected 时显示什么」这一层展示回退。
      typedConfirmExpected.value = typedConfirmExpectationOf(e, '')
      // 上次敲错的串必须清掉：留着它下一次点提交会原样重发，用户以为自己在重试，
      // 实际发出去的还是那个已经被判定敲错的字符串
      typedConfirmText.value = ''
      ElMessage.warning(t('ipList.refusedTypedConfirm'))
    } else if (refusal === 'no_rescue_path') {
      // 敲多少遍都没用：这条要用户先去给自己加**永久**白名单，与「缺确认串」的下一步
      // 动作完全不同，故单列一档；不亮确认输入框（亮了等于把人往无解的重试里推）
      ElMessage.warning(t('ipList.refusedNoRescuePath'))
    } else if (refusal === 'operator_inside') {
      ElMessage.warning(t('ipList.refusedOperatorInside'))
    } else if (refusal === 'live_traffic_inside') {
      ElMessage.warning(t('ipList.refusedLiveTraffic'))
    }
    // 其余错误已在拦截器统一提示
  } finally {
    adding.value = false
    addSubmitting.value = false
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
      // 具体原因已由响应拦截器提示，组件不再叠加一条泛化「删除失败」
      // 删除侧 403 多了一种触发（删掉全网段黑名单的唯一救援路径）：它与「权限不足」的
      // 下一步动作完全不同（删了就再也没人能自行解除封锁），不能与泛化删除失败同档
      const code = e?.response?.data?.errors?.errorCode
      if (!isHandledApiError(e)) {
        ElMessage.error(
          code === 'FULL_RANGE_FORBIDDEN'
            ? t('ipList.deleteRescueForbidden')
            : t('messages.deleteFailed')
        )
      }
    }
  }
}

// 计算切换时沿用原条目的剩余时长，避免“加入另一名单”意外从临时规则变成永久规则。
const remainingDurationHours = (row) => {
  if (!row?.expiresAt) return 0
  const remainingMs = new Date(row.expiresAt).getTime() - Date.now()
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) return 1
  return Math.min(8760, Math.max(1, Math.ceil(remainingMs / (60 * 60 * 1000))))
}

const switchReason = (row, type) => {
  const fallback = type === 'white' ? 'trusted_source' : 'manual_configuration'
  return String(row?.reason || fallback).slice(0, 200)
}

// 将当前条目切换到另一侧名单。黑转白可直接复用 POST（后端会先写白再解除同 IP 黑名单）；
// 白转黑先移除白名单再新增黑名单，新增失败时恢复原白名单，避免请求中断造成放行窗口。
/**
 * 行内切换的逐字确认：让用户自己敲网段，**不**替他回填。
 * 返回 null 表示用户取消（调用方按原拒绝结束流程，并走白名单恢复）。
 * 不在前端判「该不该要确认」：是否要，只由后端在拒绝时说出来（ADR-018 ③）。
 */
const promptTypedConfirm = async (expected) => {
  try {
    const { value } = await ElMessageBox.prompt(
      t('ipList.typedConfirmPrompt', { ip: expected }),
      t('messages.confirmTitle'),
      {
        inputPlaceholder: expected,
        inputValidator: (v) => (v || '').trim() === expected || t('ipList.typedConfirmMismatch'),
        type: 'warning',
      }
    )
    return String(value || '').trim()
  } catch (e) {
    return null
  }
}

/** 切换被护栏拒绝时按原因分档提示；返回 true 表示这条错误已被本函数处理 */
const showSwitchRefusal = (e) => {
  const refusal = refusalReasonOf(e)
  if (!refusal) return false
  if (refusal === 'operator_inside') ElMessage.warning(t('ipList.refusedOperatorInside'))
  else if (refusal === 'live_traffic_inside') ElMessage.warning(t('ipList.refusedLiveTraffic'))
  else if (refusal === 'union_covers_family') ElMessage.warning(t('ipList.refusedUnionCovers'))
  else if (refusal === 'whitelist_covers') ElMessage.warning(t('ipList.refusedWhitelistCovers'))
  else if (refusal === 'typed_confirmation_required')
    ElMessage.warning(t('ipList.refusedTypedConfirm'))
  else if (refusal === 'no_rescue_path') ElMessage.warning(t('ipList.refusedNoRescuePath'))
  else ElMessage.warning(t('security.switchFailed'))
  return true
}

const handleSwitchList = async (row) => {
  if (!row?._id || switchingId.value !== null) return
  const targetType = row.type === 'black' ? 'white' : 'black'
  const targetLabel = targetType === 'black' ? t('security.blacklist') : t('security.whitelist')
  try {
    await ElMessageBox.confirm(
      t('security.switchListConfirm', { ip: row.ip, target: targetLabel }),
      t('messages.confirmTitle'),
      { type: 'warning' }
    )
  } catch (e) {
    if (e !== 'cancel' && e !== 'close' && !isHandledApiError(e)) {
      ElMessage.error(t('security.switchFailed'))
    }
    return
  }

  switchingId.value = row._id
  const payload = {
    ip: row.ip,
    type: targetType,
    reason: switchReason(row, targetType),
    durationHours: remainingDurationHours(row),
  }
  const restoreOriginalWhitelist = async () => {
    try {
      // 恢复白名单只写白名单：typedConfirm 是"封段"语义的字段，沿 ...payload 传过去既是
      // 语义错位（靠后端 type!=='black' 短路才没出事），也会让"确认过"这件事看起来发生过。
      const { typedConfirm: _ignored, ...whiteOnly } = payload
      await apiClient.post('/security/ip-list', {
        ...whiteOnly,
        type: 'white',
        reason: switchReason(row, 'white'),
      })
      return true
    } catch (restoreError) {
      ElMessage.error(t('security.switchRestoreFailed'))
      return false
    }
  }

  /**
   * 加黑提交：**不带** typedConfirm 先发一次，只有后端明确答 typed_confirmation_required
   * 才带确认串重发。
   *
   * 为什么不在这里判 row.ip.includes('/')：那等于把后端的门槛（hostCount>=256、
   * 且比对的是 normalizeCIDR 之后的值）在前端重算一遍——两份事实，等价只是当下巧合。
   * 一旦某天门槛改成 /25 或后端归一化口径变化，前端就会"该带不带"（必被拒）或
   * "不该带却带"（把没确认过的写操作伪装成确认过）。ADR-018 ③ 已写明这条归后端算。
   * 第二次用 row.ip 原文当确认串仍是需要的：后端比对的是归一化后的 cidr，回填原始文本
   * 在非规范写法下会漂移；故这里用**后端已经接受过的那个值**（即拒绝时读回的信息）——
   * 至少有据可依，且失败会如实抛给调用方走恢复流程。
   */
  const submitBlackWithTypedConfirm = async () => {
    try {
      await apiClient.post('/security/ip-list', payload)
    } catch (e) {
      if (refusalReasonOf(e) !== 'typed_confirmation_required') throw e
      // **不许**自动回填 row.ip 当确认串：那等于替用户签字。逐字确认的全部意义在于
      // 「人看过这段影响面并复述一遍」，机器复述一遍只证明字符串可复制。行内没有输入框，
      // 故这里亮出与新增同款的确认框，让用户自己敲；敲的内容与原网段不符就不提交。
      // 提示与校验都用后端回带的**归一化**形态：确认串比对的就是它。拿 row.ip 原文
      // 当提示会把用户钉在一个后端永不接受的字符串上（2001:DB8::/64 敲对了也 400）。
      // 老后端不回带 expected 时退回 row.ip 原文。
      const typed = await promptTypedConfirm(typedConfirmExpectationOf(e, row.ip))
      if (typed === null) throw e
      await apiClient.post('/security/ip-list', { ...payload, typedConfirm: typed })
    }
  }

  try {
    if (targetType === 'white') {
      await apiClient.post('/security/ip-list', payload)
    } else {
      try {
        await apiClient.delete(`/security/ip-list/${row._id}`)
      } catch (e) {
        // 网络错误或 5xx 时删除结果可能未知：先恢复白名单再结束，避免出现放行窗口。
        if (!e?.response || e.response.status >= 500) await restoreOriginalWhitelist()
        throw e
      }
      try {
        await submitBlackWithTypedConfirm()
      } catch (e) {
        // **无条件恢复**：上一段 DELETE 已经真的删掉了白名单条目（后端 ip_whitelist_removed
        // 有审计），所以此刻该 IP 两边名单都不在。按拒绝原因决定要不要补偿是错的——
        // 判据类拒绝（罩住自己/还有活跃流量）只是"黑名单写不进去"，不代表白名单还在。
        // 跳过恢复 = 静默丢条目：用户看到「拒绝：这个网段罩住了你自己」，以为什么都没变，
        // 而实际上放行规则已经没了。恢复失败也要显式告警，便于管理员立即复核判定。
        await restoreOriginalWhitelist()
        throw e
      }
    }

    ElMessage.success(t('security.switchSuccess', { ip: row.ip, target: targetLabel }))
    // 查询模式保持当前查询；普通模式刷新当前名单，确保已切换条目立即消失。
    if (queryMode.value) {
      await handleQuery()
    } else {
      await loadData()
    }
  } catch (e) {
    // 判据类拒绝必须说清"为什么"：operator_inside（你自己就在里面）与
    // live_traffic_inside（这栋楼还在用）的下一步动作完全不同，笼统一句"切换失败"
    // 等于让运维去猜，而猜错的方向是把自己锁在门外。
    if (!showSwitchRefusal(e) && !isHandledApiError(e)) {
      ElMessage.error(t('security.switchFailed'))
    }
  } finally {
    switchingId.value = null
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
.load-error {
  margin-bottom: var(--xf-spacing-md);
}
.ip-cell {
  font-family: var(--xf-font-mono);
  font-weight: 600;
  color: var(--xf-gray-800);
}
/* 归属地：与等宽 IP 同行但弱一级（辅助信息，不与主键值抢视觉权重） */
.ip-location {
  color: var(--xf-text-secondary);
  font-size: var(--xf-font-size-sm);
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
