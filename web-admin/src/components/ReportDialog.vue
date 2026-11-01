<template>
  <el-dialog
    :model-value="visible"
    :title="$t('security.report')"
    width="480px"
    @update:model-value="$emit('update:visible', $event)"
    @close="resetForm"
  >
    <el-form ref="formRef" :model="form" :rules="rules" label-width="90px">
      <el-form-item :label="$t('security.reportTargetType')" prop="targetType">
        <el-select v-model="form.targetType" style="width: 100%">
          <el-option :label="$t('security.reportTargetSystem')" value="system" />
          <el-option :label="$t('security.reportTargetUser')" value="user" />
          <el-option :label="$t('security.reportTargetDevice')" value="device" />
          <el-option :label="$t('security.reportTargetAlarm')" value="alarm" />
        </el-select>
      </el-form-item>
      <!-- 记录型才需要具体对象：system 型若携带 targetId，后端路由直接 400
           （否则改一下类型就能绕过「目标必须是数据范围内的真实记录」的核验）。
           控件是**可搜索下拉**而不是 ID 输入框：用户认的是名称/编号，
           24 位 ObjectId 在界面上从不显示，原先让人"粘贴 ObjectId"等于功能不可用。
           候选来自 GET /api/security/report-targets（免权限码、按本人数据范围过滤，
           与提交时的目标核验同判据）。 -->
      <el-form-item
        v-if="form.targetType !== 'system'"
        :label="$t('security.reportTargetRecord')"
        prop="targetId"
      >
        <el-select
          v-model="form.targetId"
          name="targetId"
          filterable
          remote
          reserve-keyword
          style="width: 100%"
          :remote-method="onSearchInput"
          :loading="targetLoading"
          :placeholder="$t('security.reportTargetRecordPlaceholder')"
          :no-data-text="$t('security.reportTargetRecordEmpty')"
          :loading-text="$t('security.reportTargetRecordLoading')"
        >
          <el-option
            v-for="item in targetOptions"
            :key="item.id"
            :label="labelOf(item)"
            :value="item.id"
          />
        </el-select>
      </el-form-item>
      <el-form-item :label="$t('security.reportReason')" prop="reason">
        <el-input
          v-model="form.reason"
          name="reason"
          maxlength="200"
          :placeholder="$t('security.reportReasonPlaceholder')"
        />
      </el-form-item>
      <el-form-item :label="$t('security.reportDescription')" prop="description">
        <el-input
          v-model="form.description"
          name="description"
          type="textarea"
          :rows="3"
          maxlength="500"
          show-word-limit
          :placeholder="$t('security.reportDescriptionPlaceholder')"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <button
        type="button"
        class="glass-btn glass-btn--default"
        @click="emit('update:visible', false)"
      >
        {{ $t('common.cancel') }}
      </button>
      <!-- 举报刻意不挂权限码：一线人员必须报得了警（securityRoutes.js 的
           PERMISSION-EXEMPT 注释同源），安全由「目标记录存在性+数据范围核验」
           与账号级限流承担，而不是把按钮藏起来 -->
      <button
        type="button"
        class="glass-btn glass-btn--primary"
        :class="{ 'is-loading': submitting }"
        :disabled="submitting"
        @click="submit"
      >
        {{ $t('common.submit') }}
      </button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 举报异常对话框（挂在顶栏，人人可用）
 *
 * 契约对齐 POST /api/security/report（securityRoutes.js: 101-146, 244-250）：
 *  · targetType ∈ user/device/alarm/system；记录型 targetId 必填且必须是
 *    数据范围内的真实记录，system 型不得携带 targetId（携带即 400）；
 *  · reason 必填 1-200；description 可选 ≤500；
 *  · 目标记录的存在性与数据范围由服务端核验（这里只做必填前置，避免注定 400 的请求出网）。
 * 成功后关闭并清空；失败提示归 api.js 拦截器，组件不重复弹。
 *
 * 「具体对象」为什么是远程搜索下拉、而不是 ID 输入框（2026-10-21 修）：
 * 一线人员拿不到 24 位 ObjectId —— 它只出现在接口响应里，界面上从不显示，
 * 所以"粘贴 ObjectId"这条路实际不可走。候选由 GET /api/security/report-targets
 * 提供（免权限码：举报对全员开放；按**举报人数据范围**过滤，与提交核验同判据），
 * 界面上只出现名称/编号，targetId 作为选中值随载荷上行、用户不可见。
 */
import { computed, ref, reactive, watch, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api } from '@/utils/api'
import { makeAlarmTypeLabels } from '@/utils/labelMaps'

defineProps({
  visible: { type: Boolean, default: false },
})

const emit = defineEmits(['update:visible'])

const { t } = useI18n()
const formRef = ref(null)
const submitting = ref(false)

const form = reactive({
  targetType: 'system',
  targetId: '',
  reason: '',
  description: '',
})

/** 候选列表与加载态（记录型才有候选；system 型不发请求） */
const targetOptions = ref([])
const targetLoading = ref(false)
/**
 * 当前已选中的候选对象。
 *
 * 远程搜索会**整体替换** options：用户选完再改搜索词时，Element Plus 找不到
 * 对应 option 就会把已选值回显成裸 id（用户看到一串 24 位十六进制）。
 * 记住选中项并在每次刷新时把它拼回列表首部，标签才不会丢。
 */
const selectedTarget = ref(null)
/** 请求序号：远程搜索是并发的，后发先至会让旧关键词的结果覆盖新结果 */
let searchSeq = 0
/** 输入防抖定时器（见 onSearchInput） */
let searchTimer = null

const alarmTypeLabels = computed(() => makeAlarmTypeLabels(t))

/** 候选 → 一行可读标签（id 只作为 option 的 value，不出现在界面上） */
const labelOf = (item) => {
  if (item.kind === 'user') {
    return item.name ? t('common.entityWithCode', { name: item.name, code: item.code }) : item.code
  }
  if (item.kind === 'device') {
    const base = item.name
      ? t('common.entityWithCode', { name: item.name, code: item.code })
      : item.code
    return item.detail ? `${base} · ${item.detail}` : base
  }
  // 报警：编号 · 类型 · 位置（类型是后端稳定码，中文映射在前端 labelMaps）
  const type = alarmTypeLabels.value[item.name] || item.name || ''
  return [item.code, type, item.detail].filter(Boolean).join(' · ')
}

/**
 * 拉取候选。
 *
 * 失败时只清空列表、不弹错：提示归 api.js 响应拦截器（与其余列表页同契约），
 * 组件再弹一条就是同一次失败弹两次。
 */
const loadTargets = async (keyword = '') => {
  if (form.targetType === 'system') return
  const seq = ++searchSeq
  targetLoading.value = true
  try {
    const res = await api.security.searchReportTargets({
      type: form.targetType,
      keyword: String(keyword || '').trim(),
    })
    if (seq !== searchSeq) return
    const items = res?.data?.data?.items
    const list = Array.isArray(items) ? items : []
    const keep =
      selectedTarget.value && !list.some((i) => i.id === selectedTarget.value.id)
        ? [selectedTarget.value]
        : []
    targetOptions.value = [...keep, ...list]
  } catch (_) {
    if (seq === searchSeq) targetOptions.value = selectedTarget.value ? [selectedTarget.value] : []
  } finally {
    if (seq === searchSeq) targetLoading.value = false
  }
}

// 切类型：清空已选与旧候选，再按新类型拉一次首屏
watch(
  () => form.targetType,
  (type) => {
    form.targetId = ''
    selectedTarget.value = null
    targetOptions.value = []
    searchSeq += 1 // 作废在途的旧类型请求，避免结果串台
    targetLoading.value = false
    if (searchTimer) {
      clearTimeout(searchTimer)
      searchTimer = null
    }
    if (type !== 'system') loadTargets('')
  }
)

/**
 * 远程搜索的输入防抖（300ms）
 *
 * 不只是省流量：这个端点是 GET，而全局审计中间件对 GET **默认全量留痕**
 * （middleware/security/auditLog.js 的「敏感读取判据」）。不防抖的话，
 * 输入"烟感一号"会连发 4 次请求、写 4 条审计行——搜索噪声会把真正的
 * 安全事件稀释掉。300ms 让一次输入只落一条。
 */
const onSearchInput = (keyword) => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    searchTimer = null
    loadTargets(keyword)
  }, 300)
}

onBeforeUnmount(() => {
  if (searchTimer) clearTimeout(searchTimer)
})

watch(
  () => form.targetId,
  (id) => {
    if (!id) {
      selectedTarget.value = null
      return
    }
    const found = targetOptions.value.find((i) => i.id === id)
    if (found) selectedTarget.value = found
  }
)

const rules = computed(() => ({
  targetId: [
    {
      required: true,
      message: t('validation.reportTargetIdRequired'),
      trigger: 'change',
    },
  ],
  reason: [
    {
      // required 规则不感知首尾空白（' ' 能过），而后端是先 .trim() 再判 1-200，
      // 纯空格提交只在服务端失败——这里用 trim 后的长度做同一判据
      validator: (_, value, callback) => {
        const text = String(value || '').trim()
        if (!text) return callback(new Error(t('validation.reportReasonRequired')))
        if (text.length > 200) return callback(new Error(t('validation.reportReasonLen')))
        callback()
      },
      trigger: 'blur',
    },
  ],
}))

const resetForm = () => {
  form.targetType = 'system'
  form.targetId = ''
  form.reason = ''
  form.description = ''
  targetOptions.value = []
  selectedTarget.value = null
  searchSeq += 1
  targetLoading.value = false
  if (searchTimer) {
    clearTimeout(searchTimer)
    searchTimer = null
  }
  formRef.value?.clearValidate()
}

const submit = async () => {
  if (!formRef.value) return
  // 重入防护必须同步置位（同 RoleFormDialog）：el-form 的 validate(callback)
  // 是异步的，按钮 :disabled 等下一帧才生效，同一 tick 的二次点击会穿透
  if (submitting.value) return
  submitting.value = true
  try {
    let valid = false
    try {
      valid = await formRef.value.validate()
    } catch (_) {
      return
    }
    if (!valid) return
    try {
      const payload = {
        targetType: form.targetType,
        reason: form.reason.trim(),
      }
      if (form.targetType !== 'system') payload.targetId = form.targetId
      const description = form.description.trim()
      if (description) payload.description = description
      await api.security.report(payload)
      ElMessage.success(t('security.reportSuccess'))
      emit('update:visible', false)
      resetForm()
    } catch (_) {
      // 错误已在拦截器处理（含目标不存在/越权等码化文案）
    }
  } finally {
    // 覆盖校验未通过与校验链抛错两条路径，确保解锁
    submitting.value = false
  }
}
</script>
