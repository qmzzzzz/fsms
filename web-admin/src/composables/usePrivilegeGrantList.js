import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { api, isCanceledError, isHandledApiError } from '@/utils/api'
import { useLatestRequest } from '@/composables/useLatestRequest'

/**
 * PrivilegeGrantView 的列表/汇总加载域（P1-3 拆分）：分页、状态筛选、
 * 竞态门票与两条加载请求收口在这里；视图只保留编排与展示派生。
 * 汇总失败必须以「未知」呈现而不是 0（见 summaryFailed）。
 */
export function usePrivilegeGrantList({ canApprove }) {
  const { t } = useI18n()
  const listGuard = useLatestRequest()

  const loading = ref(false)
  const loadError = ref(false)
  const rows = ref([])
  const summary = ref(null)
  // 复核汇总失败：与「待审批 0 条 / 超期 0 条」是两件事。前者必须给「—」+ 明确提示，
  // 后者才能给 0——把「没读到」画成 0 会让复核人以为没有待办，正好漏掉该处理的授权。
  const summaryFailed = ref(false)
  const page = reactive({ current: 1, size: 20, total: 0 })

  // 有签批权限的人打开页面先看待办；只读/申请人直接看全部，避免落在永远空的「待审批」
  const statusFilter = ref(canApprove.value ? 'pending' : '')

  const loadData = async () => {
    const isCurrent = listGuard()
    loading.value = true
    try {
      const res = await api.permissions.getGrants({
        status: statusFilter.value || undefined,
        page: page.current,
        limit: page.size,
      })
      if (!isCurrent()) return
      const payload = res?.data?.data
      rows.value = Array.isArray(payload) ? payload : []
      // WF-06（2026-11-02 核对）：本视图未接三态契约（页头 loadError 承担等价语义），
      // total 保持数字域；兜底改 ?? —— total=0 是合法值，|| 会让"删空后的 0 条"
      // 被当前页长度顶替成假总数（与下方 clamp 的 lastPage 计算互相矛盾）。
      page.total = res?.data?.pagination?.total ?? rows.value.length
      loadError.value = false
      // 撤销/驳回掉末页最后一条后，当前页可能已越过末页：回退到最后一页再拉一次，
      // 否则用户停在一个永远空白的页上，看起来像「数据没了」
      if (isCurrent() && rows.value.length === 0 && page.total > 0 && page.current > 1) {
        const lastPage = Math.max(1, Math.ceil(page.total / page.size))
        if (lastPage < page.current) {
          page.current = lastPage
          await loadData()
          return
        }
      }
    } catch (e) {
      if (isCanceledError(e)) return
      if (!isCurrent()) return
      loadError.value = true
      if (rows.value.length === 0) page.total = 0
    } finally {
      if (isCurrent()) loading.value = false
    }
  }

  const loadSummary = async () => {
    try {
      const res = await api.permissions.getGrantReview()
      summary.value = res?.data?.data || null
      summaryFailed.value = false
    } catch (e) {
      if (isCanceledError(e)) return
      // 失败即未知：保留 summary=null 让卡片走 '—' 分支，并单独标记错误态；
      // 此前这里只置 null，模板 v-if 把整块摘要摘掉——复核汇总静默消失，连计数都没了。
      summary.value = null
      summaryFailed.value = true
      // 拦截器已按具体状态码提示过的不再重复；没有提示的（非 axios 异常）必须留一条 warn，
      // 否则这条链路失败后没有任何痕迹。
      if (!isHandledApiError(e)) ElMessage.warning(t('privilegeGrant.summaryLoadFailed'))
    }
  }

  const loadAll = () => Promise.all([loadData(), loadSummary()])

  const handleStatusChange = () => {
    page.current = 1
    loadData()
  }

  const setStatus = (status) => {
    if (statusFilter.value === status) return
    statusFilter.value = status
    handleStatusChange()
  }

  const handleSizeChange = () => {
    page.current = 1
    loadData()
  }

  return {
    loading,
    loadError,
    rows,
    summary,
    summaryFailed,
    page,
    statusFilter,
    loadData,
    loadSummary,
    loadAll,
    handleStatusChange,
    setStatus,
    handleSizeChange,
  }
}
