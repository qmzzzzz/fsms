/**
 * 列表加载三态契约（P1③ / P1④ 的共用判据）
 *
 * 为什么要有它：修复前 6 个列表视图各自在 catch 里「清表 + total=0」，
 * 失败与「真的没有数据」在界面上完全一致——审计页尤其致命（「今天没有
 * 审计记录」与「查询失败」不可区分）。若每个视图各写一套修法，下一轮必
 * 然变成 6 份互相漂移的实现，所以把判据收在这里，视图只允许接线。
 *
 * 三个状态互斥且完备：
 *   idle    还没开始
 *   ready   成功且有数据
 *   empty   成功且真的为空  ← 只有它允许渲染「暂无数据」
 *   failed  失败且无旧数据  ← 表格让位于错误块
 *   stale   失败但有旧数据  ← 旧数据保留，必须标注「上次数据」
 *
 * 两条硬约束：
 *   1. 「失败」永远不等于「空」：failed 态下 isEmpty 必须为 false，
 *      否则模板会走空态分支把失败画成「暂无数据」。
 *   2. total 缺失回退成当前页长度是静默降级：分页器会显示「共 10 条/1 页」，
 *      第 2 页起永远不出现。所以 total 未知时给 null，绝不拿 count 顶替。
 */
import { ref, computed } from 'vue'

export function useListLoadState() {
  const phase = ref('idle')
  // total 的三态：数字=已知，null=未知（契约漂移/字段缺失）
  const total = ref(null)

  const failed = computed(() => phase.value === 'failed' || phase.value === 'stale')
  const stale = computed(() => phase.value === 'stale')
  // 只有「成功且真的为空」才算空；失败绝不能被当成空
  const isEmpty = computed(() => phase.value === 'empty')
  const totalKnown = computed(() => total.value !== null)
  // 失败必须显式可见：表格让位（无旧数据时）或与旧数据并存并加标注
  const showErrorBlock = computed(() => failed.value)
  const showTable = computed(() => !failed.value || stale.value)

  const begin = () => {
    phase.value = phase.value === 'idle' ? 'loading' : phase.value
  }

  /** 成功回包：total 显式传入（undefined 即未知），count 只用于判空，绝不顶替 total */
  const commit = ({ total: t, count }) => {
    total.value = t === undefined || t === null ? null : t
    phase.value = count > 0 ? 'ready' : 'empty'
  }

  const fail = () => {
    // 有旧数据 ⇒ stale（保留 + 标注）；没有 ⇒ failed（让位给错误块）
    phase.value = phase.value === 'ready' || phase.value === 'empty' ? 'stale' : 'failed'
  }

  /** 取消（路由切换 abort）不算失败，不留错误态 */
  const abort = () => {
    if (phase.value === 'loading') phase.value = 'idle'
  }

  const reset = () => {
    phase.value = 'idle'
    total.value = null
  }

  /** 末页 clamp：请求页超出总页数时给出应回退到的页码（P1④） */
  const clampPage = (current, size) => {
    if (total.value === null || !size || size <= 0) return current
    const maxPage = Math.max(1, Math.ceil(total.value / size))
    return Math.min(current, maxPage)
  }

  return {
    phase,
    total,
    failed,
    stale,
    isEmpty,
    totalKnown,
    showErrorBlock,
    showTable,
    begin,
    commit,
    fail,
    abort,
    reset,
    clampPage,
  }
}
