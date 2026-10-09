/**
 * SecurityStatsCard（管理员安全统计）行为测试
 *
 * 端点在 securityRoutes.js:232-237，挂 checkPermission('security:stats')，返回
 *   { overview:{todayLogins,todayFailedLogins,highRiskOperations},
 *     anomalies:{failedOperationUsers[],unusualTimeUsers[]}, securityLevel }。
 * 此前 api.js 只封装不消费（B 组 4 个自助端点之一），本卡是它的界面入口。
 *
 * 为什么值得测：这是**值班界面**上的一块全局读数——今日登录/失败/高危操作。
 * 它的失败形态是静默且危险的：接口挂掉时若把上一次的数字留在屏上，值班人员会
 * 把过期读数当成"此刻的实况"（比空白更误导）。故用例逐条钉住：
 *   - 成功渲染三类数字与异常计数；
 *   - 安全等级标签按 securityLevel 分级（normal/high）；
 *   - 失败落错误态并**清空**读数；点刷新可恢复；
 *   - 已有读数后刷新失败：旧读数被清掉，不回显过期值。
 *
 * 权限门控（无 security:stats 时整卡不渲染也不请求）与首页刷新周期接线
 * （5 分钟定时 / 可见性恢复会连带刷新本卡）由 dashboardView.test.js 覆盖——
 * 门控与刷新驱动都在父视图，不在本组件。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, ref } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const getSecurityStats = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    security: {
      getSecurityStats: (...a) => getSecurityStats(...a),
    },
  },
  isCanceledError: () => false,
}))

const SecurityStatsCard = (await import('@/components/SecurityStatsCard.vue')).default

let active = null
/** 指向被测组件实例（wrapper 的模板 ref），用于调用 expose 的 load() */
let cardRef = null

/** 与父视图 DashboardView 相同的用法：模板 ref + defineExpose 的 load() */
const CardWrapper = defineComponent({
  setup() {
    cardRef = ref(null)
    return () => h(SecurityStatsCard, { ref: cardRef })
  },
})

const open = async () => {
  cardRef = null
  active = mountComponent(CardWrapper, {
    initialRoute: '/dashboard',
    routes: [{ path: '/dashboard', component: { render: () => null } }],
  })
  await flush(12)
  return active
}

/** 三格读数（今日登录 / 今日失败登录 / 高危操作），按 DOM 顺序 */
const values = (c) => c.findAll('.ss-value').map((x) => x.textContent.trim())
/** 异常区的两个标签文案 */
const anomalyTags = (c) => c.findAll('.ss-anomalies .el-tag').map((x) => x.textContent.trim())

const ok = (over = {}) => ({
  data: {
    data: {
      overview: { todayLogins: 12, todayFailedLogins: 3, highRiskOperations: 1 },
      anomalies: { failedOperationUsers: ['u1'], unusualTimeUsers: [] },
      securityLevel: 'normal',
      ...over,
    },
  },
})

const clickRetry = (c) => {
  const btn = c.findAll('button').find((b) => b.textContent.trim() === '刷新')
  expect(btn).toBeTruthy()
  click(btn)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  cardRef = null
  getSecurityStats.mockReset()
})

describe('SecurityStatsCard（管理员安全统计）', () => {
  test('成功：渲染三格读数、异常计数与正常等级标签', async () => {
    getSecurityStats.mockResolvedValue(ok())

    const c = await open()
    await waitFor(() => values(c).length === 3, { message: '三格读数渲染' })

    expect(getSecurityStats).toHaveBeenCalledTimes(1)
    // 顺序即语义：今日登录 / 今日失败登录 / 高危操作
    expect(values(c)).toEqual(['12', '3', '1'])
    // 失败登录用 is-bad、高危用 is-warn（分级配色，非涨跌色）
    expect(c.find('.ss-value.is-bad').textContent.trim()).toBe('3')
    expect(c.find('.ss-value.is-warn').textContent.trim()).toBe('1')

    // 异常区：两个标签各带计数（不是只显示名字）
    expect(anomalyTags(c)).toEqual(['失败操作用户 · 1', '非常规时段用户 · 0'])
    expect(c.text()).toContain('安全等级·正常')
  })

  test('securityLevel=high：等级标签切到「偏高」并带 danger 语义', async () => {
    getSecurityStats.mockResolvedValue(ok({ securityLevel: 'high' }))

    const c = await open()
    await waitFor(() => c.text().includes('安全等级'), { message: '等级标签渲染' })

    expect(c.text()).toContain('安全等级·偏高')
    expect(c.text()).not.toContain('安全等级·正常')
    // 原生 DOM（非 test-utils）：用 classList 判语义色，danger 与"偏高"一致
    expect(c.find('.ss-header .el-tag').classList.contains('el-tag--danger')).toBe(true)
  })

  test('字段缺失按 0 / 空数组兜底（不是 undefined / NaN）', async () => {
    getSecurityStats.mockResolvedValue({ data: { data: {} } })

    const c = await open()
    await waitFor(() => values(c).length === 3, { message: '三格读数渲染' })

    expect(values(c)).toEqual(['0', '0', '0'])
    expect(anomalyTags(c)).toEqual(['失败操作用户 · 0', '非常规时段用户 · 0'])
    // 缺 securityLevel 时按 normal（不因缺字段就宣称"偏高"）
    expect(c.text()).toContain('安全等级·正常')
  })

  test('失败：落错误态且不渲染任何读数（不留过期数字）', async () => {
    getSecurityStats.mockRejectedValue(new Error('boom'))

    const c = await open()
    await waitFor(() => c.find('.self-error') !== null, { message: '错误态出现' })

    // 错误态下不得渲染读数：值班界面把旧值当现况是危险的
    expect(values(c)).toHaveLength(0)
    expect(c.find('.ss-anomalies')).toBeNull()
    // 等级标签只在成功态出现（错误态不宣称"正常"）
    expect(c.find('.ss-header .el-tag')).toBeNull()
  })

  test('已有读数后刷新失败：清空旧读数并落错误态（不回显过期值）', async () => {
    getSecurityStats.mockResolvedValueOnce(ok())
    const c = await open()
    await waitFor(() => values(c).length === 3, { message: '首屏读数' })

    // 第二次刷新（父级定时/可见性恢复触发的同一个 load）失败：旧读数必须被清掉
    getSecurityStats.mockRejectedValueOnce(new Error('boom'))
    await cardRef.value.load()
    await flush(8)

    await waitFor(() => c.find('.self-error') !== null, { message: '错误态出现' })
    expect(values(c)).toHaveLength(0)
  })

  test('错误态点刷新可恢复：重新拉取并渲染读数', async () => {
    getSecurityStats.mockRejectedValueOnce(new Error('boom'))
    const c = await open()
    await waitFor(() => c.find('.self-error') !== null, { message: '错误态出现' })

    getSecurityStats.mockResolvedValueOnce(ok({ overview: { todayLogins: 5 } }))
    clickRetry(c)
    await waitFor(() => c.find('.ss-value') !== null, { message: '重试恢复' })

    expect(values(c)[0]).toBe('5')
    // 本次响应未给的字段按 0 兜底
    expect(values(c)).toEqual(['5', '0', '0'])
  })
})
