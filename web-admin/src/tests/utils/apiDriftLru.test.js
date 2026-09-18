/**
 * P3-66 回归：schema 漂移去重集合的 LRU 上限
 *
 * 缺陷回顾：reportedDrifts 是裸 Set，键为 `url::detail`（detail 含字段级错误信息），
 * 长时间运行可持续新增且永不淘汰 —— 无界增长。
 *
 * 修复必须同时满足两条语义，缺一即回归：
 *  ① 有界：键数不超过 DRIFT_LRU_MAX（200）；
 *  ② 真 LRU（而非插入序 FIFO 截断）：仍在持续发生的漂移会被刷新到队尾，
 *     被淘汰的是「最久没有再次出现」的键。
 *
 * 本套件用真实 apiClient + 自定义 adapter 驱动拦截器，以 console.error 的
 * '[schema-drift]' 输出次数作为「是否判定为新漂移」的观测点（命中已记录的键
 * 时该输出不产生）。200 个键用 200 个不同 URL 构造，其余字段完全相同。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { apiClient, __getDriftCount, __resetDriftReports } from '@/utils/api'

vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { error: vi.fn(), warning: vi.fn(), success: vi.fn(), info: vi.fn() },
}))

// looseObject 允许额外字段，但 success 必须是布尔 —— 用它构造唯一一种 issue
const INVALID_ENVELOPE = { success: 'not-a-boolean' }

const requestDrift = (n) => {
  apiClient.defaults.adapter = (config) =>
    Promise.resolve({
      data: INVALID_ENVELOPE,
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    })
  return apiClient.get(`/__drift/${n}`)
}

const driftReports = () =>
  console.error.mock.calls.filter((args) => String(args[0]).includes('[schema-drift]')).length

describe('漂移去重集合 LRU 上限（P3-66）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    __resetDriftReports()
  })

  afterEach(() => {
    delete apiClient.defaults.adapter
    vi.restoreAllMocks()
    __resetDriftReports()
  })

  test('同一漂移重复出现只报一次（既有语义未被 LRU 改动破坏）', async () => {
    await requestDrift(0)
    await requestDrift(0)
    await requestDrift(0)

    expect(driftReports()).toBe(1)
    expect(__getDriftCount()).toBe(1)
  })

  test('超过上限后有界：200 个键满额，第 201 个键仍为 200', async () => {
    for (let i = 0; i < 201; i += 1) await requestDrift(i)

    expect(driftReports()).toBe(201) // 每个键都是新漂移，各自告警一次
    expect(__getDriftCount()).toBe(200) // 但集合不增长
  })

  test('淘汰的是最久未再出现的键：命中刷新位置，LRU 键被挤出', async () => {
    for (let i = 0; i < 200; i += 1) await requestDrift(i)
    expect(__getDriftCount()).toBe(200)
    const afterFill = driftReports()

    // 刷新 #0：命中已记录键 → 不产生新的漂移告警
    await requestDrift(0)
    expect(driftReports()).toBe(afterFill)

    // 新增第 201 个键 → 淘汰队首。此时队首是 #1（#0 刚被刷新到队尾）
    await requestDrift(200)
    expect(__getDriftCount()).toBe(200)
    expect(driftReports()).toBe(afterFill + 1)

    // #0 仍在集合（刚刷新过）→ 命中
    await requestDrift(0)
    expect(driftReports()).toBe(afterFill + 1)

    // #1 已被淘汰 → 再次出现视为新漂移
    await requestDrift(1)
    expect(driftReports()).toBe(afterFill + 2)
  })

  test('LRU 上限不会误报关键路径告警（/auth/me 漂移仍走 ElMessage）', async () => {
    // 与 ElMessage 无关的通用包络漂移不打扰用户，专用 schema 漂移才提示
    apiClient.defaults.adapter = (config) =>
      Promise.resolve({
        data: INVALID_ENVELOPE,
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
      })
    await apiClient.get('/auth/me')
    expect(ElMessage.warning).toHaveBeenCalledTimes(1)
  })
})
