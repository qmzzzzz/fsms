/**
 * DeviceReminderDialog 行为测试（设备到期提醒清单，只读展示组件）
 *
 * 数据由 DeviceView 持有并作为 prop 传入，本套件钉住四类渲染退化：
 *
 *  1. 降级信号丢失（partial/skipped）：后端扫描互斥锁命中或未扫描完成时
 *     列表不完整，UI 不显式告知的话，用户按「清单为空」判断「无到期设备」。
 *  2. 单档截断（limits.truncated）：档内计数是页内值而非库里总数，
 *     不显示截断提示 = 用户以为看到的 20 条就是全部。
 *  3. 空态口径：summary.total === 0 与「暂无数据」必须一致（有档位标题
 *     但全空会被读成加载中）。
 *  4. 失败态与重试：failed && !data 时展示失败块，点重试必须发出 refresh。
 *
 * 日期显示用本地时区（UTC 口径会把 00:00Z 的到期日退一天）；测试用同款
 * utils/datetime 计算期望值，钉接线而不是钉时区实现。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { localDateStr, formatTime } from '@/utils/datetime'

import DeviceReminderDialog from '@/components/DeviceReminderDialog.vue'

let active = null
afterEach(() => {
  active?.handle.unmount()
  active = null
  document.body.innerHTML = ''
})

const DATA = {
  scannedAt: '2026-10-19T08:00:00.000Z',
  summary: { expired: 1, expiringSoon: 1, needMaintenance: 1, needSchedule: 0, total: 3 },
  expired: [
    {
      _id: 'd9',
      deviceCode: 'EXT-009',
      deviceName: '过期灭火器',
      location: { building: 'B栋', floor: '2', room: '201' },
      expiryDate: '2026-09-01T00:00:00.000Z',
      status: 'warning',
    },
  ],
  expiringSoon: [
    {
      _id: 'd8',
      deviceCode: 'SMK-008',
      deviceName: '临期烟感',
      location: { building: 'A栋' },
      expiryDate: '2026-10-25T00:00:00.000Z',
      status: 'normal',
    },
  ],
  needMaintenance: [
    {
      _id: 'd7',
      deviceCode: 'PMP-007',
      deviceName: '待检水泵',
      location: { building: 'C栋' },
      nextCheckDate: '2026-10-01T00:00:00.000Z',
      status: 'normal',
    },
  ],
  needSchedule: [],
  limits: {
    resultLimit: 20,
    truncated: { expired: false, expiringSoon: false, needMaintenance: false, needSchedule: false },
  },
  partial: false,
  skipped: false,
}

/** 受控宿主：把 refresh 事件记到本地，观察「重试」是否真的向上请求 */
const makeHost = (props = {}, onRefresh = null) => {
  const state = reactive({ visible: true, refreshed: 0 })
  const Host = defineComponent({
    setup() {
      return () =>
        h(DeviceReminderDialog, {
          visible: state.visible,
          'onUpdate:visible': (v) => {
            state.visible = v
          },
          ...props,
          onRefresh: () => {
            state.refreshed += 1
            if (onRefresh) onRefresh()
          },
        })
    },
  })
  active = mountComponent(Host)
  return state
}

const dlg = () => document.body.querySelector('.el-dialog')

const open = async (props = {}, onRefresh = null) => {
  const state = makeHost(props, onRefresh)
  await waitFor(() => dlg(), { message: '对话框渲染' })
  await flush(6)
  return state
}

describe('DeviceReminderDialog 清单渲染', () => {
  test('有数据：档位标题带计数，行含设备编码/名称/本地日期，空档位不渲染', async () => {
    const state = await open({ data: DATA })
    expect(state.visible).toBe(true)
    const text = dlg().textContent
    expect(text).toContain('到期提醒清单')
    expect(text).toContain('扫描时间')
    expect(text).toContain(formatTime(DATA.scannedAt))
    // 三档有数据 → 标题带计数；needSchedule 空 → 整档不渲染
    expect(text).toContain('已过期（1）')
    expect(text).toContain('即将到期（1）')
    expect(text).toContain('待维护（1）')
    expect(text).not.toContain('未排期（')
    // 行内容
    expect(text).toContain('EXT-009')
    expect(text).toContain('过期灭火器')
    expect(text).toContain(localDateStr(new Date('2026-09-01T00:00:00.000Z')))
    // 待维护档用的是 nextCheckDate
    expect(text).toContain(localDateStr(new Date('2026-10-01T00:00:00.000Z')))
    expect(active.errors).toEqual([])
  })

  test('summary.total 为 0：只显示空态，不显示任何档位标题', async () => {
    await open({
      data: {
        ...DATA,
        summary: { expired: 0, expiringSoon: 0, needMaintenance: 0, needSchedule: 0, total: 0 },
        expired: [],
        expiringSoon: [],
        needMaintenance: [],
      },
    })
    const text = dlg().textContent
    expect(text).toContain('暂无需要处理的到期/维护提醒')
    expect(text).not.toContain('已过期（')
    expect(text).not.toContain('即将到期（')
  })

  test('partial=true：降级横幅可见（列表可能不完整时必须说出来）', async () => {
    await open({ data: { ...DATA, partial: true, skipped: true } })
    expect(dlg().textContent).toContain('清单可能不完整')
  })

  test('单档截断：truncated 档显示「仅显示前 N 条」，未截断档不显示', async () => {
    await open({
      data: {
        ...DATA,
        limits: {
          resultLimit: 20,
          truncated: {
            expired: true,
            expiringSoon: false,
            needMaintenance: false,
            needSchedule: false,
          },
        },
      },
    })
    const hints = Array.from(dlg().querySelectorAll('.reminder-truncated'))
    expect(hints).toHaveLength(1)
    expect(hints[0].textContent).toContain('20')
  })
})

describe('DeviceReminderDialog 空/错状态', () => {
  test('failed 且无数据：显示失败块；点重试向上 emit refresh', async () => {
    const state = await open({ data: null, failed: true })
    expect(dlg().querySelector('.reminder-failed')).toBeTruthy()
    const retry = Array.from(dlg().querySelectorAll('button')).find((b) =>
      b.textContent.includes('刷新')
    )
    expect(retry).toBeTruthy()
    click(retry)
    await flush(4)
    expect(state.refreshed).toBe(1)
    expect(active.errors).toEqual([])
  })

  test('failed 但有历史数据：保留清单不显示失败块（陈旧但真实）', async () => {
    await open({ data: DATA, failed: true })
    expect(dlg().querySelector('.reminder-failed')).toBeNull()
    expect(dlg().textContent).toContain('过期灭火器')
  })
})
