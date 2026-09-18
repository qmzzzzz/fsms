/**
 * 前端日期/时间格式化工具测试（utils/datetime.js）
 *
 * 为何需要它：这两个函数是**唯一事实来源**（O-3 抽取），被 DeviceView /
 * AuditLogView / ReportView / IpListView / DashboardCharts 共用。此前覆盖率 0%。
 *
 * 关键不变量：口径为**本地时区**且 hour12=false。用 toISOString()（UTC）
 * 会在东八区凌晨 0-8 点把日期算成前一天——这正是本模块存在的理由，
 * 所以必须用「构造本地时间再断言本地字段」的方式钉住，不能拿 UTC 串比对。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { localDateStr, formatTime, toLocalWallClock } from '@/utils/datetime'

afterEach(() => {
  vi.useRealTimers()
})

describe('localDateStr 本地日期串', () => {
  test('补零到两位：个位数月/日输出 01/05 而非 1/5', () => {
    expect(localDateStr(new Date(2026, 0, 5))).toBe('2026-01-05')
    expect(localDateStr(new Date(2026, 8, 9))).toBe('2026-09-09')
    expect(localDateStr(new Date(2026, 11, 31))).toBe('2026-12-31')
  })

  test('缺省参数取当前时间（与系统时钟同源）', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(2026, 5, 15, 10, 30, 0))
    expect(localDateStr()).toBe('2026-06-15')
  })

  test('跨年边界：12-31 与 01-01 各自归年（不得错位一天）', () => {
    expect(localDateStr(new Date(2025, 11, 31, 23, 59, 59))).toBe('2025-12-31')
    expect(localDateStr(new Date(2026, 0, 1, 0, 0, 1))).toBe('2026-01-01')
  })

  test('本地口径而非 UTC：UTC+8 下 toISOString 会退到前一天，本函数不得退', () => {
    // 用独立参照系（Intl 的本地日期）交叉验证，而不是拿实现自己跟自己比。
    // 构造本地 2026-03-01 00:30：在 UTC+8 下 toISOString().slice(0,10) 得到
    // 2026-02-28（退一天），Intl 本地格式化得到 2026-03-01 —— 两者必然不同，
    // 因此本断言在任何时区下都有意义：它钉住的是「与本地日历一致」这个契约。
    const localMidnight = new Date(2026, 2, 1, 0, 30, 0)
    const intlLocalDate = new Intl.DateTimeFormat('en-CA', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(localMidnight)
    expect(localDateStr(localMidnight)).toBe('2026-03-01')
    // 与 Intl 的本地日历口径一致（不同参照系、相同结论）
    expect(localDateStr(localMidnight)).toBe(intlLocalDate)
  })
})

describe('formatTime 时间串', () => {
  test('空值一律返回占位符 -（null/undefined/空串/0 都要覆盖）', () => {
    for (const v of [null, undefined, '', 0, false]) {
      expect(formatTime(v)).toBe('-')
    }
  })

  test('非法日期串返回占位符 -，不抛错也不输出 Invalid Date', () => {
    for (const v of ['not-a-date', 'abc', {}, '2026-13-45T99:99:99']) {
      expect(formatTime(v)).toBe('-')
    }
  })

  test('合法输入输出「YYYY-MM-DD HH:mm:ss」且各段补零', () => {
    const d = new Date(2026, 0, 5, 9, 7, 3)
    expect(formatTime(d)).toBe('2026-01-05 09:07:03')
  })

  test('接受 ISO 字符串并转成本地口径（含日期部分，不只是时间）', () => {
    const d = new Date(2026, 6, 20, 14, 25, 30)
    const iso = d.toISOString()
    expect(formatTime(iso)).toBe(localDateStr(d) + ' 14:25:30')
  })

  test('接受毫秒时间戳', () => {
    const d = new Date(2026, 3, 10, 23, 59, 59)
    expect(formatTime(d.getTime())).toBe('2026-04-10 23:59:59')
  })

  test('hour12=false：午夜与正午都输出 00/12 而非 12:00 AM / 12:00 PM', () => {
    expect(formatTime(new Date(2026, 0, 1, 0, 0, 0))).toBe('2026-01-01 00:00:00')
    expect(formatTime(new Date(2026, 0, 1, 12, 0, 0))).toBe('2026-01-01 12:00:00')
    expect(formatTime(new Date(2026, 0, 1, 13, 0, 0))).toBe('2026-01-01 13:00:00')
  })

  test('跨日边界：23:59:59 与次日 00:00:00 各自正确（日期与时间同一口径）', () => {
    expect(formatTime(new Date(2026, 1, 28, 23, 59, 59))).toBe('2026-02-28 23:59:59')
    expect(formatTime(new Date(2026, 2, 1, 0, 0, 0))).toBe('2026-03-01 00:00:00')
  })
})

describe('toLocalWallClock 本地墙钟串（date-picker 回填口径）', () => {
  test('ISO 串按本地时区转换，与 Date 的本地 getter 一致（不是 UTC 字面小时）', () => {
    const iso = '2026-10-01T01:00:00.000Z'
    const d = new Date(iso)
    const p2 = (n) => String(n).padStart(2, '0')
    const expected =
      localDateStr(d) + ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds())
    expect(toLocalWallClock(iso)).toBe(expected)
    expect(toLocalWallClock(iso)).not.toContain('T')
    expect(toLocalWallClock(iso)).not.toContain('Z')
  })

  test('输出格式与 picker 的 value-format 同构：YYYY-MM-DD HH:mm:ss 且各段补零', () => {
    const d = new Date(2026, 0, 5, 9, 7, 3)
    expect(toLocalWallClock(d)).toBe('2026-01-05 09:07:03')
    expect(toLocalWallClock(new Date(2026, 0, 5, 9, 7, 3).toISOString())).toBe(
      '2026-01-05 09:07:03'
    )
  })

  test('接受毫秒时间戳与 Date 实例', () => {
    const d = new Date(2026, 3, 10, 23, 59, 59)
    expect(toLocalWallClock(d.getTime())).toBe('2026-04-10 23:59:59')
    expect(toLocalWallClock(d)).toBe('2026-04-10 23:59:59')
  })

  test('空值/非法值返回空串（picker 显示为空，交给必填校验拦截，不得伪造当前时间）', () => {
    for (const v of [null, undefined, 0, false, '', 'not-a-date']) {
      expect(toLocalWallClock(v)).toBe('')
    }
  })

  test('与 formatTime 同一口径：同一输入两者输出一致（单一事实来源）', () => {
    const iso = '2026-09-30T17:00:00.000Z'
    expect(toLocalWallClock(iso)).toBe(formatTime(iso))
    const d = new Date(2026, 7, 8, 6, 5, 4)
    expect(toLocalWallClock(d)).toBe(formatTime(d))
  })
})
