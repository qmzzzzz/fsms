/**
 * auditTrace 补测（2026-11-06 收敛批）：溯源区块的「空值语义」四态判据。
 *
 * 四态是本模块的契约本体：空对象/空串（本来就没有）、body===null（GET 约定）、
 * undefined 且 v6+（事件型无响应侧）、undefined 且 <v6（老记录不可回填）——
 * 任一态说错话都会把「没有证据」伪装成「没有问题」。
 */
import { describe, it, expect } from 'vitest'
import {
  EMPTY_KEYS,
  TRACE_FIELDS,
  isEmptyTrace,
  formatTraceValue,
  traceValueText,
  hashVersionOf,
  traceEmptyHint,
  httpStatusKey,
} from '@/utils/auditTrace'

describe('isEmptyTrace', () => {
  it('空值家族：undefined / null / 空串 / 空对象', () => {
    expect(isEmptyTrace(undefined)).toBe(true)
    expect(isEmptyTrace(null)).toBe(true)
    expect(isEmptyTrace('')).toBe(true)
    expect(isEmptyTrace({})).toBe(true)
  })

  it('非空：字符串、非空对象、数组（空数组本身是结论，不算空）', () => {
    expect(isEmptyTrace('x')).toBe(false)
    expect(isEmptyTrace({ a: 1 })).toBe(false)
    expect(isEmptyTrace([])).toBe(false)
  })
})

describe('formatTraceValue / traceValueText', () => {
  it('空值统一渲染 "-"', () => {
    expect(formatTraceValue(undefined)).toBe('-')
    expect(formatTraceValue(null)).toBe('-')
    expect(formatTraceValue('')).toBe('-')
    expect(formatTraceValue({})).toBe('-')
  })

  it('字符串原样；对象 JSON 美化；其余 String 化', () => {
    expect(formatTraceValue('/api/devices')).toBe('/api/devices')
    expect(formatTraceValue({ a: 1 })).toBe('{\n  "a": 1\n}')
    expect(formatTraceValue(304)).toBe('304')
  })

  it('循环引用：JSON 失败时回退 String()（不抛错打断渲染）', () => {
    const circular = {}
    circular.self = circular
    expect(formatTraceValue(circular)).toBe('[object Object]')
  })

  it('traceValueText：空值返回空串（由模板决定是否配提示行）', () => {
    expect(traceValueText({})).toBe('')
    expect(traceValueText({ a: 1 })).toBe('{\n  "a": 1\n}')
  })
})

describe('hashVersionOf', () => {
  it('数字与数字串都收敛为数值；缺失/非法一律 null（当作老记录）', () => {
    expect(hashVersionOf({ hashVersion: 6 })).toBe(6)
    expect(hashVersionOf({ hashVersion: '6' })).toBe(6)
    expect(hashVersionOf({})).toBe(null)
    expect(hashVersionOf({ hashVersion: 'abc' })).toBe(null)
    // record 本身是原始值：属性读取为 undefined ⇒ 同样落 null（0 的怪值不存在于此臂）
    expect(hashVersionOf('abc')).toBe(null)
  })
})

describe('traceEmptyHint 四态', () => {
  it('body===null：GET 约定不记请求体', () => {
    expect(traceEmptyHint({ hashVersion: 6, body: null }, 'body')).toBe('auditLog.traceGetNoBody')
  })

  it('采集到空对象/空串：用逐字段的「本来就没有」文案', () => {
    for (const field of TRACE_FIELDS) {
      expect(traceEmptyHint({ [field]: {} }, field)).toBe(EMPTY_KEYS[field])
    }
    expect(traceEmptyHint({ query: '' }, 'query')).toBe(EMPTY_KEYS.query)
  })

  it('undefined 且 v6+：事件型记录，响应侧溯源不可得', () => {
    expect(traceEmptyHint({ hashVersion: 6 }, 'responseHeaders')).toBe('auditLog.traceEventNoTrace')
  })

  it('undefined 且 <v6：老记录，字段在采集上线前不存在', () => {
    expect(traceEmptyHint({ hashVersion: 5 }, 'responseHeaders')).toBe(
      'auditLog.traceLegacyNotCollected'
    )
    // 老记录缺 hashVersion 字段：等价于无版本 ⇒ 老记录
    expect(traceEmptyHint({}, 'responseBody')).toBe('auditLog.traceLegacyNotCollected')
  })

  it('未知字段落到通用文案；record 为 null 走老记录路径', () => {
    expect(traceEmptyHint({ unknownField: {} }, 'unknownField')).toBe('auditLog.traceEmptyGeneric')
    expect(traceEmptyHint(null, 'body')).toBe('auditLog.traceLegacyNotCollected')
  })
})

describe('httpStatusKey', () => {
  it('空值返回空串（模板不渲染状态码行）；有值拼词条 key', () => {
    expect(httpStatusKey(null)).toBe('')
    expect(httpStatusKey(undefined)).toBe('')
    expect(httpStatusKey('')).toBe('')
    expect(httpStatusKey(304)).toBe('auditLog.httpStatus.304')
    expect(httpStatusKey('403')).toBe('auditLog.httpStatus.403')
  })
})
