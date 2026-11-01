/**
 * 枚举 → 前端标签映射的跨端覆盖闸（第 17 轮 r17-web F3）
 *
 * 缺陷形态：后端枚举是唯一事实来源，前端却**手抄**成各自的映射表；缺键时界面不是报错而是
 * **静默渲染空**（InspectionView.vue:108 的 \`{{ typeMap[row.inspectionType] }}\`），
 * 于是「新增一档巡检类型」在前端表现为"这一列莫名其妙空着"，没有任何一处会红。
 * 变异实测（r17-web §F3）：后端枚举 +1 后跑相关前端用例 **全绿**；对照组把
 * AUDIT_LOG_ACTIONS +1 则 auditActionCoverage 立刻 3 failed/5 —— 证明"闸是真的、可证伪的"，
 * 缺的只是覆盖面。本文件把覆盖面补到巡检/报警两族。
 *
 * 判据取 **⊇**（前端映射必须覆盖后端全集）而不是等值：前端映射里允许存在视图专用的
 * 附加键（如 resultMap 的展示档），但后端每一个值都必须有落点。反向的死键检查另有
 * 一处成本：前端可能有跨枚举复用的标签，故这里只对"键即枚举值"的映射做双向核对。
 *
 * 后端枚举**直接 require**，不在本文件手抄——手抄等于把对账退化成复制。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { makeAlarmTypeLabels, makeAlarmStatusLabels } from '@/utils/labelMaps'

const require = createRequire(import.meta.url)
const { ALARM_TYPES, ALARM_STATUSES, ALARM_CAUSES } = require('../../../../src/constants/alarm.js')
const {
  INSPECTION_TYPES,
  INSPECTION_STATUSES,
  INSPECTION_RESULTS,
} = require('../../../../src/constants/inspection.js')

const HERE = dirname(fileURLToPath(import.meta.url))
const webSrc = (rel) => readFileSync(resolve(HERE, '../../', rel), 'utf8')

/**
 * 从源码里抠出「对象字面量的顶层键」。
 * anchor 找不到时**抛出**而不是返回空集——返回空集会让上面的覆盖断言在解析失败时静默通过。
 */
const keysAfter = (src, anchor) => {
  const at = src.indexOf(anchor)
  if (at < 0) throw new Error(`锚点未命中（映射被改名/挪走后本闸必须红）：${anchor}`)
  const start = src.indexOf('{', at + anchor.length - 1)
  if (start < 0) throw new Error(`锚点之后没有对象字面量：${anchor}`)
  let depth = 0
  let end = -1
  for (let i = start; i < src.length; i += 1) {
    const c = src[i]
    if (c === '{') depth += 1
    else if (c === '}') {
      depth -= 1
      if (depth === 0) {
        end = i
        break
      }
    }
  }
  if (end < 0) throw new Error(`对象字面量未闭合：${anchor}`)
  const body = src.slice(start + 1, end)
  const keys = []
  let d = 0
  for (const line of body.split('\n')) {
    const trimmed = line.trim()
    if (d === 0) {
      const m = /^([A-Za-z_$][\w$]*):/.exec(trimmed)
      if (m) keys.push(m[1])
    }
    d += (line.match(/[{([]/g) || []).length - (line.match(/[})\]]/g) || []).length
  }
  return keys
}

/** \`<el-option value="daily">\` 形态的取值集合 */
const optionValues = (src) => [...src.matchAll(/<el-option[^>]*value="([^"]+)"/g)].map((m) => m[1])

const missingOf = (expected, actual) => expected.filter((v) => !actual.includes(v)).sort()

describe('前端枚举映射覆盖后端全集（伪装成"渲染空"的静默漂移）', () => {
  const inspectionView = webSrc('views/InspectionView.vue')
  const inspectionForm = webSrc('components/InspectionForm.vue')
  const alarmView = webSrc('views/AlarmView.vue')

  test('前提自证：六族枚举都非空且唯一（对账对象被清空时不得静默通过）', () => {
    const families = [
      INSPECTION_TYPES,
      INSPECTION_STATUSES,
      INSPECTION_RESULTS,
      ALARM_TYPES,
      ALARM_STATUSES,
      ALARM_CAUSES,
    ]
    families.forEach((f) => {
      expect(Array.isArray(f)).toBe(true)
      expect(f.length).toBeGreaterThan(1)
      expect(new Set(f).size).toBe(f.length)
    })
  })

  test('解析器自证：真源码能抠出键，少一个键立刻被 diff 抓到', () => {
    const real = keysAfter(inspectionView, 'const typeMap = computed(() => (')
    expect(real).toContain('daily')
    expect(missingOf(INSPECTION_TYPES, real)).toEqual([])
    // 反向对照：把 daily 从副本里删掉，同一条判据必须报出 daily
    const mutated = inspectionView.replace(/\n\s*daily: t\('inspection\.typeDaily'\),/, '\n')
    expect(
      missingOf(INSPECTION_TYPES, keysAfter(mutated, 'const typeMap = computed(() => ('))
    ).toEqual(['daily'])
  })

  test('巡检类型：视图表 + 表单选项都覆盖 INSPECTION_TYPES', () => {
    expect(
      missingOf(INSPECTION_TYPES, keysAfter(inspectionView, 'const typeMap = computed(() => ('))
    ).toEqual([])
    expect(missingOf(INSPECTION_TYPES, optionValues(inspectionForm))).toEqual([])
  })

  test('巡检状态与结果：视图表覆盖后端全集', () => {
    expect(
      missingOf(
        INSPECTION_STATUSES,
        keysAfter(inspectionView, 'const statusMap = computed(() => (')
      )
    ).toEqual([])
    expect(
      missingOf(INSPECTION_RESULTS, keysAfter(inspectionView, 'const resultMap = computed(() => ('))
    ).toEqual([])
  })

  test('报警原因：AlarmView 的 CAUSE_OPTIONS 覆盖 ALARM_CAUSES', () => {
    const values = [...alarmView.matchAll(/\{\s*value:\s*'([^']+)'/g)].map((m) => m[1])
    expect(values.length).toBeGreaterThanOrEqual(ALARM_CAUSES.length)
    expect(missingOf(ALARM_CAUSES, values)).toEqual([])
  })

  test('报警类型与状态：labelMaps 的键覆盖后端全集（键即枚举值）', () => {
    expect(missingOf(ALARM_TYPES, Object.keys(makeAlarmTypeLabels((k) => k)))).toEqual([])
    expect(missingOf(ALARM_STATUSES, Object.keys(makeAlarmStatusLabels((k) => k)))).toEqual([])
  })

  test('反向：labelMaps 里没有后端不认识的键（死键永远不会被渲染）', () => {
    const deadTypes = Object.keys(makeAlarmTypeLabels((k) => k)).filter(
      (k) => !ALARM_TYPES.includes(k)
    )
    const deadStatus = Object.keys(makeAlarmStatusLabels((k) => k)).filter(
      (k) => !ALARM_STATUSES.includes(k)
    )
    expect({ deadTypes, deadStatus }).toEqual({ deadTypes: [], deadStatus: [] })
  })
})
