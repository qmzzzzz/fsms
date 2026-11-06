/**
 * 攻击告警词典跨端对齐（后端注册表 ↔ 前端码表 ↔ 双语词表）
 *
 * 后端只回传审计 action 与处置码（src/constants/attackEvents.js 是单一事实来源），
 * 分类标签由前端按镜像码表派生、自然语言按当前界面语言渲染。三处任一漂移，
 * 页面不会报错：分类会退回裸码、词典 miss 会渲染出英文标识——客户看到的就是
 * 一串 `attackAlerts.types.some_new_code`。
 *
 * 本闸钉住四层：前端码表 ≡ 后端注册表（分类顺序 + 切片）、双语词表覆盖
 * 分类与全部 action、无死键、zh/en 叶子键集一致。另加变异对照，避免
 * 「词表整体被清空 ⇒ 断言恒真」。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'
import zhAlerts from '@/i18n/locales/attackAlerts.zh-CN'
import enAlerts from '@/i18n/locales/attackAlerts.en-US'
import {
  ATTACK_EVENT_TYPE_CODES,
  ATTACK_EVENT_ACTIONS,
  ALL_ATTACK_EVENT_ACTIONS,
} from '@/constants/attackAlerts'

const require = createRequire(import.meta.url)
const backend = require('../../../../src/constants/attackEvents.js')

const flattenKeys = (obj, prefix = '') =>
  Object.entries(obj).flatMap(([key, value]) =>
    value && typeof value === 'object'
      ? flattenKeys(value, `${prefix}${key}.`)
      : [`${prefix}${key}`]
  )

const emptyLeaves = (dict) =>
  Object.entries(dict)
    .flatMap(([key, value]) =>
      typeof value === 'string' ? [[key, value]] : Object.entries(value).map(([k, v]) => [k, v])
    )
    .filter(([, value]) => typeof value !== 'string' || value.trim() === '')
    .map(([key]) => key)
    .sort()

describe('攻击告警词典：后端注册表必须有前端码表与双语落点', () => {
  test('前提自证：注册表非空且前端码表已导入（对账对象被清空时不得静默通过）', () => {
    expect(backend.ATTACK_EVENT_TYPE_CODES.length).toBeGreaterThan(0)
    expect(backend.ALL_ATTACK_EVENT_ACTIONS.length).toBeGreaterThan(0)
    expect(ALL_ATTACK_EVENT_ACTIONS.length).toBe(backend.ALL_ATTACK_EVENT_ACTIONS.length)
  })

  test('前端码表 ≡ 后端注册表：分类码顺序一致、各分类切片一致', () => {
    expect(ATTACK_EVENT_TYPE_CODES).toEqual(backend.ATTACK_EVENT_TYPE_CODES)
    for (const code of backend.ATTACK_EVENT_TYPE_CODES) {
      expect([...ATTACK_EVENT_ACTIONS[code]].sort()).toEqual(
        [...backend.actionsByAttackType(code)].sort()
      )
    }
  })

  test('zh-CN / en-US 覆盖全部分类码与全部注册表 action', () => {
    for (const dict of [zhAlerts, enAlerts]) {
      expect(ATTACK_EVENT_TYPE_CODES.filter((code) => !(code in dict.types))).toEqual([])
      expect(ALL_ATTACK_EVENT_ACTIONS.filter((code) => !(code in dict.actions))).toEqual([])
      expect(['low', 'medium', 'high', 'critical'].every((k) => k in dict.severity)).toBe(true)
      expect(['banned', 'forensic', 'observing'].every((k) => k in dict.disposal)).toBe(true)
    }
  })

  test('types/actions/severity/disposal 无死键（前端键必须后端认识）', () => {
    const backendCodes = new Set(backend.ATTACK_EVENT_TYPE_CODES)
    const backendActions = new Set(backend.ALL_ATTACK_EVENT_ACTIONS)
    for (const dict of [zhAlerts, enAlerts]) {
      expect(Object.keys(dict.types).filter((k) => !backendCodes.has(k))).toEqual([])
      expect(Object.keys(dict.actions).filter((k) => !backendActions.has(k))).toEqual([])
    }
  })

  test('zh / en 的叶子键集完全一致（双语缺一即红，不靠运行时兜底）', () => {
    expect(flattenKeys(zhAlerts).sort()).toEqual(flattenKeys(enAlerts).sort())
  })

  test('文案叶子非空（空串会渲染成空白）', () => {
    for (const dict of [zhAlerts, enAlerts]) {
      expect(emptyLeaves(dict.types)).toEqual([])
      expect(emptyLeaves(dict.actions)).toEqual([])
      expect(emptyLeaves(dict.severity)).toEqual([])
      expect(emptyLeaves(dict.disposal)).toEqual([])
    }
  })

  test('判据可失败：删一个分类键、加一个死码、zh/en 键集失配，都必须被同一组判据抓到', () => {
    const mutated = JSON.parse(JSON.stringify(zhAlerts))
    delete mutated.types.honeypot
    expect(ATTACK_EVENT_TYPE_CODES.filter((code) => !(code in mutated.types))).toContain('honeypot')

    mutated.types.not_a_type = '死码'
    expect(Object.keys(mutated.types).filter((k) => !backendCodesSet.has(k))).toContain(
      'not_a_type'
    )

    mutated.actions.extra_action = '多余键'
    expect(flattenKeys(mutated).sort()).not.toEqual(flattenKeys(enAlerts).sort())
  })

  test('告警词表已移出入口词表（随工作台 chunk 懒加载，首屏预算的前提）', () => {
    expect(zhCN.attackAlerts).toBeUndefined()
    expect(enUS.attackAlerts).toBeUndefined()
    // nav.attackAlerts（tab 标题）属于入口词表的工作台导航键，必须在
    expect(zhCN.nav.attackAlerts).toBeDefined()
    expect(enUS.nav.attackAlerts).toBeDefined()
  })
})

// 变异用例里的死码判据基线（与上面的死键检查同一份来源）
const backendCodesSet = new Set(backend.ATTACK_EVENT_TYPE_CODES)
