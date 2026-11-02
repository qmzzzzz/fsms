/**
 * 攻击画像词典跨端对齐（后端枚举 ↔ 前端双语词表）
 *
 * 后端只输出行为码（constants/attackProfile.js 是单一事实来源），自然语言由前端
 * 按当前界面语言渲染。两边一旦漂移，页面不会报错：分类卡片会退回裸码
 * `attackProfile.category.some_new_code`，客户看到的就是一串英文标识。
 *
 * 本闸钉住三族：分类、判定（含 verdictHint）、处置建议。判据是 **⊇**（后端全集
 * 必须有落点），另加反向死键检查与一条变异对照，避免「词表整体被清空 ⇒ 断言恒真」。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'
import zhProfile from '@/i18n/locales/attackProfile.zh-CN'
import enProfile from '@/i18n/locales/attackProfile.en-US'

const require = createRequire(import.meta.url)
const {
  ATTACK_CATEGORIES,
  VERDICTS,
  SUGGESTIONS,
} = require('../../../../src/constants/attackProfile.js')

const categories = Object.values(ATTACK_CATEGORIES)
const verdicts = Object.values(VERDICTS)
const suggestions = Object.values(SUGGESTIONS)

const missingCodes = (codes, dict) => codes.filter((code) => !(code in dict)).sort()

const deadCodes = (codes, dict) =>
  Object.keys(dict)
    .filter((key) => !codes.includes(key))
    .sort()

const emptyLeaves = (dict) =>
  Object.entries(dict)
    .filter(([, value]) => {
      if (typeof value === 'string') return value.trim() === ''
      if (value && typeof value === 'object') {
        return Object.values(value).some((leaf) => typeof leaf !== 'string' || leaf.trim() === '')
      }
      return true
    })
    .map(([key]) => key)
    .sort()

describe('攻击画像词典：后端枚举必须有前端双语落点', () => {
  test('前提自证：三族枚举非空且唯一（对账对象被清空时不得静默通过）', () => {
    for (const family of [categories, verdicts, suggestions]) {
      expect(family.length).toBeGreaterThan(0)
      expect(new Set(family).size).toBe(family.length)
    }
    expect(categories).toHaveLength(10)
    expect(verdicts).toHaveLength(6)
    expect(suggestions).toHaveLength(11)
  })

  test('zh-CN / en-US 覆盖全部分类、判定、建议与判定提示', () => {
    for (const profile of [zhProfile, enProfile]) {
      expect(missingCodes(categories, profile.category)).toEqual([])
      expect(missingCodes(verdicts, profile.verdict)).toEqual([])
      expect(missingCodes(verdicts, profile.verdictHint)).toEqual([])
      expect(missingCodes(suggestions, profile.suggestion)).toEqual([])
    }
  })

  test('分类的 label/description 与建议文案都是非空叶子（空串会渲染成空白）', () => {
    for (const profile of [zhProfile, enProfile]) {
      expect(emptyLeaves(profile.category)).toEqual([])
      expect(emptyLeaves(profile.suggestion)).toEqual([])
      expect(emptyLeaves(profile.verdict)).toEqual([])
      expect(emptyLeaves(profile.verdictHint)).toEqual([])
    }
  })

  test('反向：词表里没有后端不认识的死码（新增前端键必须同时升级后端词典）', () => {
    for (const profile of [zhProfile, enProfile]) {
      expect(deadCodes(categories, profile.category)).toEqual([])
      expect(deadCodes(verdicts, profile.verdict)).toEqual([])
      expect(deadCodes(verdicts, profile.verdictHint)).toEqual([])
      expect(deadCodes(suggestions, profile.suggestion)).toEqual([])
    }
  })

  test('判据可失败：删掉一个分类键、加一个死码，都必须被同一组判据抓到', () => {
    const mutated = JSON.parse(JSON.stringify(zhProfile))
    delete mutated.category.honeypot
    expect(missingCodes(categories, mutated.category)).toContain('honeypot')

    mutated.category.not_a_category = {
      label: '死码',
      description: '后端永远不会返回这个码',
    }
    expect(deadCodes(categories, mutated.category)).toEqual(['not_a_category'])
  })

  test('画像词表已移出入口词表（随页面 chunk 懒加载，首屏预算的前提）', () => {
    expect(zhCN.attackProfile).toBeUndefined()
    expect(enUS.attackProfile).toBeUndefined()
    expect(Object.keys(zhProfile).length).toBeGreaterThan(0)
    expect(Object.keys(enProfile).length).toBeGreaterThan(0)
  })
})
