/**
 * 撞库画像词典跨端对齐（后端枚举 ↔ 前端双语词表）
 *
 * 后端只输出枚举值（constants/credentialShape.js 是单一事实来源），自然语言由前端
 * 按当前界面语言渲染。两边漂移时页面不报错：长度档/字符集会退回裸码——虽然视图有
 * 原值回落兜底，但运维看到的就是 `20plus` / `ld` 这类标识。
 *
 * 本闸钉住两族：口令长度档与字符集标记；另加 zh/en 顶层键、占位符与空叶子对账，
 * 避免「只补了一侧语言」或「插值参数名写错」在运行时静默漏文案。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'
import zhProfile from '@/i18n/locales/stuffingProfile.zh-CN'
import enProfile from '@/i18n/locales/stuffingProfile.en-US'

const require = createRequire(import.meta.url)
const { LENGTH_BUCKETS, CHARSET_FLAGS } = require('../../../../src/constants/credentialShape.js')

const sortedKeys = (dict) => Object.keys(dict).sort()
// s（符号）由 charsetClassOf 按补集追加，不在 CHARSET_FLAGS 区间表内
const CHARSET_CODES = [...CHARSET_FLAGS.map(([flag]) => flag), 's'].sort()
const placeholders = (value) => [...String(value).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()

describe('撞库画像词典：后端枚举必须有前端双语落点', () => {
  test('前提自证：后端两族枚举非空（对账对象被清空时不得静默通过）', () => {
    expect(LENGTH_BUCKETS.length).toBeGreaterThan(0)
    expect(CHARSET_CODES.length).toBeGreaterThan(0)
  })

  test('zh-CN / en-US 顶层键完全一致（只补一侧语言会漏文案）', () => {
    expect(sortedKeys(zhProfile)).toEqual(sortedKeys(enProfile))
  })

  test('长度档覆盖后端 LENGTH_BUCKETS 全集，且无死键', () => {
    for (const profile of [zhProfile, enProfile]) {
      expect(sortedKeys(profile.lengthBucketValue)).toEqual([...LENGTH_BUCKETS].sort())
    }
  })

  test('字符集标记覆盖后端 l/u/d/s 全集，且无死键', () => {
    for (const profile of [zhProfile, enProfile]) {
      expect(sortedKeys(profile.charsetFlag)).toEqual(CHARSET_CODES)
    }
  })

  test('文案无空叶子（空串会渲染成空白）', () => {
    for (const profile of [zhProfile, enProfile]) {
      const empty = Object.entries(profile)
        .filter(([, value]) => typeof value === 'string' && value.trim() === '')
        .map(([key]) => key)
      expect(empty).toEqual([])
      for (const nested of [profile.lengthBucketValue, profile.charsetFlag]) {
        expect(Object.values(nested).filter((v) => typeof v !== 'string' || !v.trim())).toEqual([])
      }
    }
  })

  test('插值占位符 zh/en 同形（参数名写错不会报错，只会漏值）', () => {
    for (const key of sortedKeys(zhProfile)) {
      if (typeof zhProfile[key] !== 'string') continue
      expect(placeholders(zhProfile[key]), key).toEqual(placeholders(enProfile[key]))
    }
  })

  test('撞库词表已移出入口词表（随页面 chunk 懒加载，首屏预算的前提）', () => {
    expect(zhCN.stuffingProfile).toBeUndefined()
    expect(enUS.stuffingProfile).toBeUndefined()
    expect(Object.keys(zhProfile).length).toBeGreaterThan(0)
    expect(Object.keys(enProfile).length).toBeGreaterThan(0)
  })
})
