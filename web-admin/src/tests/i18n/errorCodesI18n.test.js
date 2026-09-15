/**
 * 错误码 ↔ i18n 词表一致性防线
 *
 * 后端 errorCodes 注册表的每个码都必须在 zh-CN/en-US 的 errors.*
 * 命名空间有对应翻译（键名 = SCREAMING_SNAKE 转 camelCase），反之
 * errors 里不允许存在注册表外的孤儿键——加码忘补翻译直接在这里红。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { ERROR_CODES } = require('../../../../src/utils/errorCodes.js')
import zh from '@/i18n/locales/zh-CN'
import en from '@/i18n/locales/en-US'

const camel = (s) => s.toLowerCase().replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase())

describe('errorCodes ↔ errors 词表一致性', () => {
  const codes = Object.keys(ERROR_CODES)

  test('每个注册表码在 zh-CN/en-US 都有非空翻译', () => {
    const missing = []
    for (const code of codes) {
      const key = camel(code)
      if (!zh.errors[key] || !zh.errors[key].trim()) missing.push(`zh:${key}`)
      if (!en.errors[key] || !en.errors[key].trim()) missing.push(`en:${key}`)
    }
    expect(missing).toEqual([])
  })

  test('errors 命名空间无孤儿键（不得存在注册表外的码）', () => {
    const codeSet = new Set(codes.map(camel))
    const orphanZh = Object.keys(zh.errors).filter((k) => !codeSet.has(k))
    const orphanEn = Object.keys(en.errors).filter((k) => !codeSet.has(k))
    expect(orphanZh).toEqual([])
    expect(orphanEn).toEqual([])
  })

  test('双语同键同序覆盖（抽样新码）', () => {
    for (const key of ['authEncryptedCredentialInvalid', 'fullRangeForbidden', 'accountDisabled']) {
      expect(zh.errors[key]).toBeTruthy()
      expect(en.errors[key]).toBeTruthy()
    }
  })
})
