/**
 * 安全建议码：前端词表 ↔ 后端码表 逐一对应（i18n 缺口回归）
 *
 * 缺陷形状：`suggestions` 原是后端直接拼好的**中文句子**（my-info 两条、
 * stats 三条），于是英文界面下这两块建议永远是中文——前端拿到的是已定型的
 * 中文串，vue-i18n 无从翻译。修法是后端只出稳定码、文案归前端词表
 * （同 utils/labelMaps.js 的 DEVICE_TYPE、utils/auditLabels.js 的 audit.action.*）。
 *
 * 为什么清单必须 createRequire 自后端而不是在前端手抄一份：
 * labelMapsSemantics.test.js 文件头 F-166 记过这个教训——手抄的清单钉住的是
 * 清单的**结果**而不是清单本身，后端加一码而前端没跟，手抄件仍是旧的 N 个键，
 * 断言全绿，界面上却渲染出裸码。这里直接对账后端单一来源
 * （src/constants/securitySuggestions.js），两个方向都会红。
 *
 * 断言对象是**可观测输出**（映射结果），不是源码文本。
 */
import { createRequire } from 'node:module'
import { describe, test, expect } from 'vitest'
import { createI18n } from 'vue-i18n'
import { securitySuggestionLabel } from '@/utils/securityLabels'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

const require = createRequire(import.meta.url)
const { SECURITY_SUGGESTION_VALUES } = require('../../../../src/constants/securitySuggestions.js')

const messages = { 'zh-CN': zhCN, 'en-US': enUS }
const makeT = (locale) => {
  const i18n = createI18n({ legacy: false, locale, messages })
  return (key) => i18n.global.t(key)
}

/** vue-i18n 找不到键时原样返回 key（形如 securitySelf.suggestion.xxx） */
const KEY_PATH = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$/

const zhSuggestion = zhCN.securitySelf.suggestion
const enSuggestion = enUS.securitySelf.suggestion

describe('安全建议码表：前后端一致', () => {
  test('zh-CN 词表键集与后端码表逐一对应（后端加码而前端漏翻会红）', () => {
    expect(Object.keys(zhSuggestion).sort()).toEqual([...SECURITY_SUGGESTION_VALUES].sort())
  })

  test('en-US 词表键集与后端码表逐一对应', () => {
    expect(Object.keys(enSuggestion).sort()).toEqual([...SECURITY_SUGGESTION_VALUES].sort())
  })

  test.each(SECURITY_SUGGESTION_VALUES.map((c) => [c]))(
    '建议码 %s 在中英两种语言下都有一个"真的翻过"的文案',
    (code) => {
      const zh = securitySuggestionLabel(makeT('zh-CN'), code)
      const en = securitySuggestionLabel(makeT('en-US'), code)
      // 非空、不等于裸码、不是没解析的词条路径
      expect(zh).toBeTruthy()
      expect(zh).not.toBe(code)
      expect(KEY_PATH.test(zh)).toBe(false)
      expect(en).toBeTruthy()
      expect(en).not.toBe(code)
      expect(KEY_PATH.test(en)).toBe(false)
      // 英文不得等于中文：否则是把中文抄进了 en-US 词表，i18n 缺口原样保留
      expect(en).not.toBe(zh)
    }
  )

  test('未知码原样回退（不是空白、不是裸词条路径）', () => {
    // 后端新增一码而前端漏翻时，用户应看到可辨识的标识串，而不是整条建议消失
    const t = makeT('zh-CN')
    expect(securitySuggestionLabel(t, 'brand_new_code')).toBe('brand_new_code')
    expect(securitySuggestionLabel(t, '')).toBe('-')
    expect(securitySuggestionLabel(t, null)).toBe('-')
  })

  test('中文文案未被改坏（逐条钉死，防止只补键集不改文案）', () => {
    const t = makeT('zh-CN')
    expect(securitySuggestionLabel(t, 'account_inactive_long')).toBe(
      '账户长期未登录，请注意账户安全'
    )
    expect(securitySuggestionLabel(t, 'repeated_login_failures')).toBe(
      '检测到多次登录失败，建议修改密码'
    )
    expect(securitySuggestionLabel(t, 'high_risk_score')).toBe('高风险：建议立即审查最近的操作日志')
    expect(securitySuggestionLabel(t, 'excessive_failed_logins')).toBe(
      '登录失败次数过多：建议检查账户安全'
    )
    expect(securitySuggestionLabel(t, 'unusual_time_access')).toBe(
      '非常规时间访问：建议确认操作合法性'
    )
  })
})
