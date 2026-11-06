/**
 * securityLabels 补测（2026-11-06 收敛批）：建议码 → 界面文案的单一映射。
 *
 * 覆盖此前缺口的三条分支：命中词条、未知码原样回退（漏翻不伪装成「没有建议」）、
 * 空值占位 '-'，以及批量映射对非数组的防御。
 */
import { describe, it, expect } from 'vitest'
import { securitySuggestionLabel, securitySuggestionLabels } from '@/utils/securityLabels'

const dict = {
  'securitySelf.suggestion.enable_mfa': '启用 MFA',
  'securitySelf.suggestion.rotate_key': '轮换密钥',
}
const t = (key) => dict[key] || key

describe('securitySuggestionLabel', () => {
  it('命中词条：返回文案', () => {
    expect(securitySuggestionLabel(t, 'enable_mfa')).toBe('启用 MFA')
  })

  it('未知码原样回退：漏翻可见、不伪装成「没有建议」', () => {
    expect(securitySuggestionLabel(t, 'brand_new_code')).toBe('brand_new_code')
  })

  it('空码占位：返回 "-"', () => {
    expect(securitySuggestionLabel(t, '')).toBe('-')
    expect(securitySuggestionLabel(t, undefined)).toBe('-')
    expect(securitySuggestionLabel(t, null)).toBe('-')
  })
})

describe('securitySuggestionLabels（批量）', () => {
  it('数组逐个映射', () => {
    expect(securitySuggestionLabels(t, ['enable_mfa', 'rotate_key'])).toEqual([
      '启用 MFA',
      '轮换密钥',
    ])
  })

  it('非数组防御：返回空数组（列表渲染不崩）', () => {
    expect(securitySuggestionLabels(t, undefined)).toEqual([])
    expect(securitySuggestionLabels(t, null)).toEqual([])
    expect(securitySuggestionLabels(t, 'enable_mfa')).toEqual([])
  })
})
