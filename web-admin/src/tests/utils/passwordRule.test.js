/**
 * passwordStrengthRule 行为测试（async-validator 规则）
 *
 * 这是注册页与改密页共用的「口令强度」校验规则，直接决定用户能否提交。
 * 原实现有两处语义必须钉死，否则表现是**用户被卡住却看不出原因**：
 *
 *  1. 空值必须放行（callback 无参调用）：空口令的提示应由独立的 required 规则
 *     负责。若这里也报「强度不足」，用户会同时看到两条错误提示，且当 required
 *     规则被移除时（合法场景，如可选的口令修改）空值会永远提交不了。
 *  2. 非空但弱必须报错，且错误消息就是传入的 i18n 文案：弱口令被放行等于
 *     前后端准入线不一致；消息写死则会在英文界面弹出中文提示。
 *
 * 另外钉住规则对象的两个字段：trigger 必须是 blur（输入即校验会让用户每敲一个
 * 字符就看到一次红字），validator 必须是函数（async-validator 会静默忽略非函数
 * validator，表现为「这条规则完全没生效」）。
 */
import { describe, test, expect, vi } from 'vitest'
import { passwordStrengthRule, isStrongPassword } from '@/utils/password'

const MSG = '口令强度不足：需包含大小写字母、数字和特殊字符'
const rule = passwordStrengthRule(MSG)

describe('passwordStrengthRule', () => {
  test('规则形状：validator 为函数、trigger 为 blur', () => {
    expect(typeof rule.validator).toBe('function')
    expect(rule.trigger).toBe('blur')
  })

  test('空值放行：callback 无参调用（交给 required 规则处理）', () => {
    const cb = vi.fn()
    rule.validator(rule, '', cb)
    expect(cb).toHaveBeenCalledTimes(1)
    // 无参调用 == 校验通过；带 Error 参数才是失败
    expect(cb.mock.calls[0]).toEqual([])
  })

  test('各种「无值」形态都放行：null / undefined', () => {
    for (const empty of [null, undefined]) {
      const cb = vi.fn()
      rule.validator(rule, empty, cb)
      expect(cb.mock.calls[0]).toEqual([])
    }
  })

  test('强口令放行：callback 无参调用', () => {
    const cb = vi.fn()
    rule.validator(rule, 'Str0ng-Pass_2026', cb)
    expect(cb.mock.calls[0]).toEqual([])
  })

  test('弱口令报错：callback 收到 Error，消息为传入文案', () => {
    const cb = vi.fn()
    rule.validator(rule, 'abcdefg', cb)
    expect(cb).toHaveBeenCalledTimes(1)
    const err = cb.mock.calls[0][0]
    expect(err).toBeInstanceOf(Error)
    expect(err.message).toBe(MSG)
  })

  test('规则判据与 isStrongPassword 完全一致（同一准入线，逐样本比对）', () => {
    const samples = [
      '',
      'a',
      'abcdefgh',
      'Abcdefg1',
      'Abcdefg1!',
      'Str0ng-Pass_2026',
      'Aa1!' + 'x'.repeat(60),
      'Aa1!' + 'x'.repeat(61),
      'Aa1!' + '密'.repeat(25),
      'Str0ng-Pass_2026' + 'y'.repeat(48),
    ]
    for (const s of samples) {
      const cb = vi.fn()
      rule.validator(rule, s, cb)
      const passed = cb.mock.calls[0].length === 0
      // 空值的 required 责任已由前两条用例单独钉住，这里只比非空样本
      if (s !== '') expect(passed).toBe(isStrongPassword(s))
    }
  })

  test('消息按调用方传入的文案逐条生成（不缓存、不写死）', () => {
    const en = passwordStrengthRule('Password too weak')
    const cb = vi.fn()
    en.validator(en, 'weak', cb)
    expect(cb.mock.calls[0][0].message).toBe('Password too weak')
    // 原始规则不受影响（两条规则互不串消息）
    const cb2 = vi.fn()
    rule.validator(rule, 'weak', cb2)
    expect(cb2.mock.calls[0][0].message).toBe(MSG)
  })
})
