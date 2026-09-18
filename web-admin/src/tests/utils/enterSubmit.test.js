/**
 * 回车提交守卫测试（utils/enterSubmit.js）
 *
 * 为何需要它：该守卫被 ProfileView（4 处）、MfaSettingsCard（3 处）、
 * ChangePasswordCard（3 处）共用，覆盖的都是**安全敏感操作**（保存资料、
 * 启用/停用 MFA、改密码）。此前覆盖率 0%。
 *
 * 要防的退化有两类，方向相反：
 *  1. 守卫失效 → 中文输入法组词确认的 Enter 被当成提交，用户「输入拼音按回车
 *     上屏」会误触发改密码/MFA 操作；
 *  2. 守卫过严 → 正常英文/数字输入的回车也被吞掉，用户按回车没反应。
 * 所以下面两个方向都必须有断言。
 */
import { describe, test, expect, vi } from 'vitest'
import { enterSubmit } from '@/utils/enterSubmit'

describe('enterSubmit 输入法组词守卫', () => {
  test('isComposing=true（Safari 组词确认）→ 必须吞掉，不执行回调', () => {
    const fn = vi.fn()
    enterSubmit({ isComposing: true, keyCode: 13 }, fn)
    expect(fn).not.toHaveBeenCalled()
  })

  test('keyCode=229（Chrome/Firefox 组词期间）→ 必须吞掉，不执行回调', () => {
    const fn = vi.fn()
    enterSubmit({ isComposing: false, keyCode: 229 }, fn)
    expect(fn).not.toHaveBeenCalled()
  })

  test('两个信号同时出现 → 仍然吞掉（判据是或关系）', () => {
    const fn = vi.fn()
    enterSubmit({ isComposing: true, keyCode: 229 }, fn)
    expect(fn).not.toHaveBeenCalled()
  })

  test('正常回车（非组词）→ 必须执行回调，且只执行一次', () => {
    const fn = vi.fn()
    enterSubmit({ isComposing: false, keyCode: 13 }, fn)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  test('isComposing=false 且 keyCode 非 229 的任意键 → 不吞（守卫不越权拦截）', () => {
    const fn = vi.fn()
    enterSubmit({ isComposing: false, keyCode: 65 }, fn)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  test('事件对象为 null/undefined → 不得抛错，且回调仍执行（fail-open）', () => {
    // 模板侧写法是 enterSubmit($event, handler)；$event 理论上必有，
    // 但守卫自身带 e && 保护，这里钉住该保护真的生效——否则会抛 TypeError
    // 让整个按键处理链崩掉，用户按回车毫无反应且控制台报错。
    for (const e of [null, undefined]) {
      const fn = vi.fn()
      expect(() => enterSubmit(e, fn)).not.toThrow()
      expect(fn).toHaveBeenCalledTimes(1)
    }
  })

  test('缺失 isComposing 字段但 keyCode=229 → 仍按组词吞掉（只认可用信号）', () => {
    const fn = vi.fn()
    enterSubmit({ keyCode: 229 }, fn)
    expect(fn).not.toHaveBeenCalled()
  })

  test('isComposing=true 但 keyCode 缺失 → 仍吞掉（任一信号足够）', () => {
    const fn = vi.fn()
    enterSubmit({ isComposing: true }, fn)
    expect(fn).not.toHaveBeenCalled()
  })

  test('回调抛错必须原样向上传播，不得被守卫吞掉', () => {
    // 守卫只做判据，不负责错误处理。若它把异常吞了，保存/改密码失败会静默无提示。
    const boom = new Error('save failed')
    expect(() =>
      enterSubmit({ isComposing: false, keyCode: 13 }, () => {
        throw boom
      })
    ).toThrow(boom)
  })

  test('回调入参不被篡改：守卫不向回调传任何参数', () => {
    const fn = vi.fn()
    const e = { isComposing: false, keyCode: 13 }
    enterSubmit(e, fn)
    expect(fn.mock.calls[0]).toEqual([])
  })
})
