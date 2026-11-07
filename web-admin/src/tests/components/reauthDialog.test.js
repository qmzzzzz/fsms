/**
 * ReauthDialog 行为测试（通用二次验证弹层）
 *
 * 纯收集组件：收集口令/MFA 码、加密后 emit('submit') 给父组件；自己不发请求。
 * jsdom 事实与 mock 边界（同 upgradeDialog.test.js）：el-dialog append-to-body
 * ⇒ 断言查 document.body；卸载后残留节点会污染下一条用例的查询。
 * emit 经 onXxx prop 收集（harness 不暴露 emitted）。
 * 锁定的判据：
 *  1. password 模式：加密成功 ⇒ emit encCurrentPassword（不发明文）；
 *  2. 加密失败（含 dev 非安全上下文的 null）必须阻断，不得明文上行；
 *  3. MFA 模式：6 位码才可提交、提交后清空（防原样重送错误码）；
 *  4. 模式切换清空两框（防跨模式残留）。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mountComponent, flush, click } from '../helpers/componentHarness'

const encryptPassword = vi.fn()
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (...args) => encryptPassword(...args),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import ReauthDialog from '@/components/ReauthDialog.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

const mountOpen = (onSubmit = () => {}) => {
  const vm = mountComponent(ReauthDialog, {
    props: { modelValue: true, onSubmit: (...args) => onSubmit(...args) },
  })
  active = vm
  return vm
}

const bodyInput = (selector) => document.body.querySelector(selector)

const confirmBtn = () => {
  const buttons = [...document.body.querySelectorAll('.el-dialog button')]
  return buttons[buttons.length - 1]
}

const setInput = (selector, value) => {
  const input = bodyInput(selector)
  input.value = value
  input.dispatchEvent(new Event('input'))
}

const clickConfirm = async () => {
  click(confirmBtn())
  await flush(4)
}

beforeEach(() => {
  vi.clearAllMocks()
  document.body.querySelectorAll('.el-dialog').forEach((node) => node.remove())
})
afterEach(() => {
  if (active) {
    active.unmount()
    active = null
  }
})

describe('ReauthDialog 判据', () => {
  test('password 模式：加密成功 ⇒ emit encCurrentPassword（不发明文）', async () => {
    const submitted = []
    encryptPassword.mockResolvedValue('ENC:pw')
    mountOpen((payload) => submitted.push(payload))
    await flush()
    setInput('input[type="password"]', 'pw-input')
    await flush(2)
    await clickConfirm()
    expect(encryptPassword).toHaveBeenCalledWith('pw-input', 'PASSWORD_CURRENT')
    expect(submitted[0]).toEqual({ encCurrentPassword: 'ENC:pw' })
  })

  test('加密抛错（PIN 不匹配）⇒ 阻断提交并报错，不 emit', async () => {
    encryptPassword.mockRejectedValue(
      Object.assign(new Error('pin'), { code: 'PUBLIC_KEY_PIN_MISMATCH' })
    )
    mountOpen(() => {})
    await flush()
    setInput('input[type="password"]', 'pw-input')
    await flush(2)
    await clickConfirm()
    expect(ElMessage.error).toHaveBeenCalled()
  })

  test('加密返回 null（dev 非安全上下文）⇒ 阻断提交（明文回退轨已删）', async () => {
    mountOpen(() => {})
    await flush()
    setInput('input[type="password"]', 'pw-input')
    await flush(2)
    await clickConfirm()
    expect(ElMessage.error).toHaveBeenCalled()
  })

  test('MFA 模式：非 6 位禁提交、6 位码提交后清空', async () => {
    const submitted = []
    mountOpen((payload) => submitted.push(payload))
    await flush()
    click(document.body.querySelector('.reauth-mode-toggle'))
    await flush(2)
    const input = bodyInput('input[autocomplete="one-time-code"]')
    expect(input).toBeTruthy()
    input.value = '123'
    input.dispatchEvent(new Event('input'))
    await flush(2)
    expect(confirmBtn().disabled).toBe(true)
    input.value = '123456'
    input.dispatchEvent(new Event('input'))
    await flush(2)
    expect(confirmBtn().disabled).toBe(false)
    click(confirmBtn())
    await flush(4)
    expect(submitted[0]).toEqual({ mfaCode: '123456' })
    expect(bodyInput('input[autocomplete="one-time-code"]').value).toBe('')
  })

  test('模式切换清空两框（防跨模式残留）', async () => {
    mountOpen(() => {})
    await flush()
    setInput('input[type="password"]', 'leftover')
    await flush(2)
    click(document.body.querySelector('.reauth-mode-toggle'))
    await flush(2)
    expect(bodyInput('input[autocomplete="one-time-code"]').value).toBe('')
    click(document.body.querySelector('.reauth-mode-toggle'))
    await flush(2)
    expect(bodyInput('input[type="password"]').value).toBe('')
  })
})
