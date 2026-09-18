/**
 * ChangePasswordCard 行为测试（改密：强度门禁 / 密文双轨 / 延时登出）
 *
 * 改密是账户安全的咽喉，四类退化都只静默出错：
 *  1. 弱口令放行 -> 用户改了密码却比原来更弱（后端会拒，但界面先骗了人）；
 *  2. 两次不一致放行 -> 用户以为自己改成了新密码，下次登录失败；
 *  3. 加密失败静默降级明文 -> FE-H1 要求阻断，否则口令明文上行；
 *  4. 改密成功不延时登出 -> 旧会话 token 仍然有效（后端已吊销，但前端还挂着）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const changePassword = vi.fn()
const encryptPassword = vi.fn(async () => null)
const clearAuth = vi.fn()
vi.mock('@/utils/api', () => ({
  api: { auth: { changePassword: (...a) => changePassword(...a) } },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (...a) => encryptPassword(...a),
  isTransportCryptoAvailable: () => true,
  invalidatePublicKeyCache: () => {},
}))

import ChangePasswordCard from '@/components/ChangePasswordCard.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { useAuthStore } from '@/store'

let active = null
const STRONG = 'Str0ng-Pass_2026'

const open = async (setupStore) => {
  active = mountComponent(ChangePasswordCard, {
    initialRoute: '/profile',
    routes: [
      { path: '/profile', component: { render: () => null } },
      { path: '/login', component: { render: () => null } },
    ],
    setupStore: setupStore || ((pinia) => useAuthStore(pinia).setPermissions([])),
  })
  await flush(10)
  return active
}

const typeInto = (c, id, value) => {
  const el = c.find('#' + id)
  el.value = value
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
}
const submit = (c) => {
  const b = c.findAll('button').find((x) => x.textContent.includes('修改密码'))
  expect(b).toBeTruthy()
  click(b)
}

/** 真实等待：延时登出是 1500ms 的 setTimeout，用真实计时器最贴近用户行为 */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

afterEach(() => {
  active?.handle.unmount()
  active = null
  changePassword.mockReset()
  encryptPassword.mockReset()
  encryptPassword.mockImplementation(async () => null)
  clearAuth.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
})

describe('ChangePasswordCard 本地门禁', () => {
  test('任一字段为空：警告且不发请求', async () => {
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    await flush(4)
    submit(c)
    await waitFor(() => ElMessage.warning.mock.calls.length === 1, { message: '不完整提示' })
    expect(changePassword).not.toHaveBeenCalled()
  })

  test('两次新口令不一致：错误提示且不发请求', async () => {
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    typeInto(c, 'newPassword', STRONG)
    typeInto(c, 'confirmPassword', 'Str0ng-Pass_2027')
    await flush(4)
    submit(c)
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '不一致提示' })
    expect(changePassword).not.toHaveBeenCalled()
    expect(ElMessage.error.mock.calls[0][0]).toContain('不一致')
  })

  test('弱口令（缺特殊字符）：警告且不发请求（后端会拒，界面必须先拦）', async () => {
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    typeInto(c, 'newPassword', 'Abcdefgh1234')
    typeInto(c, 'confirmPassword', 'Abcdefgh1234')
    await flush(4)
    submit(c)
    await waitFor(() => ElMessage.warning.mock.calls.length === 1, { message: '弱口令提示' })
    expect(changePassword).not.toHaveBeenCalled()
    expect(ElMessage.warning.mock.calls[0][0]).toContain('12')
  })
})

describe('ChangePasswordCard 密文双轨（FE-H1）', () => {
  test('WebCrypto 可用：上行两个独立信封，明文口令不上行', async () => {
    encryptPassword.mockResolvedValueOnce('ENV-CURRENT').mockResolvedValueOnce('ENV-NEW')
    changePassword.mockResolvedValue({ data: { success: true } })
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    typeInto(c, 'newPassword', STRONG)
    typeInto(c, 'confirmPassword', STRONG)
    await flush(4)
    submit(c)
    await waitFor(() => changePassword.mock.calls.length === 1, { message: '改密请求发出' })
    const payload = changePassword.mock.calls[0][0]
    expect(payload.encCurrentPassword).toBe('ENV-CURRENT')
    expect(payload.encNewPassword).toBe('ENV-NEW')
    expect(payload).not.toHaveProperty('currentPassword')
    expect(payload).not.toHaveProperty('newPassword')
    // 两个字段必须各自独立加密（同一次密文复用会让服务端 nonce 去重拒绝）
    expect(encryptPassword.mock.calls).toHaveLength(2)
    expect(encryptPassword.mock.calls[0][0]).toBe('OldPass_2026')
    expect(encryptPassword.mock.calls[1][0]).toBe(STRONG)
  })

  test('WebCrypto 不可用（返回 null）：降级明文轨，属设计内', async () => {
    encryptPassword.mockResolvedValue(null)
    changePassword.mockResolvedValue({ data: { success: true } })
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    typeInto(c, 'newPassword', STRONG)
    typeInto(c, 'confirmPassword', STRONG)
    await flush(4)
    submit(c)
    await waitFor(() => changePassword.mock.calls.length === 1, { message: '改密请求发出' })
    const payload = changePassword.mock.calls[0][0]
    expect(payload.currentPassword).toBe('OldPass_2026')
    expect(payload.newPassword).toBe(STRONG)
    expect(payload).not.toHaveProperty('encCurrentPassword')
  })

  test('加密抛错：阻断提交并提示重试，绝不静默明文上行', async () => {
    encryptPassword.mockRejectedValue(new Error('crypto down'))
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    typeInto(c, 'newPassword', STRONG)
    typeInto(c, 'confirmPassword', STRONG)
    await flush(4)
    submit(c)
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '加密失败提示' })
    await flush(20)
    expect(changePassword).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
  })
})

describe('ChangePasswordCard 成功后行为', () => {
  test('改密成功：清空三个输入框，延时后清会话并跳登录', async () => {
    encryptPassword.mockResolvedValue(null)
    changePassword.mockResolvedValue({ data: { success: true } })
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    typeInto(c, 'newPassword', STRONG)
    typeInto(c, 'confirmPassword', STRONG)
    await flush(4)
    submit(c)
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    await flush(10)
    expect(c.find('#currentPassword').value).toBe('')
    expect(c.find('#newPassword').value).toBe('')
    expect(c.find('#confirmPassword').value).toBe('')
    // 定时器到期前不得跳转（用户要看到成功提示）
    expect(c.router.currentRoute.value.path).toBe('/profile')
    await sleep(1700)
    await flush(20)
    await waitFor(() => c.router.currentRoute.value.path === '/login', {
      message: '延时登出后跳转登录页',
    })
  })

  test('定时器未到期就卸载：不得在组件销毁后跳转（防内存泄漏）', async () => {
    encryptPassword.mockResolvedValue(null)
    changePassword.mockResolvedValue({ data: { success: true } })
    const c = await open()
    typeInto(c, 'currentPassword', 'OldPass_2026')
    typeInto(c, 'newPassword', STRONG)
    typeInto(c, 'confirmPassword', STRONG)
    await flush(4)
    submit(c)
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    await flush(10)
    const router = c.router
    c.handle.unmount()
    active = null
    await sleep(1700)
    await flush(20)
    // 卸载后 router 会被 Vue 的 uninstall 重置 currentRoute，改看 history 的真实位置：
    // 组件若没清掉定时器，这里会变成 /login
    expect(router.options.history.location).toBe('/profile')
  })
})
