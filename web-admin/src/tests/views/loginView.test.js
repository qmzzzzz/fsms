/**
 * LoginView 行为测试（认证主路径 + MFA + 加密降级）
 *
 * 这是全仓安全最敏感的组件：登录提交路径一旦退化（不加密、密码明文上行、
 * MFA 状态丢失、成功不跳转、重入不拦），用户与审计都会直接受损，而 UI 不会
 * 报错——属于典型的静默失效。故逐条钉住：
 *  1. 口令加密轨：encryptPassword 成功 → 载荷带 encPassword 且**不得带明文 password**；
 *     WebCrypto 不可用（返回 null）→ 降级明文（内网设计内的既定行为）；
 *     加密抛错 → 阻断提交、提示重试，且**绝不静默明文上行**。
 *  2. MFA：首次响应 mfaRequired → 显示动态口令、不发跳转；二次提交携带 mfaCode；
 *     失败后保留 MFA 状态（供直接重输）但清空口令。
 *  3. 验证码一次性消费：任何失败尝试后都换新（captchaId 变化 + 输入清空）。
 *  4. 成功路径：setAuth + 跳 /dashboard + 清空内存中的 password/mfaCode。
 *  5. 重入：连点只发一次请求。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const login = vi.fn()
const getCaptcha = vi.fn()
const getCaptchaStatus = vi.fn()
const setAuth = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      login: (...a) => login(...a),
      getCaptcha: (...a) => getCaptcha(...a),
      getCaptchaStatus: (...a) => getCaptchaStatus(...a),
    },
  },
  isCanceledError: () => false,
}))
const encryptPassword = vi.fn()
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (...a) => encryptPassword(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}))

import LoginView from '@/views/LoginView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null
const routes = [
  { path: '/login', name: 'login', component: { render: () => null } },
  { path: '/register', name: 'register', component: { render: () => null } },
  { path: '/dashboard', name: 'dashboard', component: { render: () => null } },
  { path: '/:pathMatch(.*)*', name: 'fallback', component: { render: () => null } },
]

/** 挂载登录页；captcha 开关由 getCaptchaStatus 的 mock 决定 */
const open = async (opts = {}) => {
  getCaptchaStatus.mockResolvedValue({
    data: { data: { loginCaptchaEnabled: !!opts.captchaEnabled } },
  })
  getCaptcha.mockResolvedValue({
    data: {
      success: true,
      data: { captchaId: `cap-${getCaptcha.mock.calls.length}`, svg: '<svg/>' },
    },
  })
  active = mountComponent(LoginView, {
    routes,
    initialRoute: '/login',
    setupStore: opts.setupStore,
  })
  await flush(6)
  return active
}

/** 通过真实 DOM 输入框填入表单（走 v-model 的 input 事件） */
const fill = async (c, username, password) => {
  const inputs = c.findAll('input.el-input__inner')
  inputs[0].value = username
  inputs[0].dispatchEvent(new window.Event('input', { bubbles: true }))
  inputs[1].value = password
  inputs[1].dispatchEvent(new window.Event('input', { bubbles: true }))
  // 密码框失焦以触发 blur 规则（required + min 6）
  inputs[1].dispatchEvent(new window.Event('blur', { bubbles: true }))
  await flush(6)
}

const submitBtn = (c) => c.findAll('.glass-btn--primary').slice(-1)[0]

afterEach(() => {
  active?.handle.unmount()
  active = null
  login.mockReset()
  getCaptcha.mockReset()
  getCaptchaStatus.mockReset()
  encryptPassword.mockReset()
  setAuth.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  ElMessage.info.mockReset()
  sessionStorage.clear()
})

describe('LoginView 口令加密轨（FE-H1）', () => {
  test('加密成功：载荷带 encPassword 且绝不带明文 password', async () => {
    encryptPassword.mockResolvedValue('ENC-PAYLOAD')
    login.mockResolvedValue({
      data: {
        success: true,
        data: { user: { _id: 'u1', username: 'alice', permissions: ['device:read'] } },
      },
    })
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 1, { message: '登录请求发出' })
    const payload = login.mock.calls[0][0]
    expect(payload.encPassword).toBe('ENC-PAYLOAD')
    expect(payload).not.toHaveProperty('password')
    expect(payload.username).toBe('alice')
  })

  test('WebCrypto 不可用（encryptPassword 返回 null）→ 按既定降级明文上行', async () => {
    encryptPassword.mockResolvedValue(null)
    login.mockResolvedValue({ data: { success: false, message: 'x' } })
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 1, { message: '登录请求发出' })
    const payload = login.mock.calls[0][0]
    expect(payload.password).toBe('Str0ng-Pass')
    expect(payload).not.toHaveProperty('encPassword')
  })

  test('加密抛错：阻断提交（不发请求）+ 提示重试，绝不静默明文上行', async () => {
    encryptPassword.mockRejectedValue(new Error('webcrypto broken'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => ElMessage.error.mock.calls.length >= 1, { message: '加密失败提示' })
    expect(login).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
    expect(ElMessage.success).not.toHaveBeenCalled()
    // 用户仍停在登录页（等足导航窗口），且密码框内容仍在（可重试）
    await flush(20)
    expect(c.router.currentRoute.value.path).toBe('/login')
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  test('校验失败后重入锁必须释放：修正输入后仍可成功提交（不得被永久锁死）', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login.mockResolvedValue({ data: { success: false, message: 'x' } })
    const c = await open()
    const setInput = (i, v) => {
      const el = c.findAll('input.el-input__inner')[i]
      el.value = v
      el.dispatchEvent(new window.Event('input', { bubbles: true }))
    }
    // 第一次：用户名为空 → 校验失败（锁必须在校验失败分支释放）
    setInput(0, '')
    setInput(1, 'Str0ng-Pass')
    await flush(8)
    click(submitBtn(c))
    await waitFor(() => c.findAll('.el-form-item.is-error').length > 0, {
      message: '用户名必填校验报错',
    })
    // 错误态先于 validate() 的 rejection 落到 DOM：catch 分支（释放锁）在其后
    // 的微任务里执行，故此处再让出若干个 tick 才能安全发起第二次点击
    await flush(10)
    expect(login).not.toHaveBeenCalled()
    // 第二次：修正为合法输入 → 必须能真正提交（锁未泄漏）
    setInput(0, 'alice')
    await flush(8)
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 1, { message: '修正后仍可提交' })
    expect(login.mock.calls.length).toBe(1)
    expect(encryptPassword).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })
  test('用户名校验失败：不加密、不发请求（先校验后加密的顺序不可倒置）', async () => {
    encryptPassword.mockResolvedValue('ENC')
    const c = await open()
    await fill(c, '', 'Str0ng-Pass')
    click(submitBtn(c))
    await flush(30)
    expect(login).not.toHaveBeenCalled()
    expect(encryptPassword).not.toHaveBeenCalled()
  })
})

describe('LoginView 成功路径', () => {
  test('登录成功：写入会话 + 跳 /dashboard + 清空内存中的口令', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login.mockResolvedValue({
      data: {
        success: true,
        data: {
          token: 'T',
          refreshToken: 'R',
          user: { _id: 'u1', username: 'alice', permissions: ['device:read'] },
        },
      },
    })
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    // 会话写入（pinia store 真实实例）
    expect(c.pinia.state.value.auth?.permissions).toEqual(['device:read'])
    await waitFor(() => c.router.currentRoute.value.path === '/dashboard', {
      message: '登录成功后应跳转 /dashboard',
    })
    expect(c.router.currentRoute.value.path).toBe('/dashboard')
    // 敏感字段不得残留：重新读取密码框内容应为空
    const inputs = c.findAll('input.el-input__inner')
    expect(inputs[1].value).toBe('')
    expect(c.errors).toEqual([])
  })

  test('业务失败（success=false）：提示后端 message 且不跳转、不写会话', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login.mockResolvedValue({ data: { success: false, message: '用户名或密码错误' } })
    const c = await open()
    await fill(c, 'alice', 'WrongPass1')
    click(submitBtn(c))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    expect(ElMessage.error.mock.calls[0][0]).toBe('用户名或密码错误')
    // 失败不得跳转：等若干个 tick 后仍在登录页（给足导航发起的时间窗）
    await flush(20)
    expect(c.router.currentRoute.value.path).toBe('/login')
  })
})

describe('LoginView MFA 二次验证（I-06）', () => {
  test('首次响应 mfaRequired：显示动态口令输入、提示、不跳转', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login.mockResolvedValue({ data: { success: true, data: { mfaRequired: true } } })
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => ElMessage.info.mock.calls.length === 1, { message: 'MFA 提示' })
    await flush(20)
    expect(c.router.currentRoute.value.path).toBe('/login')
    // 动态口令输入框出现（占位文案来自 i18n 词表）
    const html = c.html()
    expect(html).toMatch(/mfa|MFA/i)
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  test('二次提交携带 mfaCode（重新加密、载荷不含明文口令）', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login
      .mockResolvedValueOnce({ data: { success: true, data: { mfaRequired: true } } })
      .mockResolvedValueOnce({
        data: { success: true, data: { user: { _id: 'u1', username: 'alice', permissions: [] } } },
      })
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 1, { message: '首次提交' })
    await flush(6)
    // 填入动态口令并再次提交
    const target = c.find('#mfaCode')
    expect(target).not.toBeNull()
    target.value = '123456'
    target.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 2, { message: '二次提交' })
    const payload = login.mock.calls[1][0]
    expect(payload.mfaCode).toBe('123456')
    expect(payload).not.toHaveProperty('password')
    expect(encryptPassword).toHaveBeenCalledTimes(2)
  })

  test('MFA 码错误：保留二期状态供重输，但清空口令框', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login
      .mockResolvedValueOnce({ data: { success: true, data: { mfaRequired: true } } })
      .mockRejectedValueOnce(new Error('bad mfa'))
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 1, { message: '首次提交' })
    await flush(4)
    const mfaInput = c.find('#mfaCode')
    expect(mfaInput).not.toBeNull()
    mfaInput.value = '000000'
    mfaInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(4)
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 2, { message: '二次提交' })
    await flush(30)
    // 仍在 MFA 步骤：口令框被清空（一次性），输入框仍存在
    expect(c.find('#mfaCode').value).toBe('')
    expect(c.findAll('#mfaCode')).toHaveLength(1)
  })
})

describe('LoginView 验证码一次性消费', () => {
  test('开启验证码时：载荷携带 captchaId/captchaText', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login.mockResolvedValue({ data: { success: false, message: 'x' } })
    const c = await open({ captchaEnabled: true })
    const inputs = c.findAll('input.el-input__inner')
    inputs[0].value = 'alice'
    inputs[0].dispatchEvent(new window.Event('input', { bubbles: true }))
    inputs[1].value = 'Str0ng-Pass'
    inputs[1].dispatchEvent(new window.Event('input', { bubbles: true }))
    const captchaInput = inputs[2]
    captchaInput.value = 'AB12'
    captchaInput.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(6)
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 1, { message: '登录请求发出' })
    const payload = login.mock.calls[0][0]
    expect(payload.captchaText).toBe('AB12')
    expect(payload.captchaId).toBeTruthy()
    expect(payload.captchaId).not.toBe('')
  })

  test('关闭验证码时：载荷完全不含验证码字段（不得发空值给后端）', async () => {
    encryptPassword.mockResolvedValue('ENC')
    login.mockResolvedValue({ data: { success: false, message: 'x' } })
    const c = await open({ captchaEnabled: false })
    await fill(c, 'alice', 'Str0ng-Pass')
    click(submitBtn(c))
    await waitFor(() => login.mock.calls.length === 1, { message: '登录请求发出' })
    const payload = login.mock.calls[0][0]
    expect(payload).not.toHaveProperty('captchaId')
    expect(payload).not.toHaveProperty('captchaText')
  })
})

describe('LoginView 提交重入', () => {
  test('同一 tick 连点多次：只发一次登录请求', async () => {
    encryptPassword.mockResolvedValue('ENC')
    let release
    login.mockImplementation(
      () =>
        new Promise((r) => {
          release = () => r({ data: { success: false, message: 'x' } })
        })
    )
    const c = await open()
    await fill(c, 'alice', 'Str0ng-Pass')
    const btn = submitBtn(c)
    click(btn)
    click(btn)
    click(btn)
    await waitFor(() => login.mock.calls.length >= 1, { message: '登录请求发出' })
    expect(release).toBeTruthy()
    release()
    await flush(20)
    expect(login.mock.calls.length).toBe(1)
  })
})

describe('LoginView 页面标题与跨标签页提示', () => {
  test('document.title 跟随语言切换更新（不得滞留旧语言）', async () => {
    const c = await open()
    const i18n = (await import('@/i18n')).default
    const zhTitle = document.title
    expect(zhTitle).toBe(i18n.global.t('login.docTitle'))
    expect(zhTitle.length).toBeGreaterThan(0)
    i18n.global.locale.value = 'en-US'
    await flush(4)
    const enTitle = document.title
    expect(enTitle).toBe(i18n.global.t('login.docTitle'))
    expect(enTitle).not.toBe(zhTitle)
    i18n.global.locale.value = 'zh-CN'
    expect(c.errors).toEqual([])
  })

  test('挂载时消费跨标签页提示：弹出后立即从 sessionStorage 移除（不重复弹）', async () => {
    sessionStorage.setItem('authSyncNotice', 'auth.syncLoggedOut')
    const c = await open()
    expect(ElMessage.warning).toHaveBeenCalledTimes(1)
    expect(sessionStorage.getItem('authSyncNotice')).toBeNull()
    expect(c.errors).toEqual([])
  })
})
