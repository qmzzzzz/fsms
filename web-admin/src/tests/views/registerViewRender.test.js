/**
 * RegisterView 渲染级行为测试（多步向导 / 分步校验 / 提交载荷与失败处理）
 *
 * 注册页是唯一允许匿名写库的入口，且是一次性冷启动动作——用户注册失败后
 * 通常不会重试，因此这里的每类退化都必须被钉住：
 *  1. 分步校验失效 -> 空表单也能走到末步并提交，后端拒绝后用户不知道该填哪；
 *  2. 重入锁缺失 -> 同一 tick 连点发出多次注册请求（第 2 次因用户名重复失败，
 *     用户先看到「注册成功」再连吃错误提示）；
 *  3. 提交载荷带空串字段 -> 后端 optional 校验被空串绕过的历史问题；
 *  4. 加密失败时降级明文 -> 安全轨静默降级（FE-H1 要求阻断）；
 *  5. 验证码失败后不换新 -> 一次性验证码复用，用户永远提交不成功。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const getCaptchaStatus = vi.fn()
const getCaptcha = vi.fn()
const register = vi.fn()
const encryptPassword = vi.fn(async () => null)
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      getCaptchaStatus: (...a) => getCaptchaStatus(...a),
      getCaptcha: (...a) => getCaptcha(...a),
      register: (...a) => register(...a),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/notification/index.mjs', () => ({
  ElNotification: vi.fn(),
}))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (...a) => encryptPassword(...a),
  isTransportCryptoAvailable: () => true,
  invalidatePublicKeyCache: () => {},
}))

import RegisterView from '@/views/RegisterView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElNotification } from 'element-plus/es/components/notification/index.mjs'

let active = null
const ROUTES = [
  { path: '/register', component: { render: () => null } },
  { path: '/login', component: { render: () => null } },
]
const STRONG = 'Str0ng-Pass_2026'

/** 触发 Element Plus 输入的 v-model 更新（真实浏览器里由用户键入触发） */
const typeInto = (c, id, value) => {
  const el = c.find('#' + id)
  el.value = value
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
}

/** 挂载注册页并等首屏的验证码状态查询落定 */
const open = async ({ captchaEnabled = false } = {}) => {
  getCaptchaStatus.mockResolvedValue({ data: { data: { registerCaptchaEnabled: captchaEnabled } } })
  active = mountComponent(RegisterView, { initialRoute: '/register', routes: ROUTES })
  await waitFor(() => getCaptchaStatus.mock.calls.length === 1, { message: '验证码状态查询发出' })
  await flush(6)
  return active
}

const stepBtns = (c) => c.findAll('button').map((b) => b.textContent.trim())
const btnByText = (c, text) => c.findAll('button').find((b) => b.textContent.includes(text))
const activeStepIndex = (c) =>
  c.findAll('.register-steps__item').findIndex((el) => el.getAttribute('aria-current') === 'step')
const errCount = (c) => c.findAll('.el-form-item.is-error').length
/** 填写第 1 步并推进到第 2 步（多处用例的公共前置） */
const fillStep1AndNext = async (c) => {
  typeInto(c, 'username', 'zhangsan')
  typeInto(c, 'email', 'z@example.com')
  typeInto(c, 'password', STRONG)
  typeInto(c, 'confirmPassword', STRONG)
  await flush(6)
  click(btnByText(c, '下一步'))
  await flush(40)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  getCaptchaStatus.mockReset()
  getCaptcha.mockReset()
  register.mockReset()
  encryptPassword.mockReset()
  encryptPassword.mockImplementation(async () => null)
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  ElNotification.mockReset()
  document.body.innerHTML = ''
})

describe('RegisterView 分步向导', () => {
  test('首屏停在第 1 步，只渲染当前步的面板，且不查验证码图片', async () => {
    const c = await open()
    expect(activeStepIndex(c)).toBe(0)
    const panels = c.findAll('.register-step')
    expect(panels).toHaveLength(3)
    expect(panels[0].style.display).not.toBe('none')
    expect(panels[1].style.display).toBe('none')
    expect(panels[2].style.display).toBe('none')
    // 未开启验证码时不该去拉图片（省一次无效请求）
    expect(getCaptcha).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('第 1 步校验不过：停在原地、四个必填项标红、不发出注册请求', async () => {
    const c = await open()
    click(btnByText(c, '下一步'))
    await flush(40)
    expect(activeStepIndex(c)).toBe(0)
    expect(errCount(c)).toBe(4)
    const labels = c
      .findAll('.el-form-item.is-error')
      .map((el) => el.textContent.replace(/\s+/g, ' ').trim())
    expect(labels.join('|')).toContain('用户名')
    expect(labels.join('|')).toContain('确认密码')
    expect(register).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('两次口令不一致：确认框标红，且改回口令后自动重新校验（不必等提交）', async () => {
    const c = await open()
    typeInto(c, 'username', 'zhangsan')
    typeInto(c, 'email', 'z@example.com')
    typeInto(c, 'password', STRONG)
    typeInto(c, 'confirmPassword', 'Str0ng-Pass_2027')
    await flush(6)
    click(btnByText(c, '下一步'))
    await flush(40)
    expect(activeStepIndex(c)).toBe(0)
    const confirmItem = c.findAll('.el-form-item').find((el) => el.textContent.includes('确认密码'))
    expect(confirmItem.classList.contains('is-error')).toBe(true)
    // 改密码触发 watch 重校验：把密码改成与确认框一致后，错误态必须自己消失，
    // 否则用户改完仍看到红字（旧实现只在 confirmPassword 自身 blur 时比对）
    typeInto(c, 'password', 'Str0ng-Pass_2027')
    await flush(40)
    expect(c.find('#password').value).toBe('Str0ng-Pass_2027')
    expect(confirmItem.classList.contains('is-error')).toBe(false)
  })

  test('第 1 步填写完整后推进到第 2 步，面板与步骤条同步', async () => {
    const c = await open()
    await fillStep1AndNext(c)
    expect(activeStepIndex(c)).toBe(1)
    expect(c.findAll('.register-step')[1].style.display).not.toBe('none')
    expect(c.findAll('.register-step')[0].style.display).toBe('none')
    expect(errCount(c)).toBe(0)
    expect(c.errors).toEqual([])
  })

  test('第 2 步全为选填：直接下一步即可进入末步', async () => {
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    expect(activeStepIndex(c)).toBe(2)
    expect(errCount(c)).toBe(0)
  })

  test('末步信息核对展示第 1/2 步的填写值（未填项显示占位）', async () => {
    const c = await open()
    await fillStep1AndNext(c)
    typeInto(c, 'realName', '张三')
    await flush(4)
    click(btnByText(c, '下一步'))
    await flush(40)
    const summary = c.find('.summary').textContent.replace(/\s+/g, ' ')
    expect(summary).toContain('zhangsan')
    expect(summary).toContain('z@example.com')
    expect(summary).toContain('张三')
    // 未填的手机号/部门显示占位文案，而不是空白（空白会被误读为「已填写但为空」）
    expect(summary).toContain('未填写')
  })

  test('「上一步」回到前一步且不改动已填内容', async () => {
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '上一步'))
    await flush(40)
    expect(activeStepIndex(c)).toBe(0)
    expect(c.find('#username').value).toBe('zhangsan')
    expect(c.find('#password').value).toBe(STRONG)
  })

  test('「重置」清空全部字段并回到第 1 步', async () => {
    const c = await open()
    await fillStep1AndNext(c)
    typeInto(c, 'realName', '张三')
    await flush(4)
    click(btnByText(c, '重置'))
    await flush(40)
    expect(activeStepIndex(c)).toBe(0)
    expect(c.find('#username').value).toBe('')
    expect(c.find('#realName').value).toBe('')
  })
})

describe('RegisterView 提交载荷与失败处理', () => {
  test('注册成功：通知 + 跳转 /login', async () => {
    register.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    click(btnByText(c, '提交注册'))
    await waitFor(() => register.mock.calls.length === 1, { message: '注册请求发出' })
    expect(ElNotification).toHaveBeenCalledTimes(1)
    await waitFor(() => c.router.currentRoute.value.path === '/login', {
      message: '跳转到登录页',
    })
    expect(c.errors).toEqual([])
  })

  test('提交载荷：只带表单字段，未开启验证码时不带 captcha 字段', async () => {
    register.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await fillStep1AndNext(c)
    typeInto(c, 'realName', '张三')
    typeInto(c, 'phone', '13800138000')
    await flush(4)
    click(btnByText(c, '下一步'))
    await flush(40)
    click(btnByText(c, '提交注册'))
    await waitFor(() => register.mock.calls.length === 1, { message: '注册请求发出' })
    const payload = register.mock.calls[0][0]
    expect(payload.username).toBe('zhangsan')
    expect(payload.email).toBe('z@example.com')
    expect(payload.realName).toBe('张三')
    expect(payload.phone).toBe('13800138000')
    expect(payload).not.toHaveProperty('captchaId')
    expect(payload).not.toHaveProperty('captchaText')
    // 明文轨（WebCrypto 不可用）才带 password；可用时必须带 encPassword
    expect(payload.password).toBe(STRONG)
    expect(payload).not.toHaveProperty('encPassword')
  })

  test('WebCrypto 可用：提交 encPassword 且明文口令不上行', async () => {
    encryptPassword.mockResolvedValue('ENVELOPE-1')
    register.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    click(btnByText(c, '提交注册'))
    await waitFor(() => register.mock.calls.length === 1, { message: '注册请求发出' })
    const payload = register.mock.calls[0][0]
    expect(payload.encPassword).toBe('ENVELOPE-1')
    expect(payload).not.toHaveProperty('password')
  })

  test('口令加密失败：阻断提交并提示重试，绝不静默降级明文（FE-H1）', async () => {
    encryptPassword.mockRejectedValue(new Error('crypto down'))
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    click(btnByText(c, '提交注册'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '加密失败提示' })
    await flush(20)
    expect(register).not.toHaveBeenCalled()
    // 锁必须解开：否则用户重试时按钮永久卡死
    expect(btnByText(c, '提交注册')).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('同一 tick 连点三次只发出一次注册请求（重入锁必须同步置位）', async () => {
    register.mockImplementation(() => new Promise(() => {}))
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    const submit = btnByText(c, '提交注册')
    click(submit)
    click(submit)
    click(submit)
    await flush(80)
    expect(register.mock.calls.length).toBe(1)
    expect(c.errors).toEqual([])
  })

  test('提交中按钮换成禁用占位：加载态下不可能再点', async () => {
    register.mockImplementation(() => new Promise(() => {}))
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    click(btnByText(c, '提交注册'))
    await waitFor(() => register.mock.calls.length === 1, { message: '注册请求发出' })
    await flush(20)
    expect(btnByText(c, '提交注册')).toBeUndefined()
    const loadingBtn = c.findAll('button').find((b) => b.className.includes('is-loading'))
    expect(loadingBtn).toBeTruthy()
    expect(loadingBtn.disabled).toBe(true)
    expect(stepBtns(c).join('|')).toContain('正在提交')
  })

  test('接口返回 success=false：提示后端 message，且不跳转', async () => {
    register.mockResolvedValue({ data: { success: false, message: '用户名已存在' } })
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    click(btnByText(c, '提交注册'))
    await waitFor(() => register.mock.calls.length === 1, { message: '注册请求发出' })
    await flush(20)
    expect(ElMessage.error).toHaveBeenCalledWith('用户名已存在')
    expect(ElNotification).not.toHaveBeenCalled()
    expect(c.router.currentRoute.value.path).toBe('/register')
    expect(c.errors).toEqual([])
  })
})

describe('RegisterView 验证码分支', () => {
  test('开启验证码：末步渲染图片输入与图形验证码，图片以 data URI 内联', async () => {
    getCaptcha.mockResolvedValue({
      data: { success: true, data: { captchaId: 'cap-1', svg: '<svg></svg>' } },
    })
    const c = await open({ captchaEnabled: true })
    await waitFor(() => getCaptcha.mock.calls.length >= 1, { message: '验证码图片请求发出' })
    await flush(20)
    expect(c.find('#captcha')).toBeTruthy()
    const img = c.find('.register-card__captcha-img')
    expect(img).toBeTruthy()
    expect(img.getAttribute('src')).toContain('data:image/svg+xml')
  })

  test('验证码为空：末步校验拦下，不发出注册请求', async () => {
    getCaptcha.mockResolvedValue({
      data: { success: true, data: { captchaId: 'cap-1', svg: '<svg></svg>' } },
    })
    const c = await open({ captchaEnabled: true })
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    click(btnByText(c, '提交注册'))
    await flush(60)
    expect(register).not.toHaveBeenCalled()
    expect(errCount(c)).toBe(1)
    expect(c.errors).toEqual([])
  })

  test('提交带上 captchaId/captchaText；失败后清空输入并换新验证码（一次性消费）', async () => {
    getCaptcha.mockResolvedValue({
      data: { success: true, data: { captchaId: 'cap-1', svg: '<svg></svg>' } },
    })
    register.mockResolvedValue({ data: { success: false, message: '验证码错误' } })
    const c = await open({ captchaEnabled: true })
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    typeInto(c, 'captcha', 'ab12')
    await flush(6)
    const captchaCallsBefore = getCaptcha.mock.calls.length
    click(btnByText(c, '提交注册'))
    await waitFor(() => register.mock.calls.length === 1, { message: '注册请求发出' })
    const payload = register.mock.calls[0][0]
    expect(payload.captchaId).toBe('cap-1')
    expect(payload.captchaText).toBe('ab12')
    await waitFor(() => getCaptcha.mock.calls.length > captchaCallsBefore, {
      message: '失败后换新验证码',
    })
    expect(c.find('#captcha').value).toBe('')
    expect(c.errors).toEqual([])
  })
})

describe('RegisterView 键盘行为', () => {
  test('非末步回车 = 下一步（不会误触发注册）', async () => {
    register.mockResolvedValue({ data: { success: true } })
    const c = await open()
    typeInto(c, 'username', 'zhangsan')
    typeInto(c, 'email', 'z@example.com')
    typeInto(c, 'password', STRONG)
    typeInto(c, 'confirmPassword', STRONG)
    await flush(6)
    c.find('form').dispatchEvent(
      new window.KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true })
    )
    await flush(40)
    expect(activeStepIndex(c)).toBe(1)
    expect(register).not.toHaveBeenCalled()
  })

  test('末步回车 = 提交（与按钮口径一致）', async () => {
    register.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await fillStep1AndNext(c)
    click(btnByText(c, '下一步'))
    await flush(40)
    c.find('form').dispatchEvent(
      new window.KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true })
    )
    await waitFor(() => register.mock.calls.length === 1, { message: '回车触发注册请求' })
    expect(c.errors).toEqual([])
  })
})
