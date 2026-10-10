/**
 * 注册页 / 登录页 认证前偏好控件与判据同源的回归测试
 *
 * 本文件此前是一批「读源码字符串做断言」的静态检查（expect(source).toContain(...)）。
 * 这类断言已被实测证明是**弱断言**：把被测标签注释掉（<!-- <AuthPrefs /> -->）、
 * 加 v-if="false"、甚至把同样的字符串写进 <script> 里，断言都照样通过——
 * 它只能证明「这串字符在文件里出现过」，不能证明组件真的渲染、真的工作。
 * 故除「jsdom 物理上无法断言」的 CSS 规则外，全部改写为真实挂载 + DOM 行为断言。
 *
 * 保留为静态断言的部分及原因（jsdom 的真实限制，不是偷懒）：
 *  - <style> 里的 CSS 规则：SFC 的样式块在 vitest 下不会被注入 document，
 *    getComputedStyle 取不到任何声明，暗色覆盖选择器无从断言。
 *  - 硬编码色值扫描：需要判断「有没有写 #fff」，只能读源码文本。
 *
 * 另有跨组件不变式：口令强度条「五条全绿」必须等价于提交准入
 * （isStrongPassword）。若强度条自带一套判据，用户会看到「全绿却提交被拒」
 * 或「标红却能提交」的自相矛盾界面。此处用真实渲染的强度条状态与提交判据比对。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import {
  evaluatePasswordRules,
  isStrongPassword,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MAX_BYTES,
} from '@/utils/password'

const getCaptchaStatus = vi.fn()
const getCaptcha = vi.fn()
const register = vi.fn()
const login = vi.fn()
const encryptPassword = vi.fn(async () => null)
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      getCaptchaStatus: (...a) => getCaptchaStatus(...a),
      getCaptcha: (...a) => getCaptcha(...a),
      register: (...a) => register(...a),
      login: (...a) => login(...a),
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
import LoginView from '@/views/LoginView.vue'
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

const ROUTES = [
  { path: '/register', component: { render: () => null } },
  { path: '/login', component: { render: () => null } },
]
const STRONG = 'Str0ng-Pass_2026'

let active = null

/** 挂载注册页并等首屏的验证码状态查询落定 */
const openRegister = async () => {
  const base = getCaptchaStatus.mock.calls.length
  getCaptchaStatus.mockResolvedValue({ data: { data: { registerCaptchaEnabled: false } } })
  active = mountComponent(RegisterView, { initialRoute: '/register', routes: ROUTES })
  await waitFor(() => getCaptchaStatus.mock.calls.length > base, {
    message: '注册页首屏的验证码状态查询',
  })
  await flush(6)
  return active
}

const openLogin = async () => {
  const base = getCaptchaStatus.mock.calls.length
  getCaptchaStatus.mockResolvedValue({ data: { data: { loginCaptchaEnabled: false } } })
  active = mountComponent(LoginView, { initialRoute: '/login', routes: ROUTES })
  await waitFor(() => getCaptchaStatus.mock.calls.length > base, {
    message: '登录页首屏的验证码状态查询',
  })
  await flush(6)
  return active
}

/** 触发 Element Plus 输入的 v-model 更新（真实浏览器里由用户键入触发） */
const typeInto = (c, id, value) => {
  const el = c.find('#' + id)
  el.value = value
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
}

/**
 * 打开某个 AuthPrefs 下拉并返回其菜单项。
 * Element Plus 的下拉菜单被 teleport 到 document.body（不在组件根内），
 * 且展开是异步的，故轮询 document.body 而非固定 flush 次数。
 */
const openDropdown = async (btn) => {
  click(btn)
  for (let i = 0; i < 40; i += 1) {
    const items = Array.from(document.body.querySelectorAll('.el-dropdown-menu__item'))
    if (items.length > 0) return items
    await new Promise((r) => setTimeout(r, 20))
    await flush(2)
  }
  return []
}

/** 在 teleport 出去的菜单项上派发真实 click（与浏览器一致） */
const clickMenuItem = async (items, text) => {
  const target = items.find((e) => e.textContent.trim().includes(text))
  if (!target)
    throw new Error(
      `下拉菜单中找不到「${text}」项，实际项：${items.map((e) => e.textContent.trim()).join(' / ')}`
    )
  target.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }))
  await flush(20)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  getCaptchaStatus.mockReset()
  getCaptcha.mockReset()
  register.mockReset()
  login.mockReset()
  encryptPassword.mockReset()
  encryptPassword.mockImplementation(async () => null)
  document.body.innerHTML = ''
  document.documentElement.classList.remove('dark')
  document.documentElement.removeAttribute('lang')
  window.localStorage.clear()
  window.sessionStorage.clear()
})

describe('evaluatePasswordRules 逐条判据', () => {
  test('空口令五条全不通过', () => {
    const r = evaluatePasswordRules('')
    expect(r.passed).toBe(0)
    expect(r.satisfied).toBe(false)
    expect(r.total).toBe(5)
  })

  test('非字符串入参按空串处理（不抛错）', () => {
    for (const v of [null, undefined, 123, {}, []]) {
      expect(evaluatePasswordRules(v).passed).toBe(0)
    }
  })

  test('逐项识别缺失的规则', () => {
    // 缺大写
    expect(evaluatePasswordRules('abcdefg1!').upper).toBe(false)
    // 缺小写
    expect(evaluatePasswordRules('ABCDEFG1!').lower).toBe(false)
    // 缺数字
    expect(evaluatePasswordRules('Abcdefgh!').digit).toBe(false)
    // 缺特殊字符
    expect(evaluatePasswordRules('Abcdefg1').symbol).toBe(false)
    // 长度不足（7 位）
    expect(evaluatePasswordRules('Abcde1!').length).toBe(false)
  })

  test('合格口令五条全通过', () => {
    const r = evaluatePasswordRules('Str0ng-Pass_2026')
    expect(r).toMatchObject({
      length: true,
      upper: true,
      lower: true,
      digit: true,
      symbol: true,
    })
    expect(r.satisfied).toBe(true)
    expect(r.passed).toBe(5)
  })

  test('P3-29 放宽后的标点（- 与 _）被视为特殊字符', () => {
    expect(evaluatePasswordRules('Str0ng-Pass').symbol).toBe(true)
    expect(evaluatePasswordRules('Str0ng_Pass').symbol).toBe(true)
  })

  test('长度上限：字符数 64 与 UTF-8 字节数 72 双约束', () => {
    // 恰好 64 字符且全 ASCII（64 字节）→ 通过
    const ok = 'Aa1!' + 'x'.repeat(PASSWORD_MAX_LENGTH - 4)
    expect(ok.length).toBe(PASSWORD_MAX_LENGTH)
    expect(evaluatePasswordRules(ok).length).toBe(true)

    // 65 字符 → 超字符上限
    expect(evaluatePasswordRules(ok + 'y').length).toBe(false)

    // 25 个汉字 = 75 字节（>72），字符数只有 29 却已越过 bcrypt 边界
    const cjk = 'Aa1!' + '密'.repeat(25)
    expect(cjk.length).toBeLessThan(PASSWORD_MAX_LENGTH)
    expect(new TextEncoder().encode(cjk).length).toBeGreaterThan(PASSWORD_MAX_BYTES)
    expect(evaluatePasswordRules(cjk).length).toBe(false)
  })

  test('satisfied 与 isStrongPassword 结论完全一致（同源判据）', () => {
    const samples = [
      '',
      'a',
      'abcdefgh',
      'ABCDEFGH',
      '12345678',
      '!!!!!!!!',
      'Abcdefg1',
      'Abcdefg!',
      'abcdefg1!',
      'ABCDEFG1!',
      'Str0ng-Pass_2026',
      'Aa1!Aa1!',
      'Aa1!' + 'x'.repeat(60),
      'Aa1!' + 'x'.repeat(61),
      'Aa1!' + '密'.repeat(25),
    ]
    for (const s of samples) {
      expect(evaluatePasswordRules(s).satisfied).toBe(isStrongPassword(s))
    }
  })
})

describe('强度条「五条全绿」必须等价于提交准入（跨组件不变式）', () => {
  // 判据同源不是「源码里调用了同一个函数」，而是**渲染出来的结论**与
  // 提交校验的结论一致。若强度条自带一套正则（例如把长度判成 8 位），
  // 用户会看到「全绿却提交被拒」。故这里比对真实渲染的每一条 is-ok
  // 与 isStrongPassword 的结论，而不是比对源码字符串。
  const samples = [
    'Str0ng-Pass_2026',
    'Abcdefg1!xyz', // 11 位：仅差长度
    'Aa1!' + 'x'.repeat(60), // 恰好 64 字符
    'Aa1!' + 'x'.repeat(61), // 65 字符：超字符上限
    'Aa1!' + '密'.repeat(25), // 29 字符但 75 字节：超字节上限
    'Abcdefg1xyzw', // 12 位但缺特殊字符
  ]

  test('逐样本：强度条全绿 ⟺ isStrongPassword 为真', async () => {
    for (const s of samples) {
      const c = mountComponent(PasswordStrengthMeter, { props: { password: s } })
      await flush(4)
      const allOk = c.findAll('.pwd-meter__rules li').every((li) => li.classList.contains('is-ok'))
      expect(allOk, `口令「${s}」的强度条结论与提交判据不一致`).toBe(isStrongPassword(s))
      c.handle.unmount()
    }
  })
})

describe('RegisterView 真实渲染：偏好控件与子组件', () => {
  test('主题 + 语言偏好控件在注册页真实渲染（不是只出现在源码里）', async () => {
    const c = await openRegister()
    const btns = c.findAll('.auth-prefs__btn')
    expect(btns.length).toBe(2)
    // 图标 + 文字，非裸图标：每个按钮都带可见文案与可访问名
    for (const b of btns) {
      expect(b.querySelector('.auth-prefs__text').textContent.trim().length).toBeGreaterThan(0)
      expect(b.getAttribute('aria-label')).toBeTruthy()
      expect(b.getAttribute('title')).toBeTruthy()
    }
    expect(c.errors).toEqual([])
  })

  test('在注册页切换暗色：store 落地 + html.dark + 按钮文案跟随', async () => {
    const { useAppStore } = await import('@/store')
    let store = null
    const base = getCaptchaStatus.mock.calls.length
    getCaptchaStatus.mockResolvedValue({ data: { data: { registerCaptchaEnabled: false } } })
    active = mountComponent(RegisterView, {
      initialRoute: '/register',
      routes: ROUTES,
      setupStore: (pinia) => {
        store = useAppStore(pinia)
      },
    })
    await waitFor(() => getCaptchaStatus.mock.calls.length > base, { message: '验证码状态查询' })
    await flush(6)
    const c = active

    const themeBtn = c.findAll('.auth-prefs__btn')[0]
    const items = await openDropdown(themeBtn)
    await clickMenuItem(items, '暗色模式')

    expect(store.themeMode).toBe('dark')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(window.localStorage.getItem('themeMode')).toBe('dark')
    // 按钮文案必须跟着变，否则用户看不到当前处于哪一档
    expect(c.findAll('.auth-prefs__btn')[0].textContent.trim()).toBe('暗色模式')
    expect(c.errors).toEqual([])
  })

  test('在注册页切换语言：i18n locale + html lang + 按钮文案跟随', async () => {
    const i18n = (await import('@/i18n')).default
    const c = await openRegister()
    expect(i18n.global.locale.value).toBe('zh-CN')

    const langBtn = c.findAll('.auth-prefs__btn')[1]
    const items = await openDropdown(langBtn)
    await clickMenuItem(items, 'English')

    expect(i18n.global.locale.value).toBe('en-US')
    expect(document.documentElement.getAttribute('lang')).toBe('en-US')
    expect(c.findAll('.auth-prefs__btn')[1].textContent.trim()).toBe('English')
    // 页面正文必须真的跟着换语言，而不是只改了按钮自己
    // 断言取自真实词表 en-US.js 的 register.brandTitle / stepAccount
    expect(c.text()).toContain('Request an Account')
    expect(c.text()).toContain('Credentials')
    expect(c.errors).toEqual([])
  })

  test('口令强度条与信息核对在注册页真实渲染', async () => {
    const c = await openRegister()
    // 强度条：5 条规则 + 实时结论
    expect(c.findAll('.pwd-meter__rules li').length).toBe(5)
    // 信息核对：末步才可见，但组件必须在（v-show/v-if 由渲染结果决定）
    const summary = c.find('.summary')
    expect(summary).toBeTruthy()
    expect(summary.querySelector('.summary__title').textContent.trim()).toBe('信息核对')

    // 键入弱口令 → 强度条实时判红（证明它是活的，不是静态占位）
    typeInto(c, 'password', 'abc')
    await flush(6)
    expect(c.find('.pwd-meter__level').textContent.trim()).toBe('弱')
    // 键入强口令 → 五条全绿
    typeInto(c, 'password', STRONG)
    await flush(6)
    expect(c.findAll('.pwd-meter__rules li').every((li) => li.classList.contains('is-ok'))).toBe(
      true
    )
    expect(c.errors).toEqual([])
  })
})

describe('LoginView 真实渲染：偏好控件', () => {
  test('登录页同样渲染主题 + 语言入口（与注册页共用组件，不得单边缺失）', async () => {
    const c = await openLogin()
    const btns = c.findAll('.auth-prefs__btn')
    expect(btns.length).toBe(2)
    for (const b of btns) {
      expect(b.querySelector('.auth-prefs__text').textContent.trim().length).toBeGreaterThan(0)
    }
    expect(c.errors).toEqual([])
  })
})

describe('静态不变量（jsdom 无法断言的 CSS 规则）', () => {
  // 以下三项断言的是 <style> 块里的 CSS 规则文本：SFC 样式在 vitest 下
  // 不注入 document，getComputedStyle 取不到任何声明，故只能读源码文本。
  const source = readSrc('views/RegisterView.vue')
  const authPrefsSource = readSrc('components/AuthPrefs.vue')
  const summarySource = readSrc('components/RegisterSummary.vue')

  test('不写死背景色值：样式一律走 --xf-* 变量', () => {
    // 只检查 background 属性上的硬编码色值；--xf-* 里的 rgba() 由 global/dark.css 负责翻转
    const hardcoded = source
      .split('\n')
      .filter((line) => /^\s*background(-color)?\s*:/.test(line))
      .filter((line) => /#[0-9a-fA-F]{3,8}\b/.test(line))
    expect(hardcoded).toEqual([])
  })

  test('暗色下必须显式覆盖的位置已覆盖（提示条与光斑）', () => {
    // 变量翻转对这两处不成立：提示条前景写的是 primary-deep（深红），
    // 暗色底上不可读；光斑在深底上几乎看不见。故必须有 html.dark 覆盖规则。
    expect(summarySource).toContain('html.dark .summary__row')
    // 光斑元素本轮由 `register__aurora` 改名为 `register__decor`（并补 aria-hidden），
    // 暗色覆盖规则跟着改名 ⇒ 断言取新名。契约不变：深底上必须有一条显式的 html.dark 覆盖。
    expect(source).toContain('html.dark .register__decor')
  })

  test('偏好控件的小屏降级规则在组件内维护（不在两个页面各写一份）', () => {
    // 【保留】这条是 CSS 媒体查询：jsdom 不注入 SFC 样式，也从不应用
    // @media 断点，`getComputedStyle` 取不到任何声明（实测
    // document.querySelectorAll('style').length === 0），故只能读源码文本。
    expect(authPrefsSource).toContain('@media (max-width: 560px)')
    // 【已删除的冗余静态断言 → 替代用例（变异实测杀死）】
    //   auth-prefs__text（图标+文字，非裸图标）→ 删掉 theme 按钮的文字 span 后
    //     「主题 + 语言偏好控件在注册页真实渲染」「在注册页切换暗色」「登录页同样
    //     渲染主题 + 语言入口」共 3 例变红（都断言 .auth-prefs__text 有非空文本）。
    //   <AuthPrefs /> 挂载（注册页 / 登录页各一处）→ 注释掉后分别有 3 例 / 1 例变红。
  })
})

describe('RegisterView 分步导航与提交的同步锁（H1 / H7）', () => {
  /** 当前可见步骤下标：三个面板用 v-show 控制，未显示的 display:none */
  const visibleStep = (c) =>
    c.findAll('.register-step').findIndex((el) => el.style.display !== 'none')

  const fillStepOne = (c) => {
    typeInto(c, 'username', 'zhangsan')
    typeInto(c, 'email', 'zhangsan@example.com')
    typeInto(c, 'password', STRONG)
    typeInto(c, 'confirmPassword', STRONG)
  }

  const nextButton = (c) => c.findAll('button').find((b) => b.textContent.includes('下一步'))

  test('正对照：单击「下一步」前进一步（证明校验链路在 jsdom 里真的通，不是真空断言）', async () => {
    const c = await openRegister()
    fillStepOne(c)
    await flush(6)
    expect(visibleStep(c)).toBe(0)
    click(nextButton(c))
    await flush(30)
    expect(visibleStep(c)).toBe(1)
    expect(c.errors).toEqual([])
  })

  test('H1：校验窗口内连点两次仍只前进一步，不得 0→2 落进确认步', async () => {
    const c = await openRegister()
    fillStepOne(c)
    await flush(6)
    // 同一 tick 内连点两次：两次都进入 validateStep 的 await，恢复后各自 +1。
    // 修复前实测 activeStep 0→2——用户没填真实姓名/手机就进了信息核对步，
    // 而身份步骤的字段一个都没校验过。
    click(nextButton(c))
    click(nextButton(c))
    await flush(40)
    expect(visibleStep(c)).toBe(1)
    expect(c.errors).toEqual([])
  })

  /** 开验证码并走到第 3 步：H7 的可观测面是验证码是否被重载 */
  const openRegisterWithCaptcha = async () => {
    getCaptchaStatus.mockResolvedValue({ data: { data: { registerCaptchaEnabled: true } } })
    getCaptcha.mockResolvedValue({ data: { data: { captchaId: 'c1', svg: '<svg/>' } } })
    active = mountComponent(RegisterView, { initialRoute: '/register', routes: ROUTES })
    await waitFor(() => getCaptchaStatus.mock.calls.length > 0, { message: '验证码状态查询' })
    await flush(8)
    return active
  }

  test('H7 正对照：注册请求失败仍会换新验证码（一次性消费语义没被改坏）', async () => {
    const c = await openRegisterWithCaptcha()
    fillStepOne(c)
    await flush(6)
    click(nextButton(c))
    await flush(30)
    // 第 2 步字段后端均 optional，空值即可通过
    click(nextButton(c))
    await flush(30)
    expect(visibleStep(c)).toBe(2)
    typeInto(c, 'captcha', 'a1b2')
    await flush(4)
    const before = getCaptcha.mock.calls.length
    expect(before).toBeGreaterThan(0)
    register.mockRejectedValue(new Error('boom'))
    click(c.findAll('button').find((b) => b.textContent.includes('提交注册')))
    await flush(40)
    // 请求失败 ⇒ 必须重载验证码（一次性消费）
    expect(getCaptcha.mock.calls.length).toBeGreaterThan(before)
    expect(c.errors).toEqual([])
  })

  test('H7：整表校验失败不清验证码——与请求失败分开处理', async () => {
    const c = await openRegisterWithCaptcha()
    fillStepOne(c)
    await flush(6)
    click(nextButton(c))
    await flush(30)
    click(nextButton(c))
    await flush(30)
    expect(visibleStep(c)).toBe(2)
    typeInto(c, 'captcha', 'a1b2')
    await flush(4)
    // 三个面板用 v-show 渲染、始终挂载：把已通过校验的第 1 步字段改坏，
    // 让 onRegister 里的整表 validate() 必然 reject（这正是用户回退改错值的路径）
    typeInto(c, 'username', 'x')
    await flush(6)
    const before = getCaptcha.mock.calls.length
    click(c.findAll('button').find((b) => b.textContent.includes('提交注册')))
    await flush(40)
    // 修复前：validate() 的 reject 落进「任何失败都换验证码」的 catch，
    // 用户刚填对的验证码被清掉并重载。修复后单独一层 try 后 return，不碰验证码。
    expect(getCaptcha.mock.calls.length).toBe(before)
    expect(c.find('#captcha').value).toBe('a1b2')
    expect(c.errors).toEqual([])
  })
})
