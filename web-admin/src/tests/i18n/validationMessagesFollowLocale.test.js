/**
 * 校验文案随语言切换（i18n 响应式契约）
 *
 * 真实退化：rules 在 setup 顶层用 t(...) 求值一次，得到的是一串**固化字符串**。
 * 用户在页内切换语言（AuthPrefs / LanguageSwitcher 走的就是响应式 locale，视图不重挂载）
 * 后，字段标签与按钮都变成英文，唯独错误提示还是中文，界面自相矛盾（本轮实测复现：
 * en 下标签是 Username、错误提示仍是「请输入用户名」）。
 *
 * 覆蓋带 i18n 校验文案的入口：
 *   UserView / RegisterView / RoleFormDialog / ProfileView / InspectionReviewForm
 *
 * 用「同一挂载实例内切 locale -> 重新校验 -> 断言文案语言跟随」钉住契约，
 * 而不是静态扫源码看有没有 computed：后者会把同样正确的其它写法（如 message 用 getter）误判。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import i18n from '@/i18n'
import { useAuthStore } from '@/store'

const usersGetList = vi.fn()
const captchaStatus = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    users: {
      getList: (...a) => usersGetList(...a),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      resetMfa: vi.fn(),
      assignRoles: vi.fn(),
    },
    roles: { getAll: vi.fn(async () => ({ data: { data: [] } })) },
    auth: {
      getCaptchaStatus: (...a) => captchaStatus(...a),
      getCaptcha: vi.fn(async () => ({ data: { success: true, data: {} } })),
      register: vi.fn(),
    },
    inspections: {
      getById: vi.fn(async () => ({ data: { data: { title: 'x', findings: [] } } })),
      review: vi.fn(),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: vi.fn() },
}))
vi.mock('element-plus/es/components/notification/index.mjs', () => ({ ElNotification: vi.fn() }))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: vi.fn(async () => null),
  isTransportCryptoAvailable: () => true,
  invalidatePublicKeyCache: () => {},
}))

import UserView from '@/views/UserView.vue'
import RegisterView from '@/views/RegisterView.vue'
import RoleFormDialog from '@/components/RoleFormDialog.vue'
import ProfileView from '@/views/ProfileView.vue'
import InspectionReviewForm from '@/components/InspectionReviewForm.vue'

let active = null

/**
 * 受控宿主：把 v-model 接回本地 reactive 对象，才能在挂载后打开对话框。
 * 必须「先挂载、后翻转」——InspectionReviewForm 的数据加载只在 watch(visible) 里（无
 * onMounted），挂载时直接传 true 会得到「什么都没加载也通过」的真空断言。
 *
 * 全文件只保留这一处 defineComponent（vue/one-component-per-file）。
 * @param {object} comp 被测组件
 * @param {object} initial 初始 props（含受控开关）
 * @param {string} vModelProp 该组件用于开关的 prop 名（modelValue / visible）
 */
const makeHost = (comp, initial, vModelProp = 'modelValue') => {
  const state = reactive({ ...initial })
  const Host = defineComponent({
    setup() {
      return () =>
        h(comp, {
          ...state,
          ['onUpdate:' + vModelProp]: (v) => {
            state[vModelProp] = v
          },
        })
    },
  })
  return { Host, state }
}

/** Element Plus 的校验状态经 refDebounced(…, 100) 渲染，必须给真实定时器时间 */
const settleValidation = async () => {
  await new Promise((r) => setTimeout(r, 260))
  await flush(20)
}

const errTexts = (scopeEl) =>
  Array.from(scopeEl.querySelectorAll('.el-form-item.is-error')).map((el) =>
    el.querySelector('.el-form-item__error')?.textContent.trim()
  )
const dlgEl = () => document.body.querySelector('.el-dialog')
const dlgErrTexts = () => errTexts(dlgEl())
const dlgBtn = (texts) =>
  Array.from(dlgEl().querySelectorAll('.el-dialog__footer button')).find((b) =>
    texts.includes(b.textContent.trim())
  )
/** 断言「切到 en 后重新校验，出现的每条文案都能在英文词表里找到、且不再残留中文词表文案」 */
const expectNoZhThenEn = async (keys, revalidate) => {
  i18n.global.locale.value = 'en-US'
  await flush(20)
  await revalidate()
  const texts = dlgErrTexts()
  const enValues = keys.map((k) => i18n.global.t(k))
  expect(texts.some((s) => enValues.includes(s))).toBe(true)
  for (const zhKey of keys) {
    const zhValue = i18n.global.t(zhKey, {}, { locale: 'zh-CN' })
    expect(texts).not.toContain(zhValue)
  }
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  usersGetList.mockReset()
  captchaStatus.mockReset()
  i18n.global.locale.value = 'zh-CN'
  document.body.innerHTML = ''
})

describe('表单校验文案跟随当前语言', () => {
  test('UserView 新增用户：切到英文后重新校验，四类必填提示全部变英文', async () => {
    usersGetList.mockResolvedValue({ data: { data: [], pagination: { total: 0 } } })
    active = mountComponent(UserView, {
      setupStore: (pinia) =>
        useAuthStore(pinia).setPermissions([
          'user:read',
          'user:create',
          'user:update',
          'user:delete',
        ]),
    })
    await flush(30)
    click(active.findAll('button').find((b) => b.textContent.includes('新增')))
    await flush(30)
    const zh = (() => {
      click(dlgBtn(['新增']))
      return dlgErrTexts()
    })()
    await settleValidation()
    expect(dlgErrTexts()).toContain('请输入用户名')
    expect(zh).toBeDefined()

    await expectNoZhThenEn(
      [
        'validation.usernameRequired',
        'validation.emailRequired',
        'validation.passwordRequired',
        'validation.realNameRequired',
      ],
      async () => {
        click(dlgBtn(['Add', '新增']))
        await settleValidation()
      }
    )
    expect(active.errors).toEqual([])
  })

  test('RoleFormDialog 新增角色：切到英文后名称/编码提示全部变英文', async () => {
    // 受控宿主：把 modelValue 真正接回来，避免「传 true 但 watch 不触发」的真空断言
    const { Host } = makeHost(RoleFormDialog, { visible: true }, 'visible')
    // 提交按钮受 role:create 门控，无权限时根本不渲染（P1-8 既有修复）
    active = mountComponent(Host, {
      setupStore: (pinia) => useAuthStore(pinia).setPermissions(['role:create']),
    })
    await flush(30)
    expect(dlgEl()).toBeTruthy()
    const submit = () =>
      Array.from(dlgEl().querySelectorAll('.el-dialog__footer button')).find((b) =>
        ['新增', 'Add', '创建', 'Create'].includes(b.textContent.trim())
      )
    expect(submit()).toBeTruthy()
    click(submit())
    await settleValidation()
    const zh = dlgErrTexts()
    expect(zh.some((s) => s && s.includes('角色名称'))).toBe(true)

    i18n.global.locale.value = 'en-US'
    await flush(20)
    click(submit())
    await settleValidation()
    const en = dlgErrTexts()
    expect(en).toContain(i18n.global.t('validation.roleNameRequired'))
    expect(en).toContain(i18n.global.t('validation.roleCodeRequired'))
    expect(en).not.toContain('请输入角色名称')
    expect(active.errors).toEqual([])
  })

  test('RegisterView 第 1 步：切到英文后分步校验提示变英文', async () => {
    captchaStatus.mockResolvedValue({ data: { data: { registerCaptchaEnabled: false } } })
    active = mountComponent(RegisterView, {
      initialRoute: '/register',
      routes: [
        { path: '/register', component: { render: () => null } },
        { path: '/login', component: { render: () => null } },
      ],
    })
    await flush(30)
    const stepErrors = () =>
      Array.from(active.findAll('.el-form-item.is-error')).map((el) =>
        el.querySelector('.el-form-item__error')?.textContent.trim()
      )
    const nextBtn = (labels) =>
      active.findAll('button').find((b) => labels.some((l) => b.textContent.includes(l)))
    click(nextBtn(['下一步']))
    await settleValidation()
    expect(stepErrors()).toContain('请输入用户名')

    i18n.global.locale.value = 'en-US'
    await flush(20)
    click(nextBtn(['Next', '下一步']))
    await settleValidation()
    const en = stepErrors()
    expect(en).toContain(i18n.global.t('validation.usernameRequired'))
    expect(en).toContain(i18n.global.t('validation.emailRequired'))
    expect(en).not.toContain('请输入用户名')
    expect(active.errors).toEqual([])
  })

  test('ProfileView 资料表单：切到英文后邮箱/手机号提示变英文', async () => {
    const setVal = (sel, v) => {
      const el = active.find(sel)
      el.value = v
      el.dispatchEvent(new window.Event('input', { bubbles: true }))
      el.dispatchEvent(new window.Event('blur', { bubbles: true }))
    }
    active = mountComponent(ProfileView, {})
    await flush(40)
    // 资料表单字段是「非必填 + 格式约束」：填入非法值才触发格式提示
    setVal('#profileEmail', 'not-an-email')
    await settleValidation()
    expect(errTexts(active.root)).toContain('请输入有效的邮箱地址')

    i18n.global.locale.value = 'en-US'
    await flush(20)
    setVal('#profileEmail', 'still-not-an-email')
    await settleValidation()
    const en = errTexts(active.root)
    expect(en).toContain(i18n.global.t('validation.emailInvalid'))
    expect(en).not.toContain('请输入有效的邮箱地址')
    expect(active.errors).toEqual([])
  })

  test('InspectionReviewForm 审核意见：切到英文后必填/长度提示变英文', async () => {
    const { Host, state } = makeHost(InspectionReviewForm, {
      modelValue: false,
      inspectionId: 'insp-1',
    })
    active = mountComponent(Host, {})
    await flush(4)
    // 必须挂载后再打开：组件的加载只在 watch(visible) 里（无 onMounted）
    state.modelValue = true
    await waitFor(() => dlgEl(), { message: '审核对话框打开' })
    await flush(10)
    const submit = () =>
      Array.from(dlgEl().querySelectorAll('.el-dialog__footer button')).find(
        (b) => !/取消|Cancel/.test(b.textContent)
      )
    expect(submit()).toBeTruthy()
    click(submit())
    await settleValidation()
    expect(dlgErrTexts().length).toBeGreaterThan(0)

    i18n.global.locale.value = 'en-US'
    await flush(20)
    click(submit())
    await settleValidation()
    const en = dlgErrTexts()
    expect(en).toContain(i18n.global.t('inspection.reviewCommentPlaceholder'))
    expect(active.errors).toEqual([])
  })
})
