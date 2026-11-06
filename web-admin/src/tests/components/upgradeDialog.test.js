/**
 * UpgradeDialog 提交闸门行为测试（G2）
 *
 * 钉住三类提交路径的可观测行为：
 *  1. 最终确认（G2 新增的 ElMessageBox 人工闸）：取消 → 不发请求、busy 复位、
 *     凭据保留（用户改主意不必重打密码）；确认 → 携带密文凭据发出 triggerUpgrade。
 *  2. fail-closed：encryptPassword 返回 null（G2 后仅剩 dev 非安全上下文一种形态，
 *     生产直接抛 INSECURE_CONTEXT）时阻断提交并提示——明文回退轨已删，
 *     二次验证凭据绝不静默明文上行。
 *  3. 加密抛错（生产 INSECURE_CONTEXT / 指纹不符）：可执行文案提示且不发请求。
 *
 * jsdom 事实与 mock 边界：el-dialog append-to-body → 断言查 document.body；
 * ElMessageBox.confirm 直接 mock（真实确认框的端到端形态已由 aboutViewUpgrade.test.js
 * 过真组件钉住，这里只钉 submit 对确认结果的处理逻辑）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush } from '../helpers/componentHarness'

const h = vi.hoisted(() => ({
  triggerUpgrade: vi.fn(),
  encryptPassword: vi.fn(),
  confirm: vi.fn(),
  message: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}))

vi.mock('@/utils/api', () => ({
  api: {
    security: {
      triggerUpgrade: (...a) => h.triggerUpgrade(...a),
    },
  },
  isCanceledError: () => false,
  isHandledApiError: () => true,
}))
vi.mock('@/utils/loginCipher', () => ({
  encryptPassword: (...a) => h.encryptPassword(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({ ElMessage: h.message }))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: (...a) => h.confirm(...a) },
}))

import UpgradeDialog from '@/components/UpgradeDialog.vue'

const IMAGE = `ghcr.io/fsms/app@sha256:${'a'.repeat(64)}`

let active = null
const started = []

afterEach(() => {
  active?.unmount()
  active = null
  // el-dialog append-to-body：卸载后残留节点会污染下一条用例的查询
  document.body.querySelectorAll('.el-dialog').forEach((node) => node.remove())
  started.length = 0
  h.triggerUpgrade.mockReset()
  h.encryptPassword.mockReset()
  h.confirm.mockReset()
  // ElMessage 是模块级 mock：调用记录跨用例残留会把「第 N 次提示」断言带歪
  Object.values(h.message).forEach((fn) => fn.mockClear())
})

/** overview 传 null：ready 以「!== false」判定为就绪，不阻断升级入口 */
const open = async () => {
  active = mountComponent(UpgradeDialog, {
    props: { modelValue: true, overview: null, onStarted: (job) => started.push(job) },
  })
  await flush(8)
  return active
}

const submitBtn = () => document.body.querySelector('[data-testid="upgrade-submit"]')
const passwordInput = () => document.body.querySelector('.upgrade-password-input input')

const fillForm = async () => {
  const image = document.body.querySelector('.upgrade-image-input input')
  image.value = IMAGE
  image.dispatchEvent(new window.Event('input', { bubbles: true }))
  passwordInput().value = 'Aa1!current-password'
  passwordInput().dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(3)
}

describe('UpgradeDialog 最终确认闸（G2）', () => {
  test('确认框取消：不发请求、busy 复位、凭据保留（改主意不必重打密码）', async () => {
    h.confirm.mockRejectedValue('cancel')
    await open()
    await fillForm()

    click(submitBtn())
    await flush(6)

    // 确认框带新键文案（confirmTitle/confirmText/confirmOk）
    expect(h.confirm).toHaveBeenCalledTimes(1)
    expect(h.confirm.mock.calls[0][0]).toContain('即将提交升级任务')
    expect(h.confirm.mock.calls[0][1]).toBe('确认发起升级？')
    expect(h.confirm.mock.calls[0][2]).toMatchObject({
      type: 'warning',
      confirmButtonText: '确认发起',
      cancelButtonText: '取消',
    })

    expect(h.encryptPassword).not.toHaveBeenCalled()
    expect(h.triggerUpgrade).not.toHaveBeenCalled()
    // busy 复位：按钮可再点、不再处于提交态
    expect(submitBtn().disabled).toBe(false)
    expect(submitBtn().getAttribute('aria-busy')).toBe('false')
    // 凭据保留：finally 的清空只发生在 confirmed 路径
    expect(passwordInput().value).toBe('Aa1!current-password')
  })

  test('确认放行：携带密文凭据发出请求，入队后 emit started 并进入进度态', async () => {
    h.confirm.mockResolvedValue(true)
    h.encryptPassword.mockResolvedValue('ENC-STUB')
    h.triggerUpgrade.mockResolvedValue({
      data: {
        success: true,
        data: {
          job: { id: '0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d', state: 'queued', steps: [] },
        },
      },
    })
    await open()
    await fillForm()

    click(submitBtn())
    await flush(8)

    expect(h.encryptPassword).toHaveBeenCalledWith('Aa1!current-password', 'PASSWORD_CURRENT')
    expect(h.triggerUpgrade).toHaveBeenCalledTimes(1)
    expect(h.triggerUpgrade.mock.calls[0][0]).toEqual({
      image: IMAGE,
      mode: 'registry',
      encCurrentPassword: 'ENC-STUB',
    })
    expect(started).toHaveLength(1)
    expect(started[0].state).toBe('queued')
    expect(document.body.querySelector('[data-testid="upgrade-progress"]')).toBeTruthy()
  })
})

describe('UpgradeDialog 口令加密 fail-closed（G2 统一口径）', () => {
  test('encryptPassword 返回 null（dev 非安全上下文）：阻断提交并提示，不发请求', async () => {
    h.confirm.mockResolvedValue(true)
    h.encryptPassword.mockResolvedValue(null)
    await open()
    await fillForm()

    click(submitBtn())
    await flush(8)

    expect(h.triggerUpgrade).not.toHaveBeenCalled()
    expect(h.message.error).toHaveBeenCalledTimes(1)
    expect(h.message.error.mock.calls[0][0]).toBe(
      '当前页面不是安全连接（HTTPS），无法加密口令，已阻止提交。请通过 HTTPS 访问系统'
    )
    // busy 复位 + 凭据清空（confirmed 路径的原有语义：失败后不留旧口令）
    expect(submitBtn().getAttribute('aria-busy')).toBe('false')
    expect(passwordInput().value).toBe('')
  })

  test('encryptPassword 抛 INSECURE_CONTEXT（生产形态）：提示且不发请求', async () => {
    h.confirm.mockResolvedValue(true)
    h.encryptPassword.mockRejectedValue(
      Object.assign(new Error('no webcrypto'), { code: 'INSECURE_CONTEXT' })
    )
    await open()
    await fillForm()

    click(submitBtn())
    await flush(8)

    expect(h.triggerUpgrade).not.toHaveBeenCalled()
    expect(h.message.error.mock.calls[0][0]).toBe(
      '当前页面不是安全连接（HTTPS），无法加密口令，已阻止提交。请通过 HTTPS 访问系统'
    )
    expect(submitBtn().getAttribute('aria-busy')).toBe('false')
  })

  test('encryptPassword 抛 PUBLIC_KEY_PIN_MISMATCH：给指纹口径的可执行文案', async () => {
    h.confirm.mockResolvedValue(true)
    h.encryptPassword.mockRejectedValue(
      Object.assign(new Error('pin'), { code: 'PUBLIC_KEY_PIN_MISMATCH' })
    )
    await open()
    await fillForm()

    click(submitBtn())
    await flush(8)

    expect(h.triggerUpgrade).not.toHaveBeenCalled()
    expect(h.message.error.mock.calls[0][0]).toBe(
      '服务端安全密钥校验未通过，已阻止提交。如刚更新过服务端密钥，请刷新页面重试；如持续出现请联系管理员'
    )
  })
})

describe('UpgradeDialog 状态矩阵（2026-11-06 收敛批补测）', () => {
  const openWith = async (overview) => {
    active = mountComponent(UpgradeDialog, {
      props: { modelValue: true, overview, onStarted: (job) => started.push(job) },
    })
    await flush(8)
    return active
  }
  const setInput = async (selector, value) => {
    const input = document.body.querySelector(selector)
    input.value = value
    input.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(2)
  }

  test('ready=false：阻断横幅 + 逐条原因（含非字符串的 String 化臂），提交不可用', async () => {
    await openWith({
      upgrade: {
        ready: false,
        reasons: ['SMTP 未配置', null, 42],
        reasonCodes: ['smtp_missing', 'rc_orphan', 42],
      },
      server: { color: 'blue' },
    })
    expect(document.body.querySelector('[data-testid="upgrade-blocked"]')).toBeTruthy()
    // reasons 映射臂：字符串原样、null→String(null)='null'、数字→'42'（码侧同理）
    const blockedText = document.body.querySelector('[data-testid="upgrade-blocked"]').textContent
    expect(blockedText).toContain('SMTP 未配置')
    expect(blockedText).toContain('42')
    expect(document.body.querySelector('.upgrade-target')).toBeTruthy() // blue→green 臂
    expect(submitBtn().disabled).toBe(true)
  })

  test('color 缺失臂：overview.server.color 非字符串 → 目标色块不渲染', async () => {
    await openWith({ upgrade: { ready: true }, server: { color: 123 } })
    expect(document.body.querySelector('.upgrade-target')).toBe(null)
    // currentColor 非字符串臂下 colorLabel 落「未知色」文案由模板各臂自证
  })

  test('MFA 凭据分支：切到动态口令后 6 位数字才解锁提交（5 位不足）', async () => {
    await openWith(null)
    await setInput('.upgrade-image-input input', IMAGE)
    document.body.querySelector('.upgrade-mode-toggle').click()
    await flush(3)
    const mfa = document.body.querySelector('.upgrade-mfa-input input')
    expect(mfa).toBeTruthy()
    await setInput('.upgrade-mfa-input input', '12345')
    expect(submitBtn().disabled).toBe(true) // /^\d{6}$/ 臂：5 位不足
    await setInput('.upgrade-mfa-input input', '123456')
    expect(submitBtn().disabled).toBe(false) // 6 位 + 镜像就绪 ⇒ 解锁
  })

  test('offline 源：包选择器出现、包/落位横幅的畸形数据过滤臂、提交在未选包时不可用', async () => {
    await openWith({
      upgrade: {
        ready: true,
        bundles: { available: ['bad-entry', null, { version: 'v1.2.3', ref: 'fsms-a.zip' }] },
        intake: {
          pending: ['p1.zip', 42],
          rejected: [null, { archive: 'r1.zip', outcome: 'hash_mismatch' }],
        },
      },
    })
    // 切到 offline（el-radio 渲染为原生 radio）
    const radios = [...document.body.querySelectorAll('[data-testid="upgrade-source"] input')]
    expect(radios.length).toBe(2)
    radios[1].click()
    radios[1].dispatchEvent(new window.Event('change', { bubbles: true }))
    await flush(4)
    expect(document.body.querySelector('[data-testid="upgrade-bundle-select"]')).toBeTruthy()
    // intake 横幅臂：pending 过滤掉 42（计数=1）；rejected 过滤掉 null，逐条渲染档名
    //（outcome 走 i18n 映射，不渲染裸码——断言档名与「落位失败」字样即可）
    const bodyText = document.body.textContent
    expect(bodyText).toContain('有 1 个离线包已传完')
    expect(bodyText).toContain('r1.zip')
    expect(bodyText).toContain('落位失败')
    // offline + 未选包 ⇒ canSubmit 假（离线来源看选中的包，在线来源看手输的引用）
    expect(submitBtn().disabled).toBe(true)
  })
})
