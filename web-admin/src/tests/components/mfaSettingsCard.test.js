/**
 * MfaSettingsCard 行为测试（两步验证：状态查询 / 注册 / 启用 / 关闭 / 恢复码 / 复制 / 二维码）
 *
 * 组件定位（MfaSettingsCard.vue:1-4）：ProfileView 安全设置栏里的 MFA 自包含卡片——
 * 状态查询、注册、启用、关闭、恢复码再生成、二维码渲染、复制降级全部内聚于此，
 * 视图层不感知 MFA 细节。本套件锁定的可观测行为与各自对应的真实退化：
 *
 *  1. 状态与视图互斥（MfaSettingsCard.vue:11 / 75）：已开启只给关闭+再生成入口，
 *     未开启才给注册入口。错一边 → 已开启用户找不到关闭入口，或未开启用户误见「已开启」。
 *  2. 验证码本地门禁（:292 / :330 / :379）：/^\d{6}$/ 必须先在本地拦下，
 *     非法码不发请求（后端会拒，但界面先骗人一次）。
 *  3. 恢复码明文只出现一次（:148-178 / :367-376）：必须弹强制保存弹窗，
 *     且 ESC / 遮罩不得一键关闭（否则用户随手一按就永久丢失唯一一份明文）。
 *  4. 复制（:259-289）：安全上下文走 Clipboard API，非安全上下文（局域网 IP 访问 dev）
 *     降级 textarea+execCommand；两条路都失败必须报失败——谎报成功会让用户
 *     以为密钥/恢复码已复制，实际剪贴板里是旧内容。
 *  5. 重入（:233 / :291 / :329 / :378）：按钮有 :disabled 保护，但 Enter 提交路径
 *     没有——在途重复提交会让后端重复生成密钥/恢复码（这两个端点是非幂等的
 *     「重新生成并覆盖」语义），必须本地拦截。
 *
 * 环境事实（本轮探针实测，见交付报告）：
 *  - 对话框 append-to-body → 恢复码相关断言一律查 document，不查挂载根
 *  - 关闭动画走真实计时器（Vue Transition 的 CSS 兜底），style.display 变 'none'
 *    约需 300ms，故对话框可见性用真实计时器轮询，不用 waitFor（它只推 nextTick）
 *  - jsdom 无 navigator.clipboard / document.execCommand（实测 undefined），
 *    两个入口都按用例注入，afterEach 删除注入的属性恢复原状
 *  - QRCode.toCanvas 在 jsdom 下必然失败（无 canvas 实现），故统一 spy 掉；
 *    另有一条不 spy 的用例专门验证「二维码渲染失败不影响手动录入」的兜底
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const getMfaStatus = vi.fn()
const mfaEnroll = vi.fn()
const mfaEnable = vi.fn()
const mfaDisable = vi.fn()
const regenerateRecoveryCodes = vi.fn()

vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      getMfaStatus: (...a) => getMfaStatus(...a),
      mfaEnroll: (...a) => mfaEnroll(...a),
      mfaEnable: (...a) => mfaEnable(...a),
      mfaDisable: (...a) => mfaDisable(...a),
      regenerateRecoveryCodes: (...a) => regenerateRecoveryCodes(...a),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}))
vi.mock('element-plus/es/components/message-box/index.mjs', () => ({
  ElMessageBox: { confirm: vi.fn() },
}))

import MfaSettingsCard from '@/components/MfaSettingsCard.vue'
import QRCode from 'qrcode'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import i18n from '@/i18n'

/** 后端 /auth/mfa/enroll 的真实返回形状（mfaController.js:153-158） */
const SECRET = 'JBSWY3DPEHPK3PXP'
const URI = 'otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=xf'
/** 后端 /auth/mfa/enable 与 /auth/mfa/recovery-codes 都生成 10 个（mfaController.js:189 / :78） */
const CODES10 = Array.from({ length: 10 }, (_, i) => `CODE-${i + 1}`)
const NEW_CODES = ['NEW1-AAAA', 'NEW2-BBBB', 'NEW3-CCCC']

const BTN = {
  start: '开启两步验证',
  enable: '确认开启',
  disable: '关闭两步验证',
  regen: '重新生成恢复码',
}

const statusOn = (remaining) => ({
  data: { success: true, data: { enabled: true, recoveryCodesRemaining: remaining } },
})
const statusOff = () => ({
  data: { success: true, data: { enabled: false, recoveryCodesRemaining: 0 } },
})
const enrollOk = () => ({ data: { success: true, data: { secret: SECRET, otpauthUri: URI } } })

let active = null
let toCanvas = null

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const findButton = (c, text) => {
  const btn = c.findAll('button').find((b) => b.textContent.trim() === text)
  expect(btn, `按钮「${text}」应存在`).toBeTruthy()
  return btn
}
const findButtonText = (c, text) => c.findAll('button').find((b) => b.textContent.trim() === text)

const setInput = async (input, value) => {
  input.value = value
  input.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(3)
}

const pressEnter = (el, init = {}) =>
  el.dispatchEvent(
    new window.KeyboardEvent('keydown', {
      key: 'Enter',
      code: 'Enter',
      bubbles: true,
      cancelable: true,
      ...init,
    })
  )

/** 恢复码对话框在 body 上（append-to-body），须查 document */
const overlayEl = () => document.querySelector('.el-overlay')
const dialogVisible = () => {
  const el = overlayEl()
  return !!el && el.style.display !== 'none'
}
const dialogCodes = () =>
  Array.from(document.querySelectorAll('.recovery-code')).map((e) => e.textContent)
const dialogFooterButtons = () => Array.from(document.querySelectorAll('.el-dialog__footer button'))

/** 真实计时器轮询：关闭动画由 CSS 兜底驱动，nextTick 推不动 */
const waitForDialog = async (want, message) => {
  const deadline = Date.now() + 2500
  while (Date.now() < deadline) {
    if (dialogVisible() === want) return
    await sleep(25)
  }
  throw new Error(`等待对话框${want ? '打开' : '关闭'}超时：${message}`)
}

/** 挂载并等首次状态查询落定 */
const open = async (status = statusOff()) => {
  getMfaStatus.mockResolvedValue(status)
  // 同一用例内会多次挂载（对比余量 3/4/0、对比未开启/已开启两种视图），
  // 因此按「本次新增的调用」等待，而不是累计次数 === 1
  const before = getMfaStatus.mock.calls.length
  active = mountComponent(MfaSettingsCard, {})
  await waitFor(() => getMfaStatus.mock.calls.length > before, { message: '挂载时状态查询' })
  await flush(4)
  return active
}

/** 从未开启视图推进到「密钥已生成」视图 */
const enroll = async (c) => {
  mfaEnroll.mockResolvedValue(enrollOk())
  click(findButton(c, BTN.start))
  await waitFor(() => c.find('.mfa-secret') !== null, { message: '密钥视图渲染' })
  await flush(2)
}

/** 从「密钥已生成」视图推进到已开启视图（经确认码校验 + 恢复码弹窗落定） */
const enableToOnView = async (c, codes = CODES10) => {
  mfaEnable.mockResolvedValue({ data: { success: true, data: { recoveryCodes: codes } } })
  await setInput(c.find('input'), '123456')
  click(findButton(c, BTN.enable))
  await waitFor(() => findButtonText(c, BTN.disable) !== undefined, { message: '已开启视图' })
  await flush(3)
}

beforeEach(() => {
  toCanvas = vi.spyOn(QRCode, 'toCanvas').mockResolvedValue(undefined)
})

afterEach(() => {
  active?.handle.unmount()
  active = null
  toCanvas?.mockRestore()
  toCanvas = null
  getMfaStatus.mockReset()
  mfaEnroll.mockReset()
  mfaEnable.mockReset()
  mfaDisable.mockReset()
  regenerateRecoveryCodes.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  ElMessage.info.mockReset()
  ElMessageBox.confirm.mockReset()
  delete window.navigator.clipboard
  delete window.isSecureContext
  delete document.execCommand
  i18n.global.locale.value = 'zh-CN'
})

describe('MfaSettingsCard 状态查询与视图互斥', () => {
  test('未开启：挂载即查询状态，展示引导与开启按钮，绝不出现关闭/再生成入口', async () => {
    const c = await open(statusOff())
    expect(getMfaStatus).toHaveBeenCalledTimes(1)
    expect(c.find('.card-header').textContent.trim()).toBe('两步验证（MFA）')
    expect(c.find('.el-alert--info')).not.toBe(null)
    expect(c.text()).toContain('开启两步验证')
    // 互斥：未开启视图不得出现任何「已开启」相关入口
    expect(findButtonText(c, BTN.disable)).toBeUndefined()
    expect(findButtonText(c, BTN.regen)).toBeUndefined()
    expect(c.find('.el-alert--success')).toBe(null)
    expect(c.errors).toEqual([])
  })

  test('已开启：展示成功态与关闭/再生成入口，且不再出现开启按钮', async () => {
    const c = await open(statusOn(10))
    expect(c.find('.el-alert--success').textContent).toContain('已开启')
    expect(findButton(c, BTN.disable)).toBeTruthy()
    expect(findButton(c, BTN.regen)).toBeTruthy()
    expect(findButtonText(c, BTN.start)).toBeUndefined()
    expect(c.find('.mfa-secret')).toBe(null)
    expect(c.errors).toEqual([])
  })

  test('状态查询失败：按未开启降级展示，不崩、不抛 Vue 错误', async () => {
    getMfaStatus.mockRejectedValue(new Error('network'))
    active = mountComponent(MfaSettingsCard, {})
    await waitFor(() => getMfaStatus.mock.calls.length === 1, { message: '状态查询发出' })
    await flush(6)
    const c = active
    expect(findButton(c, BTN.start)).toBeTruthy()
    expect(findButtonText(c, BTN.disable)).toBeUndefined()
    expect(c.errors).toEqual([])
  })

  test('恢复码余量低（<=3）才提示：3 提示、4 不提示，且数量取后端值', async () => {
    const low = await open(statusOn(3))
    const lowAlerts = low.findAll('.el-alert--warning')
    expect(lowAlerts).toHaveLength(1)
    expect(lowAlerts[0].textContent.trim()).toBe('备用恢复码仅剩 3 个，建议重新生成')
    low.handle.unmount()
    active = null

    const four = await open(statusOn(4))
    expect(four.findAll('.el-alert--warning')).toHaveLength(0)
    four.handle.unmount()
    active = null

    const zero = await open(statusOn(0))
    const zeroAlerts = zero.findAll('.el-alert--warning')
    expect(zeroAlerts).toHaveLength(1)
    expect(zeroAlerts[0].textContent.trim()).toBe('备用恢复码仅剩 0 个，建议重新生成')
  })

  test('余量字段缺失（null）时不渲染低余量提醒（不得把 null 当成 0）', async () => {
    const c = await open({
      data: { success: true, data: { enabled: true, recoveryCodesRemaining: null } },
    })
    expect(c.findAll('.el-alert--warning')).toHaveLength(0)
    expect(c.text()).not.toContain('仅剩')
  })
})

describe('MfaSettingsCard 注册与二维码', () => {
  test('点击开启：发出注册请求并把 secret/otpauthUri 如实展示（密钥与 URI 可复制）', async () => {
    const c = await open(statusOff())
    await enroll(c)
    expect(mfaEnroll).toHaveBeenCalledTimes(1)
    expect(c.find('.mfa-secret').textContent.trim()).toBe(SECRET)
    const uri = c.find('.mfa-uri')
    expect(uri.textContent.trim()).toBe(URI)
    // title 属性供长 URI 截断后悬停查看（CSS 截断不影响可读性）
    expect(uri.getAttribute('title')).toBe(URI)
    // 复制按钮：密钥一个、URI 一个
    expect(c.findAll('.mfa-copy-btn')).toHaveLength(2)
    expect(c.find('canvas.mfa-qrcode')).not.toBe(null)
    expect(ElMessage.info.mock.calls[0][0]).toBe('密钥已生成，请在认证器中添加后输入验证码确认')
    expect(c.errors).toEqual([])
  })

  test('注册成功即渲染二维码：toCanvas 收到画布、URI 与深色前景配置（宽度 200/margin 1）', async () => {
    const c = await open(statusOff())
    await enroll(c)
    await waitFor(() => toCanvas.mock.calls.length === 1, { message: '二维码渲染调用' })
    const [canvasArg, textArg, opts] = toCanvas.mock.calls[0]
    expect(canvasArg).toBe(c.find('canvas.mfa-qrcode'))
    expect(textArg).toBe(URI)
    expect(opts.width).toBe(200)
    expect(opts.margin).toBe(1)
    // 深色前景必须显式给出：默认黑色在深色主题下与卡片背景对比不足
    expect(opts.color.dark).toBe('#1a1a2e')
    expect(opts.color.light).toBe('#ffffff')
  })

  test('注册响应缺 secret（success 但无密钥）：不得进入密钥视图、不得误报已生成', async () => {
    const c = await open(statusOff())
    mfaEnroll.mockResolvedValue({ data: { success: true, data: {} } })
    click(findButton(c, BTN.start))
    await flush(10)
    expect(mfaEnroll).toHaveBeenCalledTimes(1)
    expect(c.find('.mfa-secret')).toBe(null)
    expect(findButton(c, BTN.start)).toBeTruthy()
    expect(ElMessage.info).not.toHaveBeenCalled()
  })

  test('注册响应 success=false（异常包络）：不得进入密钥视图、不得误报已生成', async () => {
    const c = await open(statusOff())
    mfaEnroll.mockResolvedValue({
      data: { success: false, data: { secret: SECRET, otpauthUri: URI } },
    })
    click(findButton(c, BTN.start))
    await waitFor(() => mfaEnroll.mock.calls.length === 1, { message: '注册请求发出' })
    await flush(10)
    // 只看 data.secret 不看 success 会把「失败的注册」当成成功：用户拿到一个
    // 服务端并未落库的种子，扫码添加后永远验不过，且界面已提示「密钥已生成」
    expect(c.find('.mfa-secret')).toBe(null)
    expect(findButton(c, BTN.start)).toBeTruthy()
    expect(ElMessage.info).not.toHaveBeenCalled()
    expect(c.errors).toEqual([])
  })

  test('二维码渲染失败（jsdom 无 canvas 实现）：密钥与 URI 仍可读，不抛 Vue 错误', async () => {
    // 本用例不 spy：走真实 QRCode.toCanvas，jsdom 下必然抛错，验证兜底分支
    toCanvas.mockRestore()
    const c = await open(statusOff())
    await enroll(c)
    await sleep(50)
    await flush(6)
    expect(c.find('.mfa-secret').textContent.trim()).toBe(SECRET)
    expect(c.find('.mfa-uri').textContent.trim()).toBe(URI)
    expect(c.errors).toEqual([])
  })
})

describe('MfaSettingsCard 启用流程与恢复码', () => {
  test('确认开启：提交裁剪后的 6 位码，成功后切已开启视图、清空密钥与确认码', async () => {
    const c = await open(statusOff())
    await enroll(c)
    mfaEnable.mockResolvedValue({ data: { success: true, data: { recoveryCodes: CODES10 } } })
    const input = c.find('input')
    await setInput(input, '  123456  ')
    click(findButton(c, BTN.enable))
    await waitFor(() => mfaEnable.mock.calls.length === 1, { message: '启用请求发出' })
    expect(mfaEnable.mock.calls[0][0]).toEqual({ mfaCode: '123456' })
    await waitFor(() => findButtonText(c, BTN.disable) !== undefined, { message: '切到已开启视图' })
    // 密钥/URI/确认码必须清空：留在 DOM 里等于把 TOTP 种子明文长期摆在页面上
    expect(c.find('.mfa-secret')).toBe(null)
    expect(c.find('.mfa-uri')).toBe(null)
    expect(c.text()).not.toContain(SECRET)
    expect(ElMessage.success.mock.calls[0][0]).toBe('两步验证已开启')
    expect(c.errors).toEqual([])
  })

  test('开启成功带恢复码：弹出强制保存弹窗，10 个码逐个渲染且余量同步', async () => {
    const c = await open(statusOff())
    await enroll(c)
    await enableToOnView(c)
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    expect(dialogCodes()).toEqual(CODES10)
    expect(document.querySelector('.el-dialog__title').textContent.trim()).toBe('备用恢复码')
    expect(document.querySelector('.el-dialog__body').textContent).toContain('请立即保存！')
    // 已开启视图的低余量提醒不得因刚生成 10 个码而出现
    expect(c.findAll('.el-alert--warning')).toHaveLength(0)
    expect(c.errors).toEqual([])
  })

  test('开启成功但响应无恢复码：警告且余量归零，绝不弹空弹窗', async () => {
    const c = await open(statusOff())
    await enroll(c)
    await enableToOnView(c, [])
    await flush(10)
    expect(dialogVisible()).toBe(false)
    expect(ElMessage.warning.mock.calls.map((a) => a[0])).toEqual([
      '开启成功但未返回备用恢复码，可用数量已归零，请重新生成',
    ])
    // 余量归零 → 低余量提醒必须出现（这正是「请重新生成」的落地入口）
    expect(c.findAll('.el-alert--warning')).toHaveLength(1)
    expect(c.findAll('.el-alert--warning')[0].textContent).toContain('仅剩 0 个')
    expect(ElMessage.success.mock.calls[0][0]).toBe('两步验证已开启')
  })

  test('确认码非法（5 位/含字母/空）：本地警告且不发请求（三种入口同一判据）', async () => {
    const c = await open(statusOff())
    await enroll(c)
    const input = c.find('input')
    for (const bad of ['12345', '12345a', '', '  ']) {
      await setInput(input, bad)
      click(findButton(c, BTN.enable))
      await flush(4)
    }
    expect(mfaEnable).not.toHaveBeenCalled()
    expect(ElMessage.warning.mock.calls.map((a) => a[0])).toEqual(
      Array(4).fill('请输入 6 位数字验证码')
    )
    // 视图未切换：仍在密钥步骤，用户可继续改输入
    expect(findButtonText(c, BTN.start)).toBeUndefined()
    expect(c.find('.mfa-secret')).not.toBe(null)
  })

  test('确认码校验失败（后端 400）：停留原视图、清 busy、不弹恢复码、不谎报成功', async () => {
    const c = await open(statusOff())
    await enroll(c)
    mfaEnable.mockRejectedValue(new Error('bad code'))
    await setInput(c.find('input'), '000000')
    click(findButton(c, BTN.enable))
    await waitFor(() => mfaEnable.mock.calls.length === 1, { message: '启用请求发出' })
    await flush(10)
    expect(dialogVisible()).toBe(false)
    expect(findButtonText(c, BTN.disable)).toBeUndefined()
    expect(c.find('.mfa-secret')).not.toBe(null)
    expect(ElMessage.success).not.toHaveBeenCalled()
    // busy 必须复位：否则用户改完码再也点不动按钮
    expect(findButton(c, BTN.enable).disabled).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('Enter 提交开启（enterSubmit 契约）：组词中的 Enter 不提交，普通 Enter 提交', async () => {
    const c = await open(statusOff())
    await enroll(c)
    mfaEnable.mockResolvedValue({ data: { success: true, data: { recoveryCodes: CODES10 } } })
    const input = c.find('input')
    await setInput(input, '123456')
    // 输入法组词确认（isComposing）：不得当作提交
    pressEnter(input, { isComposing: true })
    await flush(4)
    expect(mfaEnable).not.toHaveBeenCalled()
    pressEnter(input)
    await waitFor(() => mfaEnable.mock.calls.length === 1, { message: '普通 Enter 提交' })
    expect(mfaEnable.mock.calls[0][0]).toEqual({ mfaCode: '123456' })
  })

  test('已开启 + Enter 提交关闭：提交裁剪后的码并切回未开启视图', async () => {
    const c = await open(statusOn(10))
    mfaDisable.mockResolvedValue({ data: { success: true } })
    const disableInput = c.findAll('input')[0]
    await setInput(disableInput, ' 654321 ')
    pressEnter(disableInput)
    await waitFor(() => mfaDisable.mock.calls.length === 1, { message: '关闭请求发出' })
    expect(mfaDisable.mock.calls[0][0]).toEqual({ mfaCode: '654321' })
    await waitFor(() => findButtonText(c, BTN.start) !== undefined, { message: '切回未开启视图' })
    expect(ElMessage.success.mock.calls[0][0]).toBe('两步验证已关闭')
    expect(findButtonText(c, BTN.disable)).toBeUndefined()
    expect(c.errors).toEqual([])
  })

  test('完整生命周期 enroll→enable→disable：关闭后必须回到「未开始」视图，不得残留失效密钥/二维码', async () => {
    const c = await open(statusOff())
    await enroll(c)
    expect(c.find('.mfa-secret').textContent.trim()).toBe(SECRET)
    await enableToOnView(c)
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    dialogFooterButtons()[1].dispatchEvent(
      new window.MouseEvent('click', { bubbles: true, cancelable: true })
    )
    await waitForDialog(false, '保存后关闭弹窗')

    mfaDisable.mockResolvedValue({ data: { success: true } })
    const disableInput = c.findAll('input')[0]
    await setInput(disableInput, '654321')
    click(findButton(c, BTN.disable))
    await waitFor(() => findButtonText(c, BTN.start) !== undefined, { message: '切回未开启视图' })

    // 关闭时服务端已清空 mfaSecret 与恢复码（mfaController.js:293-301），
    // 若前端不清 mfa.secret，未开启分支会落到 v-else（密钥视图）：
    // 用户看到的是一个已被服务端作废的密钥 + 一张永远验不过的二维码，
    // 且「开启两步验证」按钮消失——想重新开启只能刷新整页。
    expect(c.find('.mfa-secret')).toBe(null)
    expect(c.find('.mfa-uri')).toBe(null)
    expect(c.find('canvas.mfa-qrcode')).toBe(null)
    expect(c.text()).not.toContain(SECRET)
    expect(findButton(c, BTN.start)).toBeTruthy()
    expect(c.errors).toEqual([])
  })

  test('关闭码非法（5 位/含字母）：本地警告且不发请求', async () => {
    const c = await open(statusOn(10))
    const disableInput = c.findAll('input')[0]
    for (const bad of ['12345', '12345a']) {
      await setInput(disableInput, bad)
      click(findButton(c, BTN.disable))
      await flush(4)
    }
    expect(mfaDisable).not.toHaveBeenCalled()
    expect(ElMessage.warning.mock.calls.map((a) => a[0])).toEqual([
      '请输入 6 位数字验证码',
      '请输入 6 位数字验证码',
    ])
    expect(findButton(c, BTN.disable)).toBeTruthy()
  })

  test('关闭成功后重进已开启视图：关闭码输入框必须为空（已消费的码不得残留复用）', async () => {
    const c = await open(statusOn(10))
    mfaDisable.mockResolvedValue({ data: { success: true } })
    const disableInput = c.findAll('input')[0]
    await setInput(disableInput, '654321')
    click(findButton(c, BTN.disable))
    await waitFor(() => findButtonText(c, BTN.start) !== undefined, { message: '切回未开启视图' })
    // 未开启视图没有任何验证码输入框（v-if/v-else 整体切换，旧节点已脱离文档）
    expect(c.findAll('input')).toHaveLength(0)
    // 重新开启到已开启视图：新渲染的关闭码输入框不得带着上一次用过的码
    await enroll(c)
    await enableToOnView(c, NEW_CODES)
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    dialogFooterButtons()[1].dispatchEvent(
      new window.MouseEvent('click', { bubbles: true, cancelable: true })
    )
    await waitForDialog(false, '保存后关闭弹窗')
    const fresh = c.findAll('input')[0]
    expect(fresh).toBeTruthy()
    expect(fresh.value).toBe('')
  })

  test('关闭失败：停留已开启视图、不谎报成功、输入保留便于重试', async () => {
    const c = await open(statusOn(10))
    mfaDisable.mockRejectedValue(new Error('wrong code'))
    const disableInput = c.findAll('input')[0]
    await setInput(disableInput, '999999')
    click(findButton(c, BTN.disable))
    await waitFor(() => mfaDisable.mock.calls.length === 1, { message: '关闭请求发出' })
    await flush(10)
    expect(findButton(c, BTN.disable)).toBeTruthy()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(disableInput.value).toBe('999999')
    expect(findButton(c, BTN.disable).disabled).toBe(false)
    expect(c.errors).toEqual([])
  })
})

describe('MfaSettingsCard 恢复码再生成', () => {
  test('再生成成功：弹窗展示新码、清空再生成输入、余量同步为新码数量', async () => {
    const c = await open(statusOn(10))
    regenerateRecoveryCodes.mockResolvedValue({
      data: { success: true, data: { recoveryCodes: NEW_CODES } },
    })
    const regenInput = c.findAll('input')[1]
    await setInput(regenInput, '112233')
    click(findButton(c, BTN.regen))
    await waitFor(() => regenerateRecoveryCodes.mock.calls.length === 1, {
      message: '再生成请求发出',
    })
    expect(regenerateRecoveryCodes.mock.calls[0][0]).toEqual({ mfaCode: '112233' })
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    expect(dialogCodes()).toEqual(NEW_CODES)
    expect(regenInput.value).toBe('')
    expect(ElMessage.success.mock.calls[0][0]).toBe('已生成新恢复码，旧码全部作废')
    // 3 个新码 <= 3 → 关闭弹窗后必须出现低余量提醒（余量真的同步了）
    dialogFooterButtons()[1].dispatchEvent(
      new window.MouseEvent('click', { bubbles: true, cancelable: true })
    )
    await waitForDialog(false, '点击我已保存')
    expect(c.findAll('.el-alert--warning')).toHaveLength(1)
    expect(c.findAll('.el-alert--warning')[0].textContent).toContain('仅剩 3 个')
    expect(c.errors).toEqual([])
  })

  test('再生成响应无恢复码：报错且不弹窗、不覆盖旧码展示状态、输入保留', async () => {
    const c = await open(statusOn(10))
    regenerateRecoveryCodes.mockResolvedValue({ data: { success: true, data: {} } })
    const regenInput = c.findAll('input')[1]
    await setInput(regenInput, '112233')
    click(findButton(c, BTN.regen))
    await waitFor(() => regenerateRecoveryCodes.mock.calls.length === 1, {
      message: '再生成请求发出',
    })
    await flush(10)
    expect(ElMessage.error.mock.calls.map((a) => a[0])).toEqual(['未获取到新的恢复码，请稍后重试'])
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(dialogVisible()).toBe(false)
    expect(regenInput.value).toBe('112233')
    expect(findButton(c, BTN.regen).disabled).toBe(false)
    expect(c.errors).toEqual([])
  })

  test('再生成码非法：本地警告且不发请求（含全角数字，不得被当成合法 6 位码）', async () => {
    const c = await open(statusOn(10))
    const regenInput = c.findAll('input')[1]
    for (const bad of ['12345', 'abcdef', '１２３４５６']) {
      await setInput(regenInput, bad)
      pressEnter(regenInput)
      await flush(4)
    }
    expect(regenerateRecoveryCodes).not.toHaveBeenCalled()
    expect(ElMessage.warning.mock.calls).toHaveLength(3)
    expect(ElMessage.warning.mock.calls.every((a) => a[0] === '请输入 6 位数字验证码')).toBe(true)
  })

  test('再生成失败（后端拒绝）：不弹窗、不谎报成功、busy 复位', async () => {
    const c = await open(statusOn(10))
    regenerateRecoveryCodes.mockRejectedValue(new Error('bad code'))
    const regenInput = c.findAll('input')[1]
    await setInput(regenInput, '000000')
    click(findButton(c, BTN.regen))
    await waitFor(() => regenerateRecoveryCodes.mock.calls.length === 1, {
      message: '再生成请求发出',
    })
    await flush(10)
    expect(dialogVisible()).toBe(false)
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(findButton(c, BTN.regen).disabled).toBe(false)
    expect(c.errors).toEqual([])
  })
})

describe('MfaSettingsCard 恢复码对话框防误关', () => {
  const openDialog = async () => {
    const c = await open(statusOff())
    await enroll(c)
    await enableToOnView(c)
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    return c
  }

  test('ESC 关闭必须二次确认：取消则弹窗保持打开、码仍在（不丢唯一一份明文）', async () => {
    await openDialog()
    ElMessageBox.confirm.mockRejectedValue(new Error('cancel'))
    document.dispatchEvent(
      new window.KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true })
    )
    await flush(10)
    expect(ElMessageBox.confirm).toHaveBeenCalledTimes(1)
    expect(ElMessageBox.confirm.mock.calls[0][0]).toBe('恢复码仅展示这一次，确定不保存就关闭吗？')
    expect(ElMessageBox.confirm.mock.calls[0][1]).toBe('提示')
    expect(ElMessageBox.confirm.mock.calls[0][2]).toEqual({ type: 'warning' })
    expect(dialogVisible()).toBe(true)
    expect(dialogCodes()).toEqual(CODES10)
  })

  test('ESC 二次确认通过：弹窗真正关闭（确认路径可用，不是永远关不掉）', async () => {
    await openDialog()
    ElMessageBox.confirm.mockResolvedValue('confirm')
    document.dispatchEvent(
      new window.KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true })
    )
    await waitForDialog(false, '确认后关闭')
    expect(ElMessageBox.confirm).toHaveBeenCalledTimes(1)
  })

  test('点击遮罩不关闭弹窗（close-on-click-modal=false），且不触发关闭确认', async () => {
    await openDialog()
    // 遮罩点击的真实判据：Element Plus 把 mousedown/mouseup/click 三元组挂在
    // .el-overlay-dialog 上（use-same-target），三个事件 target 都等于 currentTarget
    // 才算「点了遮罩」。在 .el-overlay 上派发不会命中任何处理函数（实测恒真）。
    const mask = document.querySelector('.el-overlay-dialog')
    expect(mask).not.toBe(null)
    for (const type of ['mousedown', 'mouseup', 'click']) {
      mask.dispatchEvent(new window.MouseEvent(type, { bubbles: true, cancelable: true }))
    }
    await flush(10)
    expect(ElMessageBox.confirm).not.toHaveBeenCalled()
    expect(dialogVisible()).toBe(true)
    expect(dialogCodes()).toEqual(CODES10)
  })

  test('弹窗不提供右上角关闭按钮（show-close=false）：唯一出口是显式「我已保存」', async () => {
    await openDialog()
    expect(document.querySelectorAll('.el-dialog__headerbtn')).toHaveLength(0)
  })

  test('点击「我已保存」直接关闭（不再二次确认），关闭后恢复码对用户不可见', async () => {
    await openDialog()
    const buttons = dialogFooterButtons()
    expect(buttons.map((b) => b.textContent.trim())).toEqual(['复制', '我已保存'])
    buttons[1].dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }))
    await waitForDialog(false, '点击我已保存')
    expect(ElMessageBox.confirm).not.toHaveBeenCalled()
    // 注意：Element Plus 关闭是 v-show 隐藏（overlay display:none），DOM 里的
    // .recovery-code 明文仍在（见报告「未修复观察项」，与内存中 mfa.recoveryCodes
    // 的生命周期一致，未按缺陷处理）。这里断言的是用户可见性这一真实契约。
    expect(overlayEl().style.display).toBe('none')
    expect(window.getComputedStyle(overlayEl()).display).toBe('none')
  })

  test('弹窗打开期间组件卸载：DOM 中不留任何恢复码明文（append-to-body 也不得泄漏）', async () => {
    const c = await openDialog()
    expect(dialogCodes()).toEqual(CODES10)
    c.handle.unmount()
    active = null
    await flush(6)
    expect(dialogCodes()).toEqual([])
    expect(document.querySelectorAll('.el-overlay')).toHaveLength(0)
  })
})

describe('MfaSettingsCard 复制（Clipboard API / 降级 / 失败如实上报）', () => {
  const stubClipboard = (writeText) => {
    Object.defineProperty(window.navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true })
  }

  test('安全上下文：密钥与 URI 各写各的文本到 Clipboard API，不建 textarea', async () => {
    const writeText = vi.fn(async () => {})
    stubClipboard(writeText)
    const c = await open(statusOff())
    await enroll(c)
    const copyBtns = c.findAll('.mfa-copy-btn')
    click(copyBtns[0])
    await waitFor(() => writeText.mock.calls.length === 1, { message: '密钥写入剪贴板' })
    expect(writeText.mock.calls[0][0]).toBe(SECRET)
    click(copyBtns[1])
    await waitFor(() => writeText.mock.calls.length === 2, { message: 'URI 写入剪贴板' })
    expect(writeText.mock.calls[1][0]).toBe(URI)
    // 两条路径都不得把内容经 textarea 落进 DOM（非降级路径）
    expect(document.querySelectorAll('textarea')).toHaveLength(0)
    expect(ElMessage.success.mock.calls.map((a) => a[0])).toEqual([
      '已复制到剪贴板',
      '已复制到剪贴板',
    ])
    expect(ElMessage.warning).not.toHaveBeenCalled()
  })

  test('非安全上下文但 clipboard 存在（局域网 IP 访问 dev）：必须降级，不得调用 clipboard', async () => {
    // 真实场景：http://192.168.x.x 下 navigator.clipboard 可能存在于原型上，
    // 但非 secure context 调用会抛 NotAllowedError。实现以 isSecureContext 判据
    // 提前分流，避免先抛一次错再降级（也会让 ElMessage 顺序与预期不符）。
    const writeText = vi.fn(async () => {})
    Object.defineProperty(window.navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true })
    const exec = vi.fn(() => true)
    document.execCommand = exec
    const c = await open(statusOff())
    await enroll(c)
    click(c.findAll('.mfa-copy-btn')[0])
    await waitFor(() => exec.mock.calls.length === 1, { message: '非安全上下文降级到 execCommand' })
    expect(writeText).not.toHaveBeenCalled()
    expect(ElMessage.success.mock.calls.map((a) => a[0])).toEqual(['已复制到剪贴板'])
  })

  test('非安全上下文（无 clipboard）：降级 textarea + execCommand，成功后移除临时节点', async () => {
    // jsdom 默认即此状态：navigator.clipboard 与 execCommand 都不存在
    const c = await open(statusOff())
    await enroll(c)
    const exec = vi.fn(() => true)
    document.execCommand = exec
    click(c.findAll('.mfa-copy-btn')[0])
    await waitFor(() => exec.mock.calls.length === 1, { message: 'execCommand 降级' })
    expect(exec.mock.calls[0][0]).toBe('copy')
    expect(ElMessage.success.mock.calls.map((a) => a[0])).toEqual(['已复制到剪贴板'])
    // 临时 textarea 必须清理（否则每次复制泄漏一个节点）
    expect(document.querySelectorAll('textarea')).toHaveLength(0)
  })

  test('降级路径写入的是真实文本：execCommand 执行时 textarea 的 value 等于密钥', async () => {
    const c = await open(statusOff())
    await enroll(c)
    let seen = null
    document.execCommand = vi.fn(() => {
      seen = document.querySelector('textarea')?.value ?? null
      return true
    })
    click(c.findAll('.mfa-copy-btn')[0])
    await waitFor(() => seen !== null, { message: 'execCommand 降级' })
    expect(seen).toBe(SECRET)
  })

  test('Clipboard API 抛错（权限被拒）：降级到 execCommand 并如实报成功', async () => {
    const writeText = vi.fn(async () => {
      throw new Error('NotAllowedError')
    })
    stubClipboard(writeText)
    const exec = vi.fn(() => true)
    document.execCommand = exec
    const c = await open(statusOff())
    await enroll(c)
    click(c.findAll('.mfa-copy-btn')[0])
    await waitFor(() => exec.mock.calls.length === 1, { message: 'Clipboard 失败后降级' })
    expect(writeText).toHaveBeenCalledTimes(1)
    expect(ElMessage.success.mock.calls.map((a) => a[0])).toEqual(['已复制到剪贴板'])
  })

  test('两条路都失败：必须报「复制失败」，绝不谎报成功（剪贴板里可能是旧内容）', async () => {
    document.execCommand = vi.fn(() => false)
    const c = await open(statusOff())
    await enroll(c)
    click(c.findAll('.mfa-copy-btn')[0])
    await waitFor(() => ElMessage.warning.mock.calls.length === 1, { message: '复制失败提示' })
    expect(ElMessage.warning.mock.calls[0][0]).toBe('复制失败，请手动选择文本复制')
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(document.querySelectorAll('textarea')).toHaveLength(0)
  })

  test('execCommand 直接抛错：同样报失败（try/catch 不得吞成成功）', async () => {
    document.execCommand = vi.fn(() => {
      throw new Error('not supported')
    })
    const c = await open(statusOff())
    await enroll(c)
    click(c.findAll('.mfa-copy-btn')[0])
    await waitFor(() => ElMessage.warning.mock.calls.length === 1, { message: '复制失败提示' })
    expect(ElMessage.warning.mock.calls[0][0]).toBe('复制失败，请手动选择文本复制')
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(document.querySelectorAll('textarea')).toHaveLength(0)
  })

  test('URI 缺失（后端未返回 otpauthUri）：复制按钮点下去必须无任何反馈，不得谎报已复制', async () => {
    const c = await open(statusOff())
    mfaEnroll.mockResolvedValue({ data: { success: true, data: { secret: SECRET } } })
    click(findButton(c, BTN.start))
    await waitFor(() => c.find('.mfa-secret') !== null, { message: '密钥视图渲染' })
    expect(c.find('.mfa-uri').textContent.trim()).toBe('')
    const writeText = vi.fn(async () => {})
    stubClipboard(writeText)
    click(c.findAll('.mfa-copy-btn')[1])
    await flush(10)
    expect(writeText).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(ElMessage.warning).not.toHaveBeenCalled()
  })

  test('恢复码弹窗「复制」：写入的是换行拼接的全部恢复码（不是单条、不是逗号分隔）', async () => {
    const writeText = vi.fn(async () => {})
    stubClipboard(writeText)
    const c = await open(statusOff())
    await enroll(c)
    await enableToOnView(c)
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    // 开启成功本身会先弹一条 success，先清空才能只断言复制这一条的反馈
    ElMessage.success.mockReset()
    click(dialogFooterButtons()[0])
    await waitFor(() => writeText.mock.calls.length === 1, { message: '恢复码写入剪贴板' })
    expect(writeText.mock.calls[0][0]).toBe(CODES10.join('\n'))
    expect(ElMessage.success.mock.calls.map((a) => a[0])).toEqual(['已复制到剪贴板'])
  })
})

describe('MfaSettingsCard 在途重入保护（Enter 与按钮共用 busy 语义）', () => {
  test('注册在途：重复点击不得发出第二个注册请求（非幂等端点）', async () => {
    const c = await open(statusOff())
    let release
    mfaEnroll.mockImplementation(
      () =>
        new Promise((r) => {
          release = () => r(enrollOk())
        })
    )
    const start = findButton(c, BTN.start)
    // 同一宏任务内连点两次：Vue 的 DOM 更新要到 nextTick 才落盘，
    // 此刻按钮的 disabled 仍是旧值（实测 false），两次 click 都会真实派发
    // ——物理双击的两次事件在事件循环里就是这样排布的，属真实用户可达路径。
    // 拦住它的是 enrollMfa 入口的同步 busy 守卫（MfaSettingsCard.vue:233-239）。
    click(start)
    expect(start.disabled).toBe(false)
    click(start)
    expect(mfaEnroll).toHaveBeenCalledTimes(1)
    await sleep(10)
    // 落到后续宏任务后，按钮已被 :disabled="mfa.busy" 禁用
    expect(start.disabled).toBe(true)
    click(start)
    await sleep(10)
    expect(mfaEnroll).toHaveBeenCalledTimes(1)
    release()
    await waitFor(() => c.find('.mfa-secret') !== null, { message: '密钥视图渲染' })
  })

  test('启用在途：长按 Enter 的自动重复不得重复提交（重复提交会二次生成恢复码）', async () => {
    const c = await open(statusOff())
    await enroll(c)
    let release
    mfaEnable.mockImplementation(
      () =>
        new Promise((r) => {
          release = () => r({ data: { success: true, data: { recoveryCodes: CODES10 } } })
        })
    )
    const input = c.find('input')
    await setInput(input, '123456')
    for (let i = 0; i < 3; i += 1) {
      pressEnter(input)
      await sleep(5)
    }
    expect(mfaEnable).toHaveBeenCalledTimes(1)
    release()
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    expect(dialogCodes()).toEqual(CODES10)
  })

  test('再生成在途：长按 Enter 不得重复提交（避免「服务器存的码」与「界面展示的码」不一致）', async () => {
    const c = await open(statusOn(10))
    const resolvers = []
    let n = 0
    regenerateRecoveryCodes.mockImplementation(() => {
      n += 1
      const tag = `GEN${n}`
      return new Promise((r) => {
        resolvers.push(() =>
          r({ data: { success: true, data: { recoveryCodes: [`${tag}-A`, `${tag}-B`] } } })
        )
      })
    })
    const regenInput = c.findAll('input')[1]
    await setInput(regenInput, '111111')
    for (let i = 0; i < 3; i += 1) {
      pressEnter(regenInput)
      await sleep(5)
    }
    expect(regenerateRecoveryCodes).toHaveBeenCalledTimes(1)
    resolvers[0]()
    await waitFor(() => dialogVisible(), { message: '恢复码弹窗打开' })
    expect(dialogCodes()).toEqual(['GEN1-A', 'GEN1-B'])
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
  })

  test('关闭在途：重复 Enter 不得重复提交（重复关闭会二次校验并重复写审计）', async () => {
    const c = await open(statusOn(10))
    let release
    mfaDisable.mockImplementation(
      () =>
        new Promise((r) => {
          release = () => r({ data: { success: true } })
        })
    )
    const disableInput = c.findAll('input')[0]
    await setInput(disableInput, '654321')
    pressEnter(disableInput)
    await sleep(5)
    pressEnter(disableInput)
    await sleep(5)
    expect(mfaDisable).toHaveBeenCalledTimes(1)
    release()
    await waitFor(() => findButtonText(c, BTN.start) !== undefined, { message: '切回未开启视图' })
  })

  test('首个请求返回后 busy 释放：用户可再次提交（拦截不是永久锁死）', async () => {
    const c = await open(statusOn(10))
    mfaDisable.mockRejectedValueOnce(new Error('bad code'))
    mfaDisable.mockResolvedValueOnce({ data: { success: true } })
    const disableInput = c.findAll('input')[0]
    await setInput(disableInput, '000000')
    pressEnter(disableInput)
    await waitFor(() => mfaDisable.mock.calls.length === 1, { message: '首次关闭请求' })
    await flush(10)
    await setInput(disableInput, '654321')
    pressEnter(disableInput)
    await waitFor(() => mfaDisable.mock.calls.length === 2, { message: '重试关闭请求' })
    await waitFor(() => findButtonText(c, BTN.start) !== undefined, {
      message: '重试后切回未开启视图',
    })
  })
})

describe('MfaSettingsCard 文案与结构不变量', () => {
  test('英文界面：标题/按钮/占位符/弹窗文案全部走英文词表，不残留中文', async () => {
    const c = await open(statusOn(2))
    i18n.global.locale.value = 'en-US'
    await flush(6)
    expect(c.find('.card-header').textContent.trim()).toBe('Two-Factor Authentication (MFA)')
    expect(findButton(c, 'Disable Two-Factor Authentication')).toBeTruthy()
    expect(findButton(c, 'Regenerate Codes')).toBeTruthy()
    expect(c.findAll('input')[0].placeholder).toBe('Enter a code to disable')
    expect(c.findAll('input')[1].placeholder).toBe('Enter current 6-digit code')
    const low = c.find('.el-alert--warning')
    expect(low.textContent.trim()).toBe('Only 2 recovery codes left — consider regenerating')
    expect(c.text()).not.toContain('两步验证')
    expect(c.errors).toEqual([])
  })

  test('三个验证码输入框都是 6 位数字键盘语义（maxlength=6 / inputmode=numeric）', async () => {
    const off = await open(statusOff())
    await enroll(off)
    const confirmInput = off.find('input')
    expect(confirmInput.getAttribute('maxlength')).toBe('6')
    expect(confirmInput.getAttribute('inputmode')).toBe('numeric')
    expect(confirmInput.placeholder).toBe('输入 6 位验证码确认')
    off.handle.unmount()
    active = null

    const on = await open(statusOn(10))
    const inputs = on.findAll('input')
    expect(inputs).toHaveLength(2)
    for (const input of inputs) {
      expect(input.getAttribute('maxlength')).toBe('6')
      expect(input.getAttribute('inputmode')).toBe('numeric')
    }
    expect(inputs[0].placeholder).toBe('输入动态验证码以关闭')
    expect(inputs[1].placeholder).toBe('输入当前动态口令')
  })

  test('三处 Enter 提交都 preventDefault（防止单输入框表单触发原生提交导致整页刷新）', async () => {
    const keydown = (el) => {
      const ev = new window.KeyboardEvent('keydown', {
        key: 'Enter',
        code: 'Enter',
        bubbles: true,
        cancelable: true,
      })
      el.dispatchEvent(ev)
      return ev
    }
    // 提交函数在途期间视图不切换：用永不 resolve 的 Promise 让输入框保持在文档中，
    // 避免「请求返回 → 视图切换 → 元素卸载 → 监听器被摘掉」把断言变成时序竞态
    const pending = () => new Promise(() => {})

    // 1) 密钥视图的确认码输入框（@keydown.enter.prevent="…enableMfa"）
    const c = await open(statusOff())
    await enroll(c)
    mfaEnable.mockImplementation(pending)
    const confirmInput = c.find('input')
    await setInput(confirmInput, '123456')
    expect(keydown(confirmInput).defaultPrevented).toBe(true)
    await waitFor(() => mfaEnable.mock.calls.length === 1, { message: '启用请求发出' })
    c.handle.unmount()
    active = null

    // 2) 已开启视图的关闭码输入框（独立挂载：上面那个实例的 busy 仍被
    //    永不 resolve 的 Promise 占着，同一实例内后续提交会被重入守卫拦下）
    const on1 = await open(statusOn(10))
    mfaDisable.mockImplementation(pending)
    const disableInput = on1.findAll('input')[0]
    await setInput(disableInput, '654321')
    expect(keydown(disableInput).defaultPrevented).toBe(true)
    await waitFor(() => mfaDisable.mock.calls.length === 1, { message: '关闭请求发出' })
    on1.handle.unmount()
    active = null

    // 3) 已开启视图的再生成码输入框
    const on2 = await open(statusOn(10))
    regenerateRecoveryCodes.mockImplementation(pending)
    const regenInput = on2.findAll('input')[1]
    await setInput(regenInput, '112233')
    expect(keydown(regenInput).defaultPrevented).toBe(true)
    await waitFor(() => regenerateRecoveryCodes.mock.calls.length === 1, {
      message: '再生成请求发出',
    })
  })

  test('三处 el-form 都挂 @submit.prevent：原生 submit 被拦下，不触发整页刷新', async () => {
    const submitOnce = async (c) => {
      const form = c.find('form')
      expect(form, 'el-form 应渲染为原生 form').not.toBe(null)
      const ev = new window.Event('submit', { bubbles: true, cancelable: true })
      form.dispatchEvent(ev)
      await flush(4)
      // preventDefault 生效则 defaultPrevented=true；未拦截时浏览器会导航刷新、
      // 丢失当前输入（单输入框表单里 Enter 触发的隐式提交正是这条路径）
      expect(ev.defaultPrevented).toBe(true)
    }

    // 1) 密钥视图（MfaSettingsCard.vue:93）
    const c = await open(statusOff())
    await enroll(c)
    await submitOnce(c)
    c.handle.unmount()
    active = null

    // 2) 已开启视图的关闭表单（:26）与再生成表单（:50）
    const on = await open(statusOn(10))
    const forms = on.findAll('form')
    expect(forms).toHaveLength(2)
    for (const form of forms) {
      const ev = new window.Event('submit', { bubbles: true, cancelable: true })
      form.dispatchEvent(ev)
      await flush(4)
      expect(ev.defaultPrevented).toBe(true)
    }
    expect(on.errors).toEqual([])
  })

  test('全部按钮都是 type=button（不会在表单内触发原生 submit）', async () => {
    const c = await open(statusOn(10))
    const buttons = c.findAll('button')
    expect(buttons.length).toBeGreaterThanOrEqual(2)
    expect(buttons.map((b) => b.getAttribute('type'))).toEqual(buttons.map(() => 'button'))
    await flush(4)
    expect(c.errors).toEqual([])
  })
})
