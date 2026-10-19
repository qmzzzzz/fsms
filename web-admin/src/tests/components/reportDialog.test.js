/**
 * ReportDialog 行为测试（举报异常对话框）
 *
 * 组件是 POST /api/security/report 的唯一前端入口（顶栏可达，人人可用）。
 * 本套件钉住四类真实退化：
 *
 *  1. system 型不得携带 targetId：后端路由对 system + targetId 直接 400
 *     （否则改一下类型就能绕过「目标必须是数据范围内的真实记录」的核验），
 *     前端在 system 下连输入框都不渲染，提交载荷也不带该键。
 *  2. 记录型 targetId 必须是 24 位 ObjectId 形态（后端 isMongoId 同口径）：
 *     格式前置拦下"注定 400"的请求。
 *  3. 原因必填且按 trim 后判长（后端先 .trim() 再判 1-200；纯空格在
 *     async-validator 的 required 下能过，必须在提交前用同一判据拦住）。
 *  4. 成功/失败语义：成功提示 + 关闭 + 表单清空；失败不误报成功、不重复
 *     弹错（错误归 api.js 拦截器）、对话框保持打开可重试；重入守卫在
 *     同一 tick 双击下只发一个请求。
 *
 * 组件刻意不挂权限码（securityRoutes.js 的 PERMISSION-EXEMPT）：一线人员
 * 必须报得了警，约束由服务端目标核验与账号级限流承担。
 *
 * jsdom 限制如实记录：el-dialog 关闭过渡依赖真实计时器，可见性用轮询
 * visible 状态判定；el-select 下拉 teleport 到 body，用 aria-hidden 挑可见浮层。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const reportApi = vi.fn()
vi.mock('@/utils/api', () => ({
  api: { security: { report: (...a) => reportApi(...a) } },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import ReportDialog from '@/components/ReportDialog.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null
afterEach(() => {
  active?.handle.unmount()
  active = null
  reportApi.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
})

/** 带受控 visible 的宿主：组件自身不持有开关状态，观察「关闭」必须接回本地状态 */
const makeHost = (initialVisible) => {
  const state = reactive({ visible: initialVisible })
  const Host = defineComponent({
    setup() {
      return () =>
        h(ReportDialog, {
          visible: state.visible,
          'onUpdate:visible': (v) => {
            state.visible = v
          },
        })
    },
  })
  active = mountComponent(Host)
  return state
}

const dlg = () => document.body.querySelector('.el-dialog')
const footerBtn = (text) =>
  Array.from(dlg().querySelectorAll('.el-dialog__footer button')).find(
    (b) => b.textContent.trim() === text
  )
const typeInto = async (selector, value) => {
  const el = dlg().querySelector(selector)
  el.value = value
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(4)
  return el
}
/** 打开对话框并等首帧渲染完成 */
const openDialog = async () => {
  const state = makeHost(true)
  await waitFor(() => dlg(), { message: '对话框渲染' })
  await flush(6)
  return state
}

/** 真实计时器轮询（Element Plus 校验链跨宏任务，waitFor 只推 nextTick 推不动） */
const waitReal = async (predicate, message, timeoutMs = 3000) => {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return
    await new Promise((r) => setTimeout(r, 10))
    await flush(2)
  }
  if (predicate()) return
  throw new Error('waitReal 超时：' + message)
}

/** EP 的下拉 teleport 到 body，用 aria-hidden 挑出当前可见的那个 */
const visiblePopper = () =>
  Array.from(document.body.querySelectorAll('.el-popper')).find(
    (el) => el.getAttribute('aria-hidden') === 'false'
  )
const dropdownItems = () =>
  visiblePopper() ? Array.from(visiblePopper().querySelectorAll('.el-select-dropdown__item')) : []
/** 展开目标类型下拉并选中指定文案的选项 */
const pickTarget = async (labelText) => {
  click(dlg().querySelector('.el-select__wrapper'))
  await waitReal(() => dropdownItems().length === 4, '目标类型下拉展开')
  const option = dropdownItems().find((el) => el.textContent.trim() === labelText)
  if (!option) {
    throw new Error(
      '下拉项不存在：' +
        labelText +
        '；实际为 ' +
        dropdownItems()
          .map((el) => el.textContent)
          .join(' | ')
    )
  }
  click(option)
  await flush(6)
}

describe('ReportDialog 渲染与默认态', () => {
  test('标题为「举报异常」，默认 system：不渲染对象 ID 字段，页脚为「取消 + 提交」', async () => {
    await openDialog()
    expect(dlg().querySelector('.el-dialog__title').textContent.trim()).toBe('举报异常')
    expect(
      Array.from(dlg().querySelectorAll('.el-dialog__footer button')).map((b) =>
        b.textContent.trim()
      )
    ).toEqual(['取消', '提交'])
    // 系统级举报不指向具体记录：渲染了 ID 输入反而诱导用户填写（后端必 400）
    expect(dlg().querySelector('input[name="targetId"]')).toBeNull()
  })

  test('不依赖权限码：无任何权限也渲染提交按钮（刻意豁免，一线必须报得了警）', async () => {
    await openDialog()
    expect(footerBtn('提交')).toBeTruthy()
    expect(dlg().querySelector('input[name="reason"]').getAttribute('maxlength')).toBe('200')
  })
})

describe('ReportDialog 目标类型与 ID 校验', () => {
  test('切到「用户」：出现对象 ID 输入；12 位 hex 被格式校验拦下（不发请求）', async () => {
    await openDialog()
    await pickTarget('用户')
    expect(dlg().querySelector('input[name="targetId"]')).toBeTruthy()
    await typeInto('input[name="targetId"]', 'abc123abc123')
    await typeInto('input[name="reason"]', '异常登录尝试')
    click(footerBtn('提交'))
    await waitReal(
      () => dlg().querySelectorAll('.el-form-item.is-error').length > 0,
      'ID 格式错误态'
    )
    expect(reportApi).not.toHaveBeenCalled()
  })

  test('24 位 hex + 原因：载荷 {targetType,targetId,reason}，原因修剪、无多余键', async () => {
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r1' } } })
    await openDialog()
    await pickTarget('设备')
    await typeInto('input[name="targetId"]', '5f2b8c9d1e4a3b6c7d8e9f00')
    await typeInto('input[name="reason"]', '  设备被非授权拆装  ')
    click(footerBtn('提交'))
    await waitReal(() => reportApi.mock.calls.length === 1, '举报请求')
    expect(reportApi).toHaveBeenCalledWith({
      targetType: 'device',
      targetId: '5f2b8c9d1e4a3b6c7d8e9f00',
      reason: '设备被非授权拆装',
    })
  })

  test('system 型载荷不带 targetId 键（后端对 system 携带 targetId 直接 400）', async () => {
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r2' } } })
    await openDialog()
    await typeInto('input[name="reason"]', '有人尝试越权访问')
    click(footerBtn('提交'))
    await waitReal(() => reportApi.mock.calls.length === 1, '举报请求')
    expect(reportApi).toHaveBeenCalledWith({ targetType: 'system', reason: '有人尝试越权访问' })
  })

  test('描述可选：填写后随载荷修剪上行；不填则不带该键', async () => {
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r6' } } })
    await openDialog()
    await typeInto('input[name="reason"]', '异常行为')
    await typeInto('textarea[name="description"]', '  补充细节  ')
    click(footerBtn('提交'))
    await waitReal(() => reportApi.mock.calls.length === 1, '举报请求')
    expect(reportApi).toHaveBeenCalledWith({
      targetType: 'system',
      reason: '异常行为',
      description: '补充细节',
    })
  })

  test('原因纯空格不算填：不发请求（后端 trim 后 1-200，前端同判据）', async () => {
    await openDialog()
    await typeInto('input[name="reason"]', '   ')
    click(footerBtn('提交'))
    await waitReal(
      () => dlg().querySelectorAll('.el-form-item.is-error').length > 0,
      '原因必填错误态'
    )
    expect(reportApi).not.toHaveBeenCalled()
  })
})

describe('ReportDialog 提交、关闭与重开', () => {
  test('成功：提示 + 关闭 + 表单清空（重开回到默认 system、原因清空）', async () => {
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r3' } } })
    const state = await openDialog()
    await pickTarget('报警记录')
    await typeInto('input[name="targetId"]', '5f2b8c9d1e4a3b6c7d8e9f00')
    await typeInto('input[name="reason"]', '有人恶意处置报警')
    await typeInto('textarea[name="description"]', '补充细节')
    click(footerBtn('提交'))
    await waitReal(() => ElMessage.success.mock.calls.length === 1, '成功提示')
    expect(ElMessage.success).toHaveBeenCalledWith('举报已提交，安全团队将尽快处理')
    await waitReal(() => state.visible === false, '对话框关闭')
    // 重新打开：@close 已触发 resetForm
    state.visible = true
    await flush(8)
    expect(dlg().querySelector('input[name="targetId"]')).toBeNull()
    expect(dlg().querySelector('input[name="reason"]').value).toBe('')
    expect(dlg().querySelector('textarea[name="description"]').value).toBe('')
    expect(active.errors).toEqual([])
  })

  test('失败：不误报成功、不重复弹错（错误归拦截器）、对话框保持打开可重试', async () => {
    reportApi.mockRejectedValue(new Error('boom'))
    const state = await openDialog()
    await typeInto('input[name="reason"]', '异常行为')
    click(footerBtn('提交'))
    await waitReal(() => reportApi.mock.calls.length === 1, '举报请求')
    await flush(20)
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(state.visible).toBe(true)
    // 重试仍可发（submitting 已在 finally 解锁）
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r4' } } })
    click(footerBtn('提交'))
    await waitReal(() => reportApi.mock.calls.length === 2, '重试请求')
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
  })

  test('重入守卫：同一 tick 连点两次只发一个请求、只提示一次', async () => {
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r5' } } })
    await openDialog()
    await typeInto('input[name="reason"]', '异常行为')
    const btn = footerBtn('提交')
    click(btn)
    click(btn)
    await waitReal(() => reportApi.mock.calls.length === 1, '举报请求')
    await flush(10)
    expect(reportApi).toHaveBeenCalledTimes(1)
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
  })
})
