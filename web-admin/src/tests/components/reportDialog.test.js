/**
 * ReportDialog 行为测试（举报异常对话框）
 *
 * 组件是 POST /api/security/report 的唯一前端入口（顶栏可达，人人可用）。
 * 本套件钉住五类真实退化：
 *
 *  1. **界面上不得出现对象 ID**：记录型的目标由可搜索下拉从
 *     GET /api/security/report-targets 的候选里选，用户看到的是名称/编号。
 *     原先这里是 24 位 ObjectId 输入框——一线人员拿不到该值，功能等价于不可用
 *     （2026-10-21 修复）。回归形态：有人把下拉改回输入框，或把 id 渲染成文案。
 *  2. system 型不得携带 targetId：后端路由对 system + targetId 直接 400
 *     （否则改一下类型就能绕过「目标必须是数据范围内的真实记录」的核验），
 *     前端在 system 下连选择器都不渲染，提交载荷也不带该键。
 *  3. 记录型未选对象不得提交（候选为空时同样拦下，不发注定 400 的请求）。
 *  4. 原因必填且按 trim 后判长（后端先 .trim() 再判 1-200；纯空格在
 *     async-validator 的 required 下能过，必须在提交前用同一判据拦住）。
 *  5. 成功/失败语义：成功提示 + 关闭 + 表单清空；失败不误报成功、不重复
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
const targetsApi = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    security: {
      report: (...a) => reportApi(...a),
      searchReportTargets: (...a) => targetsApi(...a),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import ReportDialog from '@/components/ReportDialog.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

const USER_TARGETS = [
  {
    id: '5f2b8c9d1e4a3b6c7d8e9f01',
    kind: 'user',
    code: 'zhangsan',
    name: '张三',
    detail: '安保部',
  },
  {
    id: '5f2b8c9d1e4a3b6c7d8e9f02',
    kind: 'user',
    code: 'lisi',
    name: '李四',
    detail: '后勤部',
  },
]
const DEVICE_TARGETS = [
  {
    id: '5f2b8c9d1e4a3b6c7d8e9f03',
    kind: 'device',
    code: 'SMK-0001',
    name: '烟感一号',
    detail: '3 号楼 · 2F · 201',
  },
]

let active = null
afterEach(() => {
  active?.handle.unmount()
  active = null
  reportApi.mockReset()
  targetsApi.mockReset()
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
/** 对话框内的第二个 el-select 是「具体对象」选择器（第一个是目标类型） */
const recordSelectWrapper = () => dlg().querySelectorAll('.el-select__wrapper')[1]
/** 展开对象选择器并点选指定文案的候选 */
const pickRecord = async (labelText) => {
  click(recordSelectWrapper())
  await waitReal(
    () => dropdownItems().some((el) => el.textContent.trim() === labelText),
    '候选展开'
  )
  const option = dropdownItems().find((el) => el.textContent.trim() === labelText)
  click(option)
  await flush(6)
}

describe('ReportDialog 渲染与默认态', () => {
  test('标题为「举报异常」，默认 system：不渲染对象选择器，页脚为「取消 + 提交」', async () => {
    await openDialog()
    expect(dlg().querySelector('.el-dialog__title').textContent.trim()).toBe('举报异常')
    expect(
      Array.from(dlg().querySelectorAll('.el-dialog__footer button')).map((b) =>
        b.textContent.trim()
      )
    ).toEqual(['取消', '提交'])
    // 系统级举报不指向具体记录：渲染选择器反而诱导用户去选（后端必 400）
    expect(dlg().querySelector('input[name="targetId"]')).toBeNull()
    // system 型没有候选可拉：一次请求都不该发
    expect(targetsApi).not.toHaveBeenCalled()
  })

  test('不依赖权限码：无任何权限也渲染提交按钮（刻意豁免，一线必须报得了警）', async () => {
    await openDialog()
    expect(footerBtn('提交')).toBeTruthy()
    expect(dlg().querySelector('input[name="reason"]').getAttribute('maxlength')).toBe('200')
  })

  test('界面上不出现对象 ID：记录型只有可搜索下拉，没有可粘贴 ObjectId 的输入框', async () => {
    targetsApi.mockResolvedValue({ data: { data: { items: USER_TARGETS } } })
    await openDialog()
    await pickTarget('用户')
    // 控件存在（name 用于测试定位），但它必须是 el-select 的搜索框，而不是让用户填 ID
    const input = dlg().querySelector('input[name="targetId"]')
    expect(input).toBeTruthy()
    expect(input.closest('.el-select')).toBeTruthy()
    expect(dlg().textContent).not.toContain('ObjectId')
    expect(dlg().textContent).not.toContain('对象 ID')
  })
})

describe('ReportDialog 对象候选与提交载荷', () => {
  test('切到「用户」：按类型拉候选，候选文案用姓名/用户名而不是 id', async () => {
    targetsApi.mockResolvedValue({ data: { data: { items: USER_TARGETS } } })
    await openDialog()
    await pickTarget('用户')
    await waitReal(() => targetsApi.mock.calls.length >= 1, '候选请求')
    expect(targetsApi).toHaveBeenLastCalledWith({ type: 'user', keyword: '' })

    click(recordSelectWrapper())
    await waitReal(() => dropdownItems().length >= 2, '候选展开')
    const labels = dropdownItems().map((el) => el.textContent.trim())
    expect(labels).toContain('张三（zhangsan）')
    expect(labels.some((l) => l.includes('5f2b8c9d1e4a3b6c7d8e9f01'))).toBe(false)
  })

  test('选中候选 + 原因：载荷 {targetType,targetId,reason}，原因修剪、无多余键', async () => {
    targetsApi.mockResolvedValue({ data: { data: { items: DEVICE_TARGETS } } })
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r1' } } })
    await openDialog()
    await pickTarget('设备')
    await waitReal(() => targetsApi.mock.calls.length >= 1, '候选请求')
    expect(targetsApi).toHaveBeenLastCalledWith({ type: 'device', keyword: '' })
    await pickRecord('烟感一号（SMK-0001） · 3 号楼 · 2F · 201')
    await typeInto('input[name="reason"]', '  设备被非授权拆装  ')
    click(footerBtn('提交'))
    await waitReal(() => reportApi.mock.calls.length === 1, '举报请求')
    expect(reportApi).toHaveBeenCalledWith({
      targetType: 'device',
      targetId: '5f2b8c9d1e4a3b6c7d8e9f03',
      reason: '设备被非授权拆装',
    })
  })

  test('记录型未选对象：不发请求（required 拦在提交前，不产生注定 400 的出网）', async () => {
    targetsApi.mockResolvedValue({ data: { data: { items: USER_TARGETS } } })
    await openDialog()
    await pickTarget('用户')
    await waitReal(() => targetsApi.mock.calls.length >= 1, '候选请求')
    await typeInto('input[name="reason"]', '异常登录尝试')
    click(footerBtn('提交'))
    await waitReal(
      () => dlg().querySelectorAll('.el-form-item.is-error').length > 0,
      '对象必选错误态'
    )
    expect(reportApi).not.toHaveBeenCalled()
  })

  test('候选为空：不发举报请求，错误文案指向「请选择具体对象」', async () => {
    targetsApi.mockResolvedValue({ data: { data: { items: [] } } })
    await openDialog()
    await pickTarget('报警记录')
    await waitReal(() => targetsApi.mock.calls.length >= 1, '候选请求')
    await typeInto('input[name="reason"]', '有人恶意处置报警')
    click(footerBtn('提交'))
    await waitReal(() => dlg().textContent.includes('请选择被举报的具体对象'), '对象必选错误文案')
    expect(reportApi).not.toHaveBeenCalled()
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
    targetsApi.mockResolvedValue({ data: { data: { items: USER_TARGETS } } })
    reportApi.mockResolvedValue({ data: { data: { reportId: 'r3' } } })
    const state = await openDialog()
    await pickTarget('用户')
    await waitReal(() => targetsApi.mock.calls.length >= 1, '候选请求')
    await pickRecord('张三（zhangsan）')
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
