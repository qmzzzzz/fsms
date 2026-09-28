/**
 * 巡检两张表的「跨记录残留」（2026-09-26，Lane Z #2/#3 复核后落地）
 *
 * 共同前提（两份组件同构）：
 *  - `InspectionView` 只挂一个表单实例，处理下一条靠换 `:inspection-id`；
 *  - 提交成功路径只写 `visible.value = false`，而 el-dialog 的 `:before-close`
 *    只对**用户发起**的关闭（X / ESC / 点遮罩）生效——程序化关闭不经过 handleClose；
 *  - 所以「关闭时复位」覆盖不了最常见的那条路：填完→提交成功→下一条。
 *
 * 完成表（InspectionCompleteForm）后果：上一条的 result / 位置 / 备注
 * 原样出现在下一条里，用户看不见地提交到错误的巡检上（HEAD 的打开侧只补了
 * `findings` 一行，其余三个字段没人管）。
 * 复核表（InspectionReviewForm）后果更硬：
 *  1. 审核结论那一项的 `<el-form-item>` 没有 `prop`，而 element-plus 的 resetFields()
 *     只遍历注册过的字段（form-item 源码 `if (props.prop) formContext.addField(context)`，
 *     resetField 里还有 `if (isResettingField || !props.prop) return false`），
 *     于是**连 handleClose 那条路也复位不了 form.result**——上一轮选「不通过」，
 *     这一轮什么都不点就是「不通过」，默认值 'approved' 形同虚设；
 *  2. 重开后 GET 还在路上时，弹窗里显示的是上一条的标题与隐患；
 *  3. GET 失败时 `inspectionData` 永远停在上一条（catch 分支只弹提示），
 *     复核人看着 A 的隐患给 B 下结论——而提交载荷用的是 B 的 id。
 *
 * 另一条被核过但**不成立**的指控：复核表的 `<el-radio label="approved">` 用旧 API 会
 * 把 reviewResult 丢成 undefined。实测 element-plus 2.14.5 `use-radio.mjs`：
 *   `actualValue = computed(() => isPropAbsent(props.value) ? props.label : props.value)`
 * 且 `isPropAbsent = isNil`（types.mjs:12），所以 label 仍作为绑定值上行，只有控制台
 * deprecation 告警。T-R1 的第一段断言（选「不通过」后载荷确实是 'rejected'）把这个
 * 结论钉在运行时上：旧 API 坏在措辞，不坏在数据。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const complete = vi.fn()
const review = vi.fn()
const getById = vi.fn()
const devicesGetList = vi.fn()
const devicesGetById = vi.fn()
const isCanceledError = vi.fn(() => false)

vi.mock('@/utils/api', () => ({
  api: {
    inspections: {
      complete: (...a) => complete(...a),
      review: (...a) => review(...a),
      getById: (...a) => getById(...a),
    },
    devices: {
      getList: (...a) => devicesGetList(...a),
      getById: (...a) => devicesGetById(...a),
    },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import InspectionCompleteForm from '@/components/InspectionCompleteForm.vue'
import InspectionReviewForm from '@/components/InspectionReviewForm.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

const DEVICES = {
  data: {
    data: [{ _id: 'dev-1', deviceCode: 'SMK-001', deviceName: '一层烟感', deviceType: 'smoke' }],
  },
}

/** 详情接口的响应形状（后端 populate 后 findings.deviceId 是嵌套对象） */
const ok = (data) => ({ data: { data } })
const DETAIL_A = {
  title: '巡检A',
  findings: [
    {
      deviceId: { deviceCode: 'A-1', deviceName: '一层烟感' },
      issue: '外壳破损',
      severity: 'high',
    },
  ],
}
const DETAIL_B = { title: '巡检B', findings: [] }

let active = null

/**
 * 受控宿主（全文件仅此一个 defineComponent，vue/one-component-per-file）。
 *
 * 两张表的 v-model 契约一样，所以宿主也只有一个：换组件靠 currentComp，
 * 换记录靠改 props.inspectionId——这正好是 InspectionView 的真实用法。
 */
let currentComp = null
const host = reactive({ props: {} })
const seen = { success: 0 }

const Host = defineComponent({
  setup() {
    return () =>
      h(currentComp, {
        ...host.props,
        'onUpdate:modelValue': (v) => {
          host.props = { ...host.props, modelValue: v }
        },
        onSuccess: () => {
          seen.success += 1
        },
      })
  },
})

/** 换到下一条记录并重新打开（同一组件实例，等价于 InspectionView 点下一条） */
const reopen = async (inspectionId, impl) => {
  if (currentComp === InspectionCompleteForm) {
    devicesGetList.mockResolvedValue(DEVICES)
  } else {
    getById.mockImplementation(impl || (() => Promise.resolve(ok(DETAIL_B))))
  }
  // 先只改 id 并推一帧：打开时的复位必须在这条 id 上生效
  host.props = { ...host.props, inspectionId }
  await flush(3)
  host.props = { ...host.props, modelValue: true }
  await flush(10)
}

/** 挂载一张表并打开对话框（先挂载后翻转：加载逻辑只挂在 watch(visible) 上） */
const mountAndOpen = async (comp, options = {}) => {
  const { props = {}, detail = DETAIL_A, detailImpl } = options
  currentComp = comp
  seen.success = 0
  host.props = { modelValue: false, inspectionId: 'insp-1', ...props }
  if (comp === InspectionCompleteForm) {
    devicesGetList.mockResolvedValue(DEVICES)
    devicesGetById.mockResolvedValue(ok({}))
  } else {
    // detailImpl：由用例自己决定这条 GET 何时返回——「迟到的过期响应」只能这样造
    if (detailImpl) getById.mockImplementation(detailImpl)
    else getById.mockResolvedValue(ok(detail))
  }
  active = mountComponent(Host, {})
  await flush(4)
  host.props = { ...host.props, modelValue: true }
  await flush(10)
  return host
}

const cleanup = () => {
  active?.handle.unmount()
  active = null
  currentComp = null
  for (const fn of [complete, review, getById, devicesGetList, devicesGetById]) fn.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  document.body.innerHTML = ''
}
afterEach(cleanup)

const dlg = () => {
  const d = document.body.querySelector('.el-dialog')
  expect(d).toBeTruthy()
  return d
}
/** Element Plus 的对话框关闭过渡走 requestAnimationFrame，nextTick 推不动它 */
const waitForOverlayClosed = async () => {
  for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => requestAnimationFrame(() => r()))
    await flush(1)
    const overlay = dlg()?.closest('.el-overlay')
    if (!overlay || overlay.style.display === 'none') return
  }
  throw new Error('对话框未在 60 帧内关闭')
}
const fill = (el, v) => {
  el.value = v
  el.dispatchEvent(new window.Event('input', { bubbles: true }))
}
const radioInputs = () => Array.from(dlg().querySelectorAll('.el-radio input'))
const checkedRadioValue = () => {
  const on = radioInputs().filter((i) => i.checked)
  expect(on.length).toBe(1)
  return on[0].value
}
const pickRadio = async (value) => {
  const target = radioInputs().find((i) => i.value === value)
  expect(target).toBeTruthy()
  click(target)
  await flush(10)
}
/**
 * 第 rowIndex 行的设备下拉。el-select 的下拉是 teleport 到 body 的 .el-popper，
 * 文档顺序与 select 创建顺序一一对应（每行两个 select：设备、严重程度），故下标 = rowIndex*2。
 *
 * 为什么不用「aria-hidden=false」筛当前打开的下拉：jsdom 里上一个下拉的收起推不到终态，
 * 第二个 select 的 popper 与第一个会同时算「开着」，按它筛就点到了别行的下拉——
 * 实测第二行的 deviceId 一直空着，真正被改掉的反而是它的「严重程度」（点成了 低）。
 * 所以点完必须在这行上看到所选设备，否则本函数自己就是假绿来源。
 */
const pickDeviceOption = async (rowIndex) => {
  const rows = Array.from(dlg().querySelectorAll('.finding-item'))
  const wrappers = Array.from(dlg().querySelectorAll('.finding-item .el-select__wrapper'))
  const poppers = Array.from(document.body.querySelectorAll('.el-popper'))
  // 前提：每行两个 select、每个 select 恰好一个 popper，且顺序一致（对不上就直接红，避免又点错行）
  expect(wrappers.length).toBe(rows.length * 2)
  expect(poppers.length).toBe(wrappers.length)
  const wrapper = wrappers[rowIndex * 2]
  click(wrapper)
  await flush(12)
  click(poppers[rowIndex * 2].querySelector('.el-select-dropdown__item'))
  await flush(12)
  expect(wrapper.textContent).toContain('SMK-001')
}
/** 页脚里主/次按钮各一个（问题行的按钮在 body 内），按类取以免和文案耦合 */
const footBtn = (cls) => {
  const found = Array.from(dlg().querySelectorAll('.el-dialog__footer button')).filter((b) =>
    b.className.includes(cls)
  )
  expect(found.length).toBe(1)
  return found[0]
}
const submitPrimary = async () => {
  click(footBtn('glass-btn--primary'))
  await flush(8)
}

// ── 完成表 ──────────────────────────────────────────────────────────────
describe('InspectionCompleteForm 跨记录残留', () => {
  test('提交成功后重开下一条：位置/备注回到出厂态，二次载荷不带上一条内容', async () => {
    complete.mockResolvedValue({ data: { success: true } })
    await mountAndOpen(InspectionCompleteForm)

    // result 保持默认 normal，只填位置与备注（normal 分支不带 findings，无需凑齐问题行）
    const inputs = Array.from(dlg().querySelectorAll('.el-input__inner'))
    const textareas = Array.from(dlg().querySelectorAll('textarea'))
    // 先证明「此时表单里确实只有这两处可填」，否则下面的按序取值是真空断言
    expect(inputs.length).toBe(1)
    expect(textareas.length).toBe(1)
    fill(inputs[0], 'A栋3层走廊')
    fill(textareas[0], '上一条的备注，不该跟过来')
    await flush(10)

    await submitPrimary()
    await waitFor(() => complete.mock.calls.length === 1, { message: '第一次提交发出' })
    expect(complete.mock.calls[0][1]).toMatchObject({
      result: 'normal',
      location: 'A栋3层走廊',
      remark: '上一条的备注，不该跟过来',
    })
    await waitForOverlayClosed()

    await reopen('insp-2')
    expect(dlg().querySelector('.el-input__inner').value).toBe('')
    expect(dlg().querySelector('textarea').value).toBe('')

    await submitPrimary()
    await waitFor(() => complete.mock.calls.length === 2, { message: '第二次提交发出' })
    expect(complete.mock.calls[1][0]).toBe('insp-2')
    expect(complete.mock.calls[1][1]).toMatchObject({
      result: 'normal',
      location: '',
      remark: '',
    })
    expect(complete.mock.calls[1][1]).not.toHaveProperty('findings')
  })

  test('上一条按「异常」提交了两行完整问题：重开后勾中的必须是默认「正常」，问题行回到一行全空', async () => {
    complete.mockResolvedValue({ data: { success: true } })
    await mountAndOpen(InspectionCompleteForm)

    // 前态：异常 + 两行问题，并且要提交成功（成功只写 visible=false，不经 handleClose）
    await pickRadio('abnormal')
    const addBtn = Array.from(dlg().querySelectorAll('button')).find((b) =>
      b.textContent.includes('添加问题')
    )
    expect(addBtn).toBeTruthy()
    click(addBtn)
    await flush(10)
    const rows = Array.from(dlg().querySelectorAll('.finding-item'))
    expect(rows.length).toBe(2)
    // 两行都填完整：handleSubmit 的前置体检要求 deviceId/issue/severity/suggestion 全非空
    for (const [i, row] of rows.entries()) {
      await pickDeviceOption(i)
      fill(row.querySelector('textarea'), `隐患${i + 1}`)
      const inputs = Array.from(row.querySelectorAll('.el-input__inner'))
      expect(inputs.length).toBe(2)
      fill(inputs[0], `建议${i + 1}`)
    }
    await flush(10)

    await submitPrimary()
    // maxTicks 放大：两行问题的校验链比单行长得多（实测默认 50 个 nextTick 还落不到）
    await waitFor(() => complete.mock.calls.length === 1, {
      message: '异常结果提交成功',
      maxTicks: 200,
    })
    expect(complete.mock.calls[0][1].findings.length).toBe(2)
    await waitForOverlayClosed()

    await reopen('insp-2')
    expect(checkedRadioValue()).toBe('normal')
    await pickRadio('abnormal')
    const fresh = Array.from(dlg().querySelectorAll('.finding-item'))
    expect(fresh.length).toBe(1)
    expect(fresh[0].querySelector('textarea').value).toBe('')
    expect(Array.from(fresh[0].querySelectorAll('.el-input__inner')).map((el) => el.value)).toEqual(
      ['', '']
    )
  })
})

// ── 复核表 ──────────────────────────────────────────────────────────────
const COMMENT = '现场已复核，隐患整改到位可以闭环'
const fillComment = async (value) => {
  const box = dlg().querySelector('textarea')
  expect(box).toBeTruthy()
  fill(box, value)
  await flush(10)
}

describe('InspectionReviewForm 跨记录残留', () => {
  test('T-R1 上一条选「不通过」并提交成功：重开后的载荷必须回到默认「通过」', async () => {
    review.mockResolvedValue({ data: { success: true } })
    await mountAndOpen(InspectionReviewForm)
    await fillComment(COMMENT)
    await pickRadio('rejected')
    expect(checkedRadioValue()).toBe('rejected')

    await submitPrimary()
    await waitFor(() => seen.success === 1, { message: '第一次提交成功' })
    // 旧 API（label 当值）在这一段被实测为可用：载荷确实带出了 'rejected'
    expect(review.mock.calls[0][1]).toEqual({ reviewComment: COMMENT, reviewResult: 'rejected' })
    await waitForOverlayClosed()

    await reopen('insp-2')
    // 界面侧：勾中的必须回到默认值
    expect(checkedRadioValue()).toBe('approved')
    // 意见侧：loadInspectionDetail 也会清 reviewComment，这里同时钉住它不是残值
    expect(dlg().querySelector('textarea').value).toBe('')

    await fillComment('第二条巡检的复核意见，字数足够')
    await submitPrimary()
    await waitFor(() => review.mock.calls.length === 2, { message: '第二次提交发出' })
    expect(review.mock.calls[1][0]).toBe('insp-2')
    expect(review.mock.calls[1][1].reviewResult).toBe('approved')
  })

  test('T-R2 重开后 GET 未回／失败：不得继续显示上一条的标题与隐患', async () => {
    review.mockResolvedValue({ data: { success: true } })
    await mountAndOpen(InspectionReviewForm)
    expect(dlg().textContent).toContain('巡检A')
    expect(dlg().querySelectorAll('.finding-device').length).toBe(1)

    await fillComment(COMMENT)
    await submitPrimary()
    await waitFor(() => seen.success === 1, { message: '提交成功（程序化关闭，不经 handleClose）' })
    await waitForOverlayClosed()

    // 重开：GET 挂住不返回 —— 此刻弹窗里若还有上一条，就是「看着 A 给 B 下结论」
    let rejectGet
    await reopen('insp-2', () => new Promise((_r, j) => (rejectGet = j)))
    await waitFor(() => !dlg().textContent.includes('巡检A'), { message: '重开瞬间清空上一条详情' })
    expect(dlg().querySelectorAll('.finding-device').length).toBe(0)

    // GET 失败：catch 分支只弹提示，详情同样不得停在上一条
    rejectGet(new Error('network down'))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '加载失败提示' })
    expect(dlg().textContent).not.toContain('巡检A')
    expect(dlg().querySelectorAll('.finding-device').length).toBe(0)
  })

  /**
   * 「打开即复位」与「过期响应门票」是一对，缺前者会串内容、缺后者会被迟到响应打回串内容：
   * 重开时 resetForm() 先把详情页清空，可上一条（A）的 GET 还在飞——它后到就把整块详情
   * 又填回成 A 的（标题 + 隐患），而提交载荷用的已经是 B 的 id。慢网/重试/并行请求下
   * 这是常态而非边角，且用户完全看不出来。
   */
  test('T-R3 上一条的 GET 迟于这一条返回：过期响应不得覆盖当前记录的详情', async () => {
    let resolveA
    await mountAndOpen(InspectionReviewForm, {
      detailImpl: () => new Promise((r) => (resolveA = r)),
    })
    // A 的 GET 还没回就先关掉，再重开下一条：两次打开 = 两张门票，先发的后到
    host.props = { ...host.props, modelValue: false }
    await waitForOverlayClosed()
    await reopen('insp-2')
    expect(dlg().textContent).toContain('巡检B')

    resolveA(ok(DETAIL_A))
    await flush(10)
    expect(dlg().textContent).toContain('巡检B')
    expect(dlg().textContent).not.toContain('巡检A')
    expect(dlg().querySelectorAll('.finding-device').length).toBe(0)
  })
})
