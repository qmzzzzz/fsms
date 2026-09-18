/**
 * InspectionCompleteForm 行为测试（巡检结果提交）
 *
 * 该表单是巡检闭环的最后一环：填写完即写库并关闭工单，用户没有「再改一次」的机会，
 * 因此以下退化都只静默出错：
 *  1. normal 结果仍提交 findings -> 后端收到空问题列表却被当成异常单；
 *  2. 问题行不完整也放行 -> 库里落下没有设备/没有描述的隐患记录，事后无法追溯；
 *  3. photo 地址被 `!startsWith('blob:')` 过滤 -> P3-45 的用户录入地址被静默丢弃；
 *  4. 提交失败不提示 -> 用户以为结果已上报；
 *  5. 「正常」切换时清空 findings -> 用户误点后已录问题全丢（破坏性操作）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const complete = vi.fn()
const devicesGetList = vi.fn()
const devicesGetById = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    inspections: { complete: (...a) => complete(...a) },
    devices: {
      getList: (...a) => devicesGetList(...a),
      getById: (...a) => devicesGetById(...a),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import InspectionCompleteForm from '@/components/InspectionCompleteForm.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null
/** 受控宿主：组件的加载/重置只在 watch(visible) 里，必须先挂载、后翻转 */
const makeHost = () => {
  const state = reactive({ modelValue: false, inspectionId: 'insp-1', inspectionTitle: 'T' })
  const Host = defineComponent({
    setup() {
      return () =>
        h(InspectionCompleteForm, {
          ...state,
          'onUpdate:modelValue': (v) => {
            state.modelValue = v
          },
        })
    },
  })
  return { Host, state }
}

const DEVICES = {
  data: {
    data: [{ _id: 'dev-1', deviceCode: 'SMK-001', deviceName: '一层烟感', deviceType: 'smoke' }],
  },
}

const open = async () => {
  devicesGetList.mockResolvedValue(DEVICES)
  devicesGetById.mockResolvedValue({ data: { data: {} } })
  const { Host, state } = makeHost()
  active = mountComponent(Host, {})
  await flush(4)
  state.modelValue = true
  await waitFor(() => dlg(), { message: '对话框打开' })
  await flush(10)
  return active
}

const dlg = () => document.body.querySelector('.el-dialog')
const footBtn = (t) =>
  Array.from(dlg().querySelectorAll('.el-dialog__footer button')).find(
    (b) => b.textContent.trim() === t
  )
/** 提交按钮（文案 inspectionResult.submitBtn = 提交结果）；找不到直接报错，避免后续静默空点 */
const submitBtn = () => {
  const b = footBtn('提交结果')
  expect(b).toBeTruthy()
  return b
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

const radios = () => Array.from(dlg().querySelectorAll('.el-radio'))
const clickRadio = async (value) => {
  const found = radios().find((r) => r.querySelector('input').value === value)
  expect(found).toBeTruthy()
  click(found.querySelector('input') || found)
  await flush(10)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  complete.mockReset()
  devicesGetList.mockReset()
  devicesGetById.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  document.body.innerHTML = ''
})

describe('InspectionCompleteForm 提交载荷', () => {
  test('结果为「正常」：载荷不带 findings（后端按有无 findings 区分闭环形态）', async () => {
    complete.mockResolvedValue({ data: { success: true } })
    await open()
    click(submitBtn())
    await waitFor(() => complete.mock.calls.length === 1, { message: '提交请求发出' })
    const [id, payload] = complete.mock.calls[0]
    expect(id).toBe('insp-1')
    expect(payload.result).toBe('normal')
    expect(payload).not.toHaveProperty('findings')
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    // 成功后关闭对话框（emit update:modelValue false）
    await waitForOverlayClosed()
  })

  test('问题行不完整：拦在提交前并提示，不发出请求', async () => {
    complete.mockResolvedValue({ data: { success: true } })
    await open()
    await clickRadio('abnormal')
    // 问题行必填未填，直接提交
    click(submitBtn())
    await waitFor(() => ElMessage.warning.mock.calls.length === 1, { message: '完整度提示' })
    await flush(20)
    expect(complete).not.toHaveBeenCalled()
  })

  test('异常结果 + 完整问题：photo 地址原样上行（不得被 blob 过滤丢弃）', async () => {
    complete.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await clickRadio('abnormal')
    // 直接写组件内部 reactive 不可行，走真实输入：下拉选设备 + 填文本
    const d = dlg()
    // 设备下拉：行内只有这一个 el-select（严重程度是第二个，故按顺序取第 1 个）
    const selectWraps = Array.from(d.querySelectorAll('.finding-item .el-select__wrapper'))
    expect(selectWraps.length).toBe(2)
    click(selectWraps[0])
    await flush(12)
    const popper = Array.from(document.body.querySelectorAll('.el-popper')).find(
      (el) => el.getAttribute('aria-hidden') === 'false'
    )
    expect(popper).toBeTruthy()
    const opt = popper.querySelector('.el-select-dropdown__item')
    expect(opt).toBeTruthy()
    click(opt)
    await flush(12)
    // 行内文本字段按 DOM 顺序：问题描述(textarea) / 处理建议 / 照片地址
    const fill = (el, v) => {
      el.value = v
      el.dispatchEvent(new window.Event('input', { bubbles: true }))
    }
    const dsc = d.querySelector('.finding-item textarea')
    expect(dsc).toBeTruthy()
    fill(dsc, '灭火器压力不足')
    const textInputs = Array.from(d.querySelectorAll('.finding-item input.el-input__inner'))
    expect(textInputs.length).toBe(2)
    fill(textInputs[0], '更换灭火器')
    fill(textInputs[1], '/uploads/fire/photo-1.jpg')
    await flush(20)
    click(submitBtn())
    await waitFor(() => complete.mock.calls.length === 1, { message: '提交请求发出' })
    const payload = complete.mock.calls[0][1]
    expect(payload.result).toBe('abnormal')
    expect(Array.isArray(payload.findings)).toBe(true)
    expect(payload.findings[0].deviceId).toBe('dev-1')
    expect(payload.findings[0].issue).toBe('灭火器压力不足')
    expect(payload.findings[0].photo).toBe('/uploads/fire/photo-1.jpg')
    expect(c.errors).toEqual([])
  })
  test('只剩最后一行问题：点删除不得把列表清空（否则用户看到空行，也无从补录）', async () => {
    await open()
    await clickRadio('abnormal')
    const d = dlg()
    expect(d.querySelectorAll('.finding-item').length).toBe(1)
    const removeBtn = Array.from(d.querySelectorAll('.finding-item button')).find(
      (b) => b.textContent.trim() === '×'
    )
    expect(removeBtn).toBeTruthy()
    click(removeBtn)
    await flush(10)
    expect(d.querySelectorAll('.finding-item').length).toBe(1)
  })
})

describe('InspectionCompleteForm 失败与重置', () => {
  test('提交失败：提示失败且不关闭对话框（用户可重试）', async () => {
    complete.mockRejectedValue(new Error('boom'))
    await open()
    click(submitBtn())
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    await flush(20)
    expect(ElMessage.success).not.toHaveBeenCalled()
    await flush(20)
    // 关闭过渡走 rAF + display:none，未关闭时不得变成 none
    expect(dlg().closest('.el-overlay').style.display).not.toBe('none')
  })

  test('切到「异常」再切回「正常」，已录问题不被清空（破坏性操作防护）', async () => {
    await open()
    await clickRadio('abnormal')
    const addBtn = Array.from(dlg().querySelectorAll('button')).find((b) =>
      b.textContent.includes('添加问题')
    )
    expect(addBtn).toBeTruthy()
    click(addBtn)
    await flush(10)
    const countAfterAdd = dlg().querySelectorAll('.finding-item').length
    expect(countAfterAdd).toBe(2)
    await clickRadio('normal')
    // 切回正常：问题行只是不再显示，数据仍在（再切回异常应看到 2 行）
    await clickRadio('abnormal')
    expect(dlg().querySelectorAll('.finding-item').length).toBe(2)
    // 删除一行
    const removeBtn = Array.from(dlg().querySelectorAll('.finding-item button')).find(
      (b) => b.textContent.trim() === '×'
    )
    click(removeBtn)
    await flush(10)
    expect(dlg().querySelectorAll('.finding-item').length).toBe(1)
  })
})
