/**
 * InspectionForm 远程搜索候选项跨记录残留（第 34 轮 M3）
 *
 * 缺陷（修复前实测）：searchDevices / searchUsers 的 catch 是空的，且没有
 * useLatestRequest 竞态门票；initForm 只重置 form.devices / assignedTo 的 id 数组，
 * 不清 deviceOptions / userOptions。于是切记录后下拉里仍是上一次搜索的结果——
 * 那些候选项的 value 属于上一条记录选过的对象，用户看不见地提交到错误目标上。
 *
 * 断言口径：可观测输出是「该下拉自己的 listbox 里出现的候选项文案」（用输入框的
 * aria-controls 精确定位，页面同时存在多个 select 的 popper），不是源码字符串。
 *
 * 环境事实（实测）：element-plus 的 remote 搜索带 300ms 防抖，故用假定时器推进；
 * 2.14 的 filterable 输入框不带 placeholder 属性，改用 el-form-item 的标签定位。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const create = vi.fn()
const update = vi.fn()
const devicesGetList = vi.fn()
const usersGetList = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    inspections: {
      create: (...a) => create(...a),
      update: (...a) => update(...a),
    },
    // 组件的远端搜索走这两个端点
    devices: { getList: (...a) => devicesGetList(...a) },
    users: { getList: (...a) => usersGetList(...a) },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import i18n from '@/i18n'
import InspectionForm from '@/components/InspectionForm.vue'

let active = null

const DEVICE_ROWS = [
  { _id: 'dev-A', deviceCode: 'SMK-001', deviceName: '一层烟感', deviceType: 'smoke' },
]
const USER_ROWS = [{ _id: 'user-A', username: 'zhang', realName: '张三' }]
const DEVICE_LABEL = 'SMK-001 - 一层烟感 (smoke)'
const USER_LABEL = '张三 (zhang)'

const editRow = (over = {}) => ({
  _id: 'insp-1',
  title: '季度巡检计划',
  inspectionType: 'daily',
  devices: [],
  assignedTo: [],
  planStartTime: '2026-10-01T01:00:00.000Z',
  planEndTime: '2026-10-02T01:00:00.000Z',
  checkItems: [{ name: '烟感外观', standard: '无破损' }],
  ...over,
})

/** 受控宿主：同一实例换 editData，等价于 InspectionView 处理下一条 */
const open = async (editData = null) => {
  const props = reactive({ modelValue: false, editData })
  const Host = defineComponent({
    setup() {
      return () =>
        h(InspectionForm, {
          modelValue: props.modelValue,
          editData: props.editData,
          'onUpdate:modelValue': (v) => {
            props.modelValue = v
          },
        })
    },
  })
  active = mountComponent(Host, {})
  await flush(2)
  props.modelValue = true
  await flush(12)
  return props
}

/** 按 el-form-item 标签定位 el-select 的点击区（2.14 的 .el-select__wrapper） */
const selectWrapper = (c, labelText) => {
  const item = c.findAll('.el-form-item').find((it) => {
    const label = it.querySelector('.el-form-item__label')
    return label && label.textContent.trim() === labelText
  })
  return item ? item.querySelector('.el-select__wrapper') : undefined
}

/** 该下拉自己的 listbox 里的候选项文案（aria-controls 精确关联，避免串到别的 select） */
const itemsOf = (wrapper) => {
  const input = wrapper.querySelector('input')
  const listboxId = input.getAttribute('aria-controls')
  const listbox = Array.from(document.body.querySelectorAll('[role=listbox]')).find(
    (lb) => lb.id === listboxId
  )
  return listbox
    ? Array.from(listbox.querySelectorAll('.el-select-dropdown__item')).map((el) =>
        el.textContent.trim()
      )
    : []
}

/** 键入关键词并推过 element-plus 的 300ms remote 防抖 */
const search = async (wrapper, text) => {
  const input = wrapper.querySelector('input')
  input.value = text
  input.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(3)
  vi.advanceTimersByTime(300)
  await flush(6)
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  create.mockReset()
  update.mockReset()
  devicesGetList.mockReset()
  usersGetList.mockReset()
})

describe('InspectionForm 远程搜索候选项不跨记录残留', () => {
  test('切记录后重新打开设备/负责人下拉：上一条的候选项不得残留', async () => {
    vi.useFakeTimers()
    try {
      devicesGetList.mockResolvedValue({ data: { data: DEVICE_ROWS } })
      usersGetList.mockResolvedValue({ data: { data: USER_ROWS } })
      const props = await open(editRow())

      // 第一条：设备与负责人都搜出候选项
      const devWrapper = selectWrapper(active, i18n.global.t('inspection.selectDevices'))
      expect(devWrapper).toBeTruthy()
      await search(devWrapper, '烟')
      await waitFor(() => devicesGetList.mock.calls.length === 1, { message: '设备搜索请求' })
      expect(itemsOf(devWrapper)).toContain(DEVICE_LABEL)

      const userWrapper = selectWrapper(active, i18n.global.t('inspection.ownerLabel'))
      expect(userWrapper).toBeTruthy()
      await search(userWrapper, '张')
      await waitFor(() => usersGetList.mock.calls.length === 1, { message: '负责人搜索请求' })
      expect(itemsOf(userWrapper)).toContain(USER_LABEL)

      // 换到下一条记录（同一实例换 editData）
      props.editData = editRow({ _id: 'insp-2', title: '另一条巡检' })
      await flush(12)

      // 不输入任何关键词，直接点开两个下拉：不得再出现上一条的候选项
      click(selectWrapper(active, i18n.global.t('inspection.selectDevices')))
      await flush(12)
      expect(itemsOf(selectWrapper(active, i18n.global.t('inspection.selectDevices')))).toEqual([])

      click(selectWrapper(active, i18n.global.t('inspection.ownerLabel')))
      await flush(12)
      expect(itemsOf(selectWrapper(active, i18n.global.t('inspection.ownerLabel')))).toEqual([])
    } finally {
      vi.useRealTimers()
    }
  })

  test('搜索失败同样清空候选项（不留着上次结果让用户误选）', async () => {
    vi.useFakeTimers()
    try {
      devicesGetList.mockResolvedValueOnce({ data: { data: DEVICE_ROWS } })
      devicesGetList.mockRejectedValueOnce(new Error('search down'))
      await open(editRow())

      const devWrapper = selectWrapper(active, i18n.global.t('inspection.selectDevices'))
      await search(devWrapper, '烟')
      await waitFor(() => devicesGetList.mock.calls.length === 1, { message: '第一次搜索' })
      expect(itemsOf(devWrapper)).toContain(DEVICE_LABEL)

      await search(devWrapper, '烟感')
      await waitFor(() => devicesGetList.mock.calls.length === 2, { message: '第二次搜索' })
      await waitFor(() => itemsOf(devWrapper).length === 0, { message: '失败后候选项被清空' })
    } finally {
      vi.useRealTimers()
    }
  })
})
