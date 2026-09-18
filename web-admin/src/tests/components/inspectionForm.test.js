/**
 * InspectionForm 时间回填 / 提交重入 回归（2026-09-18）
 *
 * 两个已复现缺陷（修复前均实测）：
 *
 *  ② 编辑回填时区平移：`initForm` 把后端 ISO 串（如 2026-10-01T01:00:00.000Z）
 *     直接塞给 value-format="YYYY-MM-DD HH:mm:ss" 的 el-date-picker。picker 会把
 *     ISO 里的小时当**字面小时**显示（实测显示 01:00，真实本地时间是 09:00），
 *     提交时 parseLocalDateTime 又按本地时间转回 ISO —— 于是「打开-保存」一次
 *     就把计划时间平移一个时区偏移（东八区 -8 小时）。实测回环：
 *     2026-10-01T01:00:00.000Z → 提交 2026-09-30T17:00:00.000Z。
 *
 *  ④ 提交无重入锁：`loading` 只在 el-form.validate 的异步回调里置位，同一 tick
 *     内连点 N 次会排队 N 次校验并全部提交（实测 3 次点击 → 3 次 PUT）。
 *
 * 断言口径：期望值在本文件内独立计算（Date 的本地 getter + 补零），不调用被测工具，
 * 避免实现错了两边一起错。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const create = vi.fn()
const update = vi.fn()
const searchDevicesApi = vi.fn()
const searchUsersApi = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    inspections: {
      create: (...a) => create(...a),
      update: (...a) => update(...a),
    },
    // 组件的远端搜索走这两个端点（此前 mock 缺失 → 搜索分支从未被测到）
    devices: { getList: (...a) => searchDevicesApi(...a) },
    users: { getList: (...a) => searchUsersApi(...a) },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import i18n from '@/i18n'
import InspectionForm from '@/components/InspectionForm.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

/** 独立计算 ISO → 本地墙钟串（与实现无关的口径） */
const localWall = (iso) => {
  const d = new Date(iso)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const START = '2026-10-01T01:00:00.000Z'
const END = '2026-10-02T01:00:00.000Z'

const editRow = (over = {}) => ({
  _id: 'insp-1',
  title: '季度巡检计划',
  inspectionType: 'daily',
  devices: ['d1'],
  assignedTo: ['u1'],
  planStartTime: START,
  planEndTime: END,
  checkItems: [{ name: '烟感外观', standard: '无破损' }],
  ...over,
})

/** 挂载受控宿主并打开对话框（组件在 watch(visible) 里 initForm） */
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
  return { props, ...active }
}

const saveBtn = (c) => c.findAll('footer .glass-btn--primary').slice(-1)[0]
const pickerValues = (c) => c.findAll('.el-date-editor input').map((i) => i.value)

afterEach(() => {
  active?.handle.unmount()
  active = null
  create.mockReset()
  update.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  searchDevicesApi.mockReset()
  searchUsersApi.mockReset()
})

describe('InspectionForm 检查项逐行校验（提交前拦截）', () => {
  /** 把第 index 个检查项的某个输入框写入值（Element Plus 的 el-input 需真实派发 input） */
  const setCheckItemField = async (c, index, placeholderText, value) => {
    const inputs = c
      .findAll('.el-input__inner')
      .filter((i) => i.getAttribute('placeholder') === placeholderText)
    const target = inputs[index]
    target.value = value
    target.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(2)
  }

  test('第 1 项缺名称：定位到第 1 项并阻止提交（不发请求）', async () => {
    const { props } = await open(null)
    const c = active
    await setCheckItemField(c, 0, i18n.global.t('inspection.checkItemNameLabel'), '')
    await setCheckItemField(c, 0, i18n.global.t('inspection.standardLabel'), '标准A')
    create.mockClear()
    ElMessage.warning.mockClear()

    click(saveBtn(c))
    await flush(10)

    expect(create).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith(
      i18n.global.t('inspection.checkItemNameRequired', { index: 1 })
    )
    expect(props.modelValue).toBe(true)
  })

  test('第 2 项缺标准：提示中的序号是 2（不是恒为 1 的写死值）', async () => {
    await open(
      editRow({
        checkItems: [
          { name: '外观', standard: '无破损' },
          { name: '压力', standard: '' },
        ],
      })
    )
    const c = active
    update.mockClear()
    ElMessage.warning.mockClear()

    click(saveBtn(c))
    await flush(10)

    expect(update).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith(
      i18n.global.t('inspection.checkItemStandardRequired', { index: 2 })
    )
  })

  test('纯空白名称视为缺失（trim 后判定，不得放行）', async () => {
    await open(editRow({ checkItems: [{ name: '   ', standard: '标准' }] }))
    const c = active
    update.mockClear()
    ElMessage.warning.mockClear()

    click(saveBtn(c))
    await flush(10)

    expect(update).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith(
      i18n.global.t('inspection.checkItemNameRequired', { index: 1 })
    )
  })

  test('第 2 项缺名称：名称分支的序号也必须是 2（不得写死为 1）', async () => {
    await open(
      editRow({
        checkItems: [
          { name: '外观', standard: '无破损' },
          { name: '', standard: '压力合格' },
        ],
      })
    )
    const c = active
    update.mockClear()
    ElMessage.warning.mockClear()

    click(saveBtn(c))
    await flush(10)

    expect(update).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith(
      i18n.global.t('inspection.checkItemNameRequired', { index: 2 })
    )
  })

  test('纯空白标准视为缺失（标准也要 trim 后判定，不得放行）', async () => {
    await open(editRow({ checkItems: [{ name: '外观', standard: '   ' }] }))
    const c = active
    update.mockClear()
    ElMessage.warning.mockClear()

    click(saveBtn(c))
    await flush(10)

    expect(update).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith(
      i18n.global.t('inspection.checkItemStandardRequired', { index: 1 })
    )
  })

  test('校验被拦下后重入锁必须已释放（用户补全后可正常提交）', async () => {
    // 用编辑态（editRow 自带 devices/assignedTo/时间），使表单除检查项外本身满足必填；
    // 这样「补齐检查项后能否提交」只取决于重入锁是否被正确释放。
    await open(editRow({ checkItems: [{ name: '', standard: '无破损' }] }))
    const c = active
    update.mockClear()
    click(saveBtn(c))
    await flush(10)
    expect(update).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalledWith(
      i18n.global.t('inspection.checkItemNameRequired', { index: 1 })
    )

    // 补齐检查项名称后再提交：应当真的发出请求（证明锁已释放）。
    // 时序说明：Element Plus 的表单校验链（async-validator → 回调）跨真实宏任务边界，
    // 只推 nextTick 到不了终态；此处按基座的既定做法等一个真实定时器窗口，
    // 再断言「请求已发出」。锁若泄漏（submitting 未复位），等多久都不会发出请求 → 本例如红。
    await setCheckItemField(c, 0, i18n.global.t('inspection.checkItemNameLabel'), '外观检查')
    update.mockResolvedValue({ data: { success: true } })
    click(saveBtn(c))
    await new Promise((resolve) => setTimeout(resolve, 50))
    await flush(8)
    expect(update, '补齐后仍被锁死 = 用户被永久卡住').toHaveBeenCalledTimes(1)
  })
})

describe('InspectionForm 编辑回填的时间口径', () => {
  test('ISO 串按本地时区回填到日期选择器（不得把 UTC 小时当字面小时）', async () => {
    const c = await open(editRow())
    const shown = pickerValues(c)
    expect(shown).toHaveLength(2)
    // 期望值独立计算：证明它不是 ISO 原串、也不是被截断的 UTC 片段
    expect(localWall(START)).not.toBe(START)
    expect(localWall(START)).not.toContain('T')
    expect(shown[0]).toBe(localWall(START))
    expect(shown[1]).toBe(localWall(END))
    expect(shown[0]).not.toContain('T')
    expect(shown[0]).not.toContain('Z')
    expect(c.errors).toEqual([])
  })

  test('打开后原样保存：计划时间回环不变（不得每次保存平移一个时区偏移）', async () => {
    update.mockResolvedValue({ data: { success: true } })
    const c = await open(editRow())
    click(saveBtn(c))
    await waitFor(() => update.mock.calls.length === 1, { message: '保存请求发出' })
    const payload = update.mock.calls[0][1]
    // 未改动任何字段就保存，两个时间必须与后端下发的 ISO 完全一致
    expect(payload.planStartTime).toBe(START)
    expect(payload.planEndTime).toBe(END)
  })

  test('空时间不被伪造：缺失时保持必填校验拦截，而不是回填成「现在」', async () => {
    const c = await open(editRow({ planStartTime: null, planEndTime: null }))
    expect(pickerValues(c)).toEqual(['', ''])
    update.mockResolvedValue({ data: { success: true } })
    click(saveBtn(c))
    await flush(30)
    expect(update).not.toHaveBeenCalled()
  })
})

describe('InspectionForm 提交重入防护', () => {
  test('同一 tick 连点 3 次：只提交 1 次，且按钮被锁定', async () => {
    let release
    update.mockImplementation(
      () =>
        new Promise((r) => {
          release = () => r({ data: { success: true } })
        })
    )
    const c = await open(editRow())
    const btn = saveBtn(c)
    // 连点发生在同一 tick：此时 DOM 尚未重渲染（按钮仍可点），
    // 三次点击都会真正进入 handleSubmit —— 正是重入锁要拦的场景
    click(btn)
    click(btn)
    click(btn)
    await flush(1)
    expect(saveBtn(c).disabled).toBe(true)
    expect(saveBtn(c).classList.contains('is-loading')).toBe(true)
    await waitFor(() => update.mock.calls.length >= 1, { message: '提交请求发出' })
    expect(release).toBeTruthy()
    release()
    await flush(20)
    // 后两次点击必须被丢弃：只发一个请求、只弹一次成功
    expect(update.mock.calls.length).toBe(1)
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('请求失败后解除锁定：提示错误，且能再次提交成功', async () => {
    update.mockRejectedValueOnce(new Error('boom'))
    update.mockResolvedValueOnce({ data: { success: true } })
    const c = await open(editRow())
    click(saveBtn(c))
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '失败提示' })
    await waitFor(() => !saveBtn(c).disabled, { message: '失败后解锁' })
    expect(update.mock.calls.length).toBe(1)
    click(saveBtn(c))
    await waitFor(() => update.mock.calls.length === 2, { message: '重试提交' })
    await flush(10)
    expect(update.mock.calls.length).toBe(2)
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('校验不通过时解锁：按钮不停留在 loading（否则用户被永久卡死）', async () => {
    const c = await open(editRow({ title: '' }))
    click(saveBtn(c))
    // 等校验真正判定失败：表单项进入 is-error 状态，且不得发出请求
    // 等校验真正判定失败：错误态出现，且重入锁必须已释放
    await waitFor(() => c.findAll('.el-form-item.is-error').length > 0, {
      message: '标题必填校验报错',
    })
    await waitFor(() => !saveBtn(c).disabled, { message: '校验失败后按钮解锁' })
    expect(update).not.toHaveBeenCalled()
    expect(saveBtn(c).disabled).toBe(false)
    expect(saveBtn(c).classList.contains('is-loading')).toBe(false)
    expect(c.findAll('.el-form-item.is-error').length).toBeGreaterThan(0)
    // 解锁后可重试（锁没有泄漏成永久锁定）
    click(saveBtn(c))
    await flush(30)
    expect(update).not.toHaveBeenCalled()
  })
})

describe('InspectionForm 检查项增删（编辑态真实交互）', () => {
  /**
   * 真实退化（每条都只会「看起来正常」）：
   *  - 「添加检查项」按钮失效（用户无法补充检查内容）；
   *  - 删除按 index 却删错行（splice 目标错位）；
   *  - 删到只剩 1 项后仍可继续删（表单进入无检查项状态，提交被后端拒）。
   *
   * 说明：新建态提交路径需要选设备与日期，而 jsdom 下 el-select 的下拉项点击
   * 与 el-date-picker 的值回写不可靠（实测下拉项点击后选中态不生效、picker
   * 写值后校验仍报必填），故提交路径不在本文件覆盖——已在
   * inspectionView.test.js 与后端契约测试中另行覆盖。
   */
  const namesOf = (c) =>
    c.findAll('.check-item').map((el) => el.querySelectorAll('.el-input__inner')[0].value)
  const stdsOf = (c) =>
    c.findAll('.check-item').map((el) => el.querySelectorAll('.el-input__inner')[1].value)

  test('添加检查项：点一次多一行空白检查项（用户能补充检查内容）', async () => {
    await open(editRow({ checkItems: [{ name: '外观', standard: '无破损' }] }))
    const c = active
    expect(c.findAll('.check-item').length).toBe(1)

    const addBtn = Array.from(c.findAll('button')).find((b) => b.textContent.includes('添加检查项'))
    expect(addBtn).toBeTruthy()
    click(addBtn)
    await flush(4)

    expect(c.findAll('.check-item').length).toBe(2)
    // 新增行必须是空白的（复制上一行内容会让用户误提交重复项）
    expect(namesOf(c)).toEqual(['外观', ''])
    expect(stdsOf(c)).toEqual(['无破损', ''])
    expect(c.errors).toEqual([])
  })

  test('删除检查项：删掉指定行，剩余行顺序不变（不得删错行）', async () => {
    await open(
      editRow({
        checkItems: [
          { name: '第一项', standard: 'S1' },
          { name: '第二项', standard: 'S2' },
          { name: '第三项', standard: 'S3' },
        ],
      })
    )
    const c = active
    expect(namesOf(c)).toEqual(['第一项', '第二项', '第三项'])

    // 删中间那行
    click(c.findAll('.check-item button')[1])
    await flush(4)
    expect(namesOf(c)).toEqual(['第一项', '第三项'])
    expect(stdsOf(c)).toEqual(['S1', 'S3'])
    expect(c.errors).toEqual([])
  })

  test('只剩 1 个检查项时不可再删（否则进入无检查项状态）', async () => {
    await open(editRow({ checkItems: [{ name: '唯一项', standard: 'S' }] }))
    const c = active
    expect(c.findAll('.check-item').length).toBe(1)
    click(c.findAll('.check-item button')[0])
    await flush(4)
    expect(c.findAll('.check-item').length).toBe(1)
    expect(namesOf(c)).toEqual(['唯一项'])
  })

  test('删除后补一项：新行序号连续且不串值（uid key 不得复用）', async () => {
    await open(
      editRow({
        checkItems: [
          { name: 'A项', standard: 'SA' },
          { name: 'B项', standard: 'SB' },
        ],
      })
    )
    const c = active
    click(c.findAll('.check-item button')[0]) // 删 A
    await flush(4)
    expect(namesOf(c)).toEqual(['B项'])

    const addBtn = Array.from(c.findAll('button')).find((b) => b.textContent.includes('添加检查项'))
    click(addBtn)
    await flush(4)
    // 新行空白且 B 项内容不被覆盖（uid key 复用会导致输入框内容错位）
    expect(namesOf(c)).toEqual(['B项', ''])
    expect(stdsOf(c)).toEqual(['SB', ''])
    expect(c.errors).toEqual([])
  })

  test('多行检查项各自绑定自己的值（v-model 不得串到别的行）', async () => {
    // 防退化：v-model 绑错（如绑到 form.checkItems[0]）→ 用户在第 3 行输入，
    // 第 1 行内容被改；或删除后剩余行内容错位。
    // 注：本用例对「行 key 复用（__uid 常量化）」是**等价变异**——实测 Vue 3
    // 在该路径下重复 key 不产生可观测差异（无警告、splice 后内容仍正确），
    // 故不宣称能抓该变异；它抓的是 v-model 绑定目标错误。
    await open(editRow({ checkItems: [{ name: 'A项', standard: 'SA' }] }))
    const c = active
    const addBtn = Array.from(c.findAll('button')).find((b) => b.textContent.includes('添加检查项'))
    click(addBtn)
    await flush(4)
    click(addBtn)
    await flush(4)
    expect(c.findAll('.check-item').length).toBe(3)

    const setRow = async (idx, name, std) => {
      const ins = c.findAll('.check-item')[idx].querySelectorAll('.el-input__inner')
      ins[0].value = name
      ins[0].dispatchEvent(new window.Event('input', { bubbles: true }))
      ins[1].value = std
      ins[1].dispatchEvent(new window.Event('input', { bubbles: true }))
      await flush(3)
    }
    await setRow(0, '第一行', 'S1')
    await setRow(1, '第二行', 'S2')
    await setRow(2, '第三行', 'S3')

    const namesOf = (cc) =>
      cc.findAll('.check-item').map((el) => el.querySelectorAll('.el-input__inner')[0].value)
    const stdsOf = (cc) =>
      cc.findAll('.check-item').map((el) => el.querySelectorAll('.el-input__inner')[1].value)
    expect(namesOf(c)).toEqual(['第一行', '第二行', '第三行'])
    expect(stdsOf(c)).toEqual(['S1', 'S2', 'S3'])

    // 删除中间行后，剩余两行内容必须仍各自正确
    click(c.findAll('.check-item button')[1])
    await flush(4)
    expect(namesOf(c)).toEqual(['第一行', '第三行'])
    expect(stdsOf(c)).toEqual(['S1', 'S3'])
  })

  test('结束时间与开始时间完全相同：同样必须拦下（边界含等号）', async () => {
    // 防退化：校验用 `<` 而非 `<=` → 零时长计划被放行（后端会拒或产生无意义计划）
    update.mockResolvedValue({ data: { success: true } })
    const { props } = await open(
      editRow({
        planStartTime: '2026-10-03T01:00:00.000Z',
        planEndTime: '2026-10-03T01:00:00.000Z',
      })
    )
    const c = active
    update.mockClear()
    click(saveBtn(c))
    await new Promise((r) => setTimeout(r, 60))
    await flush(8)

    expect(update).not.toHaveBeenCalled()
    expect(c.findAll('.el-form-item.is-error').length).toBeGreaterThan(0)
    expect(props.modelValue).toBe(true)
  })

  test('结束时间早于开始时间：校验拦下，不发请求', async () => {
    update.mockResolvedValue({ data: { success: true } })
    const { props } = await open(
      editRow({
        planStartTime: '2026-10-05T01:00:00.000Z',
        planEndTime: '2026-10-01T01:00:00.000Z',
      })
    )
    const c = active
    update.mockClear()
    click(saveBtn(c))
    await new Promise((r) => setTimeout(r, 60))
    await flush(8)

    expect(update).not.toHaveBeenCalled()
    expect(c.findAll('.el-form-item.is-error').length).toBeGreaterThan(0)
    expect(props.modelValue).toBe(true)
  })
})
