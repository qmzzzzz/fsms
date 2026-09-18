/**
 * InspectionReviewForm 行为测试（2026-09-18）
 *
 * 已修复缺陷（修复前实测复现）：组件读 `finding.deviceCode`，但后端
 * `InspectionService.getInspectionById` 用 `populate("findings.deviceId",
 * select:"deviceCode deviceName")` 返回**嵌套**对象（src/services/InspectionService.js:114，
 * probe 实测响应形状为 { deviceId: { deviceCode, deviceName }, issue, severity }）。
 * 原写法两个插值都是 undefined，隐患行渲染成「 - 」，复核人无法辨认是哪台设备出的问题。
 *
 * 挂载方式：组件自己按 inspectionId 拉数据，且只在 watch(visible) 里加载（无 onMounted），
 * 因此必须用受控宿主「先挂载、后翻转 modelValue」——若挂载时直接传 true，watch 不会触发，
 * 测试会变成「什么都没加载也通过」的真空断言（本轮首版即踩此坑）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, flush, click, waitFor } from '../helpers/componentHarness'

const getById = vi.fn()
const review = vi.fn()
const isCanceledError = vi.fn(() => false)
vi.mock('@/utils/api', () => ({
  api: {
    inspections: {
      getById: (...a) => getById(...a),
      review: (...a) => review(...a),
    },
  },
  isCanceledError: (...a) => isCanceledError(...a),
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import InspectionReviewForm from '@/components/InspectionReviewForm.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

/**
 * 受控宿主：把 v-model 接回本地 reactive 对象，才能在挂载后打开对话框，
 * 并断言组件真实 emit 的 update:modelValue / success。
 * 全文件只保留这一处 defineComponent（避免 vue/one-component-per-file 告警）。
 */
const makeHost = (inspectionId = 'insp-1') => {
  const props = reactive({ modelValue: false, inspectionId })
  const seen = { success: 0 }
  const Host = defineComponent({
    setup() {
      return () =>
        h(InspectionReviewForm, {
          modelValue: props.modelValue,
          inspectionId: props.inspectionId,
          'onUpdate:modelValue': (v) => {
            props.modelValue = v
          },
          onSuccess: () => {
            seen.success += 1
          },
        })
    },
  })
  return { Host, props, seen }
}

/** 打开对话框并等待 loadInspectionDetail 的异步 GET 落地 */
const open = async (detail, inspectionId) => {
  getById.mockResolvedValue({ data: { data: detail } })
  const host = makeHost(inspectionId)
  active = mountComponent(host.Host, {})
  await flush(2)
  host.props.modelValue = true
  await waitFor(
    () =>
      active.text().includes(detail?.title ?? '\u0000') ||
      active.findAll('.finding-device').length > 0,
    {
      message: '巡检详情加载完成',
    }
  )
  await flush(2)
  return { host, props: host.props, seen: host.seen, ...active }
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  getById.mockReset()
  review.mockReset()
  isCanceledError.mockReset()
  isCanceledError.mockReturnValue(false)
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
})

const textOf = (el) => el.textContent.replace(/\s+/g, ' ').trim()

describe('InspectionReviewForm 隐患设备展示（后端 populate 的嵌套形状）', () => {
  test('deviceCode/deviceName 在 deviceId 下时正确渲染（而非「 - 」）', async () => {
    const c = await open({
      title: '季度巡检',
      status: 'completed',
      findings: [
        {
          deviceId: { _id: 'd1', deviceCode: 'SMK-001', deviceName: '一层烟感' },
          issue: '外壳破损',
          severity: 'medium',
        },
      ],
    })
    expect(getById).toHaveBeenCalledWith('insp-1')
    // 先证明数据真的到了（否则下面的断言可能因为「根本没渲染」而假绿）
    expect(c.text()).toContain('季度巡检')
    expect(textOf(c.find('.finding-device'))).toBe('SMK-001 - 一层烟感')
    expect(c.find('.finding-device').textContent).not.toContain('undefined')
    expect(c.errors).toEqual([])
  })

  test('多条隐患逐条渲染各自的设备（不是只渲染第一条）', async () => {
    const c = await open({
      findings: [
        { deviceId: { deviceCode: 'A-1', deviceName: '甲' }, issue: 'i1', severity: 'low' },
        { deviceId: { deviceCode: 'B-2', deviceName: '乙' }, issue: 'i2', severity: 'high' },
      ],
    })
    expect(c.findAll('.finding-device').map(textOf)).toEqual(['A-1 - 甲', 'B-2 - 乙'])
    expect(c.findAll('.finding-issue').map(textOf)).toEqual(['i1', 'i2'])
  })

  test('兼容平铺形状（历史数据/其他调用方）：两个位置都读', async () => {
    const c = await open({
      findings: [{ deviceCode: 'FLAT-9', deviceName: '平铺设备', issue: 'x', severity: 'low' }],
    })
    expect(textOf(c.find('.finding-device'))).toBe('FLAT-9 - 平铺设备')
  })

  test('嵌套形状优先于平铺（两处都有值时取 deviceId，不产生错配）', async () => {
    const c = await open({
      findings: [
        {
          deviceId: { deviceCode: 'NESTED', deviceName: '嵌套' },
          deviceCode: 'TYPED',
          deviceName: '笔误',
          issue: 'x',
          severity: 'low',
        },
      ],
    })
    expect(textOf(c.find('.finding-device'))).toBe('NESTED - 嵌套')
  })

  test('无隐患时不渲染隐患区块，但基本信息区块照常渲染（防真空通过）', async () => {
    const c = await open({ title: '季度巡检', status: 'completed', findings: [] })
    expect(getById).toHaveBeenCalledWith('insp-1')
    expect(c.text()).toContain('季度巡检')
    expect(c.findAll('.finding-device')).toEqual([])
    expect(c.findAll('.el-alert')).toHaveLength(1)
    expect(c.errors).toEqual([])
  })
})

describe('InspectionReviewForm 提交与关闭契约', () => {
  /** 填审核意见（表单 rules 要求 min 10） */
  const fillComment = async (c, value) => {
    const box = c.find('textarea')
    box.value = value
    box.dispatchEvent(new window.Event('input', { bubbles: true }))
    await flush(3)
  }

  test('提交成功：审核结论随载荷提交（reviewResult 不得丢失）、关闭并 emit success', async () => {
    const c = await open({ title: '巡检A', findings: [] })
    review.mockResolvedValue({ data: { success: true } })
    await fillComment(c, '现场确认隐患已整改完毕')
    click(c.findAll('footer .glass-btn--primary')[0])
    await waitFor(() => c.seen.success === 1, { message: '提交成功后 success 事件' })
    expect(review).toHaveBeenCalledWith('insp-1', {
      reviewComment: '现场确认隐患已整改完毕',
      reviewResult: 'approved',
    })
    expect(c.seen.success).toBe(1)
    expect(c.props.modelValue).toBe(false)
    expect(ElMessage.success).toHaveBeenCalledTimes(1)
    expect(c.errors).toEqual([])
  })

  test('审核意见不足 10 字：不发起请求、不 emit success', async () => {
    const c = await open({ title: '巡检A', findings: [] })
    await fillComment(c, '太短')
    click(c.findAll('footer .glass-btn--primary')[0])
    await flush(8)
    expect(review).not.toHaveBeenCalled()
    expect(c.seen.success).toBe(0)
    expect(c.props.modelValue).toBe(true)
  })

  test('提交失败：提示错误且 loading 复位（按钮可再次点击）', async () => {
    const c = await open({ title: '巡检A', findings: [] })
    review.mockRejectedValue(new Error('boom'))
    await fillComment(c, '现场确认隐患已整改完毕')
    click(c.findAll('footer .glass-btn--primary')[0])
    await waitFor(
      () =>
        ElMessage.error.mock.calls.length === 1 &&
        c.findAll('footer .glass-btn--primary')[0].disabled === false,
      { message: '提交失败提示出现且按钮恢复可点击' }
    )
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
    expect(c.seen.success).toBe(0)
    const btn = c.findAll('footer .glass-btn--primary')[0]
    expect(btn.disabled).toBe(false)
    expect(btn.classList.contains('is-loading')).toBe(false)
  })

  test('关闭对话框：emit update:modelValue=false 且重新打开时不残留上一条数据', async () => {
    const c = await open({ title: '旧巡检', findings: [] })
    expect(c.text()).toContain('旧巡检')
    click(c.findAll('footer .glass-btn--default')[0])
    await flush(3)
    expect(c.props.modelValue).toBe(false)
    // 重新打开（同一组件实例）必须重新拉取，且旧数据先被清空
    getById.mockResolvedValue({ data: { data: { title: '新巡检', findings: [] } } })
    c.props.modelValue = true
    await waitFor(() => c.text().includes('新巡检'), { message: '重新打开后加载新数据' })
    expect(c.text()).toContain('新巡检')
    expect(c.text()).not.toContain('旧巡检')
    expect(getById).toHaveBeenCalledTimes(2)
  })
})

describe('InspectionReviewForm 加载失败路径', () => {
  test('加载失败：提示错误且不渲染隐患区块', async () => {
    getById.mockRejectedValue(new Error('network down'))
    const host = makeHost()
    active = mountComponent(host.Host, {})
    await flush(2)
    host.props.modelValue = true
    await waitFor(() => ElMessage.error.mock.calls.length === 1, { message: '加载失败提示' })
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
    expect(active.findAll('.finding-device')).toEqual([])
    expect(active.findAll('.el-alert')).toEqual([])
    expect(active.errors).toEqual([])
  })

  test('路由切换 abort 的在途请求：静默失败不弹错误（FE-L1）', async () => {
    isCanceledError.mockReturnValue(true)
    getById.mockRejectedValue(new Error('canceled'))
    const host = makeHost()
    active = mountComponent(host.Host, {})
    await flush(2)
    host.props.modelValue = true
    await waitFor(() => isCanceledError.mock.calls.length === 1, { message: 'abort 分支被走到' })
    expect(isCanceledError).toHaveBeenCalled()
    expect(ElMessage.error).not.toHaveBeenCalled()
    expect(active.errors).toEqual([])
  })
})
