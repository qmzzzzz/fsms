/**
 * DeviceMaintenanceDialog 提交防护测试（G3）
 *
 * 钉住三类可观测行为，各对应一个真实退化：
 *  1. 前置锁（G3）：validate 是 async——若 submitting 置位晚于第一个 await，
 *     确认窗口期里的第二次点击会并行跑进第二个 POST /devices/:id/maintenance，
 *     同设备同内容重复登记。受控 validate Promise 悬置第一次 submit，
 *     期间第二次点击必须被同步挡下，放行后也只发一次请求。
 *  2. validate 失败：无论 reject（async-validator 的失败形态）还是 resolve(false)
 *     （防御分支），都不得发出请求，且 submitting 由既有 finally 复位。
 *  3. 成功：emit saved + 收起弹窗；请求失败不误报成功。
 *
 * jsdom 事实：el-dialog append-to-body → 断言查 document.body。
 * validate 受控 = 拿 setupState.formRef（el-form 暴露实例）就地替换 validate；
 * 成功路径保留真实 validate 链（async-validator）不被 mock。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'

const m = vi.hoisted(() => ({
  addMaintenance: vi.fn(),
  message: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}))

vi.mock('@/utils/api', () => ({
  api: {
    devices: {
      addMaintenance: (...a) => m.addMaintenance(...a),
    },
  },
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({ ElMessage: m.message }))

import DeviceMaintenanceDialog from '@/components/DeviceMaintenanceDialog.vue'

const DEVICE = { _id: 'd1', deviceCode: 'HYD-001', deviceName: '1号消防泵' }

let active = null

afterEach(() => {
  active?.unmount()
  active = null
  document.body.querySelectorAll('.el-dialog').forEach((node) => node.remove())
  m.addMaintenance.mockReset()
  Object.values(m.message).forEach((fn) => fn.mockClear())
})

/** 受控宿主：visible/saved 记在本地 state，观察 emit 是否真实向上 */
const open = async (device = DEVICE) => {
  const state = reactive({ visible: true, saved: 0 })
  const Host = defineComponent({
    setup() {
      return () =>
        h(DeviceMaintenanceDialog, {
          visible: state.visible,
          device,
          'onUpdate:visible': (v) => {
            state.visible = v
          },
          onSaved: () => {
            state.saved += 1
          },
        })
    },
  })
  active = mountComponent(Host)
  await waitFor(() => document.body.querySelector('.el-dialog'), { message: '对话框渲染' })
  await flush(6)
  return state
}

const dlg = () => document.body.querySelector('.el-dialog')
const footerBtn = (text) =>
  Array.from(dlg().querySelectorAll('button')).find((b) => b.textContent.trim() === text)

const typeContent = async (text) => {
  const textarea = dlg().querySelector('.el-textarea__inner')
  textarea.value = text
  textarea.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(3)
}

/**
 * 拿 el-form 的暴露实例（defineExpose 出来的 validate/clearValidate 等）。
 * dev 模式下 Vue 在元素上挂 __vueParentComponent；组件 ref（formRef.value）
 * 读的正是 exposed 对象，就地替换 validate 即可让 submit 走受控 Promise。
 */
const formExposed = () => document.body.querySelector('.el-form').__vueParentComponent.exposed

describe('DeviceMaintenanceDialog 前置锁（G3）', () => {
  test('validate 悬置期间第二次点击被挡下：放行后只发一次 POST', async () => {
    let releaseValidate
    let resolvePost
    m.addMaintenance.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolvePost = resolve
        })
    )
    const state = await open()
    await typeContent('例行更换泵机密封圈')

    // 卡住第一次 submit 的 validate：换成永不自行落定的受控 Promise
    formExposed().validate = () =>
      new Promise((resolve) => {
        releaseValidate = resolve
      })

    const btn = footerBtn('确定')
    click(btn)
    click(btn)
    await flush(6)

    // validate 悬置：既不该发请求，也不该出现第二个并行 submit
    expect(m.addMaintenance).not.toHaveBeenCalled()

    releaseValidate(true)
    await waitFor(() => m.addMaintenance.mock.calls.length === 1, { message: '维护登记请求' })
    expect(m.addMaintenance.mock.calls[0][0]).toBe('d1')
    expect(m.addMaintenance.mock.calls[0][1]).toEqual({
      content: '例行更换泵机密封圈',
      type: 'routine',
    })

    resolvePost({ data: { success: true } })
    await flush(8)
    expect(m.message.success).toHaveBeenCalledWith('维护记录已添加')
    expect(state.saved).toBe(1)
    expect(state.visible).toBe(false)
  })

  test('提交中点遮罩不关窗：close-on-click-modal 已显式关闭（G3）', async () => {
    let releaseValidate
    m.addMaintenance.mockResolvedValue({ data: { success: true } })
    await open()
    await typeContent('例行更换泵机密封圈')
    formExposed().validate = () =>
      new Promise((resolve) => {
        releaseValidate = resolve
      })
    click(footerBtn('确定'))
    await flush(4)
    // 组件 props 直查：遮罩关窗会在提交中丢结果，必须显式禁用。
    // overlay 归 ElDialog 渲染，但中间可能隔渲染包装层，沿 parent 链找到持有
    // closeOnClickModal prop 的实例再断言（不猜层级）。
    const overlay = document.body.querySelector('.el-overlay')
    expect(overlay).toBeTruthy()
    let inst = overlay.__vueParentComponent
    while (inst && inst.props && !('closeOnClickModal' in inst.props)) inst = inst.parent
    expect(inst?.props?.closeOnClickModal).toBe(false)
    // 点击遮罩层本身：弹窗不得关闭
    overlay.dispatchEvent(new window.MouseEvent('click', { bubbles: true }))
    await flush(4)
    expect(dlg()).toBeTruthy()
    releaseValidate(true)
    await flush(8)
  })
})

describe('DeviceMaintenanceDialog validate 失败', () => {
  test('validate reject（async-validator 失败形态）：不出请求、submitting 复位', async () => {
    m.addMaintenance.mockResolvedValue({ data: { success: true } })
    await open()
    await typeContent('例行更换泵机密封圈')
    formExposed().validate = () => Promise.reject(new Error('content is required'))

    click(footerBtn('确定'))
    await flush(6)

    expect(m.addMaintenance).not.toHaveBeenCalled()
    expect(m.message.success).not.toHaveBeenCalled()
    // finally 复位：按钮可重试
    expect(footerBtn('确定').disabled).toBe(false)
  })

  test('validate resolve(false)（防御分支）：同样不出请求且复位', async () => {
    m.addMaintenance.mockResolvedValue({ data: { success: true } })
    await open()
    await typeContent('例行更换泵机密封圈')
    formExposed().validate = () => Promise.resolve(false)

    click(footerBtn('确定'))
    await flush(6)

    expect(m.addMaintenance).not.toHaveBeenCalled()
    expect(footerBtn('确定').disabled).toBe(false)
  })
})

describe('DeviceMaintenanceDialog 成功与失败路径', () => {
  test('成功（真实 validate 链）：成功提示 + emit saved + 收起弹窗', async () => {
    m.addMaintenance.mockResolvedValue({ data: { success: true } })
    const state = await open()
    await typeContent('年度检验并更换压力表')

    click(footerBtn('确定'))
    await waitFor(() => m.addMaintenance.mock.calls.length === 1, { message: '维护登记请求' })
    await flush(8)

    expect(m.message.success).toHaveBeenCalledWith('维护记录已添加')
    expect(state.saved).toBe(1)
    expect(state.visible).toBe(false)
  })

  test('请求失败：不误报成功、弹窗保持打开、按钮解锁可重试', async () => {
    m.addMaintenance.mockRejectedValue(new Error('boom'))
    const state = await open()
    await typeContent('例行更换泵机密封圈')

    click(footerBtn('确定'))
    await waitFor(() => m.addMaintenance.mock.calls.length === 1, { message: '维护登记请求' })
    await flush(8)

    expect(m.message.success).not.toHaveBeenCalled()
    expect(state.visible).toBe(true)
    expect(footerBtn('确定').disabled).toBe(false)
  })
})
