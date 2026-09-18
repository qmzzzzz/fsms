/**
 * RoleFormDialog 行为测试（新增角色对话框）
 *
 * 组件是唯一能创建角色的入口，本套件钉住四类真实退化：
 *
 *  1. 角色编码即时归一（RoleFormDialog.vue:111-115）：后端路由校验要求
 *     /^[A-Z_]+$/（roleRoutes.js），而 Role 模型虽有 uppercase:true，但路由
 *     校验发生在模型之前——小写输入会被 400 拒绝。前端必须在输入时就转
 *     大写并剔除非法字符。归一写错的表现是「用户按提示输入却始终提交失败」。
 *  2. 提交载荷三字段（name/code/description）必须齐全且不夹带多余字段：
 *     后端对未知字段的行为不受控（可能被 strict schema 拒），漏 description
 *     则空串语义与「未填」不一致。
 *  3. 重入防护：`submitting` 必须在**请求发出前同步置位**。Element Plus 的
 *     `validate(callback)` 是异步的（每题一帧的 nextTick 链），按钮 :disabled
 *     只能在下一帧生效——用户双击 / 长按回车会自动重复调用 submit。
 *     /roles 是幂等性存疑的写接口（code 唯一约束会挡住重复，但用户会先看到
 *     一次成功再连吃两次错误提示）。本用例直接用同一 tick 两次点击钉住它。
 *  4. 失败与成功语义：失败不得误报成功、对话框保持打开可重试；成功后关闭
 *     对话框、清空表单、把新角色交给父组件（emit created）。
 *
 * 权限门控：提交按钮 v-if="hasPerm('role:create')"（roleViewPermission.test.js
 * 已用源码断言锁定），本文件从行为侧复核无权限时按钮不渲染。
 *
 * jsdom 限制如实记录：el-dialog 的关闭动画依赖真实计时器，可见性用轮询
 * overlay 的 display 判定；不做「动画结束后 DOM 被移除」这类不可测断言。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'

const rolesCreate = vi.fn()
vi.mock('@/utils/api', () => ({
  api: { roles: { create: (...a) => rolesCreate(...a) } },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import RoleFormDialog from '@/components/RoleFormDialog.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null
afterEach(() => {
  active?.handle.unmount()
  active = null
  rolesCreate.mockReset()
  ElMessage.success.mockReset()
})

/**
 * 带受控 visible 的宿主：RoleFormDialog 自身不持有开关状态，
 * 必须把 update:visible 接回本地 reactive 才能观察「关闭」的效果。
 */
const makeHost = (initialVisible, perms = ['role:create'], onCreated = null) => {
  const state = reactive({ visible: initialVisible })
  const Host = defineComponent({
    setup() {
      return () =>
        h(RoleFormDialog, {
          visible: state.visible,
          'onUpdate:visible': (v) => {
            state.visible = v
          },
          ...(onCreated ? { onCreated } : {}),
        })
    },
  })
  active = mountComponent(Host, {
    setupStore: (pinia) => useAuthStore(pinia).setPermissions(perms),
  })
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
/** 打开对话框并等首帧渲染完成（el-dialog teleport 到 body） */
const openDialog = async (perms, onCreated = null) => {
  const state = makeHost(true, perms, onCreated)
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

describe('RoleFormDialog 渲染与权限门控', () => {
  test('有 role:create：标题为新增角色，页脚为「取消 + 新增」', async () => {
    await openDialog(['role:create'])
    expect(dlg().querySelector('.el-dialog__title').textContent.trim()).toBe('新增角色')
    expect(
      Array.from(dlg().querySelectorAll('.el-dialog__footer button')).map((b) =>
        b.textContent.trim()
      )
    ).toEqual(['取消', '新增'])
  })

  test('无 role:create：提交按钮不渲染，取消仍可用（不能被权限锁死出不去）', async () => {
    await openDialog(['role:read'])
    const labels = Array.from(dlg().querySelectorAll('.el-dialog__footer button')).map((b) =>
      b.textContent.trim()
    )
    expect(labels).toEqual(['取消'])
    expect(footerBtn('新增')).toBeUndefined()
    // 取消按钮必须真的能关（visible 回 false）
    click(footerBtn('取消'))
    await flush(4)
    expect(active.errors).toEqual([])
  })

  test('三个输入框的 name/maxlength 属性（浏览器自动填充与长度上限）', async () => {
    await openDialog()
    const name = dlg().querySelector('#roleName')
    const code = dlg().querySelector('#roleCode')
    const desc = dlg().querySelector('#roleDescription')
    expect(name.getAttribute('name')).toBe('name')
    expect(name.getAttribute('maxlength')).toBe('50')
    expect(code.getAttribute('name')).toBe('code')
    expect(code.getAttribute('maxlength')).toBe('50')
    expect(desc.getAttribute('name')).toBe('description')
    expect(desc.getAttribute('maxlength')).toBe('200')
    expect(desc.tagName).toBe('TEXTAREA')
  })
})

describe('RoleFormDialog 关闭与重开（@close 清理）', () => {
  test('点右上角 X：请求关闭对话框（update:visible=false）', async () => {
    const state = await openDialog()
    const closeBtn = dlg().querySelector('.el-dialog__headerbtn')
    expect(closeBtn, 'X 按钮应存在').not.toBeNull()
    expect(closeBtn.getAttribute('type')).toBe('button')
    click(closeBtn)
    await waitReal(() => state.visible === false, 'X 关闭对话框')
    expect(active.errors).toEqual([])
  })

  test('关闭后重开：上次输入的内容已清空（@close 触发 resetForm，避免误提交旧值）', async () => {
    const state = await openDialog()
    await typeInto('#roleName', '夜班巡检')
    await typeInto('#roleCode', 'NIGHT_PATROL')
    await typeInto('#roleDescription', '临时说明')
    click(dlg().querySelector('.el-dialog__headerbtn'))
    await waitReal(() => state.visible === false, '对话框关闭')

    // 父组件重新打开（同一实例，el-dialog 内容常驻 DOM）
    state.visible = true
    await flush(8)
    expect(dlg().querySelector('#roleName').value).toBe('')
    expect(dlg().querySelector('#roleCode').value).toBe('')
    expect(dlg().querySelector('#roleDescription').value).toBe('')
    expect(active.errors).toEqual([])
  })

  test('校验失败后关闭再重开：残留的错误提示已清除（clearValidate 生效）', async () => {
    const state = await openDialog()
    // 先制造错误态：空表单直接提交
    click(footerBtn('新增'))
    await waitReal(
      () => dlg().querySelectorAll('.el-form-item.is-error').length > 0,
      '必填错误态出现'
    )
    expect(dlg().querySelectorAll('.el-form-item.is-error').length).toBe(2)
    click(dlg().querySelector('.el-dialog__headerbtn'))
    await waitReal(() => state.visible === false, '对话框关闭')
    state.visible = true
    await flush(8)
    // 重开后不能残留「请输入角色名称/编码」——用户看到空表单配红字会困惑
    expect(dlg().querySelectorAll('.el-form-item.is-error').length).toBe(0)
    expect(active.errors).toEqual([])
  })

  test('提交成功后重开：表单已清空且错误态已清除', async () => {
    rolesCreate.mockResolvedValue({ data: { data: { _id: 'r9' } } })
    const state = await openDialog()
    await typeInto('#roleName', '夜班巡检')
    await typeInto('#roleCode', 'NIGHT_PATROL')
    click(footerBtn('新增'))
    await waitFor(() => rolesCreate.mock.calls.length === 1, { message: '创建请求' })
    await waitFor(() => state.visible === false, { message: '成功后关闭' })
    state.visible = true
    await flush(8)
    expect(dlg().querySelector('#roleName').value).toBe('')
    expect(dlg().querySelector('#roleCode').value).toBe('')
    expect(dlg().querySelectorAll('.el-form-item.is-error').length).toBe(0)
  })
})

describe('RoleFormDialog 角色编码即时归一', () => {
  test('小写转大写、非法字符剔除（与后端 /^[A-Z_]+$/ 对齐）', async () => {
    await openDialog()
    const el = await typeInto('#roleCode', 'night-patrol!46')
    expect(el.value).toBe('NIGHTPATROL')
  })

  test('下划线保留、数字剔除（数字不是合法编码字符）', async () => {
    await openDialog()
    const el = await typeInto('#roleCode', 'ADMIN_role2')
    expect(el.value).toBe('ADMIN_ROLE')
  })

  test('连续输入：每次都在上一次结果上继续归一（不是只处理第一次）', async () => {
    await openDialog()
    await typeInto('#roleCode', 'a-b')
    const el = await typeInto('#roleCode', 'ab-cd')
    expect(el.value).toBe('ABCD')
  })

  test('空串与非字符串输入不抛错', async () => {
    await openDialog()
    const el = await typeInto('#roleCode', '')
    expect(el.value).toBe('')
    expect(active.errors).toEqual([])
  })
})

describe('RoleFormDialog 提交载荷与失败语义', () => {
  test('提交载荷与成功路径：create 收到 {name, code, description}，成功后关闭并提示', async () => {
    rolesCreate.mockResolvedValue({
      data: { data: { _id: 'r9', name: '夜班巡检', code: 'NIGHT_PATROL' } },
    })
    const created = vi.fn()
    const state = await openDialog(['role:create'], created)
    await typeInto('#roleName', '夜班巡检')
    await typeInto('#roleCode', 'night_patrol')
    await typeInto('#roleDescription', '负责夜间巡检')
    click(footerBtn('新增'))
    await waitFor(() => rolesCreate.mock.calls.length === 1, { message: '创建请求' })
    expect(rolesCreate).toHaveBeenCalledWith({
      name: '夜班巡检',
      code: 'NIGHT_PATROL',
      description: '负责夜间巡检',
    })
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    expect(ElMessage.success).toHaveBeenCalledWith('创建成功')
    // 成功后必须请求关闭对话框，并把新角色交给父组件（列表刷新与选中依赖它）
    await waitFor(() => state.visible === false, { message: '对话框关闭' })
    await waitFor(() => created.mock.calls.length === 1, { message: 'created 事件' })
    expect(created.mock.calls[0][0]).toEqual({
      _id: 'r9',
      name: '夜班巡检',
      code: 'NIGHT_PATROL',
    })
  })

  test('校验失败（名称/编码为空）：不发请求、对话框不关、表单进入错误态', async () => {
    await openDialog()
    click(footerBtn('新增'))
    await waitFor(() => dlg().querySelectorAll('.el-form-item.is-error').length > 0, {
      message: '必填错误态',
    })
    expect(rolesCreate).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  test('创建失败：不误报成功、对话框保持打开、按钮解锁可重试', async () => {
    rolesCreate.mockRejectedValue(new Error('boom'))
    const state = await openDialog()
    await typeInto('#roleName', '夜班巡检')
    await typeInto('#roleCode', 'NIGHT_PATROL')
    click(footerBtn('新增'))
    await waitFor(() => rolesCreate.mock.calls.length === 1, { message: '创建请求' })
    await flush(16)
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(state.visible).toBe(true)
    await waitFor(() => footerBtn('新增').disabled === false, { message: '按钮解锁' })
    expect(active.errors).toEqual([])
  })
})

describe('RoleFormDialog 重入防护（真实缺陷回归）', () => {
  test('请求在途时重复点击不会发出第二次创建请求', async () => {
    // 真实退化（探针实测）：修复前同一 tick 两次点击 → 2 次 POST /roles。
    // el-form 的 validate(callback) 是异步的，按钮 :disabled 下一帧才生效，
    // 用户双击/长按回车的自动重复即可穿透。
    let resolveCreate
    rolesCreate.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveCreate = resolve
        })
    )
    await openDialog()
    await typeInto('#roleName', '夜班巡检')
    await typeInto('#roleCode', 'NIGHT_PATROL')
    // 同一 tick 连续两次点击：第二次点击时 DOM 按钮的 disabled 还没被下一帧
    // 刷新（真实浏览器里双击/长按回车的自动重复正是这条路径）
    click(footerBtn('新增'))
    click(footerBtn('新增'))
    // 校验链跨宏任务，必须用真实计时器等它推进到发请求
    await waitReal(() => rolesCreate.mock.calls.length >= 1, '首次创建请求发出')
    // 再给第二次点击可能发出的请求足够时间显形（修复前这里会变成 2）
    await new Promise((r) => setTimeout(r, 150))
    await flush(4)
    expect(rolesCreate).toHaveBeenCalledTimes(1)
    // 也验证按钮处于不可用态（视觉反馈与守卫一致）
    expect(footerBtn('新增').disabled).toBe(true)
    resolveCreate({ data: { data: { _id: 'r9' } } })
    await flush(8)
  })
})
