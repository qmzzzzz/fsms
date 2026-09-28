/**
 * ProfileView：迟到的 /auth/me 不得吃掉用户还没保存的输入
 *
 * 组件挂载时会发一次 `/auth/me` 刷新资料。它是**异步**的：用户完全可能在它回来
 * 之前就开始编辑（慢网络下这个窗口有几百毫秒到几秒）。旧实现的 `watch(user)` 是
 * 无条件把服务端值灌进表单，于是这次刷新表现为"我刚才打的字自己没了"——
 * 不报错、不提示，只是输入消失。
 *
 * 四条用例分别钉住这条通道的四个方向：
 *   1. 已经动过表单 ⇒ 迟到的回包只能更新只读展示位，不得覆盖输入；
 *   2. 没动过表单 ⇒ 同步通道必须照常工作（防止"为了不覆盖就干脆不同步"这种过修）；
 *   3. 用户点过「重置」⇒ 重置是丢弃输入，不得把表单标成脏，否则随后的回包会被挡掉；
 *   4. 保存成功 ⇒ 服务端规范化值（邮箱小写）必须落回表单，哪怕此前表单是脏的。
 *
 * 时序用 deferred promise 确定性制造，不靠 sleep。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush, waitFor } from '../helpers/componentHarness'
import { useAuthStore } from '@/store'
import i18n from '@/i18n'

const getMe = vi.fn()
const updateProfile = vi.fn()
vi.mock('@/utils/api', () => ({
  api: {
    auth: {
      getMe: (...a) => getMe(...a),
      updateProfile: (...a) => updateProfile(...a),
    },
  },
  isCanceledError: () => false,
}))
vi.mock('element-plus/es/components/message/index.mjs', () => ({
  ElMessage: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

import ProfileView from '@/views/ProfileView.vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

let active = null

const ME = {
  _id: 'u1',
  username: 'alice',
  realName: '爱丽丝',
  email: 'alice@example.com',
  phone: '13800000000',
  department: '技术部',
  roles: [{ name: 'Operator' }],
  createdAt: '2026-01-01T00:00:00.000Z',
}

const inputByLabel = (c, labelText) => {
  const item = c.findAll('.el-form-item').find((it) => {
    const lb = it.querySelector('.el-form-item__label')
    return lb && lb.textContent.includes(labelText)
  })
  return item ? item.querySelector('input') : null
}

const setInput = async (input, value) => {
  input.value = value
  input.dispatchEvent(new window.Event('input', { bubbles: true }))
  await flush(4)
}

/** 挂载并让 /auth/me 停在"已发出、未返回"的状态 */
const mountWithPendingMe = () => {
  let resolveMe
  getMe.mockImplementation(
    () =>
      new Promise((r) => {
        resolveMe = r
      })
  )
  active = mountComponent(ProfileView, {
    setupStore: (pinia) => {
      useAuthStore(pinia).setCurrentUser({ ...ME })
    },
  })
  return { meResolved: (user) => resolveMe({ data: { success: true, data: { user } } }) }
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  // locale 与 ElMessage 都是跨用例/跨文件共享的单例状态，不还原会让"第一次成功提示"
  // 这种断言在文件执行顺序变化后偶然变红。
  i18n.global.locale.value = 'zh-CN'
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
  getMe.mockReset()
  updateProfile.mockReset()
})

describe('迟到的 /auth/me 与未保存的输入', () => {
  test('用户已开始编辑：回包不得覆盖输入，但只读展示位照常更新', async () => {
    const { meResolved } = mountWithPendingMe()
    await flush(6)

    const nameInput = inputByLabel(active, '真实姓名')
    await setInput(nameInput, '正在输入的名字')

    // 回包带着"另一个人的名字"迟到落地
    meResolved({
      ...ME,
      realName: '服务端的名字',
      department: '安全部',
      roles: [{ name: '审计专员' }],
    })
    // 先等到"确实刷新了"这一终态，再断言输入没被吃掉：
    // 反过来的话，"整页都没更新"也会让输入保持不变，用例就成了恒真。
    await waitFor(() => active.text().includes('安全部') && active.text().includes('审计专员'), {
      message: '只读展示位未随回包更新',
    })

    expect(inputByLabel(active, '真实姓名').value).toBe('正在输入的名字')
    // 反向确认这不是"整页都没刷新"。两个只读位走的是两条不同的路：
    // 部门由模板直读 user，角色文案由 watch 里的 updateRoleText 命令式刷新——
    // 后者才真正检验"闸门只管输入框，不管展示位"这条边界。
    expect(active.text()).toContain('安全部')
    expect(active.text()).toContain('审计专员')
    expect(active.errors).toEqual([])
  })

  test('用户没动过表单：同步通道必须照常把服务端值灌进来', async () => {
    const { meResolved } = mountWithPendingMe()
    await flush(6)
    expect(inputByLabel(active, '真实姓名').value).toBe('爱丽丝')

    meResolved({ ...ME, realName: '服务端的新名字' })
    await waitFor(() => inputByLabel(active, '真实姓名').value === '服务端的新名字', {
      message: '未编辑过表单时，迟到的回包没有同步进表单',
    })

    expect(inputByLabel(active, '真实姓名').value).toBe('服务端的新名字')
  })

  /**
   * 这条用例是 `flush: 'sync'` 的唯一牙齿。
   *
   * 脏标记的抑制靠 `syncingFromServer` 这个同步标志：`applyFromServer` 里赋值完
   * 就在 finally 把它复原。默认的 pre-flush 回调要晚一个微任务才跑，那时标志已经
   * 是 false，于是"服务端赋值"被记成"用户动过"。本页只有 onMounted 一次非请求式
   * 回包，保存路径又显式撤销脏标记，所以唯一能观察到这个缺陷的入口是「重置」：
   * 它走同一条 applyFromServer 通道，却没有人替它撤销被误标的脏标记。
   */
  test('用户点过重置但没留下输入：迟到的回包仍要同步（重置不算脏）', async () => {
    const { meResolved } = mountWithPendingMe()
    await flush(6)

    await setInput(inputByLabel(active, '真实姓名'), '随手打的字')
    click(active.findAll('button').find((b) => b.textContent.includes('重置')))
    await flush(6)
    expect(inputByLabel(active, '真实姓名').value).toBe('爱丽丝')

    meResolved({ ...ME, realName: '服务端的新名字' })
    await waitFor(() => inputByLabel(active, '真实姓名').value === '服务端的新名字', {
      message: '点过重置之后，迟到的回包被误标的脏标记挡掉了',
    })
    expect(inputByLabel(active, '真实姓名').value).toBe('服务端的新名字')
  })

  test('保存成功：规范化后的服务端值必须落回表单（此前表单是脏的）', async () => {
    getMe.mockResolvedValue({ data: { success: true, data: { user: { ...ME } } } })
    updateProfile.mockResolvedValue({
      data: { success: true, data: { ...ME, email: 'alice@example.com' } },
    })
    active = mountComponent(ProfileView, {
      setupStore: (pinia) => {
        useAuthStore(pinia).setCurrentUser({ ...ME })
      },
    })
    await flush(8)

    // 大写邮箱：后端会小写化落库，界面必须显示数据库里的形态而不是用户敲的形态
    await setInput(inputByLabel(active, '邮箱'), 'ALICE@Example.com')
    click(active.findAll('.glass-btn--primary')[0])
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '保存成功提示' })

    // 提交的是用户敲的形态（规范化归后端），表单显示的是回包形态
    expect(updateProfile).toHaveBeenCalledTimes(1)
    expect(updateProfile.mock.calls[0][0].email).toBe('ALICE@Example.com')
    // 表单回填要过 watch(user) → 渲染两跳，等终态而不是写死 tick 数
    await waitFor(() => inputByLabel(active, '邮箱').value === 'alice@example.com', {
      message: '保存后未把服务端规范化值回填表单',
    })
    expect(inputByLabel(active, '邮箱').value).toBe('alice@example.com')
    expect(active.errors).toEqual([])
  })
})
