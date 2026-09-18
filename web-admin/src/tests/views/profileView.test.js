/**
 * ProfileView 行为测试（个人资料读取/保存/重置）
 *
 * 组件定位：登录后用户改自己的资料。三类真实退化都不会报错、只会「看起来正常」：
 *  1. 保存时把只读字段（username/roles）一并发给后端 → 后端 400 或静默忽略，
 *     用户以为改了；且**空值必须以 undefined 剔除**，不能发空串覆盖已有值。
 *  2. 保存成功后不更新本地 user 与 store → 左侧卡片与「重置」按钮仍显示旧值，
 *     用户会以为没保存成功。
 *  3. 重置按钮必须回填**当前 user**，而不是回到挂载时的快照（同会话内保存过两次
 *     就会把第二次的修改回滚掉）。
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

const open = async (me = ME) => {
  getMe.mockResolvedValue({ data: { success: true, data: { user: { ...me } } } })
  active = mountComponent(ProfileView, {
    setupStore: (pinia) => {
      useAuthStore(pinia).setCurrentUser({ ...me })
    },
  })
  await waitFor(() => active.text().includes(me.realName || me.username), {
    message: '资料加载完成',
  })
  await flush(3)
  return active
}

/** 按 label 文案定位输入框（Element Plus 的 el-input 在 el-form-item 内） */
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
  input.dispatchEvent(new window.Event('blur', { bubbles: true }))
  await flush(4)
}

/** 保存按钮：资料卡里的第一个 primary 按钮（改密卡/两步验证卡的按钮在后） */
const saveBtn = (c) => c.findAll('.glass-btn--primary')[0]

afterEach(() => {
  active?.handle.unmount()
  active = null
  // locale 是 i18n 单例上的全局状态：本文件有「同一实例切语言」的用例，
  // 不还原会渗到下一个用例（挂载时 mountComponent 虽会重设，但读源码的用例不受其管辖）
  i18n.global.locale.value = 'zh-CN'
  getMe.mockReset()
  updateProfile.mockReset()
  ElMessage.success.mockReset()
  ElMessage.error.mockReset()
  ElMessage.warning.mockReset()
})

describe('ProfileView 加载与回填', () => {
  test('挂载时拉取 /me 并回填表单与头像首字母', async () => {
    const c = await open()
    expect(getMe).toHaveBeenCalledTimes(1)
    expect(inputByLabel(c, '用户名').value).toBe('alice')
    expect(inputByLabel(c, '真实姓名').value).toBe('爱丽丝')
    expect(inputByLabel(c, '邮箱').value).toBe('alice@example.com')
    expect(inputByLabel(c, '手机号').value).toBe('13800000000')
    // 头像取用户名首字母大写
    expect(c.text()).toContain('A')
    expect(c.errors).toEqual([])
  })

  test('getMe 失败：静默降级为缓存数据（不得清空界面、不抛 Vue 错误）', async () => {
    getMe.mockRejectedValue(new Error('network'))
    active = mountComponent(ProfileView, {
      setupStore: (pinia) => {
        useAuthStore(pinia).setCurrentUser({ ...ME })
      },
    })
    await flush(10)
    const c = active
    // store 里的用户名仍在（组件挂载时从 store 初始化 user）
    expect(c.text()).toContain('alice')
    expect(c.errors).toEqual([])
  })
})

describe('ProfileView 保存载荷', () => {
  test('只提交可改字段，不得携带 username/_id/roles', async () => {
    updateProfile.mockResolvedValue({ data: { success: true } })
    const c = await open()
    click(saveBtn(c))
    await waitFor(() => updateProfile.mock.calls.length === 1, { message: '保存请求发出' })
    const payload = updateProfile.mock.calls[0][0]
    expect(Object.keys(payload).sort()).toEqual(['department', 'email', 'phone', 'realName'])
    expect(payload.username).toBeUndefined()
    expect(payload._id).toBeUndefined()
    expect(payload.roles).toBeUndefined()
  })

  test('清空可选字段：以 undefined 剔除，不得用空串覆盖后端已有值', async () => {
    updateProfile.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await setInput(inputByLabel(c, '邮箱'), '')
    await setInput(inputByLabel(c, '手机'), '')
    click(saveBtn(c))
    await waitFor(() => updateProfile.mock.calls.length === 1, { message: '保存请求发出' })
    const payload = updateProfile.mock.calls[0][0]
    expect(payload.email).toBeUndefined()
    expect(payload.phone).toBeUndefined()
    expect(payload.email).not.toBe('')
    expect(payload.phone).not.toBe('')
  })

  test('保存的值是用户实际输入（不是初始回填值）', async () => {
    updateProfile.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await setInput(inputByLabel(c, '姓名'), '鲍勃')
    await setInput(inputByLabel(c, '部门'), '运维部')
    click(saveBtn(c))
    await waitFor(() => updateProfile.mock.calls.length === 1, { message: '保存请求发出' })
    const payload = updateProfile.mock.calls[0][0]
    expect(payload.realName).toBe('鲍勃')
    expect(payload.department).toBe('运维部')
  })

  test('手机号格式非法：不提交（校验拦在请求之前）', async () => {
    updateProfile.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await setInput(inputByLabel(c, '手机'), '12345')
    click(saveBtn(c))
    await flush(40)
    expect(updateProfile).not.toHaveBeenCalled()
  })
})

describe('ProfileView 保存后的本地同步', () => {
  test('保存成功：更新 store 与界面（左侧卡片跟随新值）', async () => {
    updateProfile.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await setInput(inputByLabel(c, '姓名'), '新名字')
    click(saveBtn(c))
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '成功提示' })
    // store 已同步
    const auth = useAuthStore(c.pinia)
    expect(auth.currentUser.realName).toBe('新名字')
    // 界面上的回填值同样是新值
    expect(inputByLabel(c, '姓名').value).toBe('新名字')
    expect(c.errors).toEqual([])
  })

  test('重置按钮回到当前 user（保存后的值），而不是挂载时的旧快照', async () => {
    updateProfile.mockResolvedValue({ data: { success: true } })
    const c = await open()
    await setInput(inputByLabel(c, '姓名'), '第一改')
    click(saveBtn(c))
    await waitFor(() => ElMessage.success.mock.calls.length === 1, { message: '首次保存' })
    // 再改一次但不保存，然后重置 → 必须回到「第一改」而不是「爱丽丝」
    await setInput(inputByLabel(c, '姓名'), '未保存的第二改')
    const resetBtn = c.findAll('button').find((b) => b.textContent.includes('重置'))
    expect(resetBtn).toBeTruthy()
    click(resetBtn)
    await flush(6)
    expect(inputByLabel(c, '姓名').value).toBe('第一改')
  })
})

/**
 * O-3 时间格式：最近登录时间必须走单一事实来源（utils/datetime.formatTime）
 *
 * 真实退化有两类，且都是「看起来正常」的静默问题：
 *  1. 走 toLocaleString(locale)：格式随界面语言漂移——同一实例切到 en 后，同一列时间
 *     从「2026/10/1 09:00:00」变成「10/1/2026, 09:00:00」（月日顺序、分隔符、逗号全变），
 *     用户只是换了个语言，读时间的方式却变了；
 *  2. 脏数据（非空但不可解析的时间串）被直接 new Date 后 toLocaleString，渲染成
 *     "Invalid Date" —— 后端字段漂移或历史脏数据会以「界面坏了」的形式暴露给用户。
 *
 * 期望值一律用 Date 的本地 getter 独立计算，**不 import @/utils/datetime**：
 * 直接调用被测实现算期望值，会在实现写错时两边一起错。
 */
describe('ProfileView 时间格式（O-3 单一事实来源）', () => {
  const ISO_LOGIN = '2026-10-01T01:00:00.000Z'

  /** 本地时区「YYYY-MM-DD HH:mm:ss」定长串（各段补零），与实现无关 */
  const localStamp = (iso) => {
    const d = new Date(iso)
    const p = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  }

  const lastLoginRow = (c) =>
    c.findAll('.profile-meta li').find((li) => /最近登录|Last Login/.test(li.textContent))

  test('合法时间：精确渲染为本地 YYYY-MM-DD HH:mm:ss（不是原始 ISO、不含 Invalid）', async () => {
    const c = await open({ ...ME, lastLoginAt: ISO_LOGIN })
    const row = lastLoginRow(c)
    expect(row).toBeTruthy()
    // 前提自检：本地定长串与原始 ISO 必然不同（含 T/Z），故下面的精确断言不会变成
    // 「回显原始串也算过」；TZ=UTC 时它只证明格式契约，不宣称验证了时区换算。
    expect(localStamp(ISO_LOGIN)).not.toBe(ISO_LOGIN)
    expect(row.textContent.trim()).toBe(`最近登录：${localStamp(ISO_LOGIN)}`)
    // 合法值不得被误判为空值而显示占位符（变异注入「恒返回 —」必须在此红）
    expect(row.textContent.trim().endsWith('—')).toBe(false)
    expect(c.text()).not.toContain('Invalid')
  })

  test('脏数据（不可解析的时间串）：渲染占位符 —，不得出现 Invalid Date', async () => {
    const c = await open({ ...ME, lastLoginAt: 'not-a-date' })
    const row = lastLoginRow(c)
    expect(row).toBeTruthy()
    expect(row.textContent.trim()).toBe('最近登录：—')
    expect(c.text()).not.toContain('Invalid')
    expect(c.text()).not.toContain('NaN')
  })

  test('空值（null/undefined/空串）：该行整体不渲染（既有 v-if），页面不得出现 Invalid/undefined', async () => {
    for (const empty of [null, undefined, '']) {
      const c = await open({ ...ME, lastLoginAt: empty })
      expect(lastLoginRow(c)).toBeUndefined()
      expect(c.text()).not.toContain('Invalid')
      expect(c.text()).not.toContain('undefined')
      expect(c.text()).not.toContain('NaN')
      c.handle.unmount()
      active = null
    }
  })

  test('语言漂移守卫：同一实例切到 en-US 后时间文本完全不变（标签变英文证明切换真的生效）', async () => {
    const c = await open({ ...ME, lastLoginAt: ISO_LOGIN })
    expect(lastLoginRow(c).textContent.trim()).toBe(`最近登录：${localStamp(ISO_LOGIN)}`)

    i18n.global.locale.value = 'en-US'
    await flush(8)

    const row = lastLoginRow(c)
    expect(row).toBeTruthy()
    // 正：标签确实切成了英文（证明 locale 已切换，本用例不是恒真）
    expect(row.textContent.trim()).toBe(`Last Login：${localStamp(ISO_LOGIN)}`)
    // 反：时间串必须仍是同一个本地定长串，不得出现 en-US 的 toLocaleString 形态
    expect(row.textContent).not.toContain('10/1/2026')
    // 同实例的其它文案也切了英文
    expect(c.text()).toContain('Basic Info')
    expect(c.text()).not.toContain('基本信息')
  })
})
