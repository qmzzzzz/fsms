/**
 * RoleListPanel 组件级行为测试（角色列表：骨架 / 门控 / 选中 / 事件）
 *
 * 与 roleView.test.js 的分工：那份是**集成**路径（挂 RoleView 走完整加载链路），
 * 本文件把 RoleListPanel 单独挂载，钉住四条独立契约——它们各自对应一种
 * 在集成测试里看不见（或被掩盖）的真实退化：
 *
 *  1. 骨架屏条件必须是 `loading && roles.length === 0`：
 *     - 漏掉 roles.length 判断 → 刷新列表时把已有数据换成骨架，界面闪烁；
 *     - 漏掉 loading → 空列表与「加载中」看起来一样，用户不知道要不要等。
 *  2. 删除按钮门控 `canDelete && !role.isBuiltIn` 的四象限：
 *     只测「有权限且非内置」会让另外三象限静默回退（尤其
 *     「无权限但非内置」必须**什么都不显示**——v-else-if 写成 v-else 会
 *     给无权用户显示「内置角色」标签，语义完全错位）。
 *  3. `@click.stop` 不可省：删除按钮的点击若不阻止冒泡，会同时触发行的
 *     select —— 用户点「删除」的瞬间右侧面板已切到该角色，确认框还在问
 *     「是否删除」，操作对象与视线对象不一致。
 *  4. 选中高亮按 _id 比对：用对象引用比对会在列表重拉（新对象）后丢失高亮，
 *     用 name/code 比对则在重名角色上串高亮。
 *
 * 事件断言用「emit 参数」而不是「被调用过」：select 必须带上 role 对象本身，
 * 父组件（RoleView）依赖它的 _id 去拉权限；delete 同理。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { mountComponent, click, flush } from '../helpers/componentHarness'
import RoleListPanel from '@/components/RoleListPanel.vue'

const BUILTIN = { _id: 'r1', name: '管理员', code: 'ADMIN', userCount: 3, isBuiltIn: true }
const PLAIN = { _id: 'r2', name: '巡检员', code: 'INSPECTOR', userCount: 0, isBuiltIn: false }

let active = null
const open = async (props) => {
  active = mountComponent(RoleListPanel, { props })
  await flush(4)
  return active
}
const items = (c) =>
  c.findAll('.glass-role-item').map((el) => ({
    name: el.querySelector('.glass-role-item__name').textContent,
    code: el.querySelector('.glass-role-item__code').textContent,
    count: el.querySelector('.glass-role-item__count').textContent,
    builtin: el.querySelector('.glass-role-item__builtin')?.textContent ?? null,
    deleteBtn: el.querySelector('.role-delete-btn') !== null,
    active: el.classList.contains('glass-role-item--active'),
  }))

afterEach(() => {
  active?.handle.unmount()
  active = null
})

describe('RoleListPanel 骨架与空态', () => {
  test('加载中且无数据：渲染骨架屏，不渲染任何行', async () => {
    const c = await open({ roles: [], loading: true })
    expect(c.findAll('.glass-skeleton')).toHaveLength(1)
    expect(c.findAll('.glass-role-item')).toEqual([])
  })

  test('加载中但有数据：渲染列表而非骨架（刷新时不闪烁）', async () => {
    const c = await open({ roles: [BUILTIN, PLAIN], loading: true })
    expect(c.findAll('.glass-skeleton')).toEqual([])
    expect(c.findAll('.glass-role-item')).toHaveLength(2)
  })

  test('非加载且无数据：空列表（不渲染骨架，避免「永远在加载」的错觉）', async () => {
    const c = await open({ roles: [], loading: false })
    expect(c.findAll('.glass-skeleton')).toEqual([])
    expect(c.findAll('.glass-role-item')).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('默认 props（不传 roles/loading）等价于空列表非加载态，不抛错', async () => {
    const c = await open({})
    expect(c.findAll('.glass-role-item')).toEqual([])
    expect(c.findAll('.glass-skeleton')).toEqual([])
    expect(c.errors).toEqual([])
  })
})

describe('RoleListPanel 行内容与门控四象限', () => {
  test('行渲染 name/code/计数；userCount 缺省显示 0', async () => {
    const c = await open({
      roles: [BUILTIN, { _id: 'r3', name: '新角色', code: 'NEW' }],
    })
    expect(items(c)).toEqual([
      {
        name: '管理员',
        code: 'ADMIN',
        count: '3用户管理',
        builtin: '内置角色',
        deleteBtn: false,
        active: false,
      },
      {
        name: '新角色',
        code: 'NEW',
        count: '0用户管理',
        builtin: null,
        deleteBtn: false,
        active: false,
      },
    ])
  })

  test('canDelete=true 且非内置：显示删除按钮，不显示内置标记', async () => {
    const c = await open({ roles: [BUILTIN, PLAIN], canDelete: true })
    expect(items(c).map((r) => ({ builtin: r.builtin, deleteBtn: r.deleteBtn }))).toEqual([
      { builtin: '内置角色', deleteBtn: false },
      { builtin: null, deleteBtn: true },
    ])
  })

  test('canDelete=false 且非内置：既不显示删除按钮也不显示内置标记（v-else-if 语义）', async () => {
    // 这是最容易被写错的一格：v-else-if 若写成 v-else，无权用户会看到
    // 「内置角色」标签，把普通角色误报成内置角色
    const c = await open({ roles: [PLAIN], canDelete: false })
    expect(items(c)).toEqual([
      {
        name: '巡检员',
        code: 'INSPECTOR',
        count: '0用户管理',
        builtin: null,
        deleteBtn: false,
        active: false,
      },
    ])
  })

  test('canDelete=true 且内置：仍不显示删除按钮，显示内置标记', async () => {
    const c = await open({ roles: [BUILTIN], canDelete: true })
    expect(items(c)[0]).toMatchObject({ builtin: '内置角色', deleteBtn: false })
  })
})

describe('RoleListPanel 选中高亮', () => {
  test('按 _id 比对：命中高亮、未命中不高亮', async () => {
    const c = await open({ roles: [BUILTIN, PLAIN], currentRole: { _id: 'r2', name: '别的对象' } })
    expect(items(c).map((r) => r.active)).toEqual([false, true])
  })

  test('currentRole 为 null 时全部不高亮（不抛错）', async () => {
    const c = await open({ roles: [BUILTIN, PLAIN], currentRole: null })
    expect(items(c).map((r) => r.active)).toEqual([false, false])
    expect(c.errors).toEqual([])
  })

  test('同 name/code 但 _id 不同的角色不会误高亮（不能用显示字段比对）', async () => {
    const twin = { _id: 'r9', name: '管理员', code: 'ADMIN', userCount: 0, isBuiltIn: false }
    const c = await open({ roles: [BUILTIN, twin], currentRole: { _id: 'r1' } })
    expect(items(c).map((r) => r.active)).toEqual([true, false])
  })
})

describe('RoleListPanel 事件', () => {
  test('点击行 emit select 并带 role 对象本身', async () => {
    const onSelect = vi.fn()
    const c = await open({ roles: [BUILTIN, PLAIN], onSelect })
    click(c.findAll('.glass-role-item')[1])
    await flush(2)
    expect(onSelect).toHaveBeenCalledTimes(1)
    expect(onSelect.mock.calls[0][0]).toBe(PLAIN)
    expect(c.errors).toEqual([])
  })

  test('点击删除按钮 emit delete 且**不**触发 select（stopPropagation）', async () => {
    const onSelect = vi.fn()
    const onDelete = vi.fn()
    const c = await open({ roles: [PLAIN], canDelete: true, onSelect, onDelete })
    click(c.find('.role-delete-btn'))
    await flush(2)
    expect(onDelete).toHaveBeenCalledTimes(1)
    expect(onDelete.mock.calls[0][0]).toBe(PLAIN)
    expect(onSelect).not.toHaveBeenCalled()
  })

  test('内置角色行没有删除按钮，点击只触发 select', async () => {
    const onSelect = vi.fn()
    const onDelete = vi.fn()
    const c = await open({ roles: [BUILTIN], canDelete: true, onSelect, onDelete })
    click(c.find('.glass-role-item'))
    await flush(2)
    expect(onSelect).toHaveBeenCalledTimes(1)
    expect(onDelete).not.toHaveBeenCalled()
  })

  test('删除按钮是 type=button 且带 title（不触发表单提交、可悬停识别）', async () => {
    const c = await open({ roles: [PLAIN], canDelete: true })
    const btn = c.find('.role-delete-btn')
    expect(btn.getAttribute('type')).toBe('button')
    expect(btn.getAttribute('title')).toBe('删除')
  })
})
