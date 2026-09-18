/**
 * 审计报告 §13 V-6：useRolePermissions「模块级全选/清空」的边界语义
 *
 * 两个真实边界（此前无任何测试覆盖，`git grep toggleModule -- src/tests` 为空）：
 *  1. 搜索态下点「全选本模块」只应作用于**当前可见（过滤后）**的权限，
 *     被关键字过滤掉的权限不得被误改（前端复审 B-1 的修复目标）；
 *  2. 过滤结果为空时（理论上模块已不可见）保守不动集合、不置脏标记。
 * 非搜索态行为不变：作用于模块全部权限。
 *
 * 断言对象是 checkedPermIds / hasUnsavedChanges / moduleList.activeCount 等**可观测状态**，
 * 不是源码文本：把 useRolePermissions.js:173-179 的 `kw ? filter : module.permissions`
 * 改回 `module.permissions`，第 1、2 条用例会立即变红。
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { createI18n } from 'vue-i18n'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

const messages = { 'zh-CN': zhCN, 'en-US': enUS }
const makeT = (locale) => {
  const i18n = createI18n({ legacy: false, locale, messages })
  return (key, params) => i18n.global.t(key, params)
}
const tZh = makeT('zh-CN')

// composable 内部调 useI18n()，替换为绑定真实词表的翻译函数（与 labelMapsSemantics 同法）
vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, useI18n: () => ({ t: (key, params) => tZh(key, params) }) }
})

const perm = (id, code, name) => ({ _id: id, code, name, type: 'api' })
const oid = (n) => String(n).padStart(24, '0')

// 一个模块两颗权限，编码/名称都便于用 "alarm" 精确命中其中一颗
const TWO_PERMS = [perm(oid(1), 'device:read', '设备查看'), perm(oid(2), 'alarm:read', '报警查看')]

const build = async (permIds = []) => {
  setActivePinia(createPinia())
  const { useRolePermissions } = await import('@/composables/useRolePermissions')
  const ui = useRolePermissions()
  ui.setTree([{ module: 'device', name: '设备管理', children: TWO_PERMS }])
  ui.setChecked(new Set(permIds))
  return ui
}

describe('§13 V-6 useRolePermissions.toggleModule 过滤态与全选/清空语义', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  test('非搜索态：全选作用于模块全部权限', async () => {
    const ui = await build([])
    ui.toggleModule(ui.moduleList.value[0])

    expect([...ui.checkedPermIds.value].sort()).toEqual([oid(1), oid(2)].sort())
    expect(ui.moduleList.value[0].activeCount).toBe(2)
    expect(ui.hasUnsavedChanges.value).toBe(true)
  })

  test('toggleModule 后集合被替换为新 Set（原地 mutate 不会触发 Vue 依赖，卡片不重绘）', async () => {
    const ui = await build([])
    const before = ui.checkedPermIds.value

    ui.toggleModule(ui.moduleList.value[0])

    // 与 togglePerm 同契约：原地 add 只改 Set 内部，Vue 无法感知（ref 未变）；
    // 必须整体替换才能让卡片/统计重算。实测：去掉 :200 的替换后本用例变红。
    expect(ui.checkedPermIds.value).not.toBe(before)
    expect(ui.checkedPermIds.value.size).toBe(2)
  })

  test('非搜索态：已全选时再次点击即清空整个模块', async () => {
    const ui = await build([oid(1), oid(2)])
    ui.toggleModule(ui.moduleList.value[0])

    expect(ui.checkedPermIds.value.size).toBe(0)
    expect(ui.moduleList.value[0].activeCount).toBe(0)
  })

  test('搜索态全选：只加被过滤命中的权限，被过滤掉的权限不被误改（V-6 核心）', async () => {
    // device:read 已勾选，alarm:read 未勾选；搜索 "alarm" 只应看见后者
    const ui = await build([oid(1)])
    ui.permSearch.value = 'alarm'

    const visible = ui.filteredModules.value
    expect(visible).toHaveLength(1)
    expect(visible[0].permissions.map((p) => p._id)).toEqual([oid(2)])

    // 卡片上点击的是**过滤后**的模块对象（RoleView 用 filteredModules 渲染）
    ui.toggleModule(visible[0])

    // 未被搜索命中的 device:read 保持原状（仍勾选、未被误删）
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    // 命中的 alarm:read 被加上
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(true)
    expect(ui.checkedPermIds.value.size).toBe(2)
  })

  test('搜索态清空：只移除可见且已勾选的权限，不可见权限保持勾选（V-6 核心）', async () => {
    const ui = await build([oid(1), oid(2)])
    ui.permSearch.value = 'alarm'

    const visible = ui.filteredModules.value
    expect(visible[0].permissions.map((p) => p._id)).toEqual([oid(2)])

    ui.toggleModule(visible[0])

    // 关键回归：修复前会让整模块清空，device:read 一并丢失
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(false)
    expect(ui.checkedPermIds.value.size).toBe(1)
  })

  test('搜索态按编码匹配同样生效（name 未命中但 code 命中）', async () => {
    const ui = await build([])
    ui.permSearch.value = 'device:r'

    const visible = ui.filteredModules.value
    expect(visible[0].permissions.map((p) => p._id)).toEqual([oid(1)])

    ui.toggleModule(visible[0])

    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(false)
  })

  test('过滤结果为空：保守不动集合，也不置脏标记（源码 :180-181 的防御分支）', async () => {
    const ui = await build([oid(1)])
    ui.permSearch.value = 'alarm'

    // 绕过 filteredModules（正常情况下空模块不会渲染），直接喂一个「可见权限为空」的模块对象
    const emptyVisibleModule = {
      ...ui.moduleList.value[0],
      permissions: [],
    }
    ui.toggleModule(emptyVisibleModule)

    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    expect(ui.checkedPermIds.value.size).toBe(1)
    expect(ui.hasUnsavedChanges.value).toBe(false)
  })

  test('清空后再全选：同一搜索态下可来回切换且不残留', async () => {
    const ui = await build([oid(1), oid(2)])
    ui.permSearch.value = 'alarm'
    const visible = () => ui.filteredModules.value[0]

    ui.toggleModule(visible()) // 清可见（仅 alarm:read）
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(false)
    ui.toggleModule(visible()) // 再全选回来
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(true)
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    expect(ui.checkedPermIds.value.size).toBe(2)
  })

  test('清空搜索词后回到非搜索态语义：作用于模块全部权限', async () => {
    const ui = await build([oid(1)])
    ui.permSearch.value = 'alarm'
    ui.toggleModule(ui.filteredModules.value[0]) // 勾上 alarm:read
    ui.permSearch.value = ''

    ui.toggleModule(ui.filteredModules.value[0]) // 非搜索态：两颗都已勾选 → 清空
    expect(ui.checkedPermIds.value.size).toBe(0)
  })
  // ===== 内层防御：调用方传入「未过滤模块」时，函数自身仍按搜索词收敛范围 =====
  //
  // 说明：RoleView 用 filteredModules 渲染卡片（外层已过滤），因此下面这些用例
  // 走的是 toggleModule 内部的第二道 `kw ? filter` 防御。保留它的理由是
  // toggleModule 是 composable 的公开 API，不能假设调用方一定先过滤；
  // 若删掉 useRolePermissions.js:173-179 的内层过滤，本组用例会变红
  //（首版仅用 filteredModules 调用的用例无法区分，实测变异存活——故补此组）。

  test('内层防御·全选：传入未过滤模块 + 搜索态，只加搜索命中的权限', async () => {
    const ui = await build([]) // 两颗都未勾选
    ui.permSearch.value = 'alarm'

    // 故意传原始（未过滤）模块：device:read 不含 "alarm"
    ui.toggleModule(ui.moduleList.value[0])

    // 未命中的 device:read 不得被加上
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(false)
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(true)
    expect(ui.checkedPermIds.value.size).toBe(1)
  })

  test('内层防御·清空：传入未过滤模块 + 搜索态，只移除搜索命中的权限', async () => {
    const ui = await build([oid(1), oid(2)])
    ui.permSearch.value = 'alarm'

    ui.toggleModule(ui.moduleList.value[0])

    // 关键回归：内层过滤缺失会把 device:read 一并清掉（集合变空）
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(false)
    expect(ui.checkedPermIds.value.size).toBe(1)
  })

  test('内层防御·权限项缺 name：搜索仍按 code 命中且不抛错（(p.name || "") 兜底）', async () => {
    const ui = await build([])
    ui.setTree([
      {
        module: 'device',
        name: '设备管理',
        children: [
          { _id: oid(1), code: 'device:read', type: 'api', children: [] },
          { _id: oid(2), code: 'alarm:read', name: '报警查看', type: 'api', children: [] },
        ],
      },
    ])
    ui.permSearch.value = 'device:r'

    // 第一颗没有 name 字段：若实现直接 p.name.toLowerCase() 会抛 TypeError
    expect(() => ui.toggleModule(ui.moduleList.value[0])).not.toThrow()
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    // 未被搜索命中的第二颗不得被改动
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(false)
  })

  test('内层防御·权限项缺 code：搜索按 name 判否后仍走 (p.code || "") 兜底，不抛错也不误命中', async () => {
    const ui = await build([])
    ui.setTree([
      {
        module: 'device',
        name: '设备管理',
        children: [
          // name 不命中搜索词，且完全没有 code 字段：
          // 左半 `(p.name || '')` 判否后必须进入右半 `(p.code || '')` 兜底，
          // 若实现写成 p.code.toLowerCase() 会在此抛 TypeError
          { _id: oid(1), name: '无关项', type: 'api', children: [] },
          { _id: oid(2), name: '报警查看', code: 'alarm:read', type: 'api', children: [] },
        ],
      },
    ])
    ui.permSearch.value = 'alarm'

    expect(() => ui.toggleModule(ui.moduleList.value[0])).not.toThrow()
    // 缺 code 的项不得被误判为命中
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(false)
    expect(ui.checkedPermIds.value.has(oid(2))).toBe(true)
    expect(ui.checkedPermIds.value.size).toBe(1)
  })

  test('内层防御·零命中：搜索词谁都不匹配时不改集合、不置脏', async () => {
    const ui = await build([oid(1)])
    ui.permSearch.value = 'no-such-perm-xyz'

    ui.toggleModule(ui.moduleList.value[0])

    expect([...ui.checkedPermIds.value]).toEqual([oid(1)])
    expect(ui.hasUnsavedChanges.value).toBe(false)
  })
})

// ============================================================================
// 权限树展平（flattenPermissionNodes）：后端存在「权限挂权限」的多级嵌套，
// 只读模块第一层 children 会丢权限 —— 已启用项显示不全、也无法单独改。
// 断言对象是 moduleList 的可观测内容（权限 _id 序列 + activeCount），
// 不是源码文本：删掉递归调用 / 放宽 ObjectId 正则 / 去掉 seen 去重，本组即红。
// ============================================================================
describe('useRolePermissions 权限树展平（嵌套权限 / 虚拟分组 / 去重）', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  const nested = () => [
    {
      module: 'device',
      name: '设备管理',
      // module-xxx 是虚拟分组节点（无合法 ObjectId），自身不该成为权限项
      _id: 'module-device',
      children: [
        { _id: oid(1), code: 'device:read', name: '查看设备', type: 'api', children: [] },
        {
          _id: oid(2),
          code: 'device:manage',
          name: '设备管理',
          type: 'menu',
          // 权限挂权限：子权限的 parent 是另一个权限而非模块
          children: [
            { _id: oid(3), code: 'device:create', name: '新增设备', type: 'button', children: [] },
            {
              _id: oid(4),
              code: 'device:delete',
              name: '删除设备',
              type: 'button',
              children: [
                { _id: oid(5), code: 'device:purge', name: '彻底删除', type: 'api', children: [] },
              ],
            },
          ],
        },
      ],
    },
  ]

  test('三级嵌套权限全部展平进同一模块（缺递归则深层权限丢失）', async () => {
    const ui = await build([])
    ui.setTree(nested())

    expect(ui.moduleList.value).toHaveLength(1)
    // 关键回归：只读第一层 children 时这里只有 [1, 2]，深层 3/4/5 全部丢失
    expect(ui.moduleList.value[0].permissions.map((p) => p._id)).toEqual([
      oid(1),
      oid(2),
      oid(3),
      oid(4),
      oid(5),
    ])
    expect(ui.totalPermCount.value).toBe(5)
  })

  test('权限层虚拟分组节点（无 _id / 非 ObjectId）自身不入列，但其子权限被下钻取出', async () => {
    const ui = await build([])
    ui.setTree([
      {
        module: 'device',
        name: '设备管理',
        children: [
          // 无 _id 的分组：走 `node._id || ''` 的兜底，再因正则不匹配进入下钻分支
          {
            children: [
              { _id: oid(1), code: 'device:read', name: '查看设备', type: 'api', children: [] },
            ],
          },
          // 有 _id 但不是 24 位 ObjectId 的分组（后端模块级虚拟节点同形）
          {
            _id: 'module-device-group',
            children: [
              {
                _id: oid(2),
                code: 'device:create',
                name: '新增设备',
                type: 'button',
                children: [],
              },
            ],
          },
        ],
      },
    ])

    // 关键回归：分组自身不得成为权限项（否则界面出现无 code 的空行），
    // 但其子权限必须被取出（否则整块权限消失）
    expect(ui.moduleList.value[0].permissions.map((p) => p._id)).toEqual([oid(1), oid(2)])
    expect(ui.moduleList.value[0].permissions.every((p) => p.code)).toBe(true)
  })

  test('虚拟分组节点自身不入列（module-device 不是合法 ObjectId）', async () => {
    const ui = await build([])
    ui.setTree(nested())

    const codes = ui.moduleList.value[0].permissions.map((p) => p.code)
    expect(codes).not.toContain(undefined)
    expect(codes).toEqual([
      'device:read',
      'device:manage',
      'device:create',
      'device:delete',
      'device:purge',
    ])
  })

  test('同一权限在多处出现时只保留一次（seen 去重，否则重复渲染/重复计数）', async () => {
    const ui = await build([])
    ui.setTree([
      {
        module: 'device',
        name: '设备管理',
        children: [
          { _id: oid(1), code: 'device:read', name: '查看设备', type: 'api', children: [] },
          // 同一 ObjectId 被挂到另一条分支下（后端数据异常 / 交叉引用）
          {
            _id: oid(2),
            code: 'device:manage',
            name: '设备管理',
            type: 'menu',
            children: [
              { _id: oid(1), code: 'device:read', name: '查看设备', type: 'api', children: [] },
            ],
          },
        ],
      },
    ])

    expect(ui.moduleList.value[0].permissions.map((p) => p._id)).toEqual([oid(1), oid(2)])
    expect(ui.totalPermCount.value).toBe(2)
  })

  test('展平后 activeCount 按展平集合计算（深层权限勾选也计入）', async () => {
    const ui = await build([oid(5)])
    ui.setTree(nested())

    // 关键回归：若展平缺失，oid(5) 不在 permissions 里，activeCount 恒为 0
    expect(ui.moduleList.value[0].activeCount).toBe(1)
    expect(ui.modulePercent(ui.moduleList.value[0])).toBe(20)
  })

  test('模块名三级兜底：未知编码且后端未给 name 时退回模块编码本身（不渲染空白）', async () => {
    const ui = await build([])
    ui.setTree([{ module: 'unknown-code', children: [] }])

    // MODULE_NAMES 无此编码、mod.name 缺失 → 必须退回 mod.module，
    // 否则卡片标题渲染成空串（用户看到一张没有名字的卡片）
    expect(ui.moduleList.value[0].name).toBe('unknown-code')
  })

  test('节点为 null / children 非数组 / 树非数组：不抛错且退化为空列表', async () => {
    const ui = await build([])
    ui.setTree(null)
    expect(ui.moduleList.value).toEqual([])

    ui.setTree('not-an-array')
    expect(ui.moduleList.value).toEqual([])

    // 模块 children 缺失（后端空模块）→ 该模块权限为空，不得抛错
    ui.setTree([{ module: 'device', name: '设备管理' }])
    expect(ui.moduleList.value).toHaveLength(1)
    expect(ui.moduleList.value[0].permissions).toEqual([])
    expect(ui.moduleList.value[0].activeCount).toBe(0)

    // 树里混入 null 元素（稀疏/异常数据）：null 不是模块，必须被丢弃而不是
    // 保留成空模块（否则会渲染出一张没有名字的卡片）；模块内的 null 子节点
    // 由 flattenPermissionNodes 丢弃，因此该模块权限为空。
    ui.setTree([null, { module: 'device', name: '设备管理', children: [null] }])
    expect(ui.moduleList.value).toHaveLength(1)
    expect(ui.moduleList.value[0].module).toBe('device')
    expect(ui.moduleList.value[0].permissions).toEqual([])
  })
})

// ============================================================================
// 顶部统计四件套：权限总数 / 已启用 / 本次新增 / 本次移除
// 差异计数是「保存前预览」的唯一数据源（RoleView 顶部摘要与卡片角标共用），
// 算错会让用户以为没改动或改错了行。
// ============================================================================
describe('useRolePermissions 统计与差异计数', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  test('四件套在「原始 + 新增 + 移除」混合场景下的精确值', async () => {
    const ui = await build([oid(1), oid(2), oid(3)])
    expect(ui.totalPermCount.value).toBe(2)

    // 当前：移除 oid(2)、保留 oid(1)、新增 oid(4)（树里只有两颗，新增属于跨模块 id）
    ui.togglePerm(oid(2))
    ui.togglePerm(oid(4))

    expect(ui.checkedCount.value).toBe(3)
    expect(ui.addedCount.value).toBe(1)
    expect(ui.removedCount.value).toBe(1)
  })

  test('addedCount 只数「当前有而原始没有」，不得把原始项也算成新增', async () => {
    const ui = await build([oid(1), oid(2)])
    expect(ui.addedCount.value).toBe(0)
    expect(ui.removedCount.value).toBe(0)

    ui.togglePerm(oid(2))
    ui.togglePerm(oid(2))
    // 取消又加回：回到原始态，既非新增也非移除
    expect(ui.addedCount.value).toBe(0)
    expect(ui.removedCount.value).toBe(0)
  })

  test('resetChecked 后差异计数归零、脏标记清除、勾选集合回到原始', async () => {
    const ui = await build([oid(1)])
    ui.togglePerm(oid(2))
    expect(ui.hasUnsavedChanges.value).toBe(true)

    ui.resetChecked()

    expect([...ui.checkedPermIds.value]).toEqual([oid(1)])
    expect(ui.addedCount.value).toBe(0)
    expect(ui.removedCount.value).toBe(0)
    expect(ui.checkedCount.value).toBe(1)
    expect(ui.hasUnsavedChanges.value).toBe(false)
  })

  test('clearChecked 后四件套全部归零且模块计数同步（不残留清空前的数字）', async () => {
    const ui = await build([oid(1), oid(2)])
    expect(ui.moduleList.value[0].activeCount).toBe(2)

    ui.clearChecked()

    expect(ui.checkedCount.value).toBe(0)
    expect(ui.addedCount.value).toBe(0)
    expect(ui.removedCount.value).toBe(0)
    expect(ui.hasUnsavedChanges.value).toBe(false)
    // 关键回归：清空若漏 refreshModuleCounts，卡片会显示「已启用 2 / 2 (100%)」而全未勾选
    expect(ui.moduleList.value[0].activeCount).toBe(0)
    expect(ui.modulePercent(ui.moduleList.value[0])).toBe(0)
  })

  test('resetChecked 同步刷新 moduleList.activeCount（不得停留在脏状态）', async () => {
    const ui = await build([oid(1)])
    ui.togglePerm(oid(2))
    expect(ui.moduleList.value[0].activeCount).toBe(2)

    ui.resetChecked()

    expect(ui.moduleList.value[0].activeCount).toBe(1)
  })
})

// ============================================================================
// setChecked 入参形状归一化：调用方（RoleView.loadRolePermissions）传的是
// _id 数组；测试与旧调用方可能传 Set。两种都必须工作且**不共享调用方的可变对象**
// ——否则后续 togglePerm 会原地改掉调用方手里的集合。
// ============================================================================
describe('useRolePermissions setChecked 入参归一化与防御', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  test('传数组：归一化为 Set 并建立原始基线', async () => {
    const ui = await build([])
    ui.setChecked([oid(1), oid(2)])

    expect(ui.checkedPermIds.value).toBeInstanceOf(Set)
    expect([...ui.checkedPermIds.value].sort()).toEqual([oid(1), oid(2)].sort())
    expect([...ui.originalPermIds.value].sort()).toEqual([oid(1), oid(2)].sort())
    expect(ui.addedCount.value).toBe(0)
  })

  test('传 Set：内容被采纳，但后续 togglePerm 不得改写调用方持有的那个 Set', async () => {
    const ui = await build([])
    const callerSet = new Set([oid(1)])
    ui.setChecked(callerSet)

    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)

    ui.togglePerm(oid(2))
    // 关键回归：若直接持有 callerSet，这里会被写成 {oid(1), oid(2)}
    expect([...callerSet]).toEqual([oid(1)])
  })

  test('传 null / undefined / 非法值：退化为空集合，不得抛错', async () => {
    const ui = await build([oid(1)])

    ui.setChecked(null)
    expect(ui.checkedPermIds.value.size).toBe(0)

    ui.setChecked(undefined)
    expect(ui.checkedPermIds.value.size).toBe(0)

    ui.setChecked('not-a-collection')
    expect(ui.checkedPermIds.value.size).toBe(0)
    expect(ui.hasUnsavedChanges.value).toBe(false)
  })

  test('setChecked 清空搜索词与脏标记（切角色后不得残留上一个角色的搜索/未保存态）', async () => {
    const ui = await build([oid(1)])
    ui.permSearch.value = 'alarm'
    ui.togglePerm(oid(2))
    expect(ui.hasUnsavedChanges.value).toBe(true)

    ui.setChecked([oid(1)])

    expect(ui.permSearch.value).toBe('')
    expect(ui.hasUnsavedChanges.value).toBe(false)
  })
})

// ============================================================================
// 单颗权限勾选/取消（togglePerm）：RoleView 里权限按钮点击的唯一入口。
// ============================================================================
describe('useRolePermissions togglePerm', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  test('勾选 → 取消 → 再勾选：集合与计数、模块 activeCount 全程一致', async () => {
    const ui = await build([])

    ui.togglePerm(oid(1))
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    expect(ui.moduleList.value[0].activeCount).toBe(1)
    expect(ui.hasUnsavedChanges.value).toBe(true)

    ui.togglePerm(oid(1))
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(false)
    expect(ui.moduleList.value[0].activeCount).toBe(0)

    ui.togglePerm(oid(1))
    expect(ui.checkedPermIds.value.has(oid(1))).toBe(true)
    expect(ui.checkedPermIds.value.size).toBe(1)
  })

  test('togglePerm 后集合被替换为新 Set（原地 mutate 不会触发 Vue 依赖）', async () => {
    const ui = await build([])
    const before = ui.checkedPermIds.value
    ui.togglePerm(oid(1))
    expect(ui.checkedPermIds.value).not.toBe(before)
  })

  test('取消一颗原始权限 → isPermRemoved 为真；加回后为假', async () => {
    const ui = await build([oid(1)])
    ui.togglePerm(oid(1))
    expect(ui.isPermRemoved(oid(1))).toBe(true)
    expect(ui.isPermAdded(oid(1))).toBe(false)

    ui.togglePerm(oid(1))
    expect(ui.isPermRemoved(oid(1))).toBe(false)
  })

  test('新增一颗 → isPermAdded 为真、isPermRemoved 为假（两个判定互斥）', async () => {
    const ui = await build([])
    ui.togglePerm(oid(1))
    expect(ui.isPermAdded(oid(1))).toBe(true)
    expect(ui.isPermRemoved(oid(1))).toBe(false)
    expect(ui.isPermChecked(oid(1))).toBe(true)
  })
})

// ============================================================================
// moduleState / moduleStateText / modulePercent 的三态与边界
// ============================================================================
describe('useRolePermissions 模块三态与百分比边界', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  const six = () => [
    {
      module: 'device',
      name: '设备管理',
      children: [1, 2, 3, 4, 5, 6].map((n) => ({
        _id: oid(n),
        code: 'device:p' + n,
        name: '权限' + n,
        type: 'api',
        children: [],
      })),
    },
  ]

  test('空模块恒为 none 且百分比为 0（0/0 不得产生 NaN）', async () => {
    const ui = await build([])
    ui.setTree([{ module: 'device', name: '设备管理', children: [] }])

    expect(ui.moduleState(ui.moduleList.value[0])).toBe('none')
    expect(ui.moduleStateText(ui.moduleList.value[0])).toBe(tZh('role.moduleNone'))
    expect(ui.modulePercent(ui.moduleList.value[0])).toBe(0)
  })

  test('部分勾选为 partial、全选为 full，文案取自词表', async () => {
    const ui = await build([])
    ui.setTree(six())

    ui.setChecked([oid(1)])
    expect(ui.moduleState(ui.moduleList.value[0])).toBe('partial')
    expect(ui.moduleStateText(ui.moduleList.value[0])).toBe(tZh('role.modulePartial'))

    ui.setChecked([1, 2, 3, 4, 5, 6].map(oid))
    expect(ui.moduleState(ui.moduleList.value[0])).toBe('full')
    expect(ui.moduleStateText(ui.moduleList.value[0])).toBe(tZh('role.moduleFull'))
  })

  test('百分比四舍五入：1/6→17、5/6→83（不得截断为 16/83 或 16/100）', async () => {
    const ui = await build([])
    ui.setTree(six())

    ui.setChecked([oid(1)])
    expect(ui.modulePercent(ui.moduleList.value[0])).toBe(17)

    ui.setChecked([oid(1), oid(2), oid(3), oid(4), oid(5)])
    expect(ui.modulePercent(ui.moduleList.value[0])).toBe(83)
  })

  test('全选态下 modulePercent 恰为 100（不得因浮点写成 99）', async () => {
    const ui = await build([])
    ui.setTree(six())
    ui.setChecked([1, 2, 3, 4, 5, 6].map(oid))
    expect(ui.modulePercent(ui.moduleList.value[0])).toBe(100)
  })
})

// ============================================================================
// permTooltip：编码 + 类型 + （可选）方法/路径 + 差异说明
// ============================================================================
describe('useRolePermissions permTooltip 组合规则', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  test('无 path 时不出现方法与路径段（不得渲染 "GET undefined"）', async () => {
    const ui = await build([])
    const tip = ui.permTooltip({ _id: oid(1), code: 'device:read', type: 'api' })
    expect(tip).toBe('device:read · API')
    expect(tip).not.toContain('undefined')
  })

  test('有 path 时带默认方法 GET；显式 method 覆盖默认值', async () => {
    const ui = await build([])
    expect(ui.permTooltip({ _id: oid(1), code: 'device:read', type: 'api', path: '/api/x' })).toBe(
      'device:read · API · GET /api/x'
    )
    expect(
      ui.permTooltip({
        _id: oid(2),
        code: 'device:write',
        type: 'api',
        path: '/api/x',
        method: 'POST',
      })
    ).toBe('device:write · API · POST /api/x')
  })

  test('新增/移除差异说明互斥且只出现一个（同时满足时优先「本次新增」）', async () => {
    const ui = await build([oid(1)])
    // 原始有 oid(1)：先取消 → 移除；再加回一颗新的 oid(2) → 新增
    ui.togglePerm(oid(1))
    ui.togglePerm(oid(2))

    expect(ui.permTooltip({ _id: oid(2), code: 'device:create', type: 'api' })).toBe(
      'device:create · API · ' + tZh('role.permAdded')
    )
    expect(ui.permTooltip({ _id: oid(1), code: 'device:read', type: 'api' })).toBe(
      'device:read · API · ' + tZh('role.permRemoved')
    )
  })

  test('无差异时不含新增/移除字样', async () => {
    const ui = await build([oid(1)])
    const tip = ui.permTooltip({ _id: oid(1), code: 'device:read', type: 'api' })
    expect(tip).not.toContain(tZh('role.permAdded'))
    expect(tip).not.toContain(tZh('role.permRemoved'))
  })
})

// ============================================================================
// 未知模块编码的图标兜底
// ============================================================================
describe('useRolePermissions 模块图标映射', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  test('六个已知模块各有专属图标，未知模块退化为 📦', async () => {
    const ui = await build([])
    ui.setTree([
      { module: 'system', name: 's', children: [] },
      { module: 'device', name: 'd', children: [] },
      { module: 'alarm', name: 'a', children: [] },
      { module: 'inspection', name: 'i', children: [] },
      { module: 'report', name: 'r', children: [] },
      { module: 'security', name: 'sec', children: [] },
      { module: 'no-such', name: 'n', children: [] },
    ])

    expect(ui.moduleList.value.map((m) => m.icon)).toEqual([
      '⚙️',
      '🔧',
      '🚨',
      '📋',
      '📊',
      '🛡️',
      '📦',
    ])
  })
})

// ============================================================================
// 搜索过滤：命中口径（name / code）与空结果
// ============================================================================
describe('useRolePermissions filteredModules 搜索口径', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  test('大小写与首尾空白不敏感（"  ALARM  " 仍命中 alarm:read）', async () => {
    const ui = await build([])
    ui.permSearch.value = '  ALARM  '

    const visible = ui.filteredModules.value
    expect(visible).toHaveLength(1)
    expect(visible[0].permissions.map((p) => p._id)).toEqual([oid(2)])
  })

  test('按名称命中（中文关键字）与按编码命中走同一入口', async () => {
    const ui = await build([])
    ui.permSearch.value = '报警'
    expect(ui.filteredModules.value[0].permissions.map((p) => p._id)).toEqual([oid(2)])

    ui.permSearch.value = 'device:'
    expect(ui.filteredModules.value[0].permissions.map((p) => p._id)).toEqual([oid(1)])
  })

  test('权限 name/code 字段缺失时不抛错（(p.name || "") 防御）', async () => {
    const ui = await build([])
    ui.setTree([
      {
        module: 'device',
        name: '设备管理',
        children: [{ _id: oid(1), type: 'api', children: [] }],
      },
    ])
    ui.permSearch.value = 'anything'

    expect(ui.filteredModules.value).toEqual([])
  })

  test('零命中时模块整体被剔除（不渲染空卡片）', async () => {
    const ui = await build([])
    ui.permSearch.value = 'no-such-perm-xyz'
    expect(ui.filteredModules.value).toEqual([])
  })

  test('无搜索词时返回模块全量（与 moduleList 同一引用，避免无谓重建）', async () => {
    const ui = await build([])
    expect(ui.filteredModules.value).toBe(ui.moduleList.value)
  })
})
