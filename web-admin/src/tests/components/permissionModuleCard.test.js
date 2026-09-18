/**
 * PermissionModuleCard 行为测试（权限模块卡片，D-2 自 RoleView 拆出）
 *
 * 组件定位（PermissionModuleCard.vue:1-5）：它是 useRolePermissions 状态机的
 * **纯渲染层**——判定函数与切换函数全部经 `ui` prop 传入，自身不持有编辑状态。
 * 因此本套件锁定三类可观测行为：
 *  1. 把 module + ui 的返回值如实渲染成 DOM（状态文案/计数/进度条/勾选/角标/类型标签/tooltip）；
 *  2. 用户点击后把「原始对象/原始 _id」回传给 ui 的切换函数（传错 → 勾选无反应或错行）；
 *  3. 父级（useRolePermissions）状态变化后卡片重算（卡片缓存快照 → 勾选/计数不刷新）。
 *
 * 环境事实（本轮探针实测，见报告）：
 *  - 卡片根：.glass-module-card，状态 class 为 is-none / is-partial / is-full
 *  - 计数文本归一空白后形如「已启用 1 / 3 (33%)」；进度条为 .glass-module-card__progress-fill 的内联 width
 *  - 权限项：.glass-perm-btn（有值类 is-on / is-added / is-removed），圈内符号 ✓ / ↺ / 空
 *  - 角标 .glass-perm-btn__badge（新增/移除）与类型标签 .glass-perm-btn__type 互斥（v-if/v-else-if/v-else）
 *  - 本组件无异步链路（composable 状态同步更新），渲染只需 nextTick，故用 flush 而非 waitFor 轮询
 *
 * 期望值一律在本文件内独立给出（中/英文字面量取自词表但对本套件是外部事实），
 * 不 import 被测组件内部实现，也不 import useRolePermissions 的辅助函数。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { defineComponent, h } from 'vue'
import { mountComponent, click, flush } from '../helpers/componentHarness'
import PermissionModuleCard from '@/components/PermissionModuleCard.vue'
import { useRolePermissions } from '@/composables/useRolePermissions'
import i18n from '@/i18n'

const oid = (n) => String(n).padStart(24, '0')
const ID1 = oid(1)
const ID2 = oid(2)
const ID3 = oid(3)
const ID4 = oid(4)
const ID5 = oid(5)
const ID6 = oid(6)

/** 三权限模块：menu / button / api 三种类型各一，便于断言类型标签与 tooltip */
const TREE3 = [
  {
    module: 'device',
    name: '设备管理',
    children: [
      { _id: ID1, name: '查看设备', code: 'device:read', type: 'menu', children: [] },
      { _id: ID2, name: '新增设备', code: 'device:create', type: 'button', children: [] },
      { _id: ID3, name: '导出设备', code: 'device:export', type: 'api', children: [] },
    ],
  },
]

/** 六权限模块：用于百分比四舍五入边界（1/6 上取 17、5/6 下取 83）与空态之外的全选场景 */
const TREE6 = [
  {
    module: 'device',
    name: '设备管理',
    children: [1, 2, 3, 4, 5, 6].map((n) => ({
      _id: oid(n),
      name: '权限' + n,
      code: 'device:p' + n,
      type: 'api',
      children: [],
    })),
  },
]

/** 双模块：验证父级列表变化时卡片集合随之增删 */
const TREE_TWO_MODULES = [
  { module: 'device', name: '设备管理', children: TREE3[0].children },
  {
    module: 'alarm',
    name: '报警管理',
    children: [{ _id: ID4, name: '查看报警', code: 'alarm:read', type: 'menu', children: [] }],
  },
]

let ui = null
let active = null

/**
 * 统一宿主：在真实 i18n/pinia/router 上下文中调用 useRolePermissions（它内部依赖 useI18n，
 * 必须在组件 setup 里调用），并把 filteredModules 逐个交给卡片——与 RoleView.vue:118-123
 * 的真实用法一致（父级传 filteredModules、key 取 module.module）。
 *
 * 只保留这一处 defineComponent（factory 内），避免 vue/one-component-per-file 告警；
 * stub 场景经同一个 factory 换一份 build 实现，因此不需要第二个组件。
 */
const makeHost = (build) =>
  defineComponent({
    setup() {
      const state = build()
      return () => {
        const list = state.modules()
        return h(
          'div',
          list.map((m) => h(PermissionModuleCard, { key: m.module, module: m, ui: state.ui }))
        )
      }
    },
  })

/** 真实状态机宿主：tree/checked 由用例给定，父级句柄存入本文件模块级 ui 变量 */
const realBuild =
  (tree, checked = []) =>
  () => {
    const instance = useRolePermissions()
    instance.setTree(tree)
    instance.setChecked(checked)
    ui = instance
    return { ui: instance, modules: () => instance.filteredModules.value }
  }

const mountReal = (tree, checked = [], options = {}) => {
  active = mountComponent(makeHost(realBuild(tree, checked)), options)
  return active
}

const mountStub = (stubModule, stubUi, options = {}) => {
  active = mountComponent(
    makeHost(() => ({ ui: stubUi, modules: () => [stubModule] })),
    options
  )
  return active
}

/** 卡片文本归一：模板换行会引入空白，断言前统一压成单空格 */
const text = (el) => el.textContent.replace(/\s+/g, ' ').trim()

const card = (c) => c.find('.glass-module-card')
const stateEl = (c) => c.find('.glass-module-card__state')
const countEl = (c) => c.find('.glass-module-card__count')
const toggleBtn = (c) => c.find('.module-toggle-btn')
const progressEl = (c) => c.find('.glass-module-card__progress-fill')
const permBtns = (c) => c.findAll('.glass-perm-btn')

/** 单个权限按钮的快照：类名集合 + 圈内符号 + 角标 + 类型标签 + tooltip */
const permView = (el) => ({
  on: el.classList.contains('is-on'),
  added: el.classList.contains('is-added'),
  removed: el.classList.contains('is-removed'),
  check: el.querySelector('.glass-perm-btn__check').textContent.trim(),
  name: el.querySelector('.glass-perm-btn__name').textContent.trim(),
  code: el.querySelector('.glass-perm-btn__code').textContent.trim(),
  badge: el.querySelector('.glass-perm-btn__badge')?.textContent.trim() ?? null,
  type: el.querySelector('.glass-perm-btn__type')?.textContent.trim() ?? null,
  title: el.getAttribute('title'),
})

afterEach(() => {
  active?.handle.unmount()
  active = null
  ui = null
  i18n.global.locale.value = 'zh-CN'
})

describe('PermissionModuleCard 渲染契约（module ⇄ DOM 逐字段对应）', () => {
  test('图标/模块名/状态文案/计数/进度条/全选按钮全部来自传入的 module 与 ui', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)
    expect(c.errors).toEqual([])
    expect(c.warnings).toEqual([])

    expect(card(c).className).toBe('glass-module-card is-partial')
    expect(c.find('.glass-module-card__icon').textContent).toBe('🔧')
    expect(c.find('.glass-module-card__name').textContent).toBe('设备管理')
    expect(stateEl(c).className).toBe('glass-module-card__state is-partial')
    expect(text(stateEl(c))).toBe('部分启用')
    expect(text(countEl(c))).toBe('已启用 1 / 3 (33%)')
    expect(progressEl(c).style.width).toBe('33%')

    // ui 的判定函数只有 3 颗权限，逐颗如实渲染：名称 / 编码 / 类型标签 / 勾选态
    expect(permBtns(c).map(permView)).toEqual([
      {
        on: true,
        added: false,
        removed: false,
        check: '✓',
        name: '查看设备',
        code: 'device:read',
        badge: null,
        type: '菜单',
        title: 'device:read · 菜单',
      },
      {
        on: false,
        added: false,
        removed: false,
        check: '',
        name: '新增设备',
        code: 'device:create',
        badge: null,
        type: '操作',
        title: 'device:create · 操作',
      },
      {
        on: false,
        added: false,
        removed: false,
        check: '',
        name: '导出设备',
        code: 'device:export',
        badge: null,
        type: 'API',
        title: 'device:export · API',
      },
    ])
  })

  test('权限项顺序与 module.permissions 一致，key 用 _id（行不错位）', async () => {
    const c = mountReal(TREE3, [])
    await flush(3)
    expect(permBtns(c).map((el) => el.querySelector('.glass-perm-btn__code').textContent)).toEqual([
      'device:read',
      'device:create',
      'device:export',
    ])
  })

  test('状态三态切换：none → partial → full 时根 class/文案/按钮文案/进度条同步换挡', async () => {
    const c = mountReal(TREE6, [])
    await flush(3)

    expect(card(c).className).toBe('glass-module-card is-none')
    expect(text(stateEl(c))).toBe('未启用')
    expect(text(countEl(c))).toBe('已启用 0 / 6 (0%)')
    expect(progressEl(c).style.width).toBe('0%')
    expect(text(toggleBtn(c))).toBe('全选本模块')
    expect(toggleBtn(c).className).toContain('glass-btn--primary')

    ui.setChecked([ID1, ID2, ID3])
    await flush(2)
    expect(card(c).className).toBe('glass-module-card is-partial')
    expect(text(stateEl(c))).toBe('部分启用')
    expect(text(countEl(c))).toBe('已启用 3 / 6 (50%)')
    expect(progressEl(c).style.width).toBe('50%')

    ui.setChecked([ID1, ID2, ID3, ID4, ID5, ID6])
    await flush(2)
    expect(card(c).className).toBe('glass-module-card is-full')
    expect(text(stateEl(c))).toBe('已全选')
    expect(text(countEl(c))).toBe('已启用 6 / 6 (100%)')
    expect(progressEl(c).style.width).toBe('100%')
    expect(text(toggleBtn(c))).toBe('清空本模块')
    expect(toggleBtn(c).className).toContain('glass-btn--default')
  })

  test('百分比四舍五入边界：1/6→17%、5/6→83%（Math.round 不得换成截断）', async () => {
    const c = mountReal(TREE6, [ID1])
    await flush(3)
    expect(text(countEl(c))).toBe('已启用 1 / 6 (17%)')
    expect(progressEl(c).style.width).toBe('17%')

    ui.setChecked([ID1, ID2, ID3, ID4, ID5])
    await flush(2)
    expect(text(countEl(c))).toBe('已启用 5 / 6 (83%)')
    expect(progressEl(c).style.width).toBe('83%')
  })

  test('空权限模块：0/0 不产生 NaN，且全选按钮点击不得改动父级集合', async () => {
    const c = mountReal([{ module: 'device', name: '设备管理', children: [] }], [ID1])
    await flush(3)
    expect(card(c).className).toBe('glass-module-card is-none')
    expect(text(countEl(c))).toBe('已启用 0 / 0 (0%)')
    expect(progressEl(c).style.width).toBe('0%')
    expect(permBtns(c)).toEqual([])

    click(toggleBtn(c))
    await flush(2)
    expect([...ui.checkedPermIds.value]).toEqual([ID1])
    expect(ui.hasUnsavedChanges.value).toBe(false)
  })

  test('多模块：每个卡片只渲染自己的权限，模块间不串数据', async () => {
    const c = mountReal(TREE_TWO_MODULES, [ID1, ID4])
    await flush(3)
    const cards = c.findAll('.glass-module-card')
    expect(cards).toHaveLength(2)
    expect(cards[0].querySelector('.glass-module-card__name').textContent).toBe('设备管理')
    expect(cards[0].querySelectorAll('.glass-perm-btn')).toHaveLength(3)
    expect(cards[1].querySelector('.glass-module-card__name').textContent).toBe('报警管理')
    expect(cards[1].querySelectorAll('.glass-perm-btn')).toHaveLength(1)
    expect(
      cards[1].querySelector('.glass-module-card__count').textContent.replace(/\s+/g, ' ').trim()
    ).toBe('已启用 1 / 1 (100%)')
  })
})
describe('PermissionModuleCard 点击回传契约（把原始对象/原始 id 交给 ui）', () => {
  test('点击「全选本模块」：切换的是本卡片对应的模块（多模块下不得串到别的模块）', async () => {
    const c = mountReal(TREE_TWO_MODULES, [])
    await flush(3)
    const cards = c.findAll('.glass-module-card')
    expect(cards).toHaveLength(2)

    // 点第 2 张卡（报警模块，只有 alarm:read 一颗）
    click(cards[1].querySelector('.module-toggle-btn'))
    await flush(3)

    expect([...ui.checkedPermIds.value]).toEqual([ID4])
    expect(
      cards[1].querySelector('.glass-module-card__count').textContent.replace(/s+/g, ' ').trim()
    ).toBe('已启用 1 / 1 (100%)')
    // 第 1 张卡（设备模块）必须纹丝不动
    expect(
      cards[0].querySelector('.glass-module-card__count').textContent.replace(/s+/g, ' ').trim()
    ).toBe('已启用 0 / 3 (0%)')
    expect(cards[0].querySelector('.glass-module-card__state').textContent.trim()).toBe('未启用')
  })

  test('点击权限项：回传该行自己的 _id（三行各点一次，id 不得串行/复用第一行）', async () => {
    const seen = []
    const c = mountReal(TREE3, [])
    await flush(3)
    const realTogglePerm = ui.togglePerm
    ui.togglePerm = (id) => {
      seen.push(id)
      realTogglePerm(id)
    }
    await flush(2)

    for (const el of permBtns(c)) click(el)
    await flush(3)

    expect(seen).toEqual([ID1, ID2, ID3])
    // 点两轮：第二轮仍是同一顺序，且集合被正确去重（3 个 id 而非 6 个）
    for (const el of permBtns(c)) click(el)
    await flush(3)
    expect(seen).toEqual([ID1, ID2, ID3, ID1, ID2, ID3])
    expect(ui.checkedPermIds.value.size).toBe(0)
  })

  test('点击单个权限后：该行换成已勾选样式、出现「新增」角标与 tooltip 差异说明，同模块其他行不受影响', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)
    click(permBtns(c)[1])
    await flush(3)

    expect(permView(permBtns(c)[1])).toEqual({
      on: true,
      added: true,
      removed: false,
      check: '✓',
      name: '新增设备',
      code: 'device:create',
      badge: '新增',
      type: null,
      title: 'device:create · 操作 · 本次新增',
    })
    // 邻行仍是「已勾选、无角标、显示类型标签」的原样
    expect(permView(permBtns(c)[0])).toEqual({
      on: true,
      added: false,
      removed: false,
      check: '✓',
      name: '查看设备',
      code: 'device:read',
      badge: null,
      type: '菜单',
      title: 'device:read · 菜单',
    })
    expect(permView(permBtns(c)[2]).type).toBe('API')
  })

  test('取消一颗原本已勾选的权限：显示 ↺ 与「移除」角标（保存前仍可点回），tooltip 同步', async () => {
    const c = mountReal(TREE3, [ID1, ID2])
    await flush(3)
    click(permBtns(c)[0])
    await flush(3)

    expect(permView(permBtns(c)[0])).toEqual({
      on: false,
      added: false,
      removed: true,
      check: '↺',
      name: '查看设备',
      code: 'device:read',
      badge: '移除',
      type: null,
      title: 'device:read · 菜单 · 本次移除',
    })
    // 点回：恢复为普通已勾选态，不残留 removed
    click(permBtns(c)[0])
    await flush(3)
    expect(permView(permBtns(c)[0]).removed).toBe(false)
    expect(permView(permBtns(c)[0]).check).toBe('✓')
    expect(permView(permBtns(c)[0]).badge).toBe(null)
  })

  test('点击模块全选：整模块进入 full，逐行都变已勾选；再点一次清空', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)
    click(toggleBtn(c))
    await flush(3)

    expect(text(stateEl(c))).toBe('已全选')
    expect(text(toggleBtn(c))).toBe('清空本模块')
    expect(permBtns(c).map((el) => el.classList.contains('is-on'))).toEqual([true, true, true])
    expect(
      permBtns(c).map((el) => el.querySelector('.glass-perm-btn__check').textContent.trim())
    ).toEqual(['✓', '✓', '✓'])

    click(toggleBtn(c))
    await flush(3)
    expect(text(stateEl(c))).toBe('未启用')
    expect(permBtns(c).map((el) => el.classList.contains('is-on'))).toEqual([false, false, false])
    // ID1 原始就有 → 清空后处于「本次移除」态（↺ + 移除角标）；ID2/ID3 从未勾选过 → 空圈
    expect(
      permBtns(c).map((el) => el.querySelector('.glass-perm-btn__check').textContent.trim())
    ).toEqual(['↺', '', ''])
    expect(permView(permBtns(c)[0]).badge).toBe('移除')
    expect(permView(permBtns(c)[2]).badge).toBe(null)
  })
})

describe('PermissionModuleCard 随父级状态重算（卡片不得持有过期快照）', () => {
  test('父级直接改集合（非本卡片点击路径）：计数/进度/勾选态同步刷新', async () => {
    const c = mountReal(TREE6, [])
    await flush(3)
    expect(text(countEl(c))).toBe('已启用 0 / 6 (0%)')

    // 模拟父级其它入口（如 WebSocket 重拉后 setChecked、外部重置）
    ui.setChecked([ID1, ID2, ID3])
    await flush(2)
    expect(text(countEl(c))).toBe('已启用 3 / 6 (50%)')
    expect(progressEl(c).style.width).toBe('50%')
    expect(
      permBtns(c)
        .slice(0, 3)
        .map((el) => el.classList.contains('is-on'))
    ).toEqual([true, true, true])
    expect(
      permBtns(c)
        .slice(3)
        .map((el) => el.classList.contains('is-on'))
    ).toEqual([false, false, false])
  })

  test('父级 resetChecked 后：勾选/角标/tooltip 全部回到原始态（不残留本次新增标记）', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)
    click(permBtns(c)[1])
    await flush(3)
    expect(permView(permBtns(c)[1]).badge).toBe('新增')

    ui.resetChecked()
    await flush(3)
    expect(permView(permBtns(c)[1])).toEqual({
      on: false,
      added: false,
      removed: false,
      check: '',
      name: '新增设备',
      code: 'device:create',
      badge: null,
      type: '操作',
      title: 'device:create · 操作',
    })
    expect(ui.hasUnsavedChanges.value).toBe(false)
  })

  test('父级 setChecked 后：未保存标记被清除、差异角标全部退场（切角色/重拉不残留脏标记）', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)
    click(permBtns(c)[1])
    await flush(3)
    expect(ui.hasUnsavedChanges.value).toBe(true)
    expect(permView(permBtns(c)[1]).badge).toBe('新增')

    // setChecked 是切角色/保存后重拉的状态原语：脏标记必须同时归零
    ui.setChecked([ID1])
    await flush(3)
    expect(ui.hasUnsavedChanges.value).toBe(false)
    expect(permView(permBtns(c)[1]).badge).toBe(null)
    expect(permView(permBtns(c)[1]).type).toBe('操作')
  })

  test('父级 setTree 换掉整个权限树：卡片渲染新模块新权限，旧行不残留', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)
    expect(permBtns(c).map((el) => permView(el).code)).toEqual([
      'device:read',
      'device:create',
      'device:export',
    ])

    ui.setTree([
      {
        module: 'alarm',
        name: '报警管理',
        children: [{ _id: ID4, name: '查看报警', code: 'alarm:read', type: 'menu', children: [] }],
      },
    ])
    await flush(3)
    expect(c.findAll('.glass-module-card')).toHaveLength(1)
    expect(c.find('.glass-module-card__name').textContent).toBe('报警管理')
    expect(permBtns(c).map((el) => permView(el).code)).toEqual(['alarm:read'])
  })

  test('父级搜索过滤后再清空关键字：卡片集合与计数都恢复（过滤依赖被正确建立）', async () => {
    const c = mountReal(TREE_TWO_MODULES, [ID1, ID4])
    await flush(3)
    expect(c.findAll('.glass-module-card')).toHaveLength(2)

    ui.permSearch.value = 'alarm'
    await flush(3)
    expect(c.findAll('.glass-module-card')).toHaveLength(1)
    expect(permBtns(c).map((el) => permView(el).code)).toEqual(['alarm:read'])
    // 搜索态下计数只统计**可见**权限：1/1 而非 1/4
    expect(text(countEl(c))).toBe('已启用 1 / 1 (100%)')
    expect(text(stateEl(c))).toBe('已全选')

    ui.permSearch.value = ''
    await flush(3)
    expect(c.findAll('.glass-module-card')).toHaveLength(2)
    expect(text(countEl(c))).toBe('已启用 1 / 3 (33%)')
    expect(text(stateEl(c))).toBe('部分启用')
  })

  test('仅替换已勾选 id（集合大小不变）：勾选态仍须重算（依赖不能只订阅 size）', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)

    ui.setChecked([ID2])
    await flush(3)
    expect(permBtns(c).map((el) => el.classList.contains('is-on'))).toEqual([false, true, false])
    expect(text(countEl(c))).toBe('已启用 1 / 3 (33%)')
  })
})
describe('PermissionModuleCard 是纯渲染层（判定/换算必须来自 ui，不得自算）', () => {
  /**
   * 用「与 module 数据故意矛盾」的 ui 替身调用：若卡片擅自用 module.activeCount /
   * permissions.length 自算百分比、或自写状态文案，本组用例立刻失败。
   * 该替身同时钉住「点击回调把原始 module/原始 id 原样回传」这一父子契约。
   */
  test('状态/文案/百分比/类型标签/tooltip 全部取自 ui（与模块数据无关）', async () => {
    const perm = { _id: 'p-1', name: '名称', code: 'code:x', type: 'type-x' }
    const module = { module: 'm', name: '模块', icon: '★', permissions: [perm], activeCount: 0 }
    const calls = []
    const stubUi = {
      moduleState: () => {
        calls.push('moduleState')
        return 'partial'
      },
      moduleStateText: () => 'UI-状态',
      toggleModule: () => {},
      modulePercent: () => {
        calls.push('modulePercent')
        return 42
      },
      isPermChecked: () => {
        calls.push('isPermChecked')
        return true
      },
      isPermAdded: () => false,
      isPermRemoved: () => false,
      permTooltip: () => 'UI-tooltip',
      togglePerm: () => {},
      typeLabel: () => 'UI-类型',
    }
    const c = mountStub(module, stubUi)
    await flush(3)

    expect(card(c).className).toBe('glass-module-card is-partial')
    expect(text(stateEl(c))).toBe('UI-状态')
    expect(stateEl(c).className).toBe('glass-module-card__state is-partial')
    expect(text(countEl(c))).toBe('已启用 0 / 1 (42%)')
    expect(progressEl(c).style.width).toBe('42%')
    expect(permView(permBtns(c)[0])).toMatchObject({
      on: true,
      check: '✓',
      badge: null,
      type: 'UI-类型',
      title: 'UI-tooltip',
    })
    // 至少证明这三个 ui 判定真的被调用（而不是被写成常量）
    expect(new Set(calls)).toEqual(new Set(['moduleState', 'modulePercent', 'isPermChecked']))
  })

  test('点击回传给 ui 的是原始 module 对象与原始权限 _id', async () => {
    const perm = { _id: 'p-9', name: '名称', code: 'code:x', type: 'api' }
    const module = { module: 'm', name: '模块', icon: '★', permissions: [perm], activeCount: 0 }
    const received = []
    const stubUi = {
      moduleState: () => 'none',
      moduleStateText: () => 'UI',
      toggleModule: (m) => received.push(['module', m]),
      modulePercent: () => 0,
      isPermChecked: () => false,
      isPermAdded: () => false,
      isPermRemoved: () => false,
      permTooltip: () => '',
      togglePerm: (id) => received.push(['perm', id]),
      typeLabel: () => 'T',
    }
    const c = mountStub(module, stubUi)
    await flush(3)

    click(toggleBtn(c))
    click(permBtns(c)[0])
    await flush(3)

    expect(received).toHaveLength(2)
    expect(received[0][0]).toBe('module')
    expect(received[0][1]).toBe(module)
    expect(received[1]).toEqual(['perm', 'p-9'])
  })
})

describe('PermissionModuleCard 语言跟随与兜底', () => {
  test('已知模块名取 i18n 词表、图标取内置映射；同实例切语言后状态/计数/按钮/角标/类型标签跟随切换', async () => {
    const c = mountReal(TREE3, [ID1])
    await flush(3)
    expect(c.find('.glass-module-card__icon').textContent).toBe('🔧')
    expect(c.find('.glass-module-card__name').textContent).toBe('设备管理')
    expect(text(toggleBtn(c))).toBe('全选本模块')

    // 制造两条差异：ID2 本次新增、ID1 本次移除（原实现 is-added / is-removed 两个角标分支都走到）
    click(permBtns(c)[1])
    await flush(3)
    click(permBtns(c)[0])
    await flush(3)
    expect(text(stateEl(c))).toBe('部分启用')
    expect(text(countEl(c))).toBe('已启用 1 / 3 (33%)')

    i18n.global.locale.value = 'en-US'
    await flush(4)
    expect(text(stateEl(c))).toBe('Partial')
    expect(text(countEl(c))).toBe('Enabled 1 / 3 (33%)')
    expect(text(toggleBtn(c))).toBe('Select All')
    // 角标与类型标签互斥（v-if/v-else-if/v-else）：
    // ID1 本次移除 → Remove 角标、无类型标签；ID2 本次新增 → Add 角标；ID3 无差异 → 类型标签 API
    expect(permBtns(c).map((el) => permView(el).badge)).toEqual(['Remove', 'Add', null])
    expect(permBtns(c).map((el) => permView(el).type)).toEqual([null, null, 'API'])
    expect(permBtns(c).map((el) => permView(el).check)).toEqual(['↺', '✓', ''])
    expect(permBtns(c).map((el) => permView(el).title)).toEqual([
      'device:read · Menu · Removed',
      'device:create · Action · Added',
      'device:export · API',
    ])

    i18n.global.locale.value = 'zh-CN'
    await flush(4)
    expect(text(stateEl(c))).toBe('部分启用')
    expect(text(countEl(c))).toBe('已启用 1 / 3 (33%)')
    expect(text(toggleBtn(c))).toBe('全选本模块')
    expect(permBtns(c).map((el) => permView(el).badge)).toEqual(['移除', '新增', null])
    expect(permBtns(c).map((el) => permView(el).title)).toEqual([
      'device:read · 菜单 · 本次移除',
      'device:create · 操作 · 本次新增',
      'device:export · API',
    ])
  })

  test('全选态切语言：清空按钮文案与「已全选」状态一并切换（不残留上一语言）', async () => {
    const c = mountReal(TREE3, [ID1, ID2, ID3])
    await flush(3)
    expect(text(toggleBtn(c))).toBe('清空本模块')
    expect(text(stateEl(c))).toBe('已全选')

    i18n.global.locale.value = 'en-US'
    await flush(4)
    expect(text(toggleBtn(c))).toBe('Clear Module')
    expect(text(stateEl(c))).toBe('All Selected')

    i18n.global.locale.value = 'zh-CN'
    await flush(4)
    expect(text(toggleBtn(c))).toBe('清空本模块')
    expect(text(stateEl(c))).toBe('已全选')
  })

  test('模块名优先取 i18n 映射而非后端 name（英文界面首挂不显示后端中文名）', async () => {
    // 后端权限树的模块 name 来自 getModuleName()，恒为中文；英文界面必须走 i18n 映射，
    // 否则英文用户看到「设备管理」。这里把后端 name 故意设成另一个中文串，确保渲染值
    // 只能来自词表（若退化为直接渲染 module.name，本用例立刻红）。
    const c = mountReal([{ module: 'device', name: '后端返回的设备管理', children: [] }], [], {
      locale: 'en-US',
    })
    await flush(3)
    expect(c.find('.glass-module-card__name').textContent).toBe('Devices')

    const c2 = mountReal([{ module: 'device', name: '后端返回的设备管理', children: [] }], [])
    await flush(3)
    expect(c2.find('.glass-module-card__name').textContent).toBe('设备管理')
  })

  /**
   * 疑似缺陷记录（test.fails = 现状不满足契约；缺陷修复后本用例会变红，届时转正为 test）：
   *
   * useRolePermissions.buildModuleList（useRolePermissions.js:94）在**构建期**求值
   * MODULE_NAMES.value[mod.module] 并把结果字符串存进 module.name；页内切换语言
   * （layout/index.vue:322 setLocale，不重载页面、不重建权限树）后模块名不跟随，
   * 直到下一次 setTree（切换角色 / WebSocket 推送）才刷新。
   *
   * 实测（探针，05:57）：英文首挂 name="Devices" → 切 zh-CN 后仍为 "Devices"；
   * 重新 setTree 后才变回「设备管理」。与本轮已修复的 8 个文件「t() 在 setup 顶层
   * 求值固化」属同一类系统性缺陷，只是位置在 composable 而非组件。
   *
   * 建议修法（最小改动，与既有修法同源）：把 moduleList 项的 name 改为渲染期求值的
   * 访问器（get name() { return MODULE_NAMES.value[mod.module] || mod.name || mod.module }），
   * 使 computed 依赖在渲染副作用内建立。修复后请把本用例改成 test。
   *
   * 说明：卡片本身是纯渲染层（渲染父级给的 module.name），该缺陷不在卡片职责内，
   * 本套件不越权替 composable 断言——故用 test.failing 如实记录，而非把错误行为钉成契约。
   */
  test('模块名随页内语言切换实时跟随（已修复：useRolePermissions 改为渲染期 getter）', async () => {
    const c = mountReal([{ module: 'device', name: '后端返回的设备管理', children: [] }], [])
    await flush(3)
    expect(c.find('.glass-module-card__name').textContent).toBe('设备管理')

    i18n.global.locale.value = 'en-US'
    await flush(4)
    expect(c.find('.glass-module-card__name').textContent).toBe('Devices')
  })

  test('未知模块编码兜底：图标用 📦、模块名退回后端给的 name（不渲染 undefined）', async () => {
    const c = mountReal([{ module: 'no-such-module', name: '后端中文模块名', children: [] }], [])
    await flush(3)
    expect(c.find('.glass-module-card__icon').textContent).toBe('📦')
    expect(c.find('.glass-module-card__name').textContent).toBe('后端中文模块名')
    expect(c.text()).not.toContain('undefined')
  })

  test('参数字段缺失（缺 code / method / type）不渲染 undefined，类型标签走兜底', async () => {
    const c = mountReal(
      [
        {
          module: 'device',
          name: '设备管理',
          children: [
            { _id: ID1, name: '无编码权限', type: 'menu', children: [] },
            {
              _id: ID2,
              name: '有路径无方法',
              code: 'x:y',
              type: 'api',
              path: '/api/x',
              children: [],
            },
            { _id: ID3, name: '未知类型', code: 'x:z', type: 'weird', children: [] },
          ],
        },
      ],
      []
    )
    await flush(3)
    const views = permBtns(c).map(permView)
    expect(views.map((v) => v.name)).toEqual(['无编码权限', '有路径无方法', '未知类型'])
    expect(views[0].code).toBe('')
    expect(views[0].title).not.toContain('undefined')
    // path 存在但 method 缺失：兜底为 GET，且不出现 undefined
    expect(views[1].title).toContain('GET /api/x')
    expect(views[1].title).not.toContain('undefined')
    // 未知 type 走 typeLabel 兜底（role.permissions 词表值），不出现原始枚举或 undefined
    expect(views[2].type).toBe('权限')
    expect(views[2].title).not.toContain('undefined')
    expect(c.text()).not.toContain('undefined')
  })

  test('搜索态下点击命中权限：可见计数/进度条/状态必须同一帧刷新（缓存快照会露馅）', async () => {
    // 场景选取说明：只勾选 ID2 且搜索只命中 ID2，此时「全量勾选数」与「可见勾选数」
    // 相等，因此本用例断言的是**刷新链路**本身，不与下方搜索态口径缺陷（test.fails）
    // 的任何表现形式耦合。
    const c = mountReal(TREE3, [ID2])
    await flush(3)
    ui.permSearch.value = 'create'
    await flush(3)
    expect(permBtns(c)).toHaveLength(1)
    expect(text(countEl(c))).toBe('已启用 1 / 1 (100%)')
    expect(text(stateEl(c))).toBe('已全选')

    click(permBtns(c)[0])
    await flush(3)
    expect(permView(permBtns(c)[0]).on).toBe(false)
    expect(text(countEl(c))).toBe('已启用 0 / 1 (0%)')
    expect(progressEl(c).style.width).toBe('0%')
    expect(text(stateEl(c))).toBe('未启用')

    click(permBtns(c)[0])
    await flush(3)
    expect(text(countEl(c))).toBe('已启用 1 / 1 (100%)')
    expect(progressEl(c).style.width).toBe('100%')
    expect(text(stateEl(c))).toBe('已全选')
  })

  test('搜索命中未勾选权限：可见计数与可见状态一致（0/1 0%）', async () => {
    const c = mountReal(TREE3, [])
    await flush(3)
    ui.permSearch.value = 'export'
    await flush(3)
    expect(permBtns(c)).toHaveLength(1)
    expect(text(countEl(c))).toBe('已启用 0 / 1 (0%)')
    expect(progressEl(c).style.width).toBe('0%')
    expect(text(stateEl(c))).toBe('未启用')
    expect(text(toggleBtn(c))).toBe('全选本模块')
  })

  /**
   * 疑似缺陷记录（test.fails = 现状不满足契约；修复后本用例会变红，届时转正为 test）：
   *
   * useRolePermissions.js:226-233 在搜索态重算 activeCount 时，分子用**全量**权限
   * （m.permissions，过滤前）统计已勾选数，分母却是**过滤后**的 permissions.length。
   * 两者口径不一致 → 搜索态下卡片显示「已启用 3 / 1 (300%)」、进度条 width:300%，
   * moduleState 也因 activeCount !== permissions.length 误判为 partial。
   *
   * 实测（探针，06:01，3 颗全勾选 + 搜 'delete' 命中 1 颗）：
   *   DOM count="已启用 3 / 1 (300%)" width=300% state=部分启用
   * 用户可达：RoleView.vue:118-123 用 filteredModules 渲染卡片集合，搜索即触发。
   * 连带后果：此处按钮按 moduleState 渲染文案，显示「全选本模块」；而
   * toggleModule（useRolePermissions.js:183）按**可见**范围判定 allOn，点击执行的是
   * 清空——文案与行为相反，用户会误以为能全选。
   *
   * 建议修法（与 toggleModule 同口径）：
   *   const visible = m.permissions.filter(matchKw)
   *   activeCount: visible.filter((p) => checkedPermIds.value.has(p._id)).length
   * 修复后请把本用例改成 test（并同步补「按钮文案与点击行为一致」的断言）。
   */
  test('搜索态下计数/状态/按钮文案只按当前可见权限统计（已修复：分子分母同口径）', async () => {
    const c = mountReal(TREE3, [ID1, ID2, ID3])
    await flush(3)
    ui.permSearch.value = 'export'
    await flush(3)
    expect(permBtns(c)).toHaveLength(1)
    expect(text(countEl(c))).toBe('已启用 1 / 1 (100%)')
    expect(progressEl(c).style.width).toBe('100%')
    expect(text(stateEl(c))).toBe('已全选')
    expect(text(toggleBtn(c))).toBe('清空本模块')
  })

  test('搜索态按钮文案与点击行为一致：显示「清空本模块」时点击必须清空可见项', async () => {
    // 这是缺陷 2 的真实危害面：口径不一致时 moduleState 误判为 partial，按钮显示
    // 「全选本模块」，而 toggleModule 按可见范围判 allOn、点击执行的是清空 ——
    // 用户点「全选」实际清空。仅断言文案不够，必须把「点了之后发生什么」钉住。
    const c = mountReal(TREE3, [ID1, ID2, ID3])
    await flush(3)
    ui.permSearch.value = 'export'
    await flush(3)
    expect(text(toggleBtn(c))).toBe('清空本模块')
    click(toggleBtn(c))
    await flush(3)
    // 可见项（ID3 = 导出设备 / device:export）被清空；
    // 模块内其余项不受影响（搜索只作用于可见集，不得误伤不可见项）
    expect(ui.checkedPermIds.value.has(ID3)).toBe(false)
    expect(ui.checkedPermIds.value.has(ID1)).toBe(true)
    expect(ui.checkedPermIds.value.has(ID2)).toBe(true)
    expect(text(toggleBtn(c))).toBe('全选本模块')
    // 点回去必须重新全选可见项（往返一致，防止单向可用的假修复）
    click(toggleBtn(c))
    await flush(3)
    expect(ui.checkedPermIds.value.has(ID3)).toBe(true)
    expect(text(toggleBtn(c))).toBe('清空本模块')
  })

  /**
   * 疑似缺陷记录（test.fails = 现状不满足契约；修复后本用例会变红，届时转正为 test）：
   *
   * useRolePermissions.clearChecked（useRolePermissions.js:125-129）清空 checkedPermIds /
   * originalPermIds 后**不调用 refreshModuleCounts()**，而它的三个兄弟原语都会刷新
   * moduleList 的 activeCount（setChecked:122、togglePerm:247、resetChecked:253）——
   * 同一文件内四个原语写法不一致，指向遗漏而非有意契约。
   *
   * 实测（探针，05:58，TREE3 先勾选 2 颗再 clearChecked）：
   *   moduleList.activeCount 仍为 2，DOM 计数「已启用 2 / 3 (67%)」、状态「部分启用」，
   *   而 checkedPermIds.size=0、三行全部无 is-on → 计数与行态自相矛盾。
   *
   * 用户可达路径（RoleView.vue:269-285 删除当前角色时）：
   *   1. currentRole=null + clearChecked()——此刻右面板走空态分支，卡片不渲染，缺陷被掩盖；
   *   2. loadRoles(true) 先同步置 currentRole=roles[0]（RoleView.vue:198-200），
   *      再 await loadRolePermissions(newId) 发起网络请求；
   *   3. 该 await 期间卡片已渲染而计数仍是上一个角色的数字 → 新角色面板短暂显示
   *      「已启用 2 / 3」且三行全部未勾选，直到 getById 返回、setChecked 刷新才修正。
   * 影响：删角色后有一个网络 RTT 时长的视觉不一致（非数据错误——保存以 checkedPermIds 为准）。
   *
   * 建议修法：clearChecked 末尾补 refreshModuleCounts()，与三个兄弟原语对齐。
   */
  test('父级 clearChecked 后：计数/状态必须与「零勾选」一致（已修复：补 refreshModuleCounts）', async () => {
    const c = mountReal(TREE3, [ID1, ID2])
    await flush(3)
    expect(text(countEl(c))).toBe('已启用 2 / 3 (67%)')

    ui.clearChecked()
    await flush(3)
    expect(permBtns(c).map((el) => permView(el).on)).toEqual([false, false, false])
    expect(text(countEl(c))).toBe('已启用 0 / 3 (0%)')
    expect(progressEl(c).style.width).toBe('0%')
    expect(text(stateEl(c))).toBe('未启用')
  })

  test('i18n 词表缺键守卫：卡片引用的全部 key 在 zh-CN 与 en-US 都存在', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const c = mountReal(TREE3, [ID1])
      await flush(3)
      i18n.global.locale.value = 'en-US'
      await flush(4)
      i18n.global.locale.value = 'zh-CN'
      await flush(2)
      // vue-i18n 缺键会在渲染时打印 [intlify] Not found ... key in ... locale messages
      const missing = warn.mock.calls
        .map((args) => String(args[0]))
        .filter((msg) => msg.includes('[intlify]'))
      expect(missing).toEqual([])
      expect(c.warnings).toEqual([])
      expect(c.errors).toEqual([])
    } finally {
      warn.mockRestore()
    }
  })
})
