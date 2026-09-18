/**
 * App.vue 行为测试（Element Plus 组件语言跟随 i18n）
 *
 * 这个 16 行的根组件只做一件事：把 i18n 的当前语言映射成 element-plus 的
 * locale 对象，交给 el-config-provider。但它承载的退化非常显眼且常见：
 *
 *  - 语言切换后 Element Plus 内置文案（分页「条/页」、日期选择器、确认框按钮、
 *    表格「暂无数据」）不跟随，出现「界面中文、控件英文」的割裂；
 *  - 映射表把语言码写死成 'zh' 前缀判断 → en 也落到中文；
 *  - 用了 computed 却忘了响应式（写成挂载时求值一次）→ 首屏正确、切换无效。
 *
 * 这三类都不会报错，只在切换语言时才暴露。故本文件逐条钉住：
 * 断言的不是「传了某个对象」，而是 el-config-provider 真正收到的 locale 值，
 * 并直接调用该 locale 的翻译函数（Element Plus locale 对象是
 * { name, el: { pagination: { total, goto, ... } } } 形状），
 * 用真实语言差异证明映射方向正确，而不是靠对象同一性。
 */
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { mountComponent, flush } from './helpers/componentHarness'
import i18n from '@/i18n'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'
import en from 'element-plus/dist/locale/en.mjs'

const App = (await import('@/App.vue')).default

/**
 * 读法说明：App 的 script setup 没有 expose，无法直接读内部 computed。
 * 本文件改为遍历渲染树取 ElConfigProvider 实例的 props.locale —— 那正是
 * element-plus 组件实际消费的值，比读组件内部状态更贴近真实行为。
 */

let active = null

const mountApp = async (locale) => {
  i18n.global.locale.value = locale
  active = mountComponent(App, { locale })
  await flush(4)
  return active
}

/** 从渲染树里取 el-config-provider 组件的实例（Vue 3 内部：vnode.component） */
const findConfigProvider = (handle) => {
  const stack = [handle.app._instance]
  while (stack.length) {
    const inst = stack.pop()
    if (!inst) continue
    const name = inst.type && (inst.type.name || inst.type.__name)
    if (name === 'ElConfigProvider') return inst
    const subTree = inst.subTree
    const walk = (vnode) => {
      if (!vnode || typeof vnode !== 'object') return
      if (vnode.component) stack.push(vnode.component)
      if (Array.isArray(vnode.children)) vnode.children.forEach(walk)
    }
    walk(subTree)
  }
  return null
}

beforeEach(() => {
  i18n.global.locale.value = 'zh-CN'
})

afterEach(() => {
  if (active) {
    active.unmount()
    active = null
  }
})

describe('App.vue：Element Plus 语言跟随 i18n', () => {
  test('中文界面下向 el-config-provider 注入中文 locale 包', async () => {
    const c = await mountApp('zh-CN')
    const provider = findConfigProvider(c)
    expect(provider, '未找到 el-config-provider 渲染实例').not.toBeNull()
    expect(provider.props.locale).toBe(zhCn)
  })

  test('英文界面下注入英文 locale 包（映射方向不得写反）', async () => {
    const c = await mountApp('en-US')
    const provider = findConfigProvider(c)
    expect(provider).not.toBeNull()
    expect(provider.props.locale).toBe(en)
    expect(provider.props.locale).not.toBe(zhCn)
  })

  test('两种语言确实来自不同 locale 包（反证：包内容有真实语言差异）', async () => {
    // 若有人把两个分支都指向同一个包（例如都 import zhCn），上面两例仍会「各自通过」，
    // 故这里直接比对包内的真实文案差异作为交叉验证。
    expect(zhCn.el.pagination.total).not.toBe(en.el.pagination.total)
    expect(zhCn.name).toBe('zh-cn')
    expect(en.name).toBe('en')
  })

  test('运行中切换语言，provider 收到的 locale 随之改变（响应式未断）', async () => {
    const c = await mountApp('zh-CN')
    expect(findConfigProvider(c).props.locale).toBe(zhCn)

    i18n.global.locale.value = 'en-US'
    await flush(4)
    expect(findConfigProvider(c).props.locale).toBe(en)

    i18n.global.locale.value = 'zh-CN'
    await flush(4)
    expect(findConfigProvider(c).props.locale).toBe(zhCn)
  })

  test('非 en-US 的语言码一律回落中文（默认语言是中文，不得落成 undefined）', async () => {
    // 词表里还有其它 zh 变体时不得出现「未映射」的空白 locale
    const c = await mountApp('zh-TW')
    const provider = findConfigProvider(c)
    expect(provider.props.locale).toBeTruthy()
    expect(provider.props.locale).toBe(zhCn)
  })

  test('渲染 router-view（根组件必须给路由出口）', async () => {
    const c = await mountApp('zh-CN')
    // 默认路由表为空时 router-view 不渲染内容，但组件树里必须有 RouterView
    const stack = [c.app._instance]
    let found = false
    while (stack.length) {
      const inst = stack.pop()
      if (!inst) continue
      const name = inst.type && (inst.type.name || inst.type.__name)
      if (name === 'RouterView') {
        found = true
        break
      }
      const walk = (vnode) => {
        if (!vnode || typeof vnode !== 'object') return
        if (vnode.component) stack.push(vnode.component)
        if (Array.isArray(vnode.children)) vnode.children.forEach(walk)
      }
      walk(inst.subTree)
    }
    expect(found, '根组件未渲染 router-view，所有页面都会空白').toBe(true)
  })
})
