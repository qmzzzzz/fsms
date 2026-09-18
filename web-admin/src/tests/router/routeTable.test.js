/**
 * 路由表契约（src/router/index.js 的路由声明本身）
 *
 * 与其他路由测试的分工：routeGuard.test.js 把视图全部替身化，只验守卫决策；
 * 本文件反过来——**不替身任何视图**，专门验证路由声明指向的目标确实可用。
 *
 * 钉住的四类真实退化（都会在生产环境炸、且构建期不一定报错）：
 *  1. 懒加载导入指向已改名/删除的视图文件 → 用户点菜单时 chunk 加载失败白屏。
 *     这正是 router/index.js 里 onError 恢复逻辑存在的原因；若导入路径本身写错，
 *     恢复逻辑只会无休止刷新。本用例让这类错误在 CI 阶段就暴露。
 *  2. meta.titleKey 在词表里缺键 → 菜单显示裸键（如 nav.devices）或空白。
 *  3. meta.permission 形状不合法（缺冒号 / 空模块）→ matchPermission 的
 *     模块通配分支永远失配，持有 `device:*` 的用户会被莫名拒绝。
 *  4. 路由 name 重复 → vue-router 静默覆盖，push({name}) 指向非预期页面。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import i18n from '@/i18n'

// 本文件位于 src/tests/router/，上溯两级即 src/
const ROUTER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../router')

const router = (await import('@/router')).default
const routes = router.getRoutes()

/** 取路由记录的懒加载工厂（vue-router 把 component 规范化为 components.default） */
const lazyFactory = (record) => record.components && record.components.default

describe('路由表契约', () => {
  test('每条路由的懒加载导入都能解析出组件（视图文件被改名/删除即红）', async () => {
    const withFactory = routes.filter((record) => typeof lazyFactory(record) === 'function')
    expect(withFactory.length).toBeGreaterThan(0)

    for (const record of withFactory) {
      const loaded = await lazyFactory(record)()
      const component = loaded && loaded.default
      expect(component, record.path + ' 的导入未提供 default 导出').toBeTruthy()
      // SFC 编译产物是对象；函数式组件则必须是函数——两者之外说明导错了东西
      expect(
        typeof component === 'object' || typeof component === 'function',
        record.path + ' 的 default 导出不是组件'
      ).toBe(true)
    }
    // 真实 .vue 视图（含 element-plus 组件）首次编译约数秒；这是本文件"不替身"
    // 的必然成本，也是它相对 routeGuard.test.js 的独有价值
  }, 120000)

  test('每个 meta.titleKey 在中英词表里都有实际译文（缺键会显示裸键）', () => {
    const keyed = routes.filter((record) => record.meta && record.meta.titleKey)
    expect(keyed.length).toBeGreaterThan(0)
    for (const record of keyed) {
      const key = record.meta.titleKey
      for (const locale of ['zh-CN', 'en-US']) {
        const text = i18n.global.t(key, {}, { locale })
        expect(text, key + ' 在 ' + locale + ' 下缺键').not.toBe(key)
        expect(String(text).length, key + ' 在 ' + locale + ' 下译文为空').toBeGreaterThan(0)
      }
    }
  })

  test('每个 meta.permission 都是 module:action 形状（模块通配才有意义）', () => {
    const guarded = routes.filter((record) => record.meta && record.meta.permission)
    expect(guarded.length).toBeGreaterThan(0)
    for (const record of guarded) {
      const permission = record.meta.permission
      expect(permission, record.path + ' 的权限码缺冒号').toContain(':')
      const [mod, action] = permission.split(':')
      expect(mod.length, record.path + ' 的权限模块名为空').toBeGreaterThan(0)
      expect(action.length, record.path + ' 的权限动作名为空').toBeGreaterThan(0)
    }
  })

  test('路由重名不复存在：每条路由的名字仍是自己的路径末段（重名会静默摘掉旧路由）', () => {
    // 为什么不能直接查「名字有无重复」：vue-router 4 注册重名路由时会**移除**
    // 先注册的那条（实测：把 devices 的 name 改成 dashboard 后，getRoutes() 里
    // /dashboard 整条消失、/devices 顶替了 dashboard 这个名字，而名字序列里
    // 一个重复都没有）。故必须比对「名字 ↔ 自身路径」，被顶替的那条会立刻露馅。
    const named = routes.filter((record) => typeof record.name === 'string')
    expect(named.length).toBeGreaterThan(0)
    for (const record of named) {
      const segment = record.path.split('/').filter(Boolean).pop()
      expect(record.name, record.path + ' 的名字与路径末段不一致（疑被重名顶替）').toBe(segment)
    }
  })

  test('每个路径都能 resolve 回自己的名字（防被同名路由阴影遮蔽）', () => {
    const named = routes.filter((record) => typeof record.name === 'string')
    for (const record of named) {
      const resolved = router.resolve(record.path)
      expect(resolved.name, record.path + ' 解析到了别的路由').toBe(record.name)
    }
  })

  test('源码里不得出现重复的路由 name（vue-router 注册时会静默摘掉先注册的那条）', () => {
    // 为什么必须查源码而不是查 getRoutes()：注册重名路由时 vue-router 4 会把
    // 先注册的那条**移除**，因此运行期路由表里看不到任何重复痕迹（实测：把
    // /profile 的 name 改成 'about' 后，/profile 整条消失，且 /about 仍在、
    // 名字与路径依然自洽）。只有回到声明文本才能发现这类被顶替的路由。
    const source = readFileSync(resolve(ROUTER_DIR, 'index.js'), 'utf8')
    const names = Array.from(source.matchAll(/\bname:\s*'([^']+)'/g)).map((m) => m[1])
    expect(names.length).toBeGreaterThan(0)
    const dupes = names.filter((name, index) => names.indexOf(name) !== index)
    expect(dupes, '重复的路由 name：' + dupes.join(', ')).toEqual([])
  })
  test('需要认证的页面默认受保护：未显式声明 requiresAuth 即须经守卫鉴权', () => {
    // requiresAuth 采用「默认 true」语义（守卫读的是 `!== false`）。
    // 若有人把某业务页写成 requiresAuth: true 忘删或误写成 false，此例不走；
    // 这里钉的是「只有 login/register 两个入口可匿名」，新增匿名页必须显式改这里。
    const anon = routes
      .filter((record) => record.meta && record.meta.requiresAuth === false)
      .map((record) => record.name)
      .sort()
    expect(anon).toEqual(['login', 'register'])
  })
})
