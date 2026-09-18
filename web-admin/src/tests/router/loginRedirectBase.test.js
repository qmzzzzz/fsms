/**
 * 子路径部署下的登录跳转（L-10 复核结论的回归锁定）
 *
 * 背景：安全评估报告 L-10 判定「4 处 router.push('/login') 未带 BASE_URL，
 * 子路径部署（如 /admin/）下会跳出应用」。本轮复核**驳回该定性**：
 *
 *   vue-router 的 createWebHistory(base) 会在 push 时自动前置 base，
 *   `push('/login')` 在 base='/admin/' 下实际落地 /admin/login，不逃逸。
 *
 * 报告作者把两件事混为一谈：store/auth.js 之所以显式拼 BASE_URL，
 * 是因为它用的是 `window.location.replace(...)`（原生跳转，确实需要手动拼）；
 * 而 router.push 走的是 vue-router 的 history 抽象，base 由 router 统一负责。
 *
 * 本文件做两件事：
 *   1. 行为级：用真实 vue-router + jsdom 断言 push('/login') 的落点；
 *   2. 源码级：断言 4 处调用点确实走 vue-router（而非 window.location），
 *      因为「改用原生跳转」才是真正会引入该 bug 的重构方向。
 */
import { describe, it, expect } from 'vitest'
import { createRouter, createWebHistory } from 'vue-router'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

// 测试文件位于 src/tests/router/，上溯三级即 web-admin 根目录
const SRC = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')

const makeRouter = (base) =>
  createRouter({
    history: createWebHistory(base),
    routes: [
      { path: '/', name: 'home', component: { template: '<div>home</div>' } },
      { path: '/login', name: 'login', component: { template: '<div>login</div>' } },
    ],
  })

describe('L-10 复核：router.push("/login") 在子路径部署下不逃逸', () => {
  it('BASE=/admin/ 时 push("/login") 落在 /admin/login', async () => {
    const router = makeRouter('/admin/')
    await router.push('/login')
    await router.isReady()
    expect(window.location.pathname).toBe('/admin/login')
    // 路由内部的 path 仍是 /login——base 由 history 层负责，不污染路由表
    expect(router.currentRoute.value.path).toBe('/login')
  })

  it('BASE=/ 时 push("/login") 落在 /login（对照，防误伤根路径部署）', async () => {
    const router = makeRouter('/')
    await router.push('/login')
    await router.isReady()
    expect(window.location.pathname).toBe('/login')
  })

  it('resolve("/login").href 自带 base（说明 base 由 router 统一负责）', () => {
    expect(makeRouter('/admin/').resolve('/login').href).toBe('/admin/login')
    expect(makeRouter('/').resolve('/login').href).toBe('/login')
  })
})

describe('L-10 复核：4 处调用点必须继续走 vue-router', () => {
  // 若哪天有人把这 4 处改成 window.location.href = '/login'，
  // 那才会真正引入报告所描述的子路径逃逸——本断言把该重构方向挡住。
  const CALL_SITES = [
    'src/utils/api.js',
    'src/components/ChangePasswordCard.vue',
    'src/layout/index.vue',
    'src/views/RegisterView.vue',
  ]

  it.each(CALL_SITES)('%s 通过 vue-router 跳转，未使用原生 location', (rel) => {
    const src = readFileSync(resolve(SRC, rel), 'utf8')
    expect(src).toContain("push('/login')")
    // 该文件不得出现「原生跳转到 /login」的写法
    expect(src).not.toMatch(/location\.(href|replace|assign)\s*[=(]\s*['"`]\/login/)
  })
})
