/**
 * 组件挂载基座（2026-09-18）
 *
 * 本仓未引入 @vue/test-utils（属新增依赖，需用户定夺），但 vitest 已在
 * vite.config.js 里把 element-plus 内联给 Vite 管道处理，因此可以直接用
 * Vue 官方 createApp 挂载真实的 .vue 单文件组件做行为断言。
 *
 * 基座提供的三个真实依赖：
 *  - i18n：用真实的 @/i18n 实例。若视图引用了不存在的键，vue-i18n 会告警，
 *    这样「词表缺键」这类问题在组件测试里也能暴露，而不是只在源码扫描里。
 *  - router：memory history + 用例自带的路由表，可断言 $router.push 的目标。
 *  - pinia：每用例独立实例，避免 store 状态跨用例串味。
 *
 * 定位：只做「把组件放进真实运行环境」这一件事。断言一律写在用例里，
 * 基座不替用例做任何判断（否则基座自身出 bug 会静默吞掉断言）。
 */
import { createApp, h, nextTick } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import i18n from '@/i18n'

/**
 * DOM 事件辅助：Element Plus 的按钮在 jsdom 下需真实派发 click 才会触发监听。
 *
 * 关键保真点：真实浏览器**不会**在被禁用的表单控件上派发 click。jsdom 的
 * dispatchEvent 不做这个判断，直接派发会让「按钮已禁用」这类回归悄悄测不出来
 * （实测：导出按钮 exporting 卡死时，合成 click 仍能触发第二次请求）。故这里
 * 显式对齐浏览器语义，禁用元素上的点击一律不派发。
 */
export const click = (el) => {
  if (el.disabled) return
  el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }))
}

export const flush = async (times = 1) => {
  for (let i = 0; i < times; i += 1) {
    await nextTick()
    // 每轮混入一个真实宏任务轮：Element Plus 对话框/消息链路里夹着定时器与
    // 渲染回调，纯微任务循环会让它们饿死——本地空载时偶发可达，CI 双核
    // runner 高负载下稳定饿死（run 68 实测 4 条「失败提示」断言全部超时/
    // 未达）。宏任务轮让出事件循环使定时器得以推进；对纯微任务链路只是
    // 无害的多等一轮。
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
}

/**
 * 挂载一个组件。
 *
 * @param {object} component   待挂载组件（import 进来的 SFC 对象）
 * @param {object} [options]
 * @param {object} [options.props]        传给组件的 props
 * @param {Array}  [options.slots]        插槽，形如 { default: () => [...] }
 * @param {Array}  [options.routes]       路由表；默认只放一条通配兜底路由
 * @param {string} [options.initialRoute] 初始路由路径
 * @param {string} [options.locale]       界面语言，默认 'zh-CN'
 * @param {boolean}[options.withI18n]     是否安装 i18n，默认 true
 * @param {Array}  [options.plugins]      额外插件（如自定义 pinia store 预置）
 * @param {Function}[options.setupStore]  挂载前对 pinia 实例做预置的回调
 * @returns 含 wrapper 语义的句柄；unmount 幂等，便于 afterEach 统一清理
 */
export const mountComponent = (component, options = {}) => {
  const {
    props = {},
    slots = {},
    routes = [{ path: '/:pathMatch(.*)*', name: 'fallback', component: { render: () => null } }],
    initialRoute = '/',
    locale = 'zh-CN',
    withI18n = true,
    plugins = [],
    setupStore = null,
  } = options

  if (withI18n) i18n.global.locale.value = locale

  const router = createRouter({ history: createMemoryHistory(), routes })
  // 初始路由必须真正落到 currentRoute 上（否则用例断言 push 目标时会与
  // 「起始就在目标页」混淆，测试变成恒真）。
  // 注意：push 必须在 app.use(router) 之后——memory history 的首次 resolve 由
  // 安装路由时触发的第一次导航驱动，装之前 push 会停在默认的 "/"（实测：
  // 装前 push('/login') 后 currentRoute 仍是 "/"，matched 为空）。
  const pinia = createPinia()
  if (setupStore) setupStore(pinia)

  const errors = []
  const warnings = []

  const app = createApp({
    render: () =>
      h(
        component,
        { ...props },
        Object.fromEntries(Object.entries(slots).map(([k, fn]) => [k, fn]))
      ),
  })
  app.config.errorHandler = (err) => errors.push(err)
  app.config.warnHandler = (msg) => warnings.push(msg)

  const useList = [router, pinia, ...plugins]
  if (withI18n) useList.unshift(i18n)
  useList.forEach((p) => app.use(p))
  // 安装后再落初始路由（见上方注释：顺序不可倒置）
  router.push(initialRoute).catch(() => {})

  const root = document.createElement('div')
  document.body.appendChild(root)
  app.mount(root)

  const handle = {
    app,
    router,
    pinia,
    root,
    errors,
    warnings,
    /** 组件渲染出的 DOM：等价于 @vue/test-utils 的 .element */
    get element() {
      return root.firstElementChild
    },
    find: (selector) => root.querySelector(selector),
    findAll: (selector) => Array.from(root.querySelectorAll(selector)),
    text: () => root.textContent,
    html: () => root.innerHTML,
    unmount: () => {
      if (handle.unmounted) return
      handle.unmounted = true
      app.unmount()
      root.remove()
    },
  }

  return { handle, ...handle }
}

/**
 * 轮询等待某个条件成立（最长 maxTicks 个 nextTick），超时立即报错并说明在等什么。
 *
 * 为什么不用固定的 flush(N)：Element Plus 表单校验（async-validator）等异步链路的
 * 微任务层数会随版本与调用路径变化，写死 tick 数会在本机通过、在 CI 负载高时偶发失败
 * （本轮实测：等待 8 个 tick 时按钮仍停在 is-loading，第 9 个才复位）。
 * 轮询断言的是「一定会到达的终态」，既不引入时长假设，也不会掩盖永久失败。
 *
 * @param {Function} predicate 返回真值即结束等待
 * @param {object}  [options]
 * @param {number}  [options.maxTicks] 上限（默认 50 个 nextTick，约等于瞬时）
 * @param {string}  [options.message]  超时提示，说明在等什么
 */
export const waitFor = async (predicate, options = {}) => {
  const { maxTicks = 50, message = '条件' } = options
  for (let i = 0; i < maxTicks; i += 1) {
    if (predicate()) return
    await nextTick()
    // 混入真实宏任务轮（理由同 flush）：失败提示链路夹定时器回调，纯微任务
    // 轮询在 CI 高负载下会饿死它们 ⇒ waitFor 超时（run 68 实测）。macrotask
    // 让出事件循环后定时器得以推进；命中条件的用例通常第一轮就返回。
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  if (predicate()) return
  throw new Error(`waitFor 超时（${maxTicks} 个 nextTick）：${message}`)
}

/**
 * 等待路由跳转稳定。memory history 下 push 是异步的（需等 resolve 与
 * 组件渲染），用例断言 $router.currentRoute 前必须等待，否则拿到旧值。
 *
 * 适用范围（实测边界，勿误用）：本函数只负责「让**已经发起**的导航落定」
 * （典型场景：mountComponent 的 initialRoute）。它**无法**等待「组件在交互中
 * 稍后才发起的导航」——那种情况下 path 在导航开始前就是稳定的，本函数会
 * 立刻返回（实测：登录成功后 push("/dashboard") 要到第 26 个 tick 才落定）。
 * 断言「点击后应到达某路由」必须显式轮询目标，例如：
 *   await waitFor(() => c.router.currentRoute.value.path === '/dashboard')
 */
export const settleRouter = async (router, times = 8) => {
  for (let i = 0; i < times; i += 1) {
    await router.isReady().catch(() => {})
    await nextTick()
  }
}
