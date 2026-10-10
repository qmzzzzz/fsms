/**
 * ExitOverlay 行为测试（退出遮罩；B5 补测——34 轮点名的零直接测试文件之一）
 *
 * 组件契约（源码注释自陈 + 与布局层的协作设计）：
 *  1. visible=false 什么都不渲染——遮罩只存在于退出期间；
 *  2. visible=true 时 Teleport 到 body：布局层在同一时刻给 .app-wrapper 加
 *     inert（layout/index.vue:13），把整块应用移出可访问性树并禁止聚焦。
 *     遮罩必须留在 inert 子树**之外**——role="alert" + aria-live 的「正在退出」
 *     播报依赖它还在可访问性树里；留在原处会被一起 inert 掉，播报静默失效。
 *     因此「挂在 document.body 直下、不在挂载根节点内」是本文件的核心断言；
 *  3. 无障碍属性齐备：role="alert" / aria-live="assertive"，装饰性 spinner
 *     对读屏隐藏（aria-hidden）；
 *  4. 文案走 i18n（common.appTitle + auth.signingOut），切语言实时跟随；
 *  5. visible 翻回 false：遮罩离场移除，不留常驻节点。
 *
 * 34 轮 M5「ExitOverlay 无 inert」的处置口径：遮罩自身**不能**加 inert（那会连
 * 它自己的 aria-live 播报一起禁掉）；下层不可交互由布局层的 inert 负责。第 2 条
 * 断言钉住的正是这个分工——遮罩在 body 直下，才在布局 inert 子树之外。
 *
 * 技术事实（实测）：
 *  - Teleport 的内容不在挂载根内，断言一律走 document.querySelector；
 *  - Transition 的 leave 在 jsdom 下靠 rAF 收尾（无 CSS 时长信息），故离场
 *    断言用墙钟轮询，不用固定 sleep 也不假设帧数。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { defineComponent, h, reactive } from 'vue'
import { mountComponent, flush } from '../helpers/componentHarness'
import i18n from '@/i18n'
import ExitOverlay from '@/components/ExitOverlay.vue'

let active = null

const overlay = () => document.body.querySelector('.exit-overlay')

afterEach(() => {
  active?.handle.unmount()
  active = null
  i18n.global.locale.value = 'zh-CN'
})

/** 受控宿主：harness 的 props 是静态的，visible 翻转必须经 reactive 宿主 */
const makeHost = () => {
  const state = reactive({ visible: false })
  const Host = defineComponent({
    setup() {
      return () => h(ExitOverlay, { visible: state.visible })
    },
  })
  return { Host, state }
}

/** 轮询等待遮罩离场（墙钟上限 2s：jsdom 的 rAF 约 16ms 一帧，给足余量） */
const waitGone = async () => {
  const deadline = Date.now() + 2000
  while (overlay() && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

describe('ExitOverlay 退出遮罩', () => {
  test('visible=false：不渲染任何遮罩节点', () => {
    active = mountComponent(ExitOverlay, { props: { visible: false } })
    expect(overlay()).toBeNull()
  })

  test('visible=true：Teleport 到 body 直下，不在挂载根节点内（布局 inert 禁不掉它）', () => {
    active = mountComponent(ExitOverlay, { props: { visible: true } })
    const el = overlay()
    expect(el).toBeTruthy()
    // 布局层对 .app-wrapper 加 inert 时会连带 inert 整个子树；遮罩若留在原处，
    // aria-live 播报静默失效。parentElement 必须是 body 本身。
    expect(el.parentElement).toBe(document.body)
    expect(active.root.contains(el)).toBe(false)
  })

  test('无障碍属性：role=alert / aria-live=assertive / spinner 对读屏隐藏', () => {
    active = mountComponent(ExitOverlay, { props: { visible: true } })
    const el = overlay()
    expect(el.getAttribute('role')).toBe('alert')
    expect(el.getAttribute('aria-live')).toBe('assertive')
    const spinner = el.querySelector('.exit-overlay__spinner')
    expect(spinner.getAttribute('aria-hidden')).toBe('true')
  })

  test('文案走 i18n：中文退出文案，切英文后实时跟随', async () => {
    i18n.global.locale.value = 'zh-CN'
    active = mountComponent(ExitOverlay, { props: { visible: true } })
    await flush(2)
    expect(overlay().textContent).toContain('消防安全管理系统')
    expect(overlay().textContent).toContain('正在安全退出…')

    i18n.global.locale.value = 'en-US'
    await flush(2)
    expect(overlay().textContent).toContain('Fire Safety Management System')
    expect(overlay().textContent).toContain('Signing out…')
  })

  test('visible 翻回 false：遮罩离场移除（不留常驻节点）', async () => {
    const { Host, state } = makeHost()
    active = mountComponent(Host)
    state.visible = true
    await flush(2)
    expect(overlay()).toBeTruthy()

    state.visible = false
    await flush(2)
    await waitGone()
    expect(overlay()).toBeNull()
  })
})
