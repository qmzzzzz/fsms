/**
 * AuthPrefs 行为测试（认证页主题 + 语言偏好控件）
 *
 * 组件契约（登录/注册页共用，两处此前各实现一遍必然漂移，故抽组件）：
 *  1. 主题三态：下拉项与 appStore.themeMode 对齐，当前项带 is-active；
 *     选择后 setThemeMode 落地并持久化（localStorage），按钮文案跟随；
 *  2. 语言切换必须三处一致：setLocale（切 i18n + 写 sessionStorage + 落 html lang）、
 *     appStore.setLanguage（持久化事实来源）、locale.value（响应式跟随）——
 *     少任何一处都会出现「文案没换/刷新后回跳/html lang 不变」类缺陷；
 *  3. 按钮文案随语言切换（主题药丸用 autoShort 短文案，认证卡头空间受限）。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { mountComponent, flush, click } from '../helpers/componentHarness'
import i18n from '@/i18n'
import { useAppStore } from '@/store'
import AuthPrefs from '@/components/AuthPrefs.vue'

let active = null
let store = null

const label = (key) => i18n.global.t(key)

/** 真实定时器 + nextTick 轮询；超时说明「在等什么」，不做静默兜底 */
const pollUntil = async (predicate, message) => {
  for (let i = 0; i < 60; i += 1) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 20))
    await flush(2)
  }
  if (predicate()) return
  throw new Error('轮询超时：' + message)
}

const visiblePopper = () =>
  Array.from(document.body.querySelectorAll('.el-popper')).find(
    (el) => el.getAttribute('aria-hidden') === 'false'
  )
const openByClick = async (trigger, message) => {
  await pollUntil(() => !visiblePopper(), '等待上一个浮层关闭')
  click(trigger)
  await pollUntil(() => !!visiblePopper(), message)
  return visiblePopper()
}
const itemLabels = (popper) =>
  Array.from(popper.querySelectorAll('.el-dropdown-menu__item')).map((el) => el.textContent.trim())
const item = (popper, text) => {
  const el = Array.from(popper.querySelectorAll('.el-dropdown-menu__item')).find(
    (it) => it.textContent.trim() === text
  )
  if (!el) throw new Error('下拉项不存在：' + text + '；实际为 ' + itemLabels(popper).join(' | '))
  return el
}
const activeItems = (popper) =>
  Array.from(popper.querySelectorAll('.el-dropdown-menu__item.is-active')).map((el) =>
    el.textContent.trim()
  )

const mountPrefs = async () => {
  active = mountComponent(AuthPrefs, {
    setupStore: (pinia) => {
      store = useAppStore(pinia)
      store.setThemeMode('system')
      store.setLanguage('zh-CN')
      i18n.global.locale.value = 'zh-CN'
    },
  })
  await flush(6)
  // jsdom 的 navigator.language 是 en-US，i18n 初始化即把 <html lang> 置为 en-US；
  // 先显式打回中文，「切换后 setLocale 写入 lang」才是可证伪的断言
  document.documentElement.setAttribute('lang', 'zh-CN')
  return active
}

const themeBtn = (c) => c.findAll('.auth-prefs__btn')[0]
const langBtn = (c) => c.findAll('.auth-prefs__btn')[1]

afterEach(() => {
  active?.handle.unmount()
  active = null
  store = null
  i18n.global.locale.value = 'zh-CN'
  window.localStorage.removeItem('themeMode')
})

describe('AuthPrefs 认证页偏好控件', () => {
  test('主题下拉：三态选项与 store 对齐，选择后落地、持久化且当前项带 is-active', async () => {
    const c = await mountPrefs()
    expect(themeBtn(c).textContent).toContain(label('common.autoShort'))

    const popper = await openByClick(themeBtn(c), '主题下拉')
    expect(itemLabels(popper)).toEqual([
      label('common.autoMode'),
      label('common.lightMode'),
      label('common.darkMode'),
    ])
    expect(activeItems(popper)).toEqual([label('common.autoMode')])

    click(item(popper, label('common.darkMode')))
    await pollUntil(() => store.themeMode === 'dark', 'themeMode=dark')
    expect(window.localStorage.getItem('themeMode')).toBe('dark')
    expect(themeBtn(c).textContent).toContain(label('common.darkMode'))

    const popper2 = await openByClick(themeBtn(c), '主题下拉（重开）')
    expect(activeItems(popper2)).toEqual([label('common.darkMode')])
    expect(c.errors).toEqual([])
  })

  test('语言切到 English：i18n、html lang、store 与按钮文案四处一致', async () => {
    const c = await mountPrefs()
    const zhAutoShort = label('common.autoShort')
    expect(langBtn(c).textContent).toContain('中文')

    const popper = await openByClick(langBtn(c), '语言下拉')
    expect(itemLabels(popper)).toEqual(['中文', 'English'])
    expect(activeItems(popper)).toEqual(['中文'])

    click(item(popper, 'English'))
    await pollUntil(() => i18n.global.locale.value === 'en-US', 'locale=en-US')
    // setLocale 的副作用：html lang 属性（读屏软件与浏览器翻译据此工作）。
    // 注意不能改用 sessionStorage 断言——appStore.setLanguage 也写同一键，
    // 那条断言分不出是谁写的（实测：删掉 setLocale 调用后 sessionStorage 仍命中）
    expect(document.documentElement.getAttribute('lang')).toBe('en-US')
    // appStore 是持久化事实来源
    expect(store.language).toBe('en-US')
    expect(langBtn(c).textContent).toContain('English')
    // 主题药丸文案同步换语言，且不再残留中文短文案
    expect(themeBtn(c).textContent).toContain(label('common.autoShort'))
    expect(themeBtn(c).textContent).not.toContain(zhAutoShort)
    expect(c.errors).toEqual([])
  })

  test('语言可切回中文：双向切换都不能瘸（防「恒英文」实现）', async () => {
    const c = await mountPrefs()
    const popper = await openByClick(langBtn(c), '语言下拉')
    click(item(popper, 'English'))
    await pollUntil(() => i18n.global.locale.value === 'en-US', 'locale=en-US')

    const popper2 = await openByClick(langBtn(c), '语言下拉（切回）')
    expect(activeItems(popper2)).toEqual(['English'])
    click(item(popper2, '中文'))
    await pollUntil(() => i18n.global.locale.value === 'zh-CN', 'locale=zh-CN')
    expect(store.language).toBe('zh-CN')
    expect(langBtn(c).textContent).toContain('中文')
    expect(c.errors).toEqual([])
  })
})
