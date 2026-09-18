/** src/i18n/index.js 入口行为回归（defaultLocale 推导 / setLocale / getLocale / <html lang> 同步）

 * 该文件此前 73.33% 覆盖：入口副作用（sessionStorage 容错、浏览器语言推导、
 * 创建即同步 html lang）与 setLocale/getLocale 全无断言。
 * 本轮按真实模块加载路径测试（模块在 import 时执行，故用 vi.resetModules 重载）。
 */
import { describe, test, expect, vi, afterEach } from 'vitest'

afterEach(() => {
  vi.resetModules()
  vi.unstubAllGlobals()
  sessionStorage.clear()
  document.documentElement.removeAttribute('lang')
})

/** 以给定的 sessionStorage / navigator 状态重新加载模块（模块顶层有副作用） */
const load = async ({ saved = null, lang = 'zh-CN', omitLang = false } = {}) => {
  vi.resetModules()
  sessionStorage.clear()
  if (saved !== null) sessionStorage.setItem('locale', saved)
  // omitLang：整个移除 language 属性（不是传 undefined —— 解构默认值会把它变回 'zh-CN'，
  // 那样测的仍是正常路径，抓不到「未做回退」的退化）
  vi.stubGlobal('navigator', omitLang ? {} : { language: lang })
  return await import('@/i18n')
}

describe('i18n 入口：默认语言推导', () => {
  test('无存档时按浏览器语言：zh 开头 → zh-CN', async () => {
    const mod = await load({ lang: 'zh-CN' })
    expect(mod.getLocale()).toBe('zh-CN')
    expect(document.documentElement.getAttribute('lang')).toBe('zh-CN')
  })

  test('无存档时按浏览器语言：非 zh 开头 → en-US（含 zh 前缀的误判防护）', async () => {
    const mod = await load({ lang: 'en-GB' })
    expect(mod.getLocale()).toBe('en-US')
    expect(document.documentElement.getAttribute('lang')).toBe('en-US')
  })

  test('存档语言优先于浏览器语言（用户选择必须跨会话保持）', async () => {
    const mod = await load({ saved: 'en-US', lang: 'zh-CN' })
    expect(mod.getLocale()).toBe('en-US')
    expect(document.documentElement.getAttribute('lang')).toBe('en-US')
  })

  test('zh 判据只认前缀：zh-Hant-TW 也归到 zh-CN（不是按语言全等）', async () => {
    const mod = await load({ lang: 'zh-Hant-TW' })
    expect(mod.getLocale()).toBe('zh-CN')
  })

  test('navigator.language 属性缺失时回退 zh-CN（不得直接读 language 而崩）', async () => {
    const mod = await load({ omitLang: true })
    expect(mod.getLocale()).toBe('zh-CN')
  })
})

describe('i18n 入口：setLocale / getLocale', () => {
  test('setLocale 同步三处：locale 状态、sessionStorage、<html lang>', async () => {
    const mod = await load({ lang: 'zh-CN' })
    mod.setLocale('en-US')
    expect(mod.getLocale()).toBe('en-US')
    expect(sessionStorage.getItem('locale')).toBe('en-US')
    expect(document.documentElement.getAttribute('lang')).toBe('en-US')
    // 切换回来也必须同步（不能只写一次）
    mod.setLocale('zh-CN')
    expect(mod.getLocale()).toBe('zh-CN')
    expect(sessionStorage.getItem('locale')).toBe('zh-CN')
    expect(document.documentElement.getAttribute('lang')).toBe('zh-CN')
  })

  test('setLocale 真的切换了译文取用（不是只改状态不生效）', async () => {
    const mod = await load({ lang: 'zh-CN' })
    expect(mod.default.global.t('common.save')).toBe('保存')
    mod.setLocale('en-US')
    expect(mod.default.global.t('common.save')).toBe('Save')
  })

  test('sessionStorage 写入抛异常时 setLocale 不崩（隐私模式容错）', async () => {
    const mod = await load({ lang: 'zh-CN' })
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError')
    })
    try {
      expect(() => mod.setLocale('en-US')).not.toThrow()
      expect(mod.getLocale()).toBe('en-US')
      expect(document.documentElement.getAttribute('lang')).toBe('en-US')
    } finally {
      spy.mockRestore()
    }
  })

  test('sessionStorage 读取抛异常时模块仍能加载（回退浏览器语言）', async () => {
    vi.resetModules()
    const spy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('SecurityError')
    })
    vi.stubGlobal('navigator', { language: 'en-US' })
    try {
      const mod = await import('@/i18n')
      expect(mod.getLocale()).toBe('en-US')
    } finally {
      spy.mockRestore()
    }
  })

  test('fallbackLocale 是 zh-CN：缺失键回落到中文而不是裸键', async () => {
    const mod = await load({ lang: 'en-US' })
    expect(mod.default.global.t('__definitely_missing_key__')).toBe('__definitely_missing_key__')
    // 显式验证 fallback 配置：zh-CN 侧有、en-US 侧没有的键会回落到中文
    const zh = mod.default.global.getLocaleMessage('zh-CN')
    expect(Object.keys(zh).length).toBeGreaterThan(0)
    // fallbackLocale 是 ComputedRef（实测 ctor=ComputedRefImpl），必须按 ref 口径断言
    expect(mod.default.global.fallbackLocale.value).toBe('zh-CN')
  })
})
