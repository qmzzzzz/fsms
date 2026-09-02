import { createI18n } from 'vue-i18n'
import zhCN from './locales/zh-CN'
import enUS from './locales/en-US'
import legacyZhCN from './locales/legacy-raw-zh'
import legacyEnUS from './locales/legacy-raw-en'

const savedLocale = (() => {
  try {
    return sessionStorage.getItem('locale')
  } catch (_) {
    return null
  }
})()

const browserLang = navigator.language || 'zh-CN'
const defaultLocale = savedLocale || (browserLang.startsWith('zh') ? 'zh-CN' : 'en-US')

/**
 * 自定义消息编译器
 * 替换 vue-i18n 默认的 JIT 编译器（compileToFunction 内部使用 new Function），
 * 否则 CSP 缺少 'unsafe-eval' 时登录等页面渲染会抛出 EvalError。
 * 本项目消息为纯文本，仅需支持 {name} 具名插值 / 位置插值，无需函数求值。
 * 说明：v9 的 ctx.named 为函数（其 .name 会干扰取参），
 *       真实具名/位置插值参数统一存放在 ctx.values 中。
 */
const messageCompiler = (message) => {
  if (typeof message !== 'string') return message
  return (ctx) => {
    if (!/[{}]/.test(message)) return message
    const values = (ctx && typeof ctx === 'object' && ctx.values) || {}
    let listIdx = 0
    return message.replace(/\{([^}]+)\}/g, (match, key) => {
      if (Object.prototype.hasOwnProperty.call(values, key)) {
        return String(values[key])
      }
      if (listIdx < (Array.isArray(ctx.list) ? ctx.list.length : 0)) {
        return String(ctx.list[listIdx++])
      }
      return match
    })
  }
}

/**
 * P3-44：合并中文裸键兼容层。
 *
 * 展开顺序刻意让 legacy 在前、正式词表在后：正式键（common.xxx 等）是嵌套
 * 对象，legacy 是顶层平铺的中文键，两者本不冲突；但若日后出现同名，
 * 应当以正式词表为准。
 */
const messages = {
  'zh-CN': { ...legacyZhCN, ...zhCN },
  'en-US': { ...legacyEnUS, ...enUS },
}

const i18n = createI18n({
  legacy: false,
  locale: defaultLocale,
  fallbackLocale: 'zh-CN',
  messages,
  messageCompiler,
})

// 创建即同步 <html lang>：index.html 的 lang 是构建期硬编码（SSG 场景无法预知
// 用户语言），而 setLocale 只在登录后主布局被调用——登录/注册页以浏览器语言
// 初始化时，lang 属性与实际界面语言不一致，影响屏幕阅读器发音与浏览器翻译提示。
// 此处在 i18n 实例创建（应用入口最早）时对齐一次，后续切换仍由 setLocale 维护
document.documentElement.setAttribute('lang', defaultLocale)

export function setLocale(locale) {
  i18n.global.locale.value = locale
  try {
    sessionStorage.setItem('locale', locale)
  } catch (_) {}
  document.documentElement.setAttribute('lang', locale)
}

export function getLocale() {
  return i18n.global.locale.value
}

export default i18n
