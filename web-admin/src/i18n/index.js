import { createI18n } from 'vue-i18n'
import zhCN from './locales/zh-CN'
import enUS from './locales/en-US'

/**
 * 支持的 locale 白名单（P3）。
 * sessionStorage 里保存的值与运行期传入的值都不可信（可被手工改写/拼接），
 * 非白名单值一律回落——否则 <html lang> 与词表查找都会落到未知 locale 上。
 */
export const SUPPORTED_LOCALES = ['zh-CN', 'en-US']

const savedLocale = (() => {
  try {
    const saved = sessionStorage.getItem('locale')
    return SUPPORTED_LOCALES.includes(saved) ? saved : null
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
 *
 * 前导 `$` 排除（本轮修复）：词表历史欠账混入了后端 JS 模板字符串的源码形态
 * （如 ${check.invalid.join(...)}），它们是**文案值**的一部分而非插值占位符。
 * 旧实现 /\{([^}]+)\}/g 会把 ${x} 中的 {x} 当占位符替换，产出「$ + 参数值」
 * 这类破相文案（参数未命中时则原样直出模板源码）。本实现显式跳过前导 `$` 的
 * 花括号，只解析 {name} 语义；词表侧同步改写，两侧共同保证文案完整。
 */
const messageCompiler = (message) => {
  if (typeof message !== 'string') return message
  return (ctx) => {
    if (!/[{}]/.test(message)) return message
    const values = (ctx && typeof ctx === 'object' && ctx.values) || {}
    let listIdx = 0
    return message.replace(/\{([^}]+)\}/g, (match, key, offset, whole) => {
      // 前导 `$`：${...} 是模板字符串源码残留，不是 {name} 插值，原样保留
      if (offset > 0 && whole[offset - 1] === '$') return match
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
 * 消息词表（P3-44 收官）：中文裸键兼容层（legacy-raw-*.js）已随
 * 143 个裸键全部迁移到规范点号键而删除，词表只保留正式键结构。
 */
const messages = {
  'zh-CN': zhCN,
  'en-US': enUS,
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
  // P3：白名单校验——未知 locale 不生效也不落盘（保持当前语言），留痕便于发现
  // 调用方传错或被注入的值。语言选择器的取值集与 SUPPORTED_LOCALES 同源。
  if (!SUPPORTED_LOCALES.includes(locale)) {
    console.warn('[i18n] 忽略未支持的语言切换请求:', locale)
    return
  }
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
