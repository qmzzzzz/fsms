import { createI18n } from 'vue-i18n'

/**
 * 支持的 locale 白名单（P3）。
 * sessionStorage 里保存的值与运行期传入的值都不可信（可被手工改写/拼接），
 * 非白名单值一律回落——否则 <html lang> 与词表查找都会落到未知 locale 上。
 */
export const SUPPORTED_LOCALES = ['zh-CN', 'en-US']

/**
 * 读取持久化的语言偏好（P3-08）：localStorage 优先；旧版本把偏好存在
 * sessionStorage（新开标签页即回退浏览器语言），读到旧值时回填 localStorage
 * 完成一次性迁移。非白名单值一律视为未设置。
 */
export const readStoredLocale = () => {
  try {
    const local = localStorage.getItem('locale')
    if (SUPPORTED_LOCALES.includes(local)) return local
  } catch (_) {}
  try {
    const legacy = sessionStorage.getItem('locale')
    if (SUPPORTED_LOCALES.includes(legacy)) {
      try {
        localStorage.setItem('locale', legacy)
      } catch (_) {}
      return legacy
    }
  } catch (_) {}
  return null
}

/**
 * 默认语言推断的单一来源（2026-11-17 审计「一致性」项）。
 * 规则：持久化偏好 > 浏览器语言（zh* 前缀 → zh-CN，其余 → en-US）。
 * 此前 store/app.js 镜像侧重复实现了这段推断，且 navigator.language 为空时
 * 兜底成 en-US，与 i18n 实际生效的 zh-CN 口径不一致；现统一从这里导出，
 * 空值兜底定为 zh-CN（与本项目用户主体及 fallbackLocale 一致）。
 */
export const resolveDefaultLocale = () => {
  const stored = readStoredLocale()
  if (stored) return stored
  const browserLang = (typeof navigator !== 'undefined' && navigator.language) || 'zh-CN'
  return browserLang.startsWith('zh') ? 'zh-CN' : 'en-US'
}

const defaultLocale = resolveDefaultLocale()

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

// P2-2（2026-11-17 审计 §3.2）：入口词表按 locale 懒加载。此前 zh-CN / en-US
// 双语词表（合计约 70KB gzip）经静态 import 全量打进首屏 chunk，运行时永远
// 只用其一，登录页同样承担。改为 import.meta.glob 动态 import 后，首屏不再
// 背词表，当前语言的词表在挂载前按需拉取（main.js await initialLocaleReady）。
// 只匹配入口词表两文件：attackAlerts / attackProfile / stuffingProfile 词典
// 仍随各自视图 chunk 静态注入（见各词典头注释与 AttackAlertsView.vue 的
// mergeLocaleMessage），机制不变，也不在此处抢加载。
const localeLoaders = import.meta.glob(['./locales/zh-CN.js', './locales/en-US.js'])

const i18n = createI18n({
  legacy: false,
  locale: defaultLocale,
  fallbackLocale: 'zh-CN',
  // 词表懒加载：实例创建时为空，由 loadLocaleMessages 按需并入。
  // 必须用 mergeLocaleMessage 而非 setLocaleMessage——视图 chunk 里
  // merge 进来的词典命名空间（attackAlerts 等）不能被入口词表补载覆盖掉。
  messages: {},
  messageCompiler,
})

const loadedLocales = new Set()

/**
 * 按需加载某语言的入口词表并并入 i18n 实例。
 * @returns {Promise<boolean>} 词表是否就位（已加载过 / 本次加载成功为 true）
 */
export const loadLocaleMessages = (locale) => {
  if (loadedLocales.has(locale)) return Promise.resolve(true)
  const loader = localeLoaders[`./locales/${locale}.js`]
  if (!loader) return Promise.resolve(false)
  return Promise.resolve(loader()).then((mod) => {
    i18n.global.mergeLocaleMessage(locale, mod.default)
    loadedLocales.add(locale)
    return true
  })
}

// 应用启动即拉取默认语言词表；main.js 在挂载前 await（测试亦可 await 保证确定性）
export const initialLocaleReady = loadLocaleMessages(defaultLocale)

// 测试环境兜底：组件测试普遍经 mountComponent 直接赋值 locale.value 切语言
// （默认 zh-CN），并不走 setLocale 的补载链路；若词表未就位会大面积裸键红。
// 生产路径不受影响——仍只加载当前语言这一份词表。
if (import.meta.env.VITEST) {
  SUPPORTED_LOCALES.forEach((l) => loadLocaleMessages(l))
}

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
    return Promise.resolve(false)
  }
  const previousLocale = i18n.global.locale.value
  // 同步切换三处（保持既有契约）：locale 状态、localStorage、<html lang>。
  // AuthPrefs / 主布局等调用方依赖「调用后立即生效」的同步语义（随后就读
  // locale.value、断言 html lang、镜像 store.language），不能等词表加载。
  i18n.global.locale.value = locale
  try {
    // 与主题偏好同一介质（localStorage）：新开标签页/登出后语言不再回退（P3-08）
    localStorage.setItem('locale', locale)
  } catch (_) {}
  document.documentElement.setAttribute('lang', locale)
  // P2-2：词表异步补载。切换瞬间新语言的词表可能尚未就位，缺失键会短暂
  // 回落 fallbackLocale（zh-CN）或显示键名，补载完成后响应式刷新——即报告
  // 建议中「切换瞬间可先回落当前语言/显示加载态」的取缔方案，避免为等词表
  // 而破坏调用方的同步契约。返回加载 promise：fire-and-forget 调用方不受
  // 影响，需要确定性的调用方（测试）可 await。
  return loadLocaleMessages(locale).then(
    () => true,
    (error) => {
      // 词表拉取失败（弱网/发版期 chunk 失效）：回退到切换前的 locale，
      // 宁可语言不变也不停在满屏键名的状态；错误留痕便于定位。
      console.error('[i18n] 词表加载失败，回退语言:', locale, error)
      i18n.global.locale.value = previousLocale
      document.documentElement.setAttribute('lang', previousLocale)
      return false
    }
  )
}

export function getLocale() {
  return i18n.global.locale.value
}

export default i18n
