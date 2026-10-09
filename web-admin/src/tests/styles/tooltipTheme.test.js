/**
 * Element Plus 浮层（tooltip / 下拉菜单 / date-picker）主题适配静态不变量
 *
 * 背景：顶栏语言/主题等入口的提示统一走 el-tooltip 后，浮层观感完全由仓库自己的 CSS
 * 决定。Element Plus 给 `.el-popper.is-dark` / `.is-light` 配的是实底配色，且箭头
 * （`.el-popper__arrow::before`，旋转 45° 的方块）是**独立元素**、取另一套变量——
 * 仓库改了浮层底色却没改箭头时，尖角处会露出一截异色；暗色下 `.is-light` 的默认箭头
 * 取 EP 自己的一套中性灰（#1d1e1f）与浅灰边（#414243），与仓库的蓝调深色表面对不上。
 *
 * jsdom 不注入外部样式表，算不出颜色，所以这里读 CSS 源码做「同色」比对：
 *  - 每个主题下，箭头底色必须等于浮层底色、箭头描边必须等于浮层描边；
 *  - 箭头规则一律不能带 !important——朝浮层的那两条边由 EP 的 placement 规则置
 *    transparent，那条规则带 !important 必须继续赢，否则旋转方块会露出实心方角。
 *  - 下拉浮层表面只画一层：外壳 .el-dropdown__popper.el-popper 必须透明化——
 *    EP 默认把底色/描边/阴影画在外壳上还带 5px 11px 内边距，与内层
 *    .el-dropdown-menu 的圆角/描边/内边距叠出双边框与错角毛边。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * 先剥掉注释再解析：声明之间夹着块注释时，(?:^|;) 锚点会失配（border 就找不到了）。
 * 用 RegExp 构造而不是字面量——字面量里 / 必须写成 \/，少一个反斜杠就会从
 * 「匹配注释」退化成「匹配两个 * 之间的任意内容」，把整段样式表啃得面目全非。
 */
const readStyles = (relPath) =>
  readFileSync(resolve(__dirname, relPath), 'utf8').replace(
    new RegExp('/\\*[\\s\\S]*?\\*/', 'g'),
    ''
  )
const APPLE = readStyles('../../assets/styles/apple-refine.css')
/* .is-light 浮层的暗色表面规则（html.dark .el-popper）在 dark.css，不在这 */
const DARK = readStyles('../../assets/styles/dark.css')

/** 选择器里的空白按 \s+ 匹配，容忍源码换行与多空格 */
const escape = (token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const ruleBody = (css, selector) => {
  const pattern = selector.trim().split(/\s+/).map(escape).join('\\s+')
  const matched = css.match(new RegExp(pattern + '\\s*\\{([^}]*)\\}'))
  return matched ? matched[1] : ''
}
const declaration = (body, prop) => {
  const matched = body.match(new RegExp('(?:^|;)\\s*' + prop + '\\s*:\\s*([^;]+)'))
  return matched ? matched[1].trim() : ''
}
/** 从声明值里取颜色片段（rgba() 自带空格与逗号，不能按空白切） */
const colorOf = (value) => {
  const matched = value.match(/rgba?\([^)]*\)|#[0-9a-fA-F]{3,8}|var\([^)]*\)/)
  return matched ? matched[0] : ''
}
const backgroundColor = (body) => colorOf(declaration(body, 'background'))
/** 优先读 border 简写（第三段是颜色），回退 border-color */
const borderColor = (body) => {
  const shorthand = declaration(body, 'border')
  return (shorthand ? colorOf(shorthand) : '') || colorOf(declaration(body, 'border-color'))
}

const TOOLTIP = '.el-popper.is-dark'
const TOOLTIP_ARROW = '.el-popper.is-dark > .el-popper__arrow::before'
const DARK_TOOLTIP = 'html.dark .el-popper.is-dark'
const DARK_TOOLTIP_ARROW = 'html.dark .el-popper.is-dark > .el-popper__arrow::before'
const DARK_MENU = 'html.dark .el-dropdown-menu'
const DARK_MENU_ARROW = 'html.dark .el-dropdown__popper > .el-popper__arrow::before'
const DARK_POPPER = 'html.dark .el-popper'
const DARK_LIGHT_ARROW =
  'html.dark .el-popper.is-light:not(.el-dropdown__popper) > .el-popper__arrow::before'
const LIGHT_MENU_ARROW = '.el-dropdown__popper.el-popper > .el-popper__arrow::before'
const DROPDOWN_SHELL = '.el-dropdown__popper.el-popper'

/** 浮层与箭头「同色」：底色、描边两项都比，缺一边就是半吊子适配 */
const expectSameSurface = (surfaceSelector, arrowSelector, surfaceCss = APPLE) => {
  const surface = ruleBody(surfaceCss, surfaceSelector)
  const arrow = ruleBody(APPLE, arrowSelector)
  expect(surface, `规则缺失：${surfaceSelector}`).not.toBe('')
  expect(arrow, `规则缺失：${arrowSelector}`).not.toBe('')
  expect(backgroundColor(arrow), `${arrowSelector} 底色须与 ${surfaceSelector} 一致`).toBe(
    backgroundColor(surface)
  )
  expect(borderColor(arrow), `${arrowSelector} 描边须与 ${surfaceSelector} 一致`).toBe(
    borderColor(surface)
  )
}

describe('Element Plus 浮层 · 主题适配（箭头与浮层同色）', () => {
  test('亮色 tooltip：箭头底色/描边跟随浮层玻璃底色', () => {
    expectSameSurface(TOOLTIP, TOOLTIP_ARROW)
  })

  test('亮色下拉菜单：箭头与菜单同描边，底色同源 EP overlay 白', () => {
    const menu = ruleBody(APPLE, '.el-dropdown-menu')
    const arrow = ruleBody(APPLE, LIGHT_MENU_ARROW)
    expect(arrow, `规则缺失：${LIGHT_MENU_ARROW}`).not.toBe('')
    // 描边不同源时箭头根部露一截异色（EP 默认取 --el-border-color-light #e4e7ed）
    expect(borderColor(arrow), '箭头描边须与菜单描边一致').toBe(borderColor(menu))
    // 底色与 EP 给 .el-dropdown-menu 的 background-color: var(--el-bg-color-overlay) 同源
    expect(backgroundColor(arrow)).toBe('var(--el-bg-color-overlay)')
  })

  test('暗色 tooltip：箭头跟随提亮后的浮层底色', () => {
    expectSameSurface(DARK_TOOLTIP, DARK_TOOLTIP_ARROW)
  })

  test('暗色下拉菜单：箭头与菜单表面同色（不再挂白三角）', () => {
    expectSameSurface(DARK_MENU, DARK_MENU_ARROW)
  })

  test('箭头规则不写 !important：placement 的透明边必须继续赢', () => {
    for (const selector of [
      TOOLTIP_ARROW,
      DARK_TOOLTIP_ARROW,
      DARK_MENU_ARROW,
      DARK_LIGHT_ARROW,
      LIGHT_MENU_ARROW,
    ]) {
      const body = ruleBody(APPLE, selector)
      expect(body, `规则缺失：${selector}`).not.toBe('')
      // 一旦 !important，连朝浮层那两条 transparent 边一起上色 → 实心方角
      expect(body, `${selector} 不能带 !important`).not.toContain('!important')
    }
  })

  test('暗色 date-picker 浮层：箭头与 html.dark .el-popper 实底同色', () => {
    expectSameSurface(DARK_POPPER, DARK_LIGHT_ARROW, DARK)
  })

  test('下拉外壳透明：表面只由 .el-dropdown-menu 画一层', () => {
    const shell = ruleBody(APPLE, DROPDOWN_SHELL)
    expect(shell, `规则缺失：${DROPDOWN_SHELL}`).not.toBe('')
    // 外壳留着 EP 的 5px 11px 内边距 + 10px 圆角 + 自己的描边时，会与 menu 的
    // 12px 圆角 + 1px 描边叠出双边框与错角毛边——边角不圆润的根因
    expect(declaration(shell, 'padding')).toBe('0 !important')
    expect(declaration(shell, 'background')).toBe('transparent !important')
    expect(declaration(shell, 'border')).toBe('none !important')
    expect(declaration(shell, 'box-shadow')).toBe('none !important')
    // 暗色 html.dark .el-popper 的实底/描边两条声明带 !important 且特异性 (0,2,1)
    // 压过上面的 (0,2,0)，不单独再盖一次，暗色菜单四周会围一圈 --xf-gray-50 实底框
    const darkShell = ruleBody(APPLE, 'html.dark .el-dropdown__popper.el-popper')
    expect(darkShell, '规则缺失：html.dark .el-dropdown__popper.el-popper').not.toBe('')
    expect(declaration(darkShell, 'background')).toBe('transparent !important')
    expect(declaration(darkShell, 'border')).toBe('none !important')
  })

  test('暗色 .is-light 规则排除下拉菜单', () => {
    // .is-light 规则特异性 (0,5,2) 高于下拉箭头规则 (0,3,2)，不排除就会把下拉
    // 箭头从 rgba(30,41,59,.95) 改成 --xf-gray-50 实底，与半透明菜单表面脱节
    expect(APPLE).toMatch(/html\.dark\s+\.el-popper\.is-light:not\(\.el-dropdown__popper\)\s*>/)
  })
})
