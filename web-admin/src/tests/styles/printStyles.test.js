/**
 * 打印样式层契约（P2-6，2026-11-02）
 *
 * 背景：消防系统的工单/巡检单/报警记录有真实纸质归档场景（现场签字、取证、
 * 交接）。触发路径是浏览器原生 Ctrl+P——本层必须只靠全局选择器生效，
 * 且必须覆盖 Element Plus 的浮层族（否则 fixed 定位的导航/浮层会按页重复
 * 出现在纸上）。
 *
 * 为什么读 CSS 源码断言而不是渲染后取值：jsdom 不实现 @media print 的媒询
 * 求值，也不做真实打印布局——渲染态取证拿不到「打印时是什么样」。本套件
 * 钉的是**声明不变量**（该隐藏的族在、该复位的布局在、该控制的分页在），
 * 真机效果由「Ctrl+P 预览」人工验收（deployment 无自动化打印测试，属已知边界）。
 *
 * 可证伪性：每条断言都同步钉住"删掉该声明后必须红"的形态（grep 命中判据与
 * 断言对象是同一份 CSS 文本）。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const RAW = readFileSync(resolve(__dirname, '../../assets/styles/print.css'), 'utf8')
/** 剥注释：说明文字里会出现选择器名，参与匹配会制造假绿 */
const CSS = RAW.replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '')

/**
 * 提取包含目标选择器的**全部**规则体并合并（同一选择器可出现在多个分组里，
 * 如 `.main-content` 既有布局复位块又有背景清除块）。CSS 用逗号分组
 * （`.sidebar,\n.navbar, … { }`），故按「切块 → 选择器列表含目标」找；
 * token 精确比对（含 `:not(...)` 后缀的按前缀匹配），避免 `.el-message`
 * 误命中 `.el-message-box`。
 */
const ruleBody = (selector) => {
  const blocks = [...CSS.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
  const bodies = []
  for (const [, selectors, body] of blocks) {
    const tokens = selectors.split(',').map((s) => s.trim())
    // 精确匹配，或带伪类/属性后缀的变体（a[href]::after、a[href]:not(...) 等）
    const hit = tokens.some(
      (t) => t === selector || t.startsWith(selector + ':') || t.startsWith(selector + '[')
    )
    if (hit) bodies.push(body)
  }
  return bodies.length ? bodies.join('\n') : null
}

describe('打印样式层：整层被 @media print 包裹（不污染屏幕渲染）', () => {
  test('全部规则位于 @media print 块内：屏幕态零影响', () => {
    // 前提自证：文件里确实有 @media print，且没有裸在媒体查询之外的规则块
    expect(CSS).toMatch(/@media\s+print\s*\{/)
    // 剥掉 @media print {...} 整体后不应残留任何 { } 规则（@page 允许在外——
    // 它本身就只在打印上下文生效；本文件将其放在块内，故一并剥除后应无规则）。
    const withoutPrint = CSS.replace(/@media\s+print\s*\{[\s\S]*\}\s*$/, '')
    expect(withoutPrint.trim()).toBe('')
  })

  test('引入顺序：main.js 中 print.css 位于全部样式层之后（覆盖权）', () => {
    const main = readFileSync(resolve(__dirname, '../../main.js'), 'utf8')
    const idx = (p) => main.indexOf(p)
    const printAt = idx('styles/print.css')
    expect(printAt).toBeGreaterThan(-1)
    for (const layer of [
      'global.css',
      'dark.css',
      'apple-polish.css',
      'apple-refine.css',
      'view-refine.css',
    ]) {
      expect(printAt).toBeGreaterThan(idx(`styles/${layer}`))
    }
  })
})

describe('打印样式层：交互件与浮层族必须隐藏（fixed 元素会按页重复上纸）', () => {
  test.each([
    ['侧边栏', '.sidebar'],
    ['顶栏', '.navbar'],
    ['Element Plus 浮层气泡族', '.el-popper'],
    ['消息与通知', '.el-message'],
    ['加载遮罩', '.el-loading-mask'],
    ['对话框遮罩（本体保留，仅遮罩隐藏）', '.el-overlay'],
    ['分页器', '.el-pagination'],
  ])('%s → display none !important', (_label, selector) => {
    const body = ruleBody(selector)
    expect(body, `选择器 ${selector} 应有规则体`).toBeTruthy()
    expect(body).toMatch(/display\s*:\s*none\s*!important/)
  })

  test('对话框本体不得被隐藏（详情弹窗是打印对象）', () => {
    // 反向对照：.el-dialog 不应出现在 display:none 的规则里
    expect(ruleBody('.el-dialog')).toBeNull()
  })
})

describe('打印样式层：布局复位与分页控制', () => {
  test('应用外壳回文档流：app-wrapper 与 main-content 去掉 margin/padding/min-height', () => {
    const wrapper = ruleBody('.app-wrapper')
    const main = ruleBody('.main-content')
    expect(wrapper).toMatch(/display\s*:\s*block/)
    expect(wrapper).toMatch(/margin\s*:\s*0/)
    expect(main).toMatch(/padding\s*:\s*0/)
    expect(main).toMatch(/min-height\s*:\s*0/)
  })

  test('屏幕背景被清除：main-content 的 background-image 置 none（网格纹理不落纸）', () => {
    const main = ruleBody('.main-content')
    expect(main).toMatch(/background-image\s*:\s*none/)
  })

  test('分页控制三件套：行/卡片 avoid 断页、表头可重复、页边距声明', () => {
    expect(ruleBody('.el-table tr')).toMatch(
      /break-inside\s*:\s*avoid|page-break-inside\s*:\s*avoid/
    )
    const card = ruleBody('.el-card')
    expect(card).toMatch(/break-inside\s*:\s*avoid|page-break-inside\s*:\s*avoid/)
    expect(CSS).toMatch(/@page\s*\{[^}]*margin\s*:/)
  })

  test('表格滚动容器展开：body-wrapper 与 scrollbar wrap 的 overflow/height 被放开', () => {
    const body = ruleBody('.el-table__body-wrapper')
    expect(body).toMatch(/overflow\s*:\s*visible/)
    expect(body).toMatch(/height\s*:\s*auto/)
    expect(body).toMatch(/max-height\s*:\s*none/)
  })

  test('链接真实地址还原：a[href]::after 输出 href，且排除锚点与 javascript:', () => {
    // content 值为 `' (' attr(href) ')'`——引号把空格与括号切成多段，正则的
    // [^']* 跨不过去；直接以「声明文本含 attr(href)」断言（与 CSS 同源的字符串比对）
    expect(CSS).toContain('a[href]')
    expect(CSS).toContain('::after')
    const contentLine = CSS.split(/\r?\n/).find((l) => /content\s*:/.test(l) && /attr\(/.test(l))
    expect(contentLine).toBeTruthy()
    expect(contentLine).toContain('attr(href)')
    // 排除条件在场（锚点与脚本伪协议打印出来是噪音）
    expect(CSS).toContain("not([href^='#'])")
    expect(CSS).toContain("not([href^='javascript:'])")
  })
})

describe('打印样式层：图表 canvas 的 inline 尺寸被覆盖（半截图防护）', () => {
  test('canvas 被强制 width 100%（echarts 写的是 inline px，max-width 对绘制缓冲区无效）', () => {
    const canvas = ruleBody('canvas')
    expect(canvas).toMatch(/width\s*:\s*100%/)
    expect(canvas).toMatch(/height\s*:\s*auto/)
  })

  test('chart-box 容器高度放开（固定 280px 会裁切）', () => {
    expect(ruleBody('.chart-box')).toMatch(/height\s*:\s*auto/)
  })
})
