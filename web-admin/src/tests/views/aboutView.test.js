/**
 * AboutView「系统运行指标」卡片样式与词表回归（O-8）
 *
 * 背景：模板与 i18n 词条早已就位，但 script 从未实现——六个绑定在模板里被引用
 * 却不存在于 script，样式类也全部缺失（.route-bar-fill 没有背景色，条形图不可见）。
 *
 * 【本文件只保留 jsdom 物理上断言不了的两类不变量】
 *  1. `<style>` 块内的 CSS 规则：实测 jsdom 下 `document.querySelectorAll('style').length === 0`
 *     （SFC 样式块在 vitest 下完全不注入），`getComputedStyle` 取不到任何声明。
 *     故「样式类有没有定义」「填充色走不走主题变量」「数字用不用 tabular-nums」
 *     只能读源码文本。
 *  2. i18n 词表本身是数据（不是源码结构），直接断言键与值。
 *
 * 【已删除的静态断言 → 替代用例（均经变异实测杀死）】
 *   - 六个绑定是否在 script 中定义        → aboutViewMetrics.test.js（重命名任一绑定 → 10~16 例变红）
 *   - 数据源走 api.reports.getMetrics     → 同上（改为裸拼 apiClient.get('/metrics') → 14 例变红）
 *   - Top 路由 slice(0, TOP_ROUTES_COUNT) → 同上「Top 路由只取前 8 条」（改为 slice(0,20) → 变红）
 *   - 轮询不以上次成败为条件              → 同上「首次失败后仍会按周期重试」
 *                                          （加上 `&& metricsSnap.value !== null` → 该用例变红）
 *   - formatUptime 分级进位               → 同上「秒/分/时/天四档进位与非法输入兜底」
 * 原文件头曾声称「jsdom 断言不出来」——该说法已被 aboutViewMetrics.test.js（17 例真实挂载）证伪。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

describe('AboutView 指标卡样式（jsdom 不注入 SFC 样式，只能读源码）', () => {
  const source = readSrc('views/AboutView.vue')

  test('模板引用的指标卡样式类都有定义（此前全部缺失）', () => {
    const used = [
      'metrics-card',
      'metrics-body',
      'metrics-stats',
      'metrics-stat',
      'metrics-stat-value',
      'metrics-stat-label',
      'metrics-routes',
      'metrics-route',
      'route-name',
      'route-bar',
      'route-bar-fill',
      'route-count',
      'metrics-alerts',
      'metrics-alert-tag',
    ]
    for (const cls of used) {
      expect(source).toContain(`.${cls}`)
    }
  })

  test('条形填充色走主题变量而非写死色值', () => {
    const fillBlock = source.slice(source.indexOf('.route-bar-fill {'))
    expect(fillBlock).toContain('var(--xf-primary)')
  })

  test('指标数字用 mono + tabular-nums（位数不同不致卡片错落）', () => {
    const valueBlock = source.slice(
      source.indexOf('.metrics-stat-value {'),
      source.indexOf('.metrics-stat-label {')
    )
    expect(valueBlock).toContain('font-variant-numeric: tabular-nums')
  })
})

describe('about.metrics i18n 词条', () => {
  test('指标词条在两种语言下都存在', async () => {
    const zh = (await import('@/i18n/locales/zh-CN')).default
    const en = (await import('@/i18n/locales/en-US')).default
    for (const key of [
      'title',
      'live',
      'totalRequests',
      'totalErrors',
      'errorRate',
      'avgLatency',
      'uptime',
    ]) {
      expect(zh.about.metrics[key]).toBeTruthy()
      expect(en.about.metrics[key]).toBeTruthy()
    }
    // 告警级别：模板按 a.level 动态拼键，缺一级就会渲染出原始键名。
    // 'unknown' 必查——src/utils/metrics.js 对无 level 的告警回吐 level:'unknown'，
    // 而 zh↔en parity 门只比两份文件彼此一致，两边都缺某键时看不见，只有按真实取值枚举才拦得住。
    for (const level of ['low', 'medium', 'high', 'critical', 'unknown']) {
      expect(zh.about.metrics.level[level]).toBeTruthy()
      expect(en.about.metrics.level[level]).toBeTruthy()
    }
  })

  test('两种语言的 about 键集合一致', async () => {
    const zh = (await import('@/i18n/locales/zh-CN')).default
    const en = (await import('@/i18n/locales/en-US')).default
    expect(Object.keys(zh.about).sort()).toEqual(Object.keys(en.about).sort())
    expect(Object.keys(zh.about.metrics).sort()).toEqual(Object.keys(en.about.metrics).sort())
  })

  test('英文词条不含中文', async () => {
    const en = (await import('@/i18n/locales/en-US')).default
    // 必须递归到叶子：上一版只取 Object.entries(en.about.metrics) 第一层的字符串，
    // 于是嵌套块 metrics.level.*（告警级别文案）整块被 typeof==='string' 挡在判据之外，
    // 往里塞中文本用例照样绿。
    const leaves = []
    const walk = (obj, prefix) => {
      for (const [k, v] of Object.entries(obj)) {
        const key = prefix ? `${prefix}.${k}` : k
        if (typeof v === 'string') leaves.push([key, v])
        else if (v && typeof v === 'object') walk(v, key)
      }
    }
    walk(en.about, '')
    // 反向自证：确实走进了嵌套层，否则"递归"退化成第一层也不会红
    expect(leaves.some(([key]) => key.startsWith('metrics.level.'))).toBe(true)
    const untranslated = leaves.filter(([, v]) => /[\u4e00-\u9fa5]/.test(v)).map(([k]) => k)
    expect(untranslated).toEqual([])
  })
})

describe('AboutView 徽标图标盒模型（jsdom 不注入 SFC 样式，只能读源码）', () => {
  // .about-icon 是 <el-icon class="about-icon">（element-plus 定尺寸 1em 盒），
  // view-refine.css 给它加 10px padding 做渐变徽标；不显式 content-box 时 border-box
  // 让 padding 吃掉内容盒，svg 被 flex-shrink 压成 28×48 细条（实测）。
  const css = readSrc('assets/styles/view-refine.css')
  const block = css.slice(css.indexOf('.about-icon {'))
  const body = block.slice(0, block.indexOf('}'))

  test('徽标图标 content-box：48px 图标 + 2×10px padding = 68×68 徽标', () => {
    expect(body).toContain('box-sizing: content-box')
  })
})
