/**
 * AboutView「系统运行指标」卡片接线回归（O-8）
 *
 * 背景：模板与 i18n 词条早已就位，但 script 从未实现——
 * `canViewMetrics`/`metricsSnap`/`topRoutes`/`metricsAlerts`/
 * `routeBarWidth`/`formatUptime` 在模板里被引用却不存在于 script，
 * 样式类也全部缺失（.route-bar-fill 没有背景色，条形图不可见）。
 * 本套件把接线后的关键决定钉住。
 *
 * 图表渲染与轮询时序是 Canvas/Timer 行为，jsdom 断言不出来，
 * 与 registerView/dashboardView 同思路，以源码不变量兜底。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

describe('AboutView 指标卡数据接线', () => {
  const source = readSrc('views/AboutView.vue')

  test('script 实现了模板引用的全部绑定（此前的断线状态）', () => {
    // 缺任何一个，Vue 都会在渲染该卡时抛 ReferenceError
    for (const binding of [
      'canViewMetrics',
      'metricsSnap',
      'topRoutes',
      'metricsAlerts',
      'routeBarWidth',
      'formatUptime',
    ]) {
      expect(source).toContain(`const ${binding}`)
    }
  })

  test('权限门控与后端 /api/metrics 的 security:audit 一致', () => {
    // 后端 app.js: authenticate + checkPermission('security:audit')。
    // 前端漏门控则无权限用户每次进页都吃 403；权限码写歪则卡片永不出现
    expect(source).toContain(`hasPerm('security:audit')`)
    expect(source).toContain('if (!canViewMetrics.value) return')
    expect(source).toContain('v-if="canViewMetrics"')
  })

  test('数据源走 reports.getMetrics 封装（不裸拼路径）', () => {
    expect(source).toContain('await api.reports.getMetrics()')
    expect(source).not.toContain("apiClient.get('/metrics')")
  })

  test('失败静默且保留上一次数据（轮询瞬时失败不清空面板）', () => {
    const loadBlock = source.slice(
      source.indexOf('const loadMetrics'),
      source.indexOf('const METRICS_POLL_MS')
    )
    // catch 分支不得把 metricsSnap 置空
    expect(loadBlock).toContain('catch')
    expect(loadBlock).not.toContain('metricsSnap.value = null')
    expect(loadBlock).not.toContain('metricsSnap.value = []')
  })

  test('轮询受页面可见性约束且卸载时清理定时器', () => {
    expect(source).toContain("document.visibilityState === 'visible'")
    expect(source).toContain('clearInterval(metricsTimer)')
    // 卸载后仍轮询等于给后端留一个隐形常驻客户端
    expect(source).toContain('onUnmounted')
  })

  test('轮询不以上次成败为条件（首次失败后必须还能重试）', () => {
    // 若写成 visible && metricsSnap.value !== null，
    // 首次加载失败就永远停在空态
    const pollBlock = source.slice(source.indexOf('metricsTimer = setInterval'))
    expect(pollBlock).not.toContain('metricsSnap.value !== null')
  })
})

describe('AboutView 指标卡展示逻辑', () => {
  const source = readSrc('views/AboutView.vue')

  test('Top 路由按后端降序切片而非前端重排', () => {
    expect(source).toContain('slice(0, TOP_ROUTES_COUNT)')
  })

  test('条形图按本批最大值归一化，不用 totalRequests 做基准', () => {
    // 以全站总请求数为基准会把所有条压成细线，图形失去对比作用
    const widthBlock = source.slice(
      source.indexOf('const routeBarWidth'),
      source.indexOf('const formatUptime')
    )
    expect(widthBlock).toContain('topRoutes.value.map((x) => x.requests)')
    expect(widthBlock).not.toContain('totalRequests')
  })

  test('formatUptime 分级进位且对非法输入有防御', () => {
    const uptimeBlock = source.slice(
      source.indexOf('const formatUptime'),
      source.indexOf('/**\n * 拉取指标快照')
    )
    expect(uptimeBlock).toContain('Number(seconds) || 0')
    expect(uptimeBlock).toContain('s < 60')
    expect(uptimeBlock).toContain('m < 60')
    expect(uptimeBlock).toContain('h < 24')
  })
})

describe('AboutView 指标卡样式', () => {
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
    // 告警级别：模板按 a.level 动态拼键，缺一级就会渲染出原始键名
    for (const level of ['low', 'medium', 'high', 'critical']) {
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
    const untranslated = Object.entries(en.about.metrics)
      .filter(([, v]) => typeof v === 'string' && /[\u4e00-\u9fa5]/.test(v))
      .map(([k]) => k)
    expect(untranslated).toEqual([])
  })
})
