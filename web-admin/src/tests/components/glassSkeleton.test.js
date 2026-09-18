/**
 * GlassSkeleton 行为测试（5 种骨架变体）
 *
 * 组件定位：首屏加载占位（个人资料卡 / 仪表盘欢迎卡 / 统计卡 / 图表 / 列表页）。
 * 契约是「占位结构与真实内容同构」——行数、列宽、头像直径若与真实内容不一致，
 * 数据到达替换时页面会跳动。因此断言落在 DOM 结构与内联几何上，而不是源码字符串。
 *
 * 覆盖要点：5 个 variant 分支 + 未知值兜底（源码 else 分支 = table 结构）、
 * rows / cols / avatarSize 三个 prop 的真实生效、无障碍 role 与 aria-label（取自 i18n 词表）。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { mountComponent, flush } from '../helpers/componentHarness'
import GlassSkeleton from '@/components/GlassSkeleton.vue'
import i18n from '@/i18n'

let active = null
const mount = (props, options = {}) => {
  active = mountComponent(GlassSkeleton, { props, ...options })
  return active
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  i18n.global.locale.value = 'zh-CN'
})

describe('GlassSkeleton 变体结构', () => {
  test('detail：默认 6 行，字段宽度按 5 值循环，头像默认 64px', async () => {
    const c = mount({ variant: 'detail' })
    await flush(2)
    expect(c.errors).toEqual([])
    expect(c.element.className).toContain('glass-skeleton--detail')
    expect(c.findAll('.gs-detail__row')).toHaveLength(6)
    expect(c.findAll('.gs-detail__icon')).toHaveLength(6)
    // fieldWidths = ['62%','78%','54%','70%','44%']；第 6 行取 (6-1)%5=0，回到首个值
    expect(c.findAll('.gs-detail__field').map((el) => el.style.width)).toEqual([
      '62%',
      '78%',
      '54%',
      '70%',
      '44%',
      '62%',
    ])
    const avatar = c.find('.gs-detail__avatar')
    expect(avatar.style.width).toBe('64px')
    expect(avatar.style.height).toBe('64px')
    // 变体结构互斥：detail 不应渲染 table / chart 的结构
    expect(c.findAll('.gs-table__row')).toEqual([])
    expect(c.findAll('.gs-chart__block')).toEqual([])
  })

  test('welcome：标题 + 副标题 + 头像三块，头像用 avatarSize', async () => {
    const c = mount({ variant: 'welcome', avatarSize: 48 })
    await flush(2)
    expect(c.errors).toEqual([])
    expect(c.element.className).toContain('glass-skeleton--welcome')
    expect(c.findAll('.gs-welcome__title')).toHaveLength(1)
    expect(c.findAll('.gs-welcome__sub')).toHaveLength(1)
    const avatar = c.find('.gs-welcome__avatar')
    expect(avatar.style.width).toBe('48px')
    expect(avatar.style.height).toBe('48px')
    expect(c.findAll('.gs-detail__row')).toEqual([])
    expect(c.findAll('.gs-table__row')).toEqual([])
  })

  test('stat：标签 / 数值 / 趋势 + 图标共 4 块', async () => {
    const c = mount({ variant: 'stat' })
    await flush(2)
    expect(c.errors).toEqual([])
    expect(c.element.className).toContain('glass-skeleton--stat')
    expect(c.findAll('.gs-stat__label')).toHaveLength(1)
    expect(c.findAll('.gs-stat__value')).toHaveLength(1)
    expect(c.findAll('.gs-stat__trend')).toHaveLength(1)
    expect(c.findAll('.gs-stat__icon')).toHaveLength(1)
    expect(c.findAll('.gs-stat .sk-block')).toHaveLength(4)
    expect(c.findAll('.gs-table__row')).toEqual([])
  })

  test('chart：整块占位，不渲染任何行 / 单元格', async () => {
    const c = mount({ variant: 'chart' })
    await flush(2)
    expect(c.errors).toEqual([])
    expect(c.element.className).toContain('glass-skeleton--chart')
    expect(c.findAll('.gs-chart__block')).toHaveLength(1)
    expect(c.findAll('.gs-table__cell')).toEqual([])
    expect(c.findAll('.gs-detail__row')).toEqual([])
  })

  test('variant 缺省即 table（prop 默认值不可悄悄改成别的变体）', async () => {
    const c = mount({})
    await flush(2)
    expect(c.element.className).toContain('glass-skeleton--table')
    expect(c.findAll('.gs-table__row')).toHaveLength(7)
    expect(c.findAll('.gs-chart__block')).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('table：默认 6 行数据 + 1 行表头，每行 5 列且列宽等于 cols 默认值', async () => {
    const c = mount({ variant: 'table' })
    await flush(2)
    expect(c.errors).toEqual([])
    expect(c.element.className).toContain('glass-skeleton--table')
    expect(c.findAll('.gs-table__row')).toHaveLength(7)
    expect(c.findAll('.gs-table__row--head')).toHaveLength(1)
    expect(c.findAll('.gs-table__cell')).toHaveLength(35)
    const widths = ['10%', '28%', '22%', '20%', '20%']
    expect(c.findAll('.gs-table__cell').map((el) => el.style.width)).toEqual(
      Array.from({ length: 7 }, () => widths).flat()
    )
    expect(c.findAll('.gs-detail__row')).toEqual([])
  })

  test('rows / cols 自定义值真实生效（表头 1 行 + rows 行数据，列数 = cols 长度）', async () => {
    const c = mount({ variant: 'table', rows: 3, cols: ['5%', '95%'] })
    await flush(2)
    expect(c.findAll('.gs-table__row')).toHaveLength(4)
    expect(c.findAll('.gs-table__cell')).toHaveLength(8)
    expect(c.findAll('.gs-table__cell').map((el) => el.style.width)).toEqual([
      '5%',
      '95%',
      '5%',
      '95%',
      '5%',
      '95%',
      '5%',
      '95%',
    ])
  })

  test('detail 的 rows 同样可控（3 行时只渲染 3 行）', async () => {
    const c = mount({ variant: 'detail', rows: 3 })
    await flush(2)
    expect(c.findAll('.gs-detail__row')).toHaveLength(3)
    expect(c.findAll('.gs-detail__field').map((el) => el.style.width)).toEqual([
      '62%',
      '78%',
      '54%',
    ])
  })

  test('未知 variant 兜底为 table 结构（else 分支），class 如实反映传入值', async () => {
    const c = mount({ variant: 'bogus' })
    await flush(2)
    expect(c.errors).toEqual([])
    expect(c.element.className).toContain('glass-skeleton--bogus')
    expect(c.findAll('.gs-table__row')).toHaveLength(7)
    expect(c.findAll('.gs-table__cell')).toHaveLength(35)
  })
})

describe('GlassSkeleton 样式钩子（global.css 依赖）', () => {
  test('根类名 glass-skeleton 与变体类名同时存在（改名会让 global.css 规则失效）', async () => {
    const c = mount({ variant: 'detail' })
    await flush(2)
    // global.css 用 .glass-skeleton 给占位容器设 width:100%，
    // 组件用 `glass-skeleton--${variant}` 做变体钩子；两者都是外部契约
    expect(c.element.classList.contains('glass-skeleton')).toBe(true)
    expect(c.element.classList.contains('glass-skeleton--detail')).toBe(true)
    expect(c.element.classList.contains('glass-skeleton--table')).toBe(false)
  })
})

describe('GlassSkeleton 无障碍与 i18n', () => {
  test('role=status 且 aria-label 取中文词表 common.loading', async () => {
    const c = mount({ variant: 'table' })
    await flush(2)
    expect(c.element.getAttribute('role')).toBe('status')
    expect(c.element.getAttribute('aria-label')).toBe('加载中...')
    // 与 i18n 实例取值一致：词表若被改动，两侧同时可见
    expect(i18n.global.t('common.loading')).toBe('加载中...')
  })

  test('英文界面下 aria-label 用英文词表（缺键会回退成键名而被抓出）', async () => {
    const c = mount({ variant: 'table' }, { locale: 'en-US' })
    await flush(2)
    expect(c.element.getAttribute('aria-label')).toBe('Loading...')
  })

  test('切换语言后 aria-label 跟随更新（setup 期不得把词表文案固化成字符串）', async () => {
    const c = mount({ variant: 'table' })
    await flush(2)
    expect(c.element.getAttribute('aria-label')).toBe('加载中...')
    i18n.global.locale.value = 'en-US'
    await flush(2)
    expect(c.element.getAttribute('aria-label')).toBe('Loading...')
    i18n.global.locale.value = 'zh-CN'
    await flush(2)
    expect(c.element.getAttribute('aria-label')).toBe('加载中...')
    expect(c.errors).toEqual([])
  })
  test('variant 变化后结构与 aria-label 仍稳定（重复挂载无残留）', async () => {
    const first = mount({ variant: 'detail', rows: 2 })
    await flush(2)
    expect(first.findAll('.gs-detail__row')).toHaveLength(2)
    first.handle.unmount()
    active = null
    const second = mount({ variant: 'table', rows: 2, cols: ['50%', '50%'] })
    await flush(2)
    expect(second.findAll('.gs-detail__row')).toEqual([])
    expect(second.findAll('.gs-table__cell')).toHaveLength(6)
    expect(second.element.getAttribute('aria-label')).toBe('加载中...')
    expect(second.errors).toEqual([])
  })
})
