/**
 * RecentAlarmsCard 行为测试（最近报警表格 + 跳转）
 *
 * 组件定位：DashboardView 的「最近报警」纯渲染卡。数据加载/权限门控留在视图层，
 * 故本组件只有两件事要做对：
 *  1. 把 rows 的 6 个字段如实映射到「时间/地点/类型/状态」四列，tagType/statusType
 *     落到 el-tag 的类型类上（映射错 → 危急报警显示成蓝色「信息」标签）；
 *  2. 「查看全部」跳到 /alarms（路由错 → 用户点了没反应或跳错页）。
 *
 * 表格是 Element Plus 的 el-table：jsdom 无布局，但 el-table 在 jsdom 下会渲染真实
 * DOM 行（实测 2 行数据渲染出 2 个 .el-table__row），故直接断言单元格文本。
 */
import { describe, test, expect, afterEach } from 'vitest'
import { mountComponent, click, flush, settleRouter } from '../helpers/componentHarness'
import RecentAlarmsCard from '@/components/RecentAlarmsCard.vue'
import i18n from '@/i18n'
import { defineComponent, h, ref } from 'vue'

let active = null

const routes = [
  { path: '/alarms', name: 'alarms', component: { render: () => null } },
  { path: '/:pathMatch(.*)*', name: 'fallback', component: { render: () => null } },
]

const mount = (props, options = {}) => {
  active = mountComponent(RecentAlarmsCard, { props, routes, ...options })
  return active
}

afterEach(() => {
  active?.handle.unmount()
  active = null
  i18n.global.locale.value = 'zh-CN'
})

/** 取数据行（排除表头行）的单元格文本矩阵 */
const bodyRows = (c) =>
  c
    .findAll('.el-table__body-wrapper .el-table__row')
    .map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => td.textContent.trim()))

const sample = () => [
  {
    time: '2026-09-18 10:00:00',
    location: 'A栋1层东侧',
    type: '火警',
    tagType: 'danger',
    status: '待处理',
    statusType: 'danger',
  },
  {
    time: '2026-09-18 09:00:00',
    location: 'B栋2层西侧',
    type: '故障',
    tagType: 'warning',
    status: '已处理',
    statusType: 'success',
  },
]

describe('RecentAlarmsCard 表格渲染', () => {
  test('rows 逐行逐列渲染：时间 / 地点 / 类型 / 状态（顺序与数据一致）', async () => {
    const c = mount({ rows: sample() })
    await flush(6)
    expect(c.errors).toEqual([])
    expect(bodyRows(c)).toEqual([
      ['2026-09-18 10:00:00', 'A栋1层东侧', '火警', '待处理'],
      ['2026-09-18 09:00:00', 'B栋2层西侧', '故障', '已处理'],
    ])
  })

  test('表头文案取 i18n 词表：创建时间 / 报警位置 / 报警类型 / 状态', async () => {
    const c = mount({ rows: [] })
    await flush(6)
    expect(c.findAll('.el-table__header th').map((th) => th.textContent.trim())).toEqual([
      '创建时间',
      '报警位置',
      '报警类型',
      '状态',
    ])
    // 与词表取值一致，防「表头硬编码中文」在英文界面下漏译
    expect(i18n.global.t('common.createTime')).toBe('创建时间')
    expect(i18n.global.t('alarm.location')).toBe('报警位置')
    expect(i18n.global.t('alarm.alarmType')).toBe('报警类型')
    expect(i18n.global.t('common.status')).toBe('状态')
  })

  test('英文界面下表头与按钮走英文词表', async () => {
    const c = mount({ rows: [] }, { locale: 'en-US' })
    await flush(6)
    expect(c.findAll('.el-table__header th').map((th) => th.textContent.trim())).toEqual([
      'Created At',
      'Location',
      'Alarm Type',
      'Status',
    ])
    expect(c.find('.glass-btn--link').textContent.trim()).toBe('View All')
  })

  test('每行两个标签：类型用 row.tagType、状态用 row.statusType 且 effect=plain', async () => {
    const c = mount({ rows: sample() })
    await flush(6)
    const tags = c.findAll('.el-tag')
    expect(tags).toHaveLength(4)
    // 类型标签：跟随 tagType（danger / warning）
    expect(tags[0].className).toContain('el-tag--danger')
    expect(tags[0].textContent.trim()).toBe('火警')
    expect(tags[2].className).toContain('el-tag--warning')
    expect(tags[2].textContent.trim()).toBe('故障')
    // 状态标签：跟随 statusType（danger / success）
    expect(tags[1].className).toContain('el-tag--danger')
    expect(tags[1].textContent.trim()).toBe('待处理')
    expect(tags[3].className).toContain('el-tag--success')
    expect(tags[3].textContent.trim()).toBe('已处理')
    // 状态标签 effect=plain（Element Plus 会加 --plain 类）；类型标签不加
    expect(tags[1].className).toContain('el-tag--plain')
    expect(tags[3].className).toContain('el-tag--plain')
    expect(tags[0].className).not.toContain('el-tag--plain')
    expect(tags[2].className).not.toContain('el-tag--plain')
    // 标签尺寸：四个标签都必须是 small（表格行内不撑高行高）
    expect(tags.map((el) => el.className.includes('el-tag--small'))).toEqual([
      true,
      true,
      true,
      true,
    ])
    expect(tags.filter((el) => el.className.includes('el-tag--large'))).toEqual([])
  })

  test('info 类型标签同样如实落到 el-tag--info（兜底档不丢样式）', async () => {
    const c = mount({
      rows: [
        {
          time: 't',
          location: 'l',
          type: '其它',
          tagType: 'info',
          status: '处理中',
          statusType: 'warning',
        },
      ],
    })
    await flush(6)
    const tags = c.findAll('.el-tag')
    expect(tags[0].className).toContain('el-tag--info')
    expect(tags[1].className).toContain('el-tag--warning')
  })

  test('rows 缺省为空数组：不渲染数据行、不崩、无 Vue 错误与告警', async () => {
    const c = mount({})
    await flush(6)
    expect(c.findAll('.el-table__body-wrapper .el-table__row')).toEqual([])
    expect(c.findAll('.el-table__header th')).toHaveLength(4)
    expect(c.errors).toEqual([])
    expect(c.warnings).toEqual([])
  })

  test('rows 从空到有数据：新增行真实渲染（props 响应式更新生效）', async () => {
    const rows = ref([])
    const Host = defineComponent({
      setup() {
        return () => h(RecentAlarmsCard, { rows: rows.value })
      },
    })
    const c = mountComponent(Host, {})
    active = c
    await flush(6)
    expect(bodyRows(c)).toEqual([])
    rows.value = sample()
    await flush(8)
    expect(bodyRows(c)).toEqual([
      ['2026-09-18 10:00:00', 'A栋1层东侧', '火警', '待处理'],
      ['2026-09-18 09:00:00', 'B栋2层西侧', '故障', '已处理'],
    ])
    rows.value = []
    await flush(8)
    expect(bodyRows(c)).toEqual([])
    expect(c.errors).toEqual([])
  })

  test('列宽声明：时间 180 / 类型 120 / 状态 120，共 4 列', async () => {
    const c = mount({ rows: [] })
    await flush(6)
    // el-table 会为表头与表体各渲染一份 colgroup（实测 8 个 col），
    // 断言表头那份即可代表列定义
    const cols = c.findAll('.el-table__header-wrapper colgroup col')
    expect(cols).toHaveLength(4)
    // 只锁组件声明的三列固定宽度（地点列不设 width，由 Element Plus 自适应，
    // 其内部默认值不属于本组件契约，故不断言）
    expect(cols[0].getAttribute('width')).toBe('180')
    expect(cols[2].getAttribute('width')).toBe('120')
    expect(cols[3].getAttribute('width')).toBe('120')
  })
})

describe('RecentAlarmsCard 查看全部跳转', () => {
  test('点击「查看全部」后路由稳定落在 /alarms', async () => {
    const c = mount({ rows: [] })
    await flush(6)
    expect(c.router.currentRoute.value.path).toBe('/')
    click(c.find('.glass-btn--link'))
    await settleRouter(c.router)
    expect(c.router.currentRoute.value.path).toBe('/alarms')
    expect(c.errors).toEqual([])
  })

  test('跳转按钮是原生 button 且带图标（不会被误当作链接或触发提交）', async () => {
    const c = mount({ rows: [] })
    await flush(6)
    const btn = c.find('.glass-btn--link')
    expect(btn.getAttribute('type')).toBe('button')
    expect(btn.tagName).toBe('BUTTON')
    expect(btn.querySelector('svg')).not.toBe(null)
  })

  test('卡片标题为「最近报警记录」，与按钮同处卡片头部', async () => {
    const c = mount({ rows: [] })
    await flush(6)
    const header = c.find('.card-header')
    expect(header).not.toBe(null)
    expect(header.textContent).toContain('最近报警记录')
    expect(header.querySelector('.glass-btn--link')).not.toBe(null)
  })
})
