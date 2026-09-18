/**
 * P2-55：`common.all` 语义错配回归（labelMaps + useRolePermissions）
 *
 * 两处独立缺陷：
 *  1. utils/labelMaps.js 的 makeAlarmTypeLabels 把报警类型 other（其他）
 *     映射到 common.all（全部）。DashboardView / ReportView 的饼图直接用它做
 *     扇区名，于是「其他」被渲染成一个名为「全部」的扇区——语义完全相反。
 *  2. composables/useRolePermissions.js 的 typeLabel 枚举与后端 Permission.type
 *     的 mongoose enum（['menu','button','api','data']，见 src/models/Permission.js:33）
 *     不一致：menu 被标成 common.all（全部），page 在后端不存在（分支永不命中），
 *     且缺 data。
 *
 * 断言对象是**可观测输出**（标签映射结果、typeLabel 返回值），不是源码文本：
 * 把 labelMaps 的 other 改回 common.all、或把 typeLabel 的 data 删掉 / 加回 page，
 * 都会让这里的断言变红。
 */
import { describe, test, expect, vi } from 'vitest'
import { createI18n } from 'vue-i18n'
import { createPinia, setActivePinia } from 'pinia'
import { makeAlarmTypeLabels, makeDeviceTypeLabels, makeAlarmStatusLabels } from '@/utils/labelMaps'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

const messages = { 'zh-CN': zhCN, 'en-US': enUS }

// 独立 i18n 实例：翻译结果即界面上真实显示的文案
const makeT = (locale) => {
  const i18n = createI18n({ legacy: false, locale, messages })
  return (key, params) => i18n.global.t(key, params)
}

// useRolePermissions 内部调 useI18n()，替换为绑定同一套词表的翻译函数
const tZh = makeT('zh-CN')
vi.mock('vue-i18n', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, useI18n: () => ({ t: (key, params) => tZh(key, params) }) }
})

describe('P2-55 labelMaps：other 不得显示为「全部」', () => {
  test('zh-CN：other → 其他，且不等于 common.all 的「全部」', () => {
    const t = makeT('zh-CN')
    const labels = makeAlarmTypeLabels(t)
    expect(labels.other).toBe('其他')
    expect(labels.other).not.toBe(t('common.all'))
  })

  test('en-US：other → Other，且不等于 common.all 的 All', () => {
    const t = makeT('en-US')
    const labels = makeAlarmTypeLabels(t)
    expect(labels.other).toBe('Other')
    expect(labels.other).not.toBe('All')
  })

  test('其余五种报警类型映射未被改坏', () => {
    const labels = makeAlarmTypeLabels(makeT('zh-CN'))
    expect(labels.smoke).toBe('烟雾报警')
    expect(labels.temp_abnormal).toBe('温度异常')
    expect(labels.manual_button).toBe('手动报警')
    expect(labels.phone_report).toBe('电话报告')
    expect(labels.patrol_find).toBe('巡检发现')
  })

  test('设备类型映射覆盖后端全部 10 个取值，fire_door/other 不再是裸码', () => {
    // 后端枚举：src/utils/constants.js DEVICE_TYPE（10 个）。
    // 旧断言「other 必须为 undefined」固化的是缺陷：DashboardCharts 用
    // makeDeviceTypeLabels(t)[type] || type 回落，缺键 => 饼图/图例上直接显示
    // 原始码 fire_door / other（词表里 device.typeFireDoor/typeOther 早有译文）。
    const labels = makeDeviceTypeLabels(makeT('zh-CN'))
    expect(Object.keys(labels).sort()).toEqual(
      [
        'emergency_light',
        'evacuation_sign',
        'extinguisher',
        'fire_alarm',
        'fire_door',
        'heat_detector',
        'hydrant',
        'other',
        'smoke_detector',
        'sprinkler',
      ].sort()
    )
    expect(labels.fire_door).toBe('防火门')
    expect(labels.other).toBe('其他')
    // 其余八项逐一钉住，防止为「补两个键」而错改既有映射
    expect(labels.fire_alarm).toBe('火灾报警器')
    expect(labels.sprinkler).toBe('喷淋系统')
    expect(labels.hydrant).toBe('消火栓')
    expect(labels.extinguisher).toBe('灭火器')
    expect(labels.smoke_detector).toBe('烟雾探测器')
    expect(labels.heat_detector).toBe('温度探测器')
    expect(labels.emergency_light).toBe('应急灯')
    expect(labels.evacuation_sign).toBe('疏散指示牌')
  })

  test('设备类型映射英文本地化：fire_door/other 不得退回中文或裸码', () => {
    const labels = makeDeviceTypeLabels(makeT('en-US'))
    expect(labels.fire_door).toBe('Fire Door')
    expect(labels.other).toBe('Other')
  })

  test('报警状态映射覆盖后端 5 个取值（含 false_alarm 专属词条）', () => {
    const labels = makeAlarmStatusLabels(makeT('zh-CN'))
    expect(labels).toEqual({
      pending: '待处理',
      processing: '处理中',
      resolved: '已处理',
      false_alarm: '误报',
      cancelled: '已取消',
    })
  })
})

describe('P2-55 useRolePermissions：typeLabel 与后端 Permission.type 对齐', () => {
  test('四种后端取值均有专属标签，menu 不再显示为「全部」', async () => {
    setActivePinia(createPinia())
    const { useRolePermissions } = await import('@/composables/useRolePermissions')
    const { typeLabel } = useRolePermissions()
    expect(typeLabel('api')).toBe('API')
    expect(typeLabel('menu')).toBe('菜单')
    expect(typeLabel('button')).toBe('操作')
    expect(typeLabel('data')).toBe('数据')
    // 关键回归：menu 此前被标为 common.all（「全部」）
    expect(typeLabel('menu')).not.toBe(tZh('common.all'))
  })

  test('data 不再落到兜底 role.permissions', async () => {
    setActivePinia(createPinia())
    const { useRolePermissions } = await import('@/composables/useRolePermissions')
    expect(useRolePermissions().typeLabel('data')).not.toBe(tZh('role.permissions'))
  })

  test('page 不是后端取值：兜底为「权限」而非「全部」', async () => {
    setActivePinia(createPinia())
    const { useRolePermissions } = await import('@/composables/useRolePermissions')
    expect(useRolePermissions().typeLabel('page')).toBe(tZh('role.permissions'))
  })

  test('未知类型统一兜底为「权限」', async () => {
    setActivePinia(createPinia())
    const { useRolePermissions } = await import('@/composables/useRolePermissions')
    expect(useRolePermissions().typeLabel('totally-unknown')).toBe(tZh('role.permissions'))
  })
})
