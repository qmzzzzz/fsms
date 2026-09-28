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
 *
 * F-166：本文件原先手抄了三份「后端取值清单」——DEVICE_TYPE 的 10 个、ALARM_TYPES
 * 的 6 个、ALARM_STATUSES 的 5 个（行 63「覆盖后端全部 10 个取值」的注释宣称对账，
 * 实际比较的是这份抄件）。抄件钉住的是清单的**结果**而不是清单本身，两个方向都错：
 *   - 后端加一档、前端没跟 => labels 仍只有旧的 N 个键，toEqual/逐条断言全绿（漏翻裸码）；
 *   - 前端按后端补齐第 N+1 档 => 断言反倒红，逼人把期望值再抄一遍。
 * 现在三份清单 createRequire 自后端单一来源（src/utils/constants.js 的 DEVICE_TYPE、
 * src/constants/alarm.js 的报警三组——两处都是 model 的 enum 指过来的真来源），
 * 逐档断言「这一档有没有一个真的翻过的标签」；具体文案仍按 P2-55 逐条钉死，
 * 因为文案的事实来源是前端词表本身，不是后端清单。
 */
import { createRequire } from 'node:module'
import { describe, test, expect, vi } from 'vitest'
import { createI18n } from 'vue-i18n'
import { createPinia, setActivePinia } from 'pinia'
import { makeAlarmTypeLabels, makeDeviceTypeLabels, makeAlarmStatusLabels } from '@/utils/labelMaps'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

const require = createRequire(import.meta.url)
const { DEVICE_TYPE } = require('../../../../src/utils/constants.js')
const { ALARM_TYPES, ALARM_STATUSES } = require('../../../../src/constants/alarm.js')
const DEVICE_TYPE_VALUES = Object.values(DEVICE_TYPE)

// 一档后端取值在前端必须有一个「真的翻过」的标签：非空、不等于原始码
// （调用方 DashboardCharts 是 labels[type] || type，缺键就渲染裸码），
// 且不是一个没解析的词条路径（vue-i18n 找不到键时原样返回 key，如 'alarm.pending'）。
const KEY_PATH = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$/
const expectTranslated = (label, rawCode) => {
  expect(label).toBeTruthy()
  expect(label).not.toBe(rawCode)
  expect(KEY_PATH.test(label)).toBe(false)
}

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

  test.each(ALARM_TYPES.map((v) => [v]))(
    '报警类型 %s（后端逐档）有一个翻过的标签，不是裸码也不是词条路径',
    (v) => {
      expectTranslated(makeAlarmTypeLabels(makeT('zh-CN'))[v], v)
    }
  )

  test('报警类型键集与后端 ALARM_TYPES 逐一对应（后端加档而前端未跟会红）', () => {
    expect(Object.keys(makeAlarmTypeLabels(makeT('zh-CN'))).sort()).toEqual([...ALARM_TYPES].sort())
  })

  test('各报警类型的中文文案未被改坏（逐条钉死，防止只补键集不改文案）', () => {
    const labels = makeAlarmTypeLabels(makeT('zh-CN'))
    expect(labels.smoke).toBe('烟雾报警')
    expect(labels.temp_abnormal).toBe('温度异常')
    expect(labels.manual_button).toBe('手动报警')
    expect(labels.phone_report).toBe('电话报告')
    expect(labels.patrol_find).toBe('巡检发现')
  })

  test('设备类型映射键集与后端 DEVICE_TYPE 逐一对应，fire_door/other 不再是裸码', () => {
    // 后端枚举：src/utils/constants.js DEVICE_TYPE（model 的 enum 指过来）。
    // 旧断言「other 必须为 undefined」固化的是缺陷：DashboardCharts 用
    // makeDeviceTypeLabels(t)[type] || type 回落，缺键 => 饼图/图例上直接显示
    // 原始码 fire_door / other（词表里 device.typeFireDoor/typeOther 早有译文）。
    // 期望键集取自后端，不再抄一份 10 个的字面量（见文件头 F-166）。
    const labels = makeDeviceTypeLabels(makeT('zh-CN'))
    expect(Object.keys(labels).sort()).toEqual([...DEVICE_TYPE_VALUES].sort())
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

  test.each(ALARM_STATUSES.map((v) => [v]))('报警状态 %s（后端逐档）有一个翻过的标签', (v) => {
    expectTranslated(makeAlarmStatusLabels(makeT('zh-CN'))[v], v)
  })

  test('报警状态键集与后端 ALARM_STATUSES 逐一对应', () => {
    // 旧断言是 toEqual(五个键的字面量)：后端加一档而前端没跟 => 仍然全绿；
    // 前端补了那一档 => 反倒红。现在一侧取后端清单，两个方向都能证伪。
    expect(Object.keys(makeAlarmStatusLabels(makeT('zh-CN'))).sort()).toEqual(
      [...ALARM_STATUSES].sort()
    )
  })

  test('报警状态中文文案逐条钉死（false_alarm 用专属词条「误报」）', () => {
    const labels = makeAlarmStatusLabels(makeT('zh-CN'))
    expect(labels.pending).toBe('待处理')
    expect(labels.processing).toBe('处理中')
    expect(labels.resolved).toBe('已处理')
    expect(labels.false_alarm).toBe('误报')
    expect(labels.cancelled).toBe('已取消')
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
