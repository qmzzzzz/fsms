/**
 * IP 归属地展示码：前端词表 ↔ 后端码表 逐一对应（i18n 缺口回归）
 *
 * 缺陷形状：`location` 原是后端直接拼好的**展示文本**，私网/环回地址收敛成
 * 中文两字「内网」（src/services/ipLocationService.js），于是英文界面下会话
 * 管理 / 审计日志 / IP 名单里内网 IP 旁边永远是中文——前端拿到的是已定型的
 * 中文串，vue-i18n 无从下手。修法是后端只出稳定码、文案归前端词表
 * （同 utils/securityLabels.js 的 securitySelf.suggestion.*、utils/auditLabels.js
 * 的 audit.action.*、utils/labelMaps.js 的 DEVICE_TYPE）。
 *
 * 为什么清单必须 createRequire 自后端而不是在前端手抄一份：手抄的清单钉住的
 * 是清单的**结果**而不是清单本身，后端加一码而前端没跟，手抄件仍是旧的 N 个键，
 * 断言全绿，界面上却渲染出裸码。这里直接对账后端单一来源
 * （src/constants/ipLocationCodes.js），两个方向都会红。
 *
 * 断言对象是**可观测输出**（映射结果），不是源码文本。
 */
import { createRequire } from 'node:module'
import { describe, test, expect } from 'vitest'
import { createI18n } from 'vue-i18n'
import { ipLocationLabel } from '@/utils/ipLocationLabels'
import i18n from '@/i18n'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

const require = createRequire(import.meta.url)
const { IP_LOCATION_CODE_VALUES } = require('../../../../src/constants/ipLocationCodes.js')

const messages = { 'zh-CN': zhCN, 'en-US': enUS }
const makeT = (locale) => {
  const i18n = createI18n({ legacy: false, locale, messages })
  return (key) => i18n.global.t(key)
}

/** vue-i18n 找不到键时原样返回 key（形如 ipLocation.xxx） */
const KEY_PATH = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$/

describe('IP 归属地展示码表：前后端一致', () => {
  test('zh-CN 词表键集与后端码表逐一对应（后端加码而前端漏翻会红）', () => {
    expect(Object.keys(zhCN.ipLocation).sort()).toEqual([...IP_LOCATION_CODE_VALUES].sort())
  })

  test('en-US 词表键集与后端码表逐一对应', () => {
    expect(Object.keys(enUS.ipLocation).sort()).toEqual([...IP_LOCATION_CODE_VALUES].sort())
  })

  test.each(IP_LOCATION_CODE_VALUES.map((c) => [c]))(
    '展示码 %s 在中英两种语言下都有一个"真的翻过"的文案',
    (code) => {
      const zh = ipLocationLabel(makeT('zh-CN'), code)
      const en = ipLocationLabel(makeT('en-US'), code)
      // 非空、不等于裸码、不是没解析的词条路径
      expect(zh).toBeTruthy()
      expect(zh).not.toBe(code)
      expect(KEY_PATH.test(zh)).toBe(false)
      expect(en).toBeTruthy()
      expect(en).not.toBe(code)
      expect(KEY_PATH.test(en)).toBe(false)
      // 英文不得等于中文：否则是把中文抄进了 en-US 词表，i18n 缺口原样保留
      expect(en).not.toBe(zh)
      // 英文侧不得残留 CJK：这正是本轮修复的缺陷形状
      expect(en).not.toMatch(/[\u4e00-\u9fa5]/)
    }
  )

  test('中文界面：非稳定码（数据文本）原样透传，不被当成词条键', () => {
    // 语言判定读的是真实 i18n 实例的 locale（utils/ipLocationLabels.js），本地实例说了不算
    i18n.global.locale.value = 'zh-CN'
    // 公网 IP 的归属地是 ip2region 数据拼出的中文文本，中文界面必须原样显示
    expect(ipLocationLabel(makeT('zh-CN'), '中国·广东省·深圳市·电信')).toBe(
      '中国·广东省·深圳市·电信'
    )
    // 老后端发来的中文「内网」也原样透传（与修复前一致，不回退成空白）
    expect(ipLocationLabel(makeT('zh-CN'), '内网')).toBe('内网')
  })

  test('英文界面：数据文本按中英对照词典逐段译名，未收录段原样透传', () => {
    i18n.global.locale.value = 'en-US'
    expect(ipLocationLabel(makeT('en-US'), '中国·广东省·深圳市·电信')).toBe(
      'China·Guangdong·Shenzhen·China Telecom'
    )
    expect(ipLocationLabel(makeT('en-US'), '美国·蒙特利')).toBe('United States·蒙特利')
  })

  test('空值返回空串（调用方据此省略分隔符，而不是渲染裸 "·"）', () => {
    for (const empty of [null, undefined, '']) {
      expect(ipLocationLabel(makeT('zh-CN'), empty)).toBe('')
    }
  })
})
