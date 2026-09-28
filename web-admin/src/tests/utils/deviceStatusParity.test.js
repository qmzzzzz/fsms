/**
 * 设备状态：前端四份清单与后端枚举对账（F-166）
 *
 * 为什么需要：后端的 6 档状态在前端有**四份独立清单**——
 *   1. `i18n/locales/zh-CN.js` / `en-US.js` 的 `deviceStatus` 词条；
 *   2. `DeviceView.vue` 的筛选下拉（六个写死的 `el-option`）；
 *   3. `DeviceView.vue` 的 `statusText` / `statusType` 两张表；
 *   4. `ReportView.vue` 的「设备状态分布」图表（六个 name/value 对）。
 * 这一族**已经炸过一次**：`ReportView.vue:327` 的注释记着"此前只画 4 项，warning 与
 * scrapped 设备在分布图里静默消失，分布图与总数对不上"。当时的修法是补上六项，
 * 而"补上"这件事本身至今没有任何门禁：唯一相关的用例
 * （tests/views/reportViewCharts.test.js:322 起）把六个值**手抄进断言**，
 * 于是它证明的是"前端 == 前端的一份抄本"，不是"前端 == 后端"。
 * 后端加第 7 档时它会继续绿——正是本仓记过的那种"绿但不设防"。
 *
 * 本文件因此只做一件事：**期望集从后端推导**（`createRequire` 直接载入
 * `src/constants/deviceStatus.js`，口径同 apiStatusCodes / passwordRulesParity 两条邻居用例）。
 * 于是"后端加一档而前端没跟"必红，"前端把某档的词条删掉"也必红。
 *
 * 断言分两层：i18n 那组打在**翻译结果**上（用户真正看到的文案，缺词条时 vue-i18n
 * 回落成键名本身，正是"界面上出现裸码"这个历史症状）；下拉/表/图表那组只能打在
 * SFC 源码上——它们是模板里的静态文本与组件内私有对象，不导出、也不值得为测试搬进
 * labelMaps（唯一的消费方就在这里）。这一点写在用例名里，不假装它是行为断言。
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import { createI18n } from 'vue-i18n'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

const require = createRequire(import.meta.url)
// 后端那份派生清单里，本文件只取全集：界面上没有"状态变更"与"报废"控件
// （`api.devices.updateStatus` 零调用方、`scrap` 连封装都没有），所以可写子集这一维
// 在前端没有任何消费方，硬断言它只会把"将来要加的控件"提前钉死——那属于待拍板项。
const { DEVICE_STATUS_VALUES } = require('../../../../src/constants/deviceStatus.js')
/**
 * 仓库根的取法：从后端模块的**真实磁盘路径**往上退两级。
 * 不用 `fileURLToPath(import.meta.url)`——vitest 把模块经 HTTP 提供，这里的
 * import.meta.url 不是 file: 协议，fileURLToPath 会直接抛「The URL must be of scheme file」
 * （实测首跑即红）。require.resolve 给的是驱动口径的绝对路径，与 cwd 无关。
 */
const ROOT = path.resolve(
  path.dirname(require.resolve('../../../../src/constants/deviceStatus.js')),
  '..',
  '..'
)
const read = (p) => readFileSync(path.join(ROOT, p), 'utf8')
/** 去掉整行注释的视图：SFC 顶部那段说明里就写着六个状态名，不过这层会自己判自己红 */
const codeOnly = (src) =>
  src
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|<!--)/.test(line))
    .join('\n')

const makeT = (locale) => {
  const i18n = createI18n({ legacy: false, locale, messages: { 'zh-CN': zhCN, 'en-US': enUS } })
  return (key) => i18n.global.t(key)
}

describe('前提自证：期望集来自后端，不是本文件里的第二份抄本', () => {
  test('推导出的全集非空且无重复（空集会让下面所有用例同色通过）', () => {
    expect(DEVICE_STATUS_VALUES.length).toBeGreaterThanOrEqual(4)
    expect(new Set(DEVICE_STATUS_VALUES).size).toBe(DEVICE_STATUS_VALUES.length)
  })

  test('本文件不出现手抄的状态名清单（出现即说明有人把推导改回了字面量）', () => {
    const self = codeOnly(read('web-admin/src/tests/utils/deviceStatusParity.test.js'))
    expect(self).not.toMatch(/'normal',\s*'warning',\s*'fault'/)
    expect(self).not.toMatch(/"normal",\s*"warning",\s*"fault"/)
  })
})

describe('i18n 词条：六档在两套词表里都在，且真有译文（不是回落成键名）', () => {
  test.each(DEVICE_STATUS_VALUES.map((v) => [v]))(
    'zh-CN 的 deviceStatus.%s 是真文案而不是键名',
    (v) => {
      const t = makeT('zh-CN')
      const key = `deviceStatus.${v}`
      expect(Object.keys(zhCN.deviceStatus)).toContain(v)
      // vue-i18n 缺词条时返回键名本身——界面上就是"normal"这种裸码
      expect(t(key)).not.toBe(key)
      expect(t(key).trim()).not.toBe('')
    }
  )

  test('en-US 的键集与 zh-CN 完全一致（谁多谁少都是分叉）', () => {
    expect(Object.keys(enUS.deviceStatus).sort()).toEqual(Object.keys(zhCN.deviceStatus).sort())
    const t = makeT('en-US')
    for (const v of DEVICE_STATUS_VALUES) {
      expect(t(`deviceStatus.${v}`)).not.toBe(`deviceStatus.${v}`)
    }
  })

  test('后端加一档时本组用例先红：词条键集必须等于后端全集', () => {
    expect(Object.keys(zhCN.deviceStatus).sort()).toEqual([...DEVICE_STATUS_VALUES].sort())
  })
})

describe('DeviceView：筛选下拉与两张表必须逐档在场（源码结构断言，非行为断言）', () => {
  const src = codeOnly(read('web-admin/src/views/DeviceView.vue'))

  test.each(DEVICE_STATUS_VALUES.map((v) => [v]))('下拉里有 value="%s" 这一项', (v) => {
    expect(src).toContain(`value="${v}"`)
  })

  test('statusText 与 statusType 两张表的键数都等于后端档数', () => {
    const keysOf = (name) => {
      const m = new RegExp(`const ${name} = \\(s\\) =>\\s*\\(([\\s\\S]*?)\\}\\)\\[s\\]`).exec(src)
      expect(m).toBeTruthy()
      return (m[1].match(/^\s*(\w+):/gm) || []).map((s) => s.trim().replace(':', ''))
    }
    for (const name of ['statusType', 'statusText']) {
      expect(keysOf(name).sort()).toEqual([...DEVICE_STATUS_VALUES].sort())
    }
  })

  test('负对照：后端没有的状态不许被单独列进下拉（防"抄一份更长的清单"）', () => {
    const options = (src.match(/value="(\w+)"/g) || []).map((s) => s.slice(7, -1))
    const legal = new Set(DEVICE_STATUS_VALUES)
    expect(options.filter((o) => legal.has(o)).length).toBe(DEVICE_STATUS_VALUES.length)
    expect(options).not.toContain('dispatched')
  })
})

describe('ReportView：分布图必须覆盖全部档（历史上就是这里少画了两档）', () => {
  const src = codeOnly(read('web-admin/src/views/ReportView.vue'))

  test.each(DEVICE_STATUS_VALUES.map((v) => [v]))('图表数据里有 statusMap["%s"] 这一档', (v) => {
    expect(src).toContain(`statusMap['${v}']`)
  })

  test('每档既喂了 value 也给了 t() 出来的 name（只有 value 会在图例上显示裸码）', () => {
    for (const v of DEVICE_STATUS_VALUES) {
      expect(src).toContain(`t('deviceStatus.${v}')`)
    }
  })
})
