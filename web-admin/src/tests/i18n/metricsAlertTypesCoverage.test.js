/**
 * 系统运行指标面板：告警类型中文化的覆盖闸（2026-11-04）
 *
 * 缺陷形状：面板把后端 incSecurityAlert 的类型字符串直接渲染成 `a.type`，于是客户看到的是
 * `audit_chain_break_detected(严重) × 12`——级别那一半已中文化（WF-12），类型那一半没有。
 * 类型是开放集合：后端每加一条告警就多一个码，前端不可能靠“看一眼清单”跟上。
 *
 * 本闸钉四层：
 *   1. 码表 ↔ 后端：ALERT_TYPES 的值、fail-open 台账（FAIL_OPEN_SITES 与 OTHER_ALERT_SIGNALS）
 *      的 type、以及散落在调用点的字面量，必须全部出现在 constants/metricsAlertTypes.js；
 *   2. 词条覆盖：每个码在 zh / en 都要有非空词条（页面才不退回裸码）；
 *   3. 无死键：词表里不能有码表之外的键（删类型不删词条也会红）；
 *   4. 反空自证：码表有量级、后端扫描真扫到字面量（扫描器失效时后面全绿也没意义）。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import path from 'node:path'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'
import { METRICS_ALERT_TYPE_CODES } from '@/constants/metricsAlertTypes'

const require = createRequire(import.meta.url)
const { ALERT_TYPES } = require('../../../../src/services/alertTypes.js')
const {
  FAIL_OPEN_ALERT_TYPES,
  OTHER_ALERT_SIGNALS,
} = require('../../../../src/constants/failOpenSites.js')

// 用 require.resolve 拿绝对路径：vitest 下 import.meta.url 不保证是 file: 协议
const SRC_ROOT = path.dirname(
  path.dirname(require.resolve('../../../../src/services/alertTypes.js'))
)

const walk = (dir, out = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'tests') continue
    const child = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(child, out)
    else if (entry.name.endsWith('.js')) out.push(child)
  }
  return out
}

/** 直接写在调用点上的告警类型字面量（变量形态不在扫描范围内，见 INDIRECT_ALERT_TYPES） */
const literalAlertTypes = () => {
  const found = new Set()
  for (const file of walk(SRC_ROOT)) {
    const text = fs.readFileSync(file, 'utf8')
    for (const m of text.matchAll(/incSecurityAlert\(\s*'([a-z0-9_]+)'/g)) found.add(m[1])
    for (const m of text.matchAll(/sendNotification\(\s*'([a-z0-9_]+)'/g)) found.add(m[1])
  }
  return found
}

/**
 * 变量/模板形态发出、扫描器看不到的类型：
 * captcha_${scope}_cap_reached 的 scope 在 captchaService.js 里只有 ip / global；
 * admin_initial_password_file_delete_failed 由 initialPasswordFile.js 的 alert() 间接投递。
 */
const INDIRECT_ALERT_TYPES = [
  'captcha_ip_cap_reached',
  'captcha_global_cap_reached',
  'admin_initial_password_file_delete_failed',
]

const backendAlertTypes = () =>
  new Set([
    ...Object.values(ALERT_TYPES),
    ...FAIL_OPEN_ALERT_TYPES,
    ...OTHER_ALERT_SIGNALS.map((signal) => signal.type),
    ...literalAlertTypes(),
    ...INDIRECT_ALERT_TYPES,
  ])

describe('系统运行指标告警类型词典', () => {
  test('反空自证：码表有量级、后端台账与字面量扫描都有输入', () => {
    expect(METRICS_ALERT_TYPE_CODES.length).toBeGreaterThanOrEqual(30)
    expect(new Set(METRICS_ALERT_TYPE_CODES).size).toBe(METRICS_ALERT_TYPE_CODES.length)
    expect(FAIL_OPEN_ALERT_TYPES.length).toBeGreaterThanOrEqual(5)
    expect(OTHER_ALERT_SIGNALS.length).toBeGreaterThanOrEqual(3)
    expect(literalAlertTypes().size).toBeGreaterThanOrEqual(10)
  })

  test('每个后端告警类型都已登记到前端码表（新增类型不登记即红）', () => {
    const registered = new Set(METRICS_ALERT_TYPE_CODES)
    const missing = [...backendAlertTypes()].filter((code) => !registered.has(code)).sort()
    expect(missing).toEqual([])
  })

  test('zh / en 词条逐码非空，且不存在码表之外的死键', () => {
    const zh = zhCN.about.metrics.alertTypes || {}
    const en = enUS.about.metrics.alertTypes || {}
    const codes = METRICS_ALERT_TYPE_CODES

    expect(Object.keys(zh).sort()).toEqual([...codes].sort())
    expect(Object.keys(en).sort()).toEqual([...codes].sort())

    const empty = codes.filter(
      (code) =>
        typeof zh[code] !== 'string' ||
        zh[code].trim() === '' ||
        typeof en[code] !== 'string' ||
        en[code].trim() === ''
    )
    expect(empty).toEqual([])
    // 变异对照：词条整体被清空时上一行恒真，这里要求中文词条真含中文
    const noChinese = codes.filter((code) => !/[\u4e00-\u9fa5]/.test(zh[code]))
    expect(noChinese).toEqual([])
  })
})
