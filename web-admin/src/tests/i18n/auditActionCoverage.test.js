/**
 * 审计动作词表覆盖闸（2026-10-30）
 *
 * 缺陷：后端 AUDIT_LOG_ACTIONS 是审计查询/筛选的枚举来源（utils/auditQuery 的
 * validateEnum），前端 utils/auditLabels.js 却只按 `audit.action.<action>` 取词——
 * 词表缺键时它**静默回退成英文动作名**（auditLabels.js 的 label === key 判定），
 * 中文界面的审计页因此混进 `permission_grants_approve` 这类裸标识符。
 * 这不是「少一条翻译」，是**新增后端动作时前端必然静默漏翻**的结构性缺口：
 * 后端加动作不需要动前端，任何人工清单都会漂移。
 *
 * 闸门口径（与后端 src/tests/constants/auditActionReconciliation.test.js 对齐）：
 *  1. 中文/英文词表键集 ⊇ AUDIT_LOG_ACTIONS 全集（差集非空即红）；
 *  2. 反向：词表里不得有后端不认识的动作键（死键——界面永远显示不到它）；
 *  3. 每条动作的中英标签非空且互不相同（把中文抄进 en-US 会被抓住）。
 * 动作全集**从后端常量表读取**，不在这里手抄——手抄等于把对账退化成复制。
 */
import { describe, test, expect } from 'vitest'
import { createRequire } from 'node:module'
import zhCN from '@/i18n/locales/zh-CN'
import enUS from '@/i18n/locales/en-US'

// 与 src/tests/utils/apiStatusCodes.test.js 同一取法：直接读后端唯一事实来源
const require = createRequire(import.meta.url)
const { AUDIT_LOG_ACTIONS } = require('../../../../src/constants/audit.js')

const zhAction = zhCN.audit.action
const enAction = enUS.audit.action
const backend = new Set(AUDIT_LOG_ACTIONS)

const missing = (labels) => AUDIT_LOG_ACTIONS.filter((a) => !Object.hasOwn(labels, a)).sort()
const extra = (labels) =>
  Object.keys(labels)
    .filter((k) => !backend.has(k))
    .sort()

describe('audit.action.* 词表 ⊇ 后端 AUDIT_LOG_ACTIONS', () => {
  test('后端动作全集非空（防止对账对象被空数组静默通过）', () => {
    expect(Array.isArray(AUDIT_LOG_ACTIONS)).toBe(true)
    expect(AUDIT_LOG_ACTIONS.length).toBeGreaterThan(100)
    // 动作名唯一：重复项会让「差集」看起来正常而实际漏掉一条
    expect(new Set(AUDIT_LOG_ACTIONS).size).toBe(AUDIT_LOG_ACTIONS.length)
  })

  test('zh-CN 不缺任何后端动作（缺一条即红）', () => {
    const diff = missing(zhAction)
    expect(diff, `zh-CN 缺少 audit.action.*：${diff.join(', ')}`).toEqual([])
  })

  test('en-US 不缺任何后端动作（缺一条即红）', () => {
    const diff = missing(enAction)
    expect(diff, `en-US 缺少 audit.action.*：${diff.join(', ')}`).toEqual([])
  })

  test('反向：词表里没有后端不认识的动作键（死键）', () => {
    const zhDead = extra(zhAction)
    const enDead = extra(enAction)
    expect(zhDead, `zh-CN 死键：${zhDead.join(', ')}`).toEqual([])
    expect(enDead, `en-US 死键：${enDead.join(', ')}`).toEqual([])
  })

  test('每条动作的中英标签都非空且互不相同（防「英文列抄中文」）', () => {
    const bad = []
    for (const action of AUDIT_LOG_ACTIONS) {
      const zh = zhAction[action]
      const en = enAction[action]
      if (typeof zh !== 'string' || zh.trim() === '') bad.push(`zh:${action}`)
      if (typeof en !== 'string' || en.trim() === '') bad.push(`en:${action}`)
      if (zh === en) bad.push(`same:${action}`)
    }
    expect(bad).toEqual([])
  })
})
