/**
 * 临时授权的策略常量与高敏判定：前端 ↔ 后端单一事实来源逐一对应
 *
 * 缺陷形状：前端为了即时提示（"还需 2 人签批""最多 20 个权限""1-168 小时"）
 * 必须自己持有一份阈值与高敏模块清单。手抄的清单钉住的是清单的**结果**，
 * 后端改了阈值或新登记一个模块而前端没跟，界面照旧提示 1 人签批，后端却要 2 人，
 * 申请人提交完才发现自己点错——比直接报错更难查。这里直接对账
 * src/constants/privilegeGrant.js，两个方向都会红。
 *
 * 断言对象是**可观测输出**（approvalPolicyOf / isHighRiskCode 的判定结果），
 * 不是源码文本：抄一遍源码文本等于把实现复制到测试里，写错时两边一起错。
 */
import { createRequire } from 'node:module'
import { describe, test, expect } from 'vitest'
import * as fe from '@/utils/privilegeGrant'

const require = createRequire(import.meta.url)
const be = require('../../../../src/constants/privilegeGrant.js')

describe('临时授权策略：前端常量与后端一致', () => {
  test('有效期上下限一致', () => {
    expect(fe.MIN_GRANT_HOURS).toBe(be.MIN_GRANT_HOURS)
    expect(fe.MAX_GRANT_HOURS).toBe(be.MAX_GRANT_HOURS)
  })

  test('单次授予的权限码上限一致', () => {
    expect(fe.MAX_GRANT_CODES).toBe(be.MAX_GRANT_CODES)
  })

  test('高敏模块清单一致（后端加一个模块而前端漏登记会红）', () => {
    expect([...fe.HIGH_RISK_MODULES].sort()).toEqual([...be.HIGH_RISK_MODULES].sort())
  })

  test('已登记模块清单一致（fail-closed 的判定面必须同尺）', () => {
    expect([...fe.KNOWN_MODULES].sort()).toEqual([...be.KNOWN_MODULES].sort())
  })
})

describe('临时授权策略：高敏判定结果逐一相同', () => {
  // 覆盖面：每个已登记模块各取一码 + 未登记模块 + 空模块 + 无冒号裸码
  const codes = [
    ...be.KNOWN_MODULES.map((m) => m + ':read'),
    ...be.HIGH_RISK_MODULES.map((m) => m + ':update'),
    'custom:read',
    'unknown-module:delete',
    ':read',
    '*:*',
    'device',
    '',
  ]

  test.each(codes.map((c) => [c || '(空)']))('权限码 %s 的高敏判定前后端一致', (code) => {
    const actual = code === '(空)' ? '' : code
    expect(fe.isHighRiskCode(actual)).toBe(be.isHighRiskCode(actual))
  })

  test.each(codes.map((c) => [c || '(空)']))('权限码 %s 的签批人数要求前后端一致', (code) => {
    const actual = code === '(空)' ? '' : code
    expect(fe.approvalPolicyOf([actual])).toEqual(be.approvalPolicyOf([actual]))
  })

  test('混合清单：只要命中一个高敏码就整体按双人复核', () => {
    const codes = ['device:read', 'alarm:read', 'role:update']
    expect(fe.approvalPolicyOf(codes)).toEqual(be.approvalPolicyOf(codes))
    expect(fe.approvalPolicyOf(codes).requiredApprovals).toBe(2)
  })

  test('空清单/非数组：按单人签批，不抛错', () => {
    expect(fe.approvalPolicyOf([])).toEqual(be.approvalPolicyOf([]))
    expect(fe.approvalPolicyOf(null)).toEqual(be.approvalPolicyOf(null))
    expect(fe.approvalPolicyOf(undefined)).toEqual(be.approvalPolicyOf(undefined))
  })
})

describe('临时授权表单的纯函数', () => {
  test('权限码解析：空格/中英文逗号混排去空去重保序', () => {
    expect(fe.parsePermissionCodes(' device:read, alarm:read ，report:read  device:read ')).toEqual(
      ['device:read', 'alarm:read', 'report:read']
    )
    expect(fe.parsePermissionCodes('')).toEqual([])
    expect(fe.parsePermissionCodes(null)).toEqual([])
  })

  test('有效期夹取与后端 clampDurationHours 同尺', () => {
    expect(fe.clampDurationHours(0)).toBe(be.MIN_GRANT_HOURS)
    expect(fe.clampDurationHours(169)).toBe(be.MAX_GRANT_HOURS)
    expect(fe.clampDurationHours(8)).toBe(8)
    expect(fe.clampDurationHours('abc')).toBeNull()
  })
})

describe('临时授权策略：保留通配权限的前端拦截与后端唯一事实来源对账', () => {
  const superAdmin = require('../../../../src/utils/superAdmin.js')

  test('保留通配权限码与后端一致，且就是 *:*', () => {
    expect(fe.RESERVED_WILDCARD_PERMISSION).toBe(superAdmin.RESERVED_WILDCARD_PERMISSION)
    expect(fe.RESERVED_WILDCARD_PERMISSION).toBe('*:*')
  })

  test('isReservedCode：只认保留码本身（允许首尾空白），近似的模块通配一律放行', () => {
    expect(fe.isReservedCode('*:*')).toBe(true)
    expect(fe.isReservedCode(' *:* ')).toBe(true)
    expect(fe.isReservedCode('device:read')).toBe(false)
    expect(fe.isReservedCode('*')).toBe(false)
    expect(fe.isReservedCode('*:read')).toBe(false)
    expect(fe.isReservedCode('')).toBe(false)
    expect(fe.isReservedCode(null)).toBe(false)
  })
})

describe('临时授权读侧：生效态与剩余时间（回收任务滞后时的口径）', () => {
  const NOW = Date.parse('2026-11-01T00:00:00.000Z')
  const grant = (over = {}) => ({
    status: 'active',
    expiresAt: '2026-11-01T01:00:00.000Z',
    ...over,
  })

  test('active 且未过期 ⇒ active', () => {
    expect(fe.effectiveStatusOf(grant(), NOW)).toBe('active')
  })

  test('active 但已到期 / 缺 expiresAt / 无法解析 ⇒ expired（与后端 expiresAt>now 同尺）', () => {
    expect(fe.effectiveStatusOf(grant({ expiresAt: '2026-10-31T23:59:00.000Z' }), NOW)).toBe(
      'expired'
    )
    expect(fe.effectiveStatusOf(grant({ expiresAt: null }), NOW)).toBe('expired')
    expect(fe.effectiveStatusOf(grant({ expiresAt: 'not-a-date' }), NOW)).toBe('expired')
  })

  test('非 active 状态原样返回，不参与过期推导', () => {
    expect(fe.effectiveStatusOf({ status: 'pending', expiresAt: null }, NOW)).toBe('pending')
    expect(
      fe.effectiveStatusOf({ status: 'revoked', expiresAt: '2026-01-01T00:00:00.000Z' }, NOW)
    ).toBe('revoked')
    expect(fe.effectiveStatusOf({}, NOW)).toBe('')
  })

  test('剩余时间分档：分钟 / 小时 / 天', () => {
    expect(fe.remainingOf('2026-11-01T00:10:00.000Z', NOW)).toEqual({ kind: 'minutes', count: 10 })
    expect(fe.remainingOf('2026-11-01T05:00:00.000Z', NOW)).toEqual({ kind: 'hours', count: 5 })
    expect(fe.remainingOf('2026-11-11T00:00:00.000Z', NOW)).toEqual({ kind: 'days', count: 10 })
  })

  test('已到期 / 无法解析 / 缺失', () => {
    expect(fe.remainingOf('2026-10-31T00:00:00.000Z', NOW)).toEqual({ kind: 'expired', count: 0 })
    expect(fe.remainingOf('not-a-date', NOW)).toBeNull()
    expect(fe.remainingOf(null, NOW)).toBeNull()
  })
})
