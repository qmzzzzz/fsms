/**
 * 隐私告知的前端常量必须与后端单一事实来源逐字一致（一-7）
 *
 * 缺陷形状：前端为在**勾选之前**显示「同意的是哪一版、覆盖哪些数据」，必须自己持有
 * 版本号与范围清单。手抄的这副本钉住的是抄写那一刻的值：后端升版（新告知生效）或
 * 增减 notice 范围而前端没跟，界面会继续显示旧版号——用户同意的其实不是屏幕上的那份
 * 告知，同意记录里的版本与告知内容不再对应。这类漂移在功能上完全静默（注册照样成功）。
 *
 * 断言取**可观测输出**（版本字符串与范围键数组），不读源码文本：
 * 抄一遍源码等于把实现复制进测试，写错时两边一起错。
 */
import { createRequire } from 'node:module'
import { describe, test, expect } from 'vitest'
import * as fe from '@/utils/privacyNotice'

const require = createRequire(import.meta.url)
const be = require('../../../../src/constants/dataClassification.js')
const consentService = require('../../../../src/services/consentService.js')

describe('隐私告知：前端常量与后端一致', () => {
  test('版本号一致（后端升版而前端没跟会红）', () => {
    expect(fe.PRIVACY_NOTICE_VERSION).toBe(consentService.PRIVACY_NOTICE_VERSION)
    expect(fe.PRIVACY_NOTICE_VERSION).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })

  test('同意范围清单一致：只含 basis=notice 的项，顺序可不同但集合必须相等', () => {
    const backendNoticeScopes = Object.entries(be.CONSENT_SCOPES)
      .filter(([, s]) => s.basis === 'notice')
      .map(([k]) => k)
      .sort()
    expect([...fe.PRIVACY_NOTICE_SCOPES].sort()).toEqual(backendNoticeScopes)
  })

  test('组织法定基础的范围不得出现在告知清单里（否则界面声称要"同意"依法无需同意的事项）', () => {
    const legalBasisOnly = Object.entries(be.CONSENT_SCOPES)
      .filter(([, s]) => s.basis === 'legalBasis')
      .map(([k]) => k)
    expect(legalBasisOnly.length).toBeGreaterThan(0)
    expect(legalBasisOnly.filter((k) => fe.PRIVACY_NOTICE_SCOPES.includes(k))).toEqual([])
  })

  test('每个范围在后端都有非空告知文案（界面对它逐项渲染，空串会渲染成空行）', () => {
    for (const key of fe.PRIVACY_NOTICE_SCOPES) {
      const scope = be.CONSENT_SCOPES[key]
      expect(scope, `后端缺少范围 ${key}`).toBeTruthy()
      expect(typeof scope.notice).toBe('string')
      expect(scope.notice.trim().length).toBeGreaterThan(0)
    }
  })
})
