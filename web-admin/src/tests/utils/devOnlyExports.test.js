/**
 * P3-26：仅供测试的模块导出必须在测试环境可用、生产构建剔除
 *
 * __getDriftCount / __isFlushInFlight 原本无条件导出；现改为
 * import.meta.env.DEV 守卫（vitest 下 DEV=true，生产构建替换为 false 后
 * 常量折叠成 undefined）。本用例钉住「测试环境仍拿到函数」——若有人把
 * 守卫写反或误删，这里先红。
 */
import { describe, test, expect } from 'vitest'
import { __getDriftCount } from '@/utils/api'
import { __isFlushInFlight } from '@/utils/errorReporter'

describe('测试探针导出的 DEV 守卫（P3-26）', () => {
  test('vitest（DEV=true）下 __getDriftCount / __isFlushInFlight 仍是函数', () => {
    expect(import.meta.env.DEV).toBe(true)
    expect(typeof __getDriftCount).toBe('function')
    expect(typeof __isFlushInFlight).toBe('function')
    expect(__getDriftCount()).toBeGreaterThanOrEqual(0)
    expect(__isFlushInFlight()).toBe(false)
  })
})
