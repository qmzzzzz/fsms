/**
 * AboutView 版本号来源回归（2026-09-18）
 *
 * 缺陷（潜伏型，修复前实测）：`APP_VERSION` 是源码里的字面量 '1.0.0'，与
 * package.json 的 version 各写一份。当前两者恰好相同，所以页面「看起来对」——
 * 但下一次发版（改 package.json 不改源码）页面就会永久显示旧版本，排障时误导。
 * 源码注释本身写着「与 package.json 的 version 字段同步维护」= 承认这是人工约定，
 * 而人工约定正是会失效的那种。
 *
 * 修复：改为构建期由 vite define 注入 __APP_VERSION__（唯一事实来源 package.json）。
 * 本套件同时钉住「渲染值 == package.json 的 version」与「不再有字面量副本」。
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { mountComponent, flush } from '../helpers/componentHarness'

vi.mock('@/utils/api', () => ({ api: {}, isCanceledError: () => false }))

import AboutView from '@/views/AboutView.vue'

let active = null
afterEach(() => {
  active?.handle.unmount()
  active = null
})

const readSrc = (rel) => readFileSync(resolve(__dirname, '../..', rel), 'utf8')

describe('AboutView 版本号单一事实来源', () => {
  test('页面渲染的版本号等于 package.json 的 version（构建注入，非手抄）', async () => {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, '../../../package.json'), 'utf8'))
    active = mountComponent(AboutView, {})
    await flush(6)
    const c = active
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+/)
    // 两处展示（头部 vX.Y.Z 与描述表）都必须出现同一个版本号
    const occurrences = c.text().split(pkg.version).length - 1
    expect(occurrences).toBeGreaterThanOrEqual(2)
    expect(c.errors).toEqual([])
  })

  test('组件内不再持有版本号字面量副本（防再次手抄漂移）', () => {
    const src = readSrc('views/AboutView.vue')
    // 形如 const APP_VERSION = '1.0.0' 的硬编码副本必须消失
    expect(src).not.toMatch(/APP_VERSION\s*=\s*['"]\d+\.\d+\.\d+/)
    // 必须走构建注入
    expect(src).toMatch(/__APP_VERSION__/)
  })

  test('vite.config.js 用 package.json 的 version 注入 __APP_VERSION__', () => {
    const cfg = readSrc('../vite.config.js')
    expect(cfg).toMatch(/__APP_VERSION__/)
    expect(cfg).toMatch(/package\.json/)
  })
})
