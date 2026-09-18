/**
 * Store 入口 barrel 的契约测试（D-3 拆分后的兼容层）
 *
 * 全仓的 import 只有两种写法：`import { useAuthStore } from '@/store'` 与
 * `import store from '@/store'`（后者见既有文档注释）。barrel 一旦漏导出某个
 * 名字，表现是**构建期**才炸的 undefined import 或运行期 `store.useAuthStore is
 * not a function`，而不是测试里某条断言变红——所以这里逐条钉住导出集合本身。
 *
 * 同时钉住「barrel 只是转发，不是第二份实现」：默认导出必须与具名导出是
 * 同一个函数对象。若哪天有人在 barrel 里重新 defineStore 一份，两处 store
 * 会各自维护状态（同 id 但不同实例），界面会出现「这里登出了、那里还登录着」
 * 这种无法解释的现象——引用相等断言是唯一能提前发现的判据。
 */
import { describe, test, expect } from 'vitest'
import * as barrel from '@/store'
import storeDefault from '@/store'
import { useAuthStore as authDirect, normalizeUser as normalizeDirect } from '@/store/auth'
import { useAppStore as appDirect } from '@/store/app'
import {
  safeStorage as safeStorageDirect,
  safeLocal as safeLocalDirect,
  readSessionState as readSessionStateDirect,
} from '@/store/storage'

describe('store/index.js barrel 契约', () => {
  test('具名导出集合完整（auth 域 / app 域 / storage 工具）', () => {
    expect(Object.keys(barrel).sort()).toEqual([
      'default',
      'normalizeUser',
      'readSessionState',
      'safeLocal',
      'safeStorage',
      'useAppStore',
      'useAuthStore',
    ])
  })

  test('默认导出的两个 store 与具名导出引用相等（不是第二份实现）', () => {
    expect(Object.keys(storeDefault).sort()).toEqual(['useAppStore', 'useAuthStore'])
    expect(storeDefault.useAuthStore).toBe(barrel.useAuthStore)
    expect(storeDefault.useAppStore).toBe(barrel.useAppStore)
  })

  test('barrel 转发的是 ./auth、./app、./storage 的原始对象（同一引用）', () => {
    expect(barrel.useAuthStore).toBe(authDirect)
    expect(barrel.normalizeUser).toBe(normalizeDirect)
    expect(barrel.useAppStore).toBe(appDirect)
    expect(barrel.safeStorage).toBe(safeStorageDirect)
    expect(barrel.safeLocal).toBe(safeLocalDirect)
    expect(barrel.readSessionState).toBe(readSessionStateDirect)
  })

  test('两个 store 的 id 分别为 auth / app（Pinia 按 id 去重，id 冲突会让两域共享状态）', () => {
    expect(barrel.useAuthStore.$id).toBe('auth')
    expect(barrel.useAppStore.$id).toBe('app')
  })
})
