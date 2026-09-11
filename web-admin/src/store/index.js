/**
 * Store 入口（D-3：按域拆分后的 barrel）
 *
 * - 认证域：./auth.js（useAuthStore / normalizeUser）
 * - 应用偏好域：./app.js（useAppStore）
 * - 共享存储工具：./storage.js（safeStorage / safeLocal / readSessionState）
 *
 * 既有调用方统一从 '@/store' 导入，保持兼容。
 */

import { useAuthStore } from './auth'
import { useAppStore } from './app'

export { useAuthStore, normalizeUser } from './auth'
export { useAppStore } from './app'
export { safeStorage, safeLocal, readSessionState } from './storage'

// 默认导出组合 store 对象（兼容 import store from '@/store' 的写法）
export default { useAuthStore, useAppStore }
