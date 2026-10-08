/**
 * 路由懒加载 chunk 悬停预取
 *
 * 用户在侧边栏悬停某菜单项时提前 import 对应视图 chunk，点击时命中浏览器
 * 模块缓存，感知切换近零延迟。预取必须与 router/index.js 中的 import 保持
 * 同一字符串字面量，Vite 才会复用同一 chunk（否则产出两份重复模块）。
 *
 * 设计约束：
 * - 仅在悬停时触发（pointer: fine 设备），移动端触摸无 hover 概念，不预取；
 * - 每个 chunk 只预取一次，重复悬停直接短路；
 * - 预取失败静默吞掉：网络抖动不应影响主导航，点击时仍走正常懒加载。
 */

// 与 router/index.js 的 import 字面量一一对应（Vite 按字面量分 chunk）
const prefetchers = {
  '/dashboard': () => import('@/views/DashboardView.vue'),
  '/devices': () => import('@/views/DeviceView.vue'),
  '/alarms': () => import('@/views/AlarmView.vue'),
  '/inspections': () => import('@/views/InspectionView.vue'),
  '/users': () => import('@/views/UserView.vue'),
  '/roles': () => import('@/views/RoleView.vue'),
  '/audit-logs': () => import('@/views/AuditLogView.vue'),
  '/ip-list': () => import('@/views/IpListView.vue'),
  '/reports': () => import('@/views/ReportView.vue'),
  '/profile': () => import('@/views/ProfileView.vue'),
  '/about': () => import('@/views/AboutView.vue'),
}

const prefetched = new Set()

// 触摸设备无悬停概念，整体禁用（避免 tap 瞬间抢带宽反而拖慢点击导航）
// matchMedia 每次调用时读取，便于测试在调用前用 vi.stubGlobal 覆盖
const canHover = () =>
  typeof window !== 'undefined' &&
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(hover: hover) and (pointer: fine)').matches

export function prefetchRoute(path) {
  if (!canHover() || prefetched.has(path)) return
  const load = prefetchers[path]
  if (!load) return
  prefetched.add(path)
  load().catch(() => {
    // 失败则从集合移除，允许下次悬停重试；不向用户报错
    prefetched.delete(path)
  })
}
