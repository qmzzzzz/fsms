/**
 * 权限热同步（免重登生效）
 *
 * 问题：管理员调整角色权限或用户角色后，被影响的用户界面上的菜单与按钮
 * 完全不变，必须退出重新登录。根因是两层：
 *   1. 服务端有 invalidateUserCache，所以**鉴权**是即时生效的 ——
 *      用户点了按钮会拿到 403，而按钮本身还显示着；
 *   2. 前端 authStore.permissions 是登录那一刻的快照，没有任何刷新机制。
 * 也就是说界面与实际授权长期不一致，用户看到的能点、点了却被拒。
 *
 * 方案：后端在权限变更后按 socket 定向下发 permission-sync（携带该用户
 * 重算后的完整权限码集合），前端收到后先乐观替换、再向 /auth/me 核对。
 *
 * 为什么挂在布局层而不是角色管理页：
 *   需要接收推送的是「权限被改的那个人」，他此刻可能在任何页面（甚至
 *   多半不在角色管理页——那页需要 role:read）。挂在布局层才能覆盖
 *   整个登录会话期间。
 */

import { onMounted, onUnmounted } from 'vue'
import { ElNotification } from 'element-plus/es/components/notification/index.mjs'
import { useI18n } from 'vue-i18n'
import { acquireWebSocket, releaseWebSocket } from '@/utils/websocket'
import { useAuthStore } from '@/store'
import { PermissionUpdateEventSchema, formatIssues } from '@/schemas'

/**
 * 在当前组件生命周期内订阅权限变更推送
 * @returns {{handlePermissionSync: (event: unknown) => Promise<void>}}
 */
export function usePermissionSync() {
  const authStore = useAuthStore()
  const { t } = useI18n()

  /**
   * 处理一次权限同步事件
   * @param {unknown} rawEvent 服务端推送的原始载荷
   */
  const handlePermissionSync = async (rawEvent) => {
    // 推送来自网络，同样要过形状校验：permissionCodes 若被误发成对象数组，
    // 直接塞进 store 会让所有权限判否（界面表现为「权限全被收回」）
    const parsed = PermissionUpdateEventSchema.safeParse(rawEvent)
    if (!parsed.success) {
      console.error(`[schema-drift] permission-sync -> ${formatIssues(parsed.error)}`)
      // 载荷不可信时不做乐观更新，直接向服务端拿权威值
      await authStore.refreshPermissionsFromServer()
      return
    }

    const before = [...(authStore.permissions || [])].sort().join('|')
    await authStore.syncPermissionsFromEvent(parsed.data)
    const after = [...(authStore.permissions || [])].sort().join('|')

    // 只有权限**确实**变了才提示。后端是按角色广播给全部持有者的，
    // 对某些用户而言最终权限集可能没有任何变化（例如他还有另一个角色
    // 覆盖了同样的权限），此时弹提示纯属噪音。
    if (before === after) return

    // duration=0 不自动消失：菜单可能已经变了，用户需要知道原因，
    // 否则会以为界面出错。这条信息比一般提示重要。
    ElNotification({
      title: t('common.info'),
      message: t('messages.permissionsUpdated'),
      type: 'info',
      duration: 0,
    })
  }

  let ws = null

  onMounted(() => {
    // 未登录不建连：登录页也会渲染布局之外的组件，且无身份的连接会被
    // 后端在认证超时后断开，白白占用连接数配额
    if (!authStore.isAuthenticated) return
    try {
      ws = acquireWebSocket()
      ws.on('permission-sync', handlePermissionSync)
    } catch (_) {
      // 建连失败退化为原有行为（下次登录或刷新页面后生效），不影响主流程
      ws = null
    }
  })

  onUnmounted(() => {
    if (!ws) return
    ws.off('permission-sync', handlePermissionSync)
    // 引用计数释放：其他使用方（如角色管理页）仍在用时不会真正断开
    releaseWebSocket()
    ws = null
  })

  return { handlePermissionSync }
}

export default usePermissionSync
