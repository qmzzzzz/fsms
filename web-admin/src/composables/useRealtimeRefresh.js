/**
 * 实时刷新订阅（列表页的 WebSocket 接入口）
 *
 * 用法：在 setup 中调用一次，传入要加入的房间与「收到事件后做什么」。
 * 挂载时 acquire 连接引用并加入房间，卸载时解绑监听、退出房间、归还引用——
 * 引用计数保证不会把布局层的权限同步订阅连带拆掉。
 *
 * 为什么刷新交给页面而不是在这里直接调 API：各页需要刷新的数据块不同
 * （报警页是列表+统计，设备页是列表+概览+提醒），刷新函数必须由页面提供，
 * 否则本模块要反过来知道每一页的接口形状。
 *
 * @param {object} options
 * @param {string[]} [options.rooms] 要加入的房间（后端 ALLOWED_ROOMS 白名单）
 * @param {Array<{event: string, handler: Function}>} [options.subscriptions] 事件与处理函数
 * @param {string} [options.label] 降级日志里的来源标签
 */
import { onMounted, onUnmounted } from 'vue'
import { acquireWebSocket, releaseWebSocket } from '@/utils/websocket'
import { reportDegradation } from '@/utils/errorReporter'

export function useRealtimeRefresh({ rooms = [], subscriptions = [], label = 'realtime' } = {}) {
  let ws = null
  // 记录「已实际加入的房间 / 已绑定的监听」：中途抛错时才能精确回滚，
  // 不在共享连接上残留本页已不需要的房间订阅（重连后还会被自动重新 join）
  const joinedRooms = new Set()
  const boundHandlers = []

  // 收口统一为一个幂等清理：挂载失败（部分加入）与正常卸载走同一条路，
  // 卸载侧不再依赖 `if (!ws) return` 短路——catch 清理后 ws 虽为 null，
  // 但不会漏掉任何已产生的副作用，重复调用也安全。
  const cleanup = () => {
    if (!ws) return
    boundHandlers.splice(0).forEach(({ event, handler }) => {
      try {
        ws.off(event, handler)
      } catch (_) {
        // 单个解绑失败不阻断其余清理
      }
    })
    joinedRooms.forEach((room) => {
      try {
        ws.leaveRoom(room)
      } catch (_) {
        // 单个退房失败不阻断其余清理
      }
    })
    joinedRooms.clear()
    releaseWebSocket()
    ws = null
  }

  onMounted(() => {
    try {
      ws = acquireWebSocket()
      rooms.forEach((room) => {
        ws.joinRoom(room)
        joinedRooms.add(room)
      })
      subscriptions.forEach(({ event, handler }) => {
        ws.on(event, handler)
        boundHandlers.push({ event, handler })
      })
    } catch (error) {
      // 建连失败退化为手动刷新，不影响页面主流程；但必须上报，否则「实时推送
      // 从未生效」会以「页面一直要手动刷」的形态长期存在而无人发现。
      reportDegradation(`${label}: WebSocket 订阅失败，实时刷新已失效`, {
        error: error?.message || String(error),
        fallback: '手动刷新',
      })
      // 与 usePermissionSync 同口径：只归还确实拿到手的那次引用；
      // 并回滚已加入的房间与已绑定的监听（2026-11-17 审计 D 组：
      // 此前部分失败时已 join 的房间不退出，且 ws 置空会短路卸载清理）
      cleanup()
    }
  })

  onUnmounted(cleanup)
}

export default useRealtimeRefresh
