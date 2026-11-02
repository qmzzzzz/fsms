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

  onMounted(() => {
    try {
      ws = acquireWebSocket()
      rooms.forEach((room) => ws.joinRoom(room))
      subscriptions.forEach(({ event, handler }) => ws.on(event, handler))
    } catch (error) {
      // 建连失败退化为手动刷新，不影响页面主流程；但必须上报，否则「实时推送
      // 从未生效」会以「页面一直要手动刷」的形态长期存在而无人发现。
      reportDegradation(`${label}: WebSocket 订阅失败，实时刷新已失效`, {
        error: error?.message || String(error),
        fallback: '手动刷新',
      })
      // 与 usePermissionSync 同口径：只归还确实拿到手的那次引用
      if (ws) releaseWebSocket()
      ws = null
    }
  })

  onUnmounted(() => {
    if (!ws) return
    subscriptions.forEach(({ event, handler }) => ws.off(event, handler))
    rooms.forEach((room) => ws.leaveRoom(room))
    releaseWebSocket()
    ws = null
  })
}

export default useRealtimeRefresh
