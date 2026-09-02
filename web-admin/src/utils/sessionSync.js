/**
 * 跨标签页会话同步（BroadcastChannel + storage 事件兜底）
 *
 * 问题背景：认证令牌走 httpOnly cookie（浏览器全局共享），而用户身份界面状态
 * （currentUser/permissions）走 sessionStorage（按标签页隔离）。当同一浏览器的
 * 另一个标签页登录了不同账号时，cookie 被新账号覆盖，本标签页出现
 * 「界面显示旧用户、请求实际以新用户身份执行」的权限错位。
 *
 * 解决方式：登录/登出时向同源的其他标签页广播事件；接收方比对本地会话身份，
 * 发现被覆盖（不同用户登录）或被终止（同用户登出）时，清除本地状态并跳转登录页。
 *
 * 同一账号在多个标签页登录是无害的（cookie 身份一致），不触发任何处理。
 */

const CHANNEL_NAME = 'auth-session-sync'
const STORAGE_MIRROR_KEY = 'authSessionSyncMirror'

let channel = null
let handler = null

/**
 * 广播通道初始化（惰性）：BroadcastChannel 优先，不可用时降级为
 * localStorage 写入（其他标签页通过 storage 事件感知）
 */
const ensureChannel = () => {
  if (channel !== null) return channel
  try {
    if (typeof BroadcastChannel !== 'undefined') {
      channel = new BroadcastChannel(CHANNEL_NAME)
    } else {
      // 降级标记：用不存在的 BroadcastChannel 对象占位，广播时走 localStorage
      channel = false
    }
  } catch (_) {
    channel = false
  }
  return channel
}

/**
 * 广播认证状态变更
 * @param {'login'|'logout'} type 事件类型
 * @param {object} user 触发事件的用户对象（取 userId/id/_id 之一作为标识）
 */
const broadcastAuthChange = (type, user) => {
  const payload = {
    type,
    userId: user?.userId ?? user?.id ?? user?._id ?? null,
    username: user?.username || null,
    ts: Date.now(),
  }
  try {
    const ch = ensureChannel()
    if (ch) {
      ch.postMessage(payload)
      return
    }
  } catch (_) {
    /* 广播失败静默，兜底路径仍可尝试 */
  }

  // 兜底：写 localStorage 触发其他标签页的 storage 事件。
  // 值必须与上次不同（含时间戳保证单调递增），否则不会触发事件
  try {
    localStorage.setItem(STORAGE_MIRROR_KEY, JSON.stringify(payload))
  } catch (_) {
    /* 隐私模式等场景写入失败，仅失去跨标签页同步能力 */
  }
}

/**
 * 初始化跨标签页监听
 * @param {(event: {type: 'login'|'logout', userId: string|null, username: string|null}) => void} onEvent
 *   收到其他标签页的认证变更事件时回调（本标签页自己广播的事件不会回环）
 */
const initSessionSync = (onEvent) => {
  if (typeof onEvent !== 'function') return
  handler = onEvent

  try {
    const ch = ensureChannel()
    if (ch) {
      ch.onmessage = (e) => handler(e.data)
    }
  } catch (_) {
    /* BroadcastChannel 初始化失败，走 storage 兜底 */
  }

  // storage 事件兜底（BroadcastChannel 可用时作为双保险也无害：
  // 同一事件可能被两条通道各投递一次，由 handler 幂等处理）
  try {
    window.addEventListener('storage', (e) => {
      if (e.key !== STORAGE_MIRROR_KEY || !e.newValue) return
      try {
        handler(JSON.parse(e.newValue))
      } catch (_) {
        /* 非法负载忽略 */
      }
    })
  } catch (_) {
    /* 无 window 环境（测试）忽略 */
  }
}

export { broadcastAuthChange, initSessionSync, CHANNEL_NAME, STORAGE_MIRROR_KEY }
