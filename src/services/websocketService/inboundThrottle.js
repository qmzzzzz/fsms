/**
 * WebSocket 入站事件限流（P1，2026-10-24）
 *
 * 挂载点是 `socket.use()`：socket.io 4.x 的派发路径是
 * `onevent → dispatch → run(fns) → super.emitUntyped`，**所有**客户端→服务端
 * 的 EVENT/BINARY_EVENT 包都要先过 `fns` 这一层，`disconnect` 这类内部事件
 * 不经此路径。所以它是唯一一个"新增事件自动覆盖"的位置——不需要谁在写新
 * handler 时记得加限流。
 *
 * 为什么不能逐个 handler 加：本文件之外已经有 4 个注册点（auth / join-room /
 * leave-room / disconnect），其中 2 个是 async。逐个加的话，下一个新增事件
 * 默认是**没有**限流的，而缺限流不会有任何症状——直到被人拿来打库。
 *
 * 超限时**不调 next()**：包被丢弃，处理器不会执行，库查询也不会发生。这比
 * "执行了再拒绝"省掉整条代价链。这是资源闸，方向是 fail-closed；丢一个
 * join-room 的后果只是客户端收不到该房间的事件，重试即可。
 *
 * 为什么不节流 leave-room / disconnect：
 *   · disconnect 是服务端内部事件，根本不经过 socket.use；
 *   · leave-room 是纯内存操作（`socket.leave()` + 一次 Map 删除），单条成本与
 *     socket.io 自身的解析成本同量级，限它没有额外收益。
 * 真正的放大器是"每条事件背后一次库查询"，而只有 join-room 具备这个性质。
 */

'use strict';

const logger = require('../../utils/logger');
const {
  WS_INBOUND_BUCKET_CAPACITY,
  WS_INBOUND_REFILL_PER_SEC,
  WS_INBOUND_MAX_VIOLATIONS,
} = require('./shared');

/**
 * socket → 桶状态。
 *
 * 用 WeakMap 而不是挂在 socket 上：socket 对象会被 logger 序列化（`{...socket}`
 * 之类），多一个可枚举字段就会渗进日志；WeakMap 还保证连接断开后桶随之回收。
 */
const buckets = new WeakMap();

function stateOf(socket, now) {
  let state = buckets.get(socket);
  if (!state) {
    state = {
      tokens: WS_INBOUND_BUCKET_CAPACITY,
      at: now,
      violations: 0, // 连续被拒次数（成功消费一次即归零）
      warned: false, // 本连接是否已经发过超限提示（避免每个被丢的包都回一条 error）
      throttled: 0, // 累计被丢弃的包数（诊断用）
      closed: false, // 是否已判定断开
    };
    buckets.set(socket, state);
  }
  return state;
}

/**
 * 取一个令牌。
 *
 * @param {object} socket Socket.IO 连接
 * @param {string} event 事件名（仅用于日志/诊断）
 * @param {number} [now] 当前毫秒时间戳（测试注入）
 * @returns {{allowed: boolean, retryAfterMs: number, disconnect: boolean, firstViolation: boolean, throttledTotal: number}}
 */
function takeInboundSlot(socket, event, now = Date.now()) {
  const state = stateOf(socket, now);

  // 已判定断开的连接：后续到达的包一律**静默**丢弃，不再计数、不再记指标。
  // 断开是异步生效的（transport close 要等事件循环转一圈），在途/排队中的包
  // 会继续流进中间件。若这里继续走"超限"分支，一次攻击会产出 N 条指标与
  // N 条 warn 日志——处置动作自己变成放大器（实测 60 个包 → 11 条指标）。
  if (state.closed) {
    return {
      allowed: false,
      silent: true,
      disconnect: false,
      firstViolation: false,
      retryAfterMs: 0,
      throttledTotal: state.throttled,
    };
  }

  // 按经过时间补充令牌。elapsed 取 max(0, …)：系统时钟回拨时不得倒扣令牌。
  const elapsed = Math.max(0, now - state.at);
  if (elapsed > 0) {
    state.tokens = Math.min(
      WS_INBOUND_BUCKET_CAPACITY,
      state.tokens + (elapsed / 1000) * WS_INBOUND_REFILL_PER_SEC
    );
    state.at = now;
  }

  if (state.tokens >= 1) {
    state.tokens -= 1;
    state.violations = 0;
    return {
      allowed: true,
      retryAfterMs: 0,
      disconnect: false,
      firstViolation: false,
      throttledTotal: state.throttled,
    };
  }

  state.violations += 1;
  state.throttled += 1;
  // O-2：丢弃必须可观测。**只在这里**计，不在上方 `state.closed` 的静默分支计——
  // 已断开连接的后续包若也计数，一次攻击会产出 N 条指标（同 noteThrottleDisconnect
  // 里"按连接计一次"的理由），处置动作自己变成放大器。
  try {
    require('../../utils/metricsRuntime').incWsInboundThrottled();
  } catch (_) {
    /* 指标端不可用不影响限流方向 */
  }
  const firstViolation = state.violations === 1;
  return {
    allowed: false,
    retryAfterMs: Math.max(1, Math.ceil(((1 - state.tokens) / WS_INBOUND_REFILL_PER_SEC) * 1000)),
    disconnect: state.violations >= WS_INBOUND_MAX_VIOLATIONS,
    firstViolation,
    throttledTotal: state.throttled,
    event,
  };
}

/** 记录一次"因超限而断开"：日志 + 指标。指标按**连接**计一次，不按被丢的包计。 */
function noteThrottleDisconnect(socket, state, event) {
  logger.warn('WebSocket 入站事件持续超速，已断开连接', {
    socketId: socket.id,
    userId: socket.userId ? String(socket.userId) : undefined,
    lastEvent: event,
    throttled: state.throttled,
    violations: state.violations,
  });
  try {
    // 每连接一次（不是每包一次）：否则单个攻击者就能把
    // SecurityAlertBurst（≥10 条/10 分钟）打成常红，告警失去区分度。
    require('../../utils/metrics').incSecurityAlert('ws_inbound_throttled', 'medium');
  } catch (_) {
    /* 指标端不可用不影响断开方向 */
  }
  try {
    // O-2：与上面的安全告警分开记——告警是"有人在打"的事件，这个计数是容量/健康信号，
    // 两者消费方不同（前者进 alert-rules，后者进面板与容量规划）。
    require('../../utils/metricsRuntime').incWsInboundDisconnect();
  } catch (_) {
    /* 同上 */
  }
}

/**
 * 给一条连接装上入站限流。
 *
 * 兼容性闸：`socket.use` 是 Socket.IO 的公开 API，但测试夹具里的假 socket
 * 往往只实现 on/emit/join/leave。缺 use 时**不装**（否则夹具会在 connection
 * 回调里抛错），生产环境不可能走到这条分支——
 * `websocketInboundThrottle.test.js` 有一条用例直接钉住真实 Socket 原型上有 use。
 *
 * @param {object} socket Socket.IO 连接
 * @returns {boolean} 是否真的装上了
 */
function installInboundThrottle(socket) {
  if (!socket || typeof socket.use !== 'function') return false;

  socket.use((packet, next) => {
    const event = Array.isArray(packet) ? packet[0] : packet;
    const verdict = takeInboundSlot(socket, event);

    if (verdict.allowed) {
      next();
      return;
    }
    // 已判定断开后的在途包：静默丢弃，不重复记日志/指标
    if (verdict.silent) return;

    if (verdict.disconnect) {
      const state = buckets.get(socket);
      if (state && !state.closed) {
        state.closed = true; // 先置位：断开是异步的，期间再来的包不得重复计数
        noteThrottleDisconnect(socket, state, event);
      }
      try {
        socket.disconnect(true);
      } catch (_) {
        /* 客户端可能已断开 */
      }
      return; // 不调 next()
    }

    if (verdict.firstViolation) {
      const state = buckets.get(socket);
      if (state && !state.warned) {
        state.warned = true;
        logger.warn('WebSocket 入站事件超速（开始丢弃）', {
          socketId: socket.id,
          event,
          throttled: state.throttled,
        });
      }
      // 每次超速连击只回一条：每个被丢的包都 emit 一次，等于把入站洪水
      // 换成出站洪水（放大方向反了，但同样耗资源）。
      try {
        socket.emit('error', {
          message: '事件频率超限，请稍后重试',
          code: 'WS_RATE_LIMITED',
          retryAfterMs: verdict.retryAfterMs,
        });
      } catch (_) {
        /* 客户端可能已断开 */
      }
    }
    // 其余被拒的包静默丢弃：不调 next() 即不执行处理器
  });

  return true;
}

/** 仅供测试：读某条连接当前的桶状态（生产不调用） */
function _peekState(socket) {
  return buckets.get(socket) || null;
}

module.exports = {
  takeInboundSlot,
  installInboundThrottle,
  _peekState,
};
