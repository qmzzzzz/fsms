/**
 * WebSocket 侧的设备会话吊销处置（#2）
 *
 * 设备级吊销（「踢除该设备」）只改 UserSession.status，既不推进 tokenVersion
 * 也不改 User.status，因此按 status/tokenVersion 复查的清扫放行它。本模块提供
 * 三条互补的处置路径：
 *  - disconnectSessionsBySession：本进程内吊销后的即时断开（由 sessionService
 *    的进程内通知驱动）；
 *  - _handleSessionRevoked：通知入口，异常不得回抛（吊销已写库成功）；
 *  - _sweepRevokedSessions：跨实例吊销的周期兜底，按库复查（最长一个清扫周期）。
 *
 * 未携带 sid 的旧令牌不走会话匹配：与握手期「无 sid 跳过会话校验」同口径，
 * 不能因升级把上线前签发的令牌全部踢下线；它们由 tokenVersion/status 清扫兜底。
 *
 * 方法是 mixin 形态，由 index.js 挂到 WebSocketService.prototype。
 */

const logger = require('../../utils/logger');

/** 通知与断开解耦：auth-error 发送失败不得推迟断开（本仓多处共用的纪律）。 */
function notifyAndDisconnect(socket, message) {
  try {
    socket.emit('auth-error', { message });
  } catch (_) {
    /* 通知失败不影响遏制 */
  }
  try {
    socket.disconnect(true);
  } catch (_) {
    /* 客户端可能已断开 */
  }
}

function matchesRevocation(socket, revokedSids, matchAll, userId) {
  if (socket.sid && revokedSids.has(String(socket.sid))) return true;
  return matchAll && String(socket.userId) === String(userId);
}

const methods = {
  /**
   * 按设备会话断开已认证长连接（#2）
   *
   * 匹配面有两条：
   *  - sids 命中：单设备/批量吊销（revokeSession / revokeOtherSessions）；
   *  - all + userId：全部会话吊销（revokeAllSessions），按归属用户断开。
   * all 但没有 userId 时不做任何事：宁可等周期清扫，也不能把全体连接断开。
   *
   * @param {object} params
   * @param {Iterable<string>} [params.sids] 被吊销的设备会话标识
   * @param {string|null} [params.userId] 全部会话吊销时的归属用户
   * @param {boolean} [params.all=false] 是否吊销该用户全部会话
   * @param {string} [params.message] 回给客户端的断开原因
   * @returns {number} 实际断开的连接数
   */
  disconnectSessionsBySession({
    sids = [],
    userId = null,
    all = false,
    message = '该设备会话已失效，请重新登录',
  } = {}) {
    const revokedSids = new Set([...sids].map((sid) => String(sid)));
    const matchAll = Boolean(all && userId);
    if (!matchAll && revokedSids.size === 0) return 0;

    const sockets = [...this.clients.keys()]
      .map((socketId) => this.io?.sockets?.sockets?.get(socketId))
      .filter((socket) => socket && matchesRevocation(socket, revokedSids, matchAll, userId));
    for (const socket of sockets) notifyAndDisconnect(socket, message);
    return sockets.length;
  },

  /**
   * 会话吊销通知的入口（由 index.js 构造器登记到 sessionService.onSessionRevoked）。
   *
   * 监听器在会话服务的吊销路径里同步调用，异常不得回抛——吊销本身已经写库成功，
   * 不能因为 WS 记账异常把一次成功的吊销变成失败。
   *
   * @param {{sids?: string[], userId?: string, all?: boolean, reason?: string}} event
   */
  _handleSessionRevoked(event) {
    try {
      const { sids = [], userId = null, all = false, reason } = event || {};
      const kicked = this.disconnectSessionsBySession({ sids, userId, all });
      if (kicked > 0) {
        logger.info('WebSocket 会话吊销生效：已断开对应长连接', {
          count: kicked,
          userId: userId ? String(userId) : undefined,
          all,
          reason,
        });
      }
    } catch (err) {
      logger.warn(`WebSocket 会话吊销通知处理失败（不影响吊销结论）：${err.message}`);
    }
  },

  /**
   * 周期复查设备会话是否仍可用（#2 的跨实例兜底）
   *
   * 本进程内的吊销会经 onSessionRevoked 即时断开；吊销落在**其他实例**时，
   * sesscache 广播只承载缓存失效语义（它无法区分「吊销成功」与「清一条不存在
   * 的缓存」），据此断开会把缓存失效误当处置，因此正确性由本趟按库复查保证，
   * 生效上限是一个清扫周期（30s）——与 HTTP 侧 15s 缓存上限同一量级。
   *
   * 与用户复查一样按 sid 去重后单次 $in 批量查询（L-29 的教训：不得逐连接打库）；
   * DB 故障时 fail-open 保留连接等下一轮——一次抖动不应清场全部在线连接。
   * sid 查不到会话记录同样判失效：HTTP 侧 validateSession 对不存在的 sid 也是拒绝。
   *
   * @param {import('socket.io').Socket[]} sockets 本轮到复查的连接
   * @returns {Promise<{alive: import('socket.io').Socket[], kicked: number}>}
   */
  async _sweepRevokedSessions(sockets) {
    const sidById = new Map();
    for (const socket of sockets) {
      if (socket.sid) sidById.set(socket.id, String(socket.sid));
    }
    // 全是无 sid 的旧令牌：不加载模型，纯内存快速返回
    if (sidById.size === 0) return { alive: sockets, kicked: 0 };

    const UserSession = require('../../models/UserSession');
    let usableBySid;
    try {
      const docs = await UserSession.find({ sid: { $in: [...new Set(sidById.values())] } }).select(
        'sid status expiresAt'
      );
      usableBySid = new Map(docs.map((doc) => [String(doc.sid), doc.isUsable()]));
    } catch (err) {
      logger.error(`WebSocket 设备会话复查异常，本轮跳过: ${err.message}`);
      return { alive: sockets, kicked: 0 };
    }

    const alive = [];
    let kicked = 0;
    for (const socket of sockets) {
      const sid = sidById.get(socket.id);
      // 无 sid 的旧令牌不参与（与握手期同口径）；sid 有效则保留
      if (!sid || usableBySid.get(sid) === true) {
        alive.push(socket);
        continue;
      }
      kicked++;
      logger.warn('WebSocket 运行期会话失效：设备会话已吊销或过期，主动断开', {
        socketId: socket.id,
        userId: socket.userId ? String(socket.userId) : undefined,
        sid: sid.slice(0, 8),
      });
      notifyAndDisconnect(socket, '该设备会话已失效，请重新登录');
    }
    return { alive, kicked };
  },
};

module.exports = { methods };
