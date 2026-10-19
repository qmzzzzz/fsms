/**
 * WebSocket 事件分发与外部推送（2026-10-18 自 services/websocketService.js 拆出）
 *
 * connection 回调（连接数上限、认证超时、auth / join-room / leave-room /
 * disconnect 监听，监听器一律经 guardSocketHandler 兜住 rejection）与对外的
 * emitRoleUpdate / emitPermissionUpdate / emitPermissionSync / emitNotification /
 * getStats。方法是 mixin 形态，由 index.js 挂到 WebSocketService.prototype。
 *
 * guardSocketHandler 的头部注释引用了本文件内的握手路径兜底（`（:NNN）` 为同文件
 * 裸锚），台账见 tests/ci/bareAnchorAttribution.test.js。
 */

const logger = require('../../utils/logger');
const sharedCache = require('../sharedCache');
const {
  MAX_CONNECTIONS_PER_PROCESS,
  AUTH_TIMEOUT,
  ALLOWED_ROOMS,
  ROOM_ROLE_REQUIREMENTS,
  roomRolesSatisfied,
  userRoom,
} = require('./shared');

/**
 * 给 async 事件监听器挂上拒绝臂
 *
 * socket.io 4.8.4 的派发路径（`node_modules/socket.io/dist/socket.js:693`
 * 的 `super.emitUntyped.apply(this, event)`）**丢弃监听器的返回值**：
 * `socket.on('x', async …)` 里 reject 掉的 promise 不会经它的手，
 * 直接成为 unhandledRejection；而本仓在 `src/index.js:466-484` 的口径是
 * 「任何未处理拒绝 ⇒ flush 审计后 `process.exit(1)`」。
 * 合起来就是：一条长连接上的一次 promise 拒绝 = 整个进程下线。
 * 同文件握手路径写的 `authenticateSocket(...).catch(() => {})`（:353）已经承认
 * 这条 promise 会 reject，只是兜底没覆盖到事件监听器形态。
 */
const guardSocketHandler =
  (event, handler) =>
  async (...args) => {
    try {
      await handler(...args);
    } catch (err) {
      logger.error(
        `WebSocket 事件处理异常（已就地吞止，避免未处理拒绝打死进程）：${event} - ${
          err && err.message ? err.message : err
        }`
      );
    }
  };

const methods = {
  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      // 连接数上限检查：使用实际 TCP 连接数而非 clients Map 大小。
      // 注意 connection 回调触发时 io.sockets.sockets.size 已计入当前这条新连接，
      // 故用「>」判断（含自身恰好等于上限时放行），确保实际允许的最大并发恰为 MAX_CONNECTIONS_PER_PROCESS
      const currentConnections = this.io.sockets.sockets.size;
      if (currentConnections > MAX_CONNECTIONS_PER_PROCESS) {
        logger.warn(
          `WebSocket 连接数达到上限 ${MAX_CONNECTIONS_PER_PROCESS}，拒绝新连接: ${socket.id}`
        );
        socket.emit('error', { message: '连接数已满，请稍后重试' });
        socket.disconnect(true);
        return;
      }

      // 立即注册到 clients Map（用于后续统计和限制检查）
      this.clients.set(socket.id, {
        id: socket.id,
        userId: null,
        rooms: new Set(),
        connectedAt: new Date(),
      });

      // 认证截止计时：超时未认证则强制断开，
      // 防止攻击者用大量未认证连接占满 MAX_CONNECTIONS_PER_PROCESS 名额（资源耗尽）
      const authTimer = setTimeout(() => {
        if (!socket.authenticated) {
          logger.warn(
            `WebSocket 连接 ${AUTH_TIMEOUT / 1000} 秒内未完成认证，强制断开: ${socket.id}`
          );
          socket.emit('auth-error', { message: '认证超时，连接已断开' });
          socket.disconnect(true);
        }
      }, AUTH_TIMEOUT);
      // 未认证连接断开/认证成功后会 clearTimeout；unref 兜底保证遗留的待处理
      // 定时器不拖住进程退出（真实服务由 HTTP server 维持事件循环，行为不变）
      if (authTimer.unref) authTimer.unref();

      logger.debug(`Client connected: ${socket.id}`);

      // 【I-01】握手阶段认证：优先读 socket.handshake.auth.token，
      // 其次回退握手请求头中的 access_token cookie（同源时浏览器自动携带）；
      // 两者均缺失时保留既有兑底：等待客户端通过 'auth' 事件提交令牌。
      const handshakeToken = this.extractHandshakeToken(socket);
      // per-socket 防重入标志：异步认证进行中时忽略新的认证请求，
      // 防止握手路径与客户端 'auth' 事件并发重复执行（重复查库/重复写连接映射）
      socket.authing = false;
      if (handshakeToken) {
        socket.authing = true;
        this.authenticateSocket(socket, handshakeToken, authTimer)
          .catch(() => {})
          .finally(() => {
            socket.authing = false;
          });
      }

      // 用户身份认证与多连接去重（兑底路径：客户端显式提交令牌）
      socket.on(
        'auth',
        guardSocketHandler('auth', async (token) => {
          // 已完成认证、或认证进行中（含握手路径）均忽略重复提交
          if (socket.authenticated || socket.authing) return;
          socket.authing = true;
          try {
            await this.authenticateSocket(socket, token, authTimer);
          } finally {
            socket.authing = false;
          }
        })
      );

      // 监听房间加入（需先完成认证，且房间名必须在白名单中）
      socket.on(
        'join-room',
        guardSocketHandler('join-room', async (room) => {
          // 必须先完成认证
          if (!socket.authenticated || !socket.userId) {
            socket.emit('error', { message: '请先完成认证' });
            return;
          }
          // 房间名必须在白名单中
          if (!ALLOWED_ROOMS.includes(room)) {
            socket.emit('error', { message: '无效的房间名' });
            return;
          }
          // 部分房间有角色要求（如 role-management 仅限管理员）
          //
          // P2-14 修复：不得使用认证时的 socket.roleCodes 静态快照。
          // 长连接可存活数小时，期间用户可能被降级/停权，而快照永不刷新——
          // 被降级的连接仍能加入 role-management 并持续接收角色/权限变更事件。
          // 受限房间在入房时强制重查数据库（同时复查 status/tokenVersion）；
          // 无角色要求的房间沿用快照，避免每次入房都打库。
          const requiredRoles = ROOM_ROLE_REQUIREMENTS[room];
          if (requiredRoles) {
            const fresh = await this.revalidateSocket(socket);
            if (!fresh.ok) {
              // revalidateSocket 内部已断开连接并发出 auth-error
              return;
            }
            if (!roomRolesSatisfied(room, fresh.roleCodes)) {
              socket.emit('error', { message: '无权加入该房间' });
              return;
            }
          }
          socket.join(room);
          logger.debug(`Client ${socket.id} joined room: ${room}`);

          // 连接建立时已在 clients Map 注册（userId 由认证成功后回写），
          // 此处必然命中已有条目，仅需追加房间；原「不存在则新建」分支为死代码，已删除
          this.clients.get(socket.id)?.rooms.add(room);
        })
      );

      // 监听房间离开
      socket.on('leave-room', (room) => {
        socket.leave(room);
        logger.debug(`Client ${socket.id} left room: ${room}`);

        const client = this.clients.get(socket.id);
        if (client) {
          client.rooms.delete(room);
        }
      });

      // 处理断开连接
      socket.on('disconnect', (reason) => {
        logger.debug(`Client disconnected: ${socket.id}, reason: ${reason}`);
        clearTimeout(authTimer);
        this.clients.delete(socket.id);

        // 清理用户连接映射
        if (socket.userId && this.userConnections.has(socket.userId)) {
          this.userConnections.get(socket.userId).delete(socket.id);
          if (this.userConnections.get(socket.userId).size === 0) {
            this.userConnections.delete(socket.userId);
          }
        }
      });
    });
  },

  /**
   * 发送角色更新事件
   */
  emitRoleUpdate(data = {}) {
    const eventData = {
      type: 'role-updated',
      timestamp: new Date().toISOString(),
      ...data,
    };

    this.io.to('role-management').emit('role-updated', eventData);
    logger.debug('Emitted role update', { eventType: eventData.type });

    return eventData;
  },

  /**
   * 发送权限更新事件
   *
   * 事件名与前端监听保持一致（'permissions-updated'，复数）。
   * 此前这里发的是单数 'permission-updated' —— 前端 RoleView 监听的是复数名，
   * 两边永不相交。因为 roleController 的 emitWebSocketEvent 又把所有事件
   * 统一转发给 emitRoleUpdate，这个方法从未被调用，错误的事件名一直没暴露。
   */
  emitPermissionUpdate(data = {}) {
    const eventData = {
      type: 'permissions-updated',
      timestamp: new Date().toISOString(),
      ...data,
    };

    this.io.to('role-management').emit('permissions-updated', eventData);
    logger.debug('Emitted permission update', { eventType: eventData.type });

    return eventData;
  },

  /**
   * 向指定用户定向下发其**完整**权限码集合（权限热生效的核心）
   *
   * 为什么必须定向而非广播：
   *   role-management 房间只有 SUPER_ADMIN / SECURITY_ADMIN 能加入，
   *   而角色权限变更影响的是「持有该角色的所有用户」——这些人绝大多数
   *   没有资格进入该房间，广播根本到不了他们。他们只能等 30 秒权限缓存
   *   过期（且前端 store 里的 permissions 是登录时的快照，连缓存过期也救不了，
   *   必须重新登录）。这正是「权限调整后要重登才生效」的根因。
   *
   * 为什么下发完整集合而非增量：
   *   增量无法表达「某权限被移除」。前端拿到完整集合直接整体替换，
   *   语义明确且天然幂等（重复投递不会累积错误）。
   *
   * 权限重算前提：调用方必须已执行 invalidateUserCache(userId)，
   * 否则 getPermissions 会命中旧缓存，下发的是变更前的权限集。
   *
   * @param {Array<string|object>} userIds 受影响的用户 id 列表
   * @param {object} [meta] 附加说明（action/roleId/roleName），仅用于前端日志与提示
   * @returns {Promise<{notified: number, offline: number}>} 实际投递与不在线的用户数
   */
  async emitPermissionSync(userIds = [], meta = {}) {
    const ids = [...new Set((userIds || []).map((id) => String(id)).filter(Boolean))];
    let notified = 0;
    let offline = 0;

    // Redis 就绪且挂载 adapter 时，在线判定与投递都走用户房间——
    // 房间成员跨实例可见，用户连在其他实例上也能收到；
    // 未配置时保持本地连接表路径（单实例语义，与历史一致）
    const redisMode = sharedCache.isRedisEnabled();

    for (const userId of ids) {
      let localSocketIds = null;
      if (redisMode) {
        // fetchSockets 在挂载 redis adapter 时返回全实例的房间成员

        const liveSockets = await this.io.in(userRoom(userId)).fetchSockets();
        if (liveSockets.length === 0) {
          offline++;
          continue;
        }
      } else {
        localSocketIds = this.userConnections.get(userId);
        // 不在线的用户无需重算权限：他下次登录/刷新时走 /auth/me 自然拿到最新值
        if (!localSocketIds || localSocketIds.size === 0) {
          offline++;
          continue;
        }
      }

      let permissionCodes;
      try {
        const User = require('../../models/User');
        permissionCodes = await User.getPermissions(userId);
      } catch (err) {
        // 重算失败不下发 permissionCodes：前端据「字段缺失」回退到主动拉取
        // /auth/me（权威来源），而不是拿一份可能过期的集合去覆盖本地状态
        logger.warn('权限同步重算失败，降级为「仅通知」', { userId, error: err.message });
        permissionCodes = undefined;
      }

      const eventData = {
        type: 'permission-sync',
        timestamp: new Date().toISOString(),
        ...meta,
        ...(permissionCodes ? { permissionCodes } : {}),
      };

      if (redisMode) {
        // 房间投递经 adapter 分发到所有实例上该用户的连接
        this.io.to(userRoom(userId)).emit('permission-sync', eventData);
      } else {
        // 逐 socket 投递而非 io.to(userId)：本服务未把用户加入以 userId 命名的
        // 房间时，userConnections 才是 userId → socketIds 的事实来源
        for (const socketId of localSocketIds) {
          this.io.to(socketId).emit('permission-sync', eventData);
        }
      }
      notified++;
    }

    if (ids.length > 0) {
      logger.info(
        `权限同步推送完成：命中 ${notified} 人在线，${offline} 人离线（离线用户下次登录自然生效）`
      );
    }
    return { notified, offline };
  },

  /**
   * 向指定房间推送通知
   *
   * P3-25：room 必须过 ALLOWED_ROOMS 白名单。当前调用面固定（仅内部服务调用），
   * 但缺少校验意味着一旦有人把 room 接到请求参数上，即可向任意房间名广播——
   * 包括 Socket.IO 用 socket.id 作为房间名的私有房间（向指定连接定向投递）。
   * 白名单校验的成本是一次数组查找，不值得省。
   */
  emitNotification(room, type, message) {
    if (!ALLOWED_ROOMS.includes(room)) {
      logger.warn(`拒绝向非白名单房间推送通知：room=${room}, type=${type}`);
      return false;
    }

    const eventData = {
      type: 'notification',
      timestamp: new Date().toISOString(),
      message,
      notificationType: type,
    };

    this.io.to(room).emit('notification', eventData);
    logger.debug(`Emitted notification to ${room}`, { notificationType: type });
    return true;
  },

  /**
   * 获取连接统计
   *
   * P3-25：默认只返回聚合指标，不再逐条列出 userId / 房间归属。
   * 原实现返回全量 clients 明细——那是一份「当前在线人员及其订阅频道」清单，
   * 对运维排障价值有限，却让任何能读到该输出的人（日志、监控面板、
   * 未来可能接上的诊断接口）掌握在线人员画像。
   * 需要明细时显式传 includeClients（调用方自行承担暴露面）。
   *
   * @param {object} [options]
   * @param {boolean} [options.includeClients=false] 是否包含逐连接明细
   */
  getStats({ includeClients = false } = {}) {
    const stats = {
      totalClients: this.clients.size,
      totalUsers: this.userConnections.size,
      maxConnections: MAX_CONNECTIONS_PER_PROCESS,
      // F-13：`maxConnections` 的**口径**必须随值一起回报，否则面板聚合时
      // 会把它当全局上限（多副本下真实容量 = 实例数 × 该值）。
      capacityScope: 'per-process',
      // 只回报白名单房间的占用情况：adapter.rooms 还包含以 socket.id 命名的
      // 私有房间，逐一列出等于泄露全部连接标识
      rooms: ALLOWED_ROOMS.filter((r) => this.io.sockets.adapter.rooms.has(r)),
    };

    if (includeClients) {
      stats.clients = Array.from(this.clients.values()).map((client) => ({
        id: client.id,
        userId: client.userId,
        rooms: Array.from(client.rooms),
        connectedAt: client.connectedAt,
      }));
    }

    return stats;
  },
};

module.exports = { methods };
