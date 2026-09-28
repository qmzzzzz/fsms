/**
 * WebSocket 服务 - 用于实时推送角色和权限更新
 */

const socketIo = require('socket.io');
const logger = require('../utils/logger');
const config = require('../config');
// trust proxy 跳数判据的单一来源：与 src/app.js 共用同一函数，避免两侧漂移
const {
  MAX_TRUST_PROXY_HOPS,
  resolveTrustProxyHops: resolveTrustProxyHopsFromConfig,
} = require('../config/validate');
const sharedCache = require('./sharedCache');
const { parseCookies, ACCESS_COOKIE_NAME } = require('../utils/cookie');
const { isIPAllowed } = require('../utils/ipRange');

// 连接管理常量
const MAX_CONNECTIONS = 1000;
const HEARTBEAT_INTERVAL = 30000; // 30秒心跳检测
const HEARTBEAT_TIMEOUT = 60000; // 60秒超时断开
const AUTH_TIMEOUT = 30000; // 连接后 30 秒内必须完成认证，否则强制断开

/**
 * 解析握手来源 IP（P0-2 修复，2026-09-17）
 *
 * HTTP 侧的 IP 判定读的是 express 的 req.ip（trust proxy 语义）；WS 侧若直接取
 * TCP 对端地址，反代部署下拿到的是代理 IP，同一个 allowedIPs 规则会在两条通道上
 * 得出不同结论——用户表现为「网页能开、实时推送连不上」，或更糟：代理 IP 恰好在
 * 白名单内时静默放宽。
 *
 * 本函数复刻 express（proxy-addr）对**数字信任跳数**的取值语义：
 *   addrs = X-Forwarded-For 链（左→右）+ 直连对端地址
 *   结果 = addrs[max(0, addrs.length - 1 - hops)]
 * 逐条比对（真实 express 5.2.1 + 真实 HTTP 请求，见
 * src/tests/services/websocketAuthScope.test.js）：
 *   hops=1 XFF="a, b"     → b（与 req.ip 同值）
 *   hops=2 XFF="a, b"     → a
 *   hops=3 XFF="a, b, c"  → a
 *   hops=2 XFF="a"        → a（链长不足时 express 取链最左值，此处一致）
 *   hops=0（不信任）      → 直连对端地址（与 trust proxy=false 时的 req.ip 同值）
 *
 * @param {object} handshake socket.handshake（socket.io 握手对象）
 * @param {number} hops 信任的代理跳数，0 表示不信任任何转发头
 * @returns {string|null} 客户端 IP 文本；无任何可用地址时返回 null
 */
const resolveHandshakeClientIP = (handshake, hops) => {
  const direct = handshake?.address || null;
  const chain = String(handshake?.headers?.['x-forwarded-for'] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const addrs = direct ? chain.concat([direct]) : chain;
  if (addrs.length === 0) return null;
  const trust = Number.isInteger(hops) && hops > 0 ? hops : 0;
  return addrs[Math.max(0, addrs.length - 1 - trust)];
};

/**
 * 信任的代理跳数（P0-2 修复，2026-09-17；F-B42 起委托给 config/validate）
 *
 * 判据（含上限 MAX_TRUST_PROXY_HOPS=5 的夹取）唯一来源是 src/config/validate.js
 * 的 resolveTrustProxyHops，本处与 src/app.js 各自调用它，于是同一条请求在 WS 与
 * HTTP 上必然得出同一个客户端 IP。一致性用例见
 * src/tests/services/websocketTrustProxyHopsParity.test.js；
 * 注意 websocketAuthScope.test.js 那条「IP 与 HTTP 侧一致」的用例是把 hops 当**入参**
 * 喂给 resolveHandshakeClientIP 的，从未检验 hops 从哪来——上限漏判因此隐身。
 *
 * 委托之前本函数自己实现了一套同样的分支，但**漏了上限夹取**：
 * TRUST_PROXY_HOPS=999999 时 HTTP 侧被压回 5，本侧原样透传 ⇒ resolveHandshakeClientIP
 * 取到 XFF 最左段（完全由请求方决定的值），配了 allowedIPs 的账户其登录 IP 白名单
 * 在 WS 握手面上失效。非 production 可达：config/validate.js 的启动硬闸对
 * staging/dev 早退，只有 app.js 那一份实现补了运行时夹取。
 *
 * 留痕：错配只在真被用到时才告警（本函数唯一调用点在用户配了 allowedIPs 时执行），
 * 且每进程一次——握手是重入路径，逐次告警会变成日志放大。
 *
 * 注：不引入 proxy-addr 依赖，也不改 index.js 传入 app 实例——保持本模块自包含，
 * 避免与 app.js 形成新的跨模块耦合面。
 * @returns {number} 信任跳数，0 表示不信任任何转发头
 */
let hopsMisconfigWarned = false;
const resolveTrustProxyHops = () => {
  const raw = process.env.TRUST_PROXY_HOPS;
  const { hops, parsed, illegal, clamped } = resolveTrustProxyHopsFromConfig(raw, config.nodeEnv);
  if ((illegal || clamped) && !hopsMisconfigWarned) {
    hopsMisconfigWarned = true;
    logger.warn(
      (illegal
        ? `TRUST_PROXY_HOPS 取值非法（${raw}）`
        : `TRUST_PROXY_HOPS 超上限（${parsed} > ${MAX_TRUST_PROXY_HOPS}）`) +
        `，WS 握手侧按 ${hops} 跳解析客户端 IP：跳数与真实代理拓扑不符时 ` +
        'allowedIPs 的握手 IP 校验会按错误地址判定（过大即被伪造 XFF 绕过）',
      { trustProxyHops: hops, illegal, clamped }
    );
  }
  return hops;
};

/**
 * 账户是否处于「临时锁定」中（暴力破解阈值写入，10 分钟后自动失效）。
 *
 * 判据与 HTTP 侧同源：`src/middleware/auth.js` 的 `assertAccountUsable` 用
 * `lockUntil && lockUntil > new Date()` 返回 ACCOUNT_TEMP_LOCKED；
 * `authService.loginUser` 用同一判据拒绝登录。而写入方（authService 的失败计数）
 * **只写 lockUntil，不动 status、也不推进 tokenVersion**，所以
 * 「status==='active' 且已有 access 令牌」在临时锁定期间依然成立——
 * HTTP 面拒绝的令牌，若 WS 面只看 status 就会放行，等于给被锁定的账户
 * 留了一条实时推送通道（含 role-management 广播）。
 * @param {object} user 需已 select lockUntil
 * @returns {boolean}
 */
const isTemporarilyLocked = (user) => Boolean(user?.lockUntil) && user.lockUntil > new Date();

/**
 * 用户定向房间名（服务端内部房间，不经客户端 join 白名单）。
 * 挂载 Redis adapter 后，向该房间投递即可触达连接在**任一实例**上的
 * 该用户连接——跨实例权限同步的落点（R-3/M-1 收尾）。
 */
const userRoom = (userId) => `user:${userId}`;

// 允许加入的房间白名单，以及对应的最低角色要求
// null 表示无角色限制（所有已认证用户可加入）
const ALLOWED_ROOMS = ['role-management', 'device-alert', 'alarm', 'notification'];
const ROOM_ROLE_REQUIREMENTS = {
  'role-management': ['SUPER_ADMIN', 'SECURITY_ADMIN'], // 角色管理频道仅限管理员
  'device-alert': null, // 设备告警：所有已认证用户
  alarm: null, // 报警通知：所有已认证用户
  notification: null, // 系统通知：所有已认证用户
};

/**
 * 角色码集合是否满足某个房间的准入要求（无角色要求的房间恒为 true）。
 *
 * 抽成一处而非两处各写 `requiredRoles.some(...)`：入房判定与复查后的清房判定
 * 必须是同一个谓词，否则会出现"入得来、却被清扫逻辑按另一套标准赶出去"（或反之）。
 * @param {string} room 房间名（须在 ROOM_ROLE_REQUIREMENTS 内）
 * @param {string[]} roleCodes 该连接当前生效的角色码
 * @returns {boolean}
 */
const roomRolesSatisfied = (room, roleCodes) => {
  const requiredRoles = ROOM_ROLE_REQUIREMENTS[room];
  if (!requiredRoles) return true;
  return requiredRoles.some((r) => roleCodes.includes(r));
};

class WebSocketService {
  constructor(server) {
    // 从统一配置读取 CORS 来源，禁止使用通配符 '*'
    const rawOrigin = config.corsOrigin || '';
    // 显式拒绝通配符：Socket.IO 的 cors.origin=* 会接受任意来源的跨域请求
    if (rawOrigin === '*') {
      logger.error('CORS_ORIGIN 不能设置为通配符 "*"，WebSocket 服务已拒绝启动（安全策略）');
      throw new Error('CORS_ORIGIN 不能为通配符 "*"');
    }
    // 【I-10】与 app.js 中 HTTP CORS 的来源回退列表保持完全一致：
    // 配置了 CORS_ORIGIN 时按逗号分隔白名单；未配置时回退同一本地开发白名单，
    // 避免 WS 与 HTTP 两侧同源策略漂移导致跨域携带 cookie 行为不一致（改动需两侧同步）
    const corsOrigin = rawOrigin
      ? rawOrigin
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : [
          'http://localhost:3001',
          'http://127.0.0.1:3001',
          'http://localhost:5173',
          'http://127.0.0.1:5173',
        ];

    this.io = socketIo(server, {
      cors: {
        origin: corsOrigin,
        methods: ['GET', 'POST'],
        credentials: true,
      },
      pingInterval: HEARTBEAT_INTERVAL,
      pingTimeout: HEARTBEAT_TIMEOUT,
      maxHttpBufferSize: 1e6, // 1MB 消息大小限制
    });

    this.clients = new Map();
    this.userConnections = new Map(); // userId -> Set of socketIds
    this._cleanupTimer = null;
    this._sweepRunning = false; // R-2 周期复查防重入标志
    this._adapterClients = []; // Redis adapter 专用连接（dispose 时回收）
    this.setupEventHandlers();
    this.setupConnectionCleanup();

    logger.info('WebSocket 服务已初始化');
  }

  /**
   * 挂载 Redis adapter（R-3/M-1 收尾）：配置 REDIS_URL 且共享缓存就绪时，
   * 房间/定向投递跨实例生效——权限变更推送能触达连接在其他实例上的用户。
   * 未配置时保持默认内存 adapter，单实例行为与历史完全一致。
   * 由 index.js 启动期调用；失败仅告警降级，不阻断服务。
   */
  async initSharedAdapter() {
    if (!sharedCache.isRedisEnabled()) return;
    try {
      const { createAdapter } = require('@socket.io/redis-adapter');
      const Redis = require('ioredis');
      const url = (process.env.REDIS_URL || '').trim();
      // 订阅端必须独立连接（ioredis 进入订阅模式后禁用普通命令）；
      // 发布端复用共享缓存主连接，少占一条连接
      const subClient = new Redis(url, { lazyConnect: false, enableOfflineQueue: true });
      this.io.adapter(createAdapter(sharedCache.getRedisClient(), subClient));
      this._adapterClients.push(subClient);
      logger.info('WebSocket 已挂载 Redis adapter：推送跨实例生效');
    } catch (err) {
      logger.warn(`WebSocket Redis adapter 挂载失败（推送降级为单实例语义）：${err.message}`);
    }
  }

  /**
   * 停止 WebSocket 服务并清理资源（供优雅关闭调用）
   */
  dispose() {
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
      this._cleanupTimer = null;
    }
    // 断开所有客户端连接
    for (const [socketId] of this.clients) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket) socket.disconnect(true);
    }
    this.clients.clear();
    this.userConnections.clear();

    // 回收 Redis adapter 专用连接（无 adapter 时为空数组，无副作用）
    for (const client of this._adapterClients) {
      try {
        client.disconnect();
      } catch (_) {
        /* 连接可能已断 */
      }
    }
    this._adapterClients = [];

    // best-effort 关闭底层 Socket.IO 服务（会一并关闭其挂载的 HTTP server），
    // 释放端口监听与内部资源；失败不阻断优雅关闭流程
    try {
      this.io.close();
    } catch (err) {
      logger.warn(`WebSocket io.close() 失败：${err.message}`);
    }
  }

  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      // 连接数上限检查：使用实际 TCP 连接数而非 clients Map 大小。
      // 注意 connection 回调触发时 io.sockets.sockets.size 已计入当前这条新连接，
      // 故用「>」判断（含自身恰好等于上限时放行），确保实际允许的最大并发恰为 MAX_CONNECTIONS
      const currentConnections = this.io.sockets.sockets.size;
      if (currentConnections > MAX_CONNECTIONS) {
        logger.warn(`WebSocket 连接数达到上限 ${MAX_CONNECTIONS}，拒绝新连接: ${socket.id}`);
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
      // 防止攻击者用大量未认证连接占满 MAX_CONNECTIONS 名额（资源耗尽）
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
      socket.on('auth', async (token) => {
        // 已完成认证、或认证进行中（含握手路径）均忽略重复提交
        if (socket.authenticated || socket.authing) return;
        socket.authing = true;
        try {
          await this.authenticateSocket(socket, token, authTimer);
        } finally {
          socket.authing = false;
        }
      });

      // 监听房间加入（需先完成认证，且房间名必须在白名单中）
      socket.on('join-room', async (room) => {
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
      });

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
  }

  /**
   * 提取握手阶段的认证令牌（I-01）：
   * socket.handshake.auth.token 优先，其次握手请求头中的 access_token cookie
   * @returns {string|null}
   */
  extractHandshakeToken(socket) {
    const authToken = socket.handshake?.auth?.token;
    if (authToken) return authToken;
    const cookieHeader = socket.handshake?.headers?.cookie;
    if (cookieHeader) {
      const cookies = parseCookies(cookieHeader);
      if (cookies[ACCESS_COOKIE_NAME]) return cookies[ACCESS_COOKIE_NAME];
    }
    return null;
  }

  /**
   * 校验令牌并完成 socket 认证（握手路径与 'auth' 事件路径共用同一套校验逻辑）
   * @param {Object} socket - Socket.IO socket
   * @param {string} token - 待校验的 JWT
   * @param {number} authTimer - 认证超时计时器句柄，认证成功后清除
   */
  async authenticateSocket(socket, token, authTimer) {
    try {
      const jwt = require('jsonwebtoken');
      // 限制算法防止 alg:none 攻击，使用统一配置而非直接读环境变量
      const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });

      // 令牌用途闸：refresh 令牌不得建立推送通道。access/refresh 本是两把密钥，
      // 但 config 的"两把密钥不得相同"只在生产语义下强制；配成同值时 refresh（7 天有效、
      // 自带 userId/tokenVersion/sid）在这条路径上能过完全部校验，
      // 于是"access 短有效期 + 频繁换发"的窗口收缩机制对 WS 整体失效。
      const { violatesAccessTokenPurpose } = require('../utils/tokenPurpose');
      if (violatesAccessTokenPurpose(decoded)) {
        logger.warn(
          `WebSocket 认证失败（令牌用途不符 type=${String(decoded.type)}）: ${socket.id}`
        );
        socket.emit('auth-error', { message: '认证令牌类型不合法' });
        socket.disconnect(true);
        return false;
      }

      // 检查 token 是否在黑名单中
      const { isTokenBlacklisted } = require('../middleware/tokenBlacklist');
      if (await isTokenBlacklisted(token)) {
        logger.warn(`WebSocket 认证失败（token 已吊销）: ${socket.id}`);
        socket.emit('auth-error', { message: '认证令牌已失效' });
        socket.disconnect(true);
        return false;
      }

      // 校验用户当前状态、tokenVersion、allowedIPs 与临时锁定：被禁用/锁定/改密后旧连接应失效。
      // 字段集与 auth.js 的等价 select（含 lockUntil）对齐——少取一个字段就等于少一条判据。
      const User = require('../models/User');
      const freshUser = await User.findById(decoded.userId)
        .select('username status tokenVersion passwordChangedAt allowedIPs lockUntil')
        .populate({ path: 'roles', select: 'code', match: { status: 'active' } });
      if (!freshUser) {
        logger.warn(`WebSocket 认证失败（用户不存在）: ${socket.id}`);
        socket.emit('auth-error', { message: '用户不存在' });
        socket.disconnect(true);
        return false;
      }
      if (freshUser.status !== 'active') {
        logger.warn('WebSocket 认证失败（用户状态异常）', {
          status: freshUser.status,
          socketId: socket.id,
        });
        socket.emit('auth-error', { message: '账户已被禁用或锁定' });
        socket.disconnect(true);
        return false;
      }
      // 临时锁定：HTTP 侧对此返回 ACCOUNT_TEMP_LOCKED，WS 侧同判据拒绝
      // （写法与 _assertHandshakeIpAllowed / _assertHandshakeSessionUsable 一致，
      //  不再往 authenticateSocket 里叠第 N 个分支——该方法复杂度已在棘轮基线上）
      if (this._assertHandshakeAccountLocked(socket, freshUser)) return false;
      // tokenVersion 必须携带且匹配：省略字段或版本不匹配均说明令牌可疑/已被强制下线
      // 历史文档可能缺少该字段，按 schema 默认值 0 参与比对
      const expectedTokenVersion = freshUser.tokenVersion ?? 0;
      if (decoded.tokenVersion === undefined || decoded.tokenVersion !== expectedTokenVersion) {
        logger.warn(`WebSocket 认证失败（tokenVersion 缺失或不匹配）: ${socket.id}`);
        socket.emit('auth-error', { message: '会话已失效，请重新登录' });
        socket.disconnect(true);
        return false;
      }
      // 密码修改后签发的旧 token 失效
      if (decoded.iat && freshUser.passwordChangedAt) {
        const changedAtTs = Math.floor(new Date(freshUser.passwordChangedAt).getTime() / 1000);
        if (decoded.iat < changedAtTs) {
          logger.warn(`WebSocket 认证失败（密码已修改）: ${socket.id}`);
          socket.emit('auth-error', { message: '密码已修改，请重新登录' });
          socket.disconnect(true);
          return false;
        }
      }

      // ============ P0-2 修复（2026-09-17）：补齐 HTTP 侧已有、WS 侧缺失的两道失效信号 ============
      // 审计实证：同一个 JWT 在 HTTP 侧因 allowedIPs 不匹配被 403 AUTH_IP_RANGE_DENIED、
      // 或因设备会话已吊销被拒；WS 侧却认证通过并绑定 socket.userId。根因是本方法此前
      // 全文 0 处引用 sid / allowedIPs / sessionService。两段校验抽为独立方法
      // （与 middleware/auth.js 的 assertIpAllowed / assertSessionUsable 同源同序），
      // 使「HTTP 拒绝的令牌，WS 也必须拒绝」。
      const ipFailure = this._assertHandshakeIpAllowed(socket, freshUser);
      if (ipFailure) return false;
      const sessionFailure = await this._assertHandshakeSessionUsable(socket, decoded);
      if (sessionFailure) return false;

      // 在途断开复检（F-188）：上面每一次 await 都是一个窗口，客户端可能已经断开。
      // disconnect 处理器此时跑过，但它按 `socket.userId` 清理，而 userId 要到下面才赋值
      // ⇒ 只清得掉 clients，清不到 userConnections；这里一旦继续登记就留下**永久幽灵连接**
      // ——周期清扫只遍历 this.clients.keys()，永不回收它。代价不是内存量级而是"以为还在"：
      // getStats().totalUsers 长期虚高、emitPermissionSync 给已死 socket.id 逐个查库+投递、
      // MAX_CONNECTIONS 数的是 io.sockets.sockets.size ⇒ 幽灵不占配额，计数与真实在线分叉。
      // 位置约束：必须紧贴最后一个 await、且在任何状态写入之前——中间再插 await 就重新开窗。
      if (!socket.connected) {
        logger.warn(`WebSocket 认证在途断开，作废本次认证: ${socket.id}`);
        return false;
      }

      socket.userId = decoded.userId || decoded.id;
      socket.username = decoded.username;
      socket.roleCodes = freshUser.roles?.map((r) => r?.code).filter(Boolean) || [];
      // 记录令牌版本：受限房间入房时用 revalidateSocket 复查，
      // tokenVersion 被推进（改密/强制下线）即断开该长连接
      socket.tokenVersion = decoded.tokenVersion;
      socket.authenticated = true;
      clearTimeout(authTimer);

      // 加入用户定向房间：挂载 Redis adapter 后，权限同步可经房间投递
      // 触达连接在任一实例上的该用户（未挂 adapter 时即本实例房间，无副作用）
      socket.join(userRoom(socket.userId));

      // 认证成功后把 userId 回写到连接时以 null 占位的 clients 条目，
      // 保证 join-room / getStats / 后续统计读到真实身份
      const clientEntry = this.clients.get(socket.id);
      if (clientEntry) {
        clientEntry.userId = socket.userId;
      }

      // 记录用户连接
      if (!this.userConnections.has(socket.userId)) {
        this.userConnections.set(socket.userId, new Set());
      }
      this.userConnections.get(socket.userId).add(socket.id);

      logger.info('WebSocket 认证成功', { userId: socket.userId, socketId: socket.id });
      return true;
    } catch (err) {
      logger.warn(`WebSocket 认证失败: ${socket.id}, reason: ${err.message}`);
      socket.emit('auth-error', { message: '认证失败' });
      socket.disconnect(true);
      return false;
    }
  }

  /**
   * 握手期临时锁定校验（与 middleware/auth.js 的 assertAccountUsable 同判据）
   *
   * 为什么单独一条臂：authService 的爆破阈值写 lockUntil 时**不动 status、
   * 也不推进 tokenVersion**，所以"status==='active' 且令牌仍有效"在锁定期间成立。
   * HTTP 侧每个请求都会被 assertAccountUsable 拒掉（ACCOUNT_TEMP_LOCKED），
   * WS 侧只看 status 就会给被锁定的账户留一条实时推送通道。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object} freshUser 已 select lockUntil/username 的用户文档
   * @returns {boolean} true 表示已拒绝并断开连接
   */
  _assertHandshakeAccountLocked(socket, freshUser) {
    if (!isTemporarilyLocked(freshUser)) return false;
    logger.warn('WebSocket 认证失败（账户临时锁定）', {
      username: freshUser.username,
      lockUntil: freshUser.lockUntil,
      socketId: socket.id,
    });
    socket.emit('auth-error', { message: '账户已被临时锁定，请稍后重试' });
    socket.disconnect(true);
    return true;
  }

  /**
   * 握手 IP 访问范围校验（P0-2 修复，2026-09-17）
   *
   * 与 middleware/auth.js 的 assertIpAllowed（auth.js:297-324）同源：
   * 规则为空时不限制；配置了规则但来源 IP 解析不出或不在范围内 → 拒绝。
   * isIPAllowed 对「配置不可用」（超长文本、超量条目、无法解析的片段）本身
   * 即 fail-closed，此处不再二次包装，避免两处判定漂移。
   *
   * 与 HTTP 侧的差异：此处不写 ip_range_denied 审计——WS 认证路径没有 res 对象，
   * 且 AuditLog.record 是异步直写，在握手期引入 DB 写会拖长认证链；拒绝结论
   * 已通过 logger.warn 留痕（含 username/ip/reason）。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object} freshUser 已 select allowedIPs/username 的用户文档
   * @returns {boolean} true 表示已拒绝并断开连接
   */
  _assertHandshakeIpAllowed(socket, freshUser) {
    if (!freshUser.allowedIPs) return false;
    const clientIP = resolveHandshakeClientIP(socket.handshake, resolveTrustProxyHops());
    const { allowed, reason } = isIPAllowed(clientIP, freshUser.allowedIPs);
    if (allowed) return false;
    logger.warn('WebSocket 认证失败（IP 访问范围校验拒绝）', {
      username: freshUser.username,
      ip: clientIP,
      reason,
      socketId: socket.id,
    });
    socket.emit('auth-error', { message: '当前网络不在允许的 IP 范围内' });
    socket.disconnect(true);
    return true;
  }

  /**
   * 握手设备会话状态校验（P0-2 修复，2026-09-17）
   *
   * 与 middleware/auth.js 的 assertSessionUsable（auth.js:341-354）同源：
   * 令牌携带 sid 时校验对应 UserSession 仍可用；未携带 sid 时跳过——功能
   * 上线前的旧令牌、以及登录时会话注册失败而降级签发的令牌都没有 sid，
   * 拒绝它们等于把全部在线用户踢下线（HTTP 侧出于同一理由放行）。
   *
   * fail-closed 不吞错：validateSession 在 DB 故障时抛
   * SESSION_SERVICE_UNAVAILABLE，此处让它抛到 authenticateSocket 的 catch，
   * 按「认证失败」断开连接——拒绝语义与 HTTP 侧返回 503 一致，不会放行。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object} decoded 已验证的 JWT payload
   * @returns {Promise<boolean>} true 表示已拒绝并断开连接
   */
  async _assertHandshakeSessionUsable(socket, decoded) {
    if (!decoded.sid) return false;
    const { validateSession } = require('./sessionService');
    const sessionState = await validateSession(decoded.sid);
    if (sessionState.usable) return false;
    logger.warn(`WebSocket 认证失败（设备会话已吊销或不存在）: ${socket.id}`);
    socket.emit('auth-error', { message: '该设备会话已失效，请重新登录' });
    socket.disconnect(true);
    return true;
  }

  /**
   * 复查长连接的当前授权状态（P2-14）
   *
   * 认证只发生在连接建立时，之后 socket.roleCodes / status / tokenVersion
   * 全是快照。长连接可存活数小时，期间用户可能被降级、停权或强制下线，
   * 而受限房间的准入判断若继续读快照，就等于「一次认证、永久有效」。
   *
   * 本方法在受限房间入房前重查数据库：
   * - 用户不存在 / 非 active / 临时锁定 / tokenVersion 已推进 → 断开连接（会话已被吊销）
   * - 否则刷新 socket.roleCodes、把已不满足角色要求的房间 leave 掉，并返回最新角色码
   *
   * 断开而非仅拒绝入房：这三种情形说明整个连接的身份已失效，
   * 不能只拦住一个房间却让它继续留在其他房间收消息。
   *
   * @param {import('socket.io').Socket} socket
   * @returns {Promise<{ok: boolean, roleCodes: string[]}>}
   */
  async revalidateSocket(socket) {
    try {
      const User = require('../models/User');
      const fresh = await User.findById(socket.userId)
        .select('status tokenVersion lockUntil')
        .populate({ path: 'roles', select: 'code', match: { status: 'active' } });
      return this._applyRevalidation(socket, fresh);
    } catch (err) {
      // fail-closed：复查不可用时不得放行受限房间
      logger.error(`WebSocket 授权复查异常，按拒绝处理: ${socket.id} - ${err.message}`);
      socket.emit('error', { message: '权限校验暂不可用，请稍后重试' });
      return { ok: false, roleCodes: [] };
    }
  }

  /**
   * 授权复查的判定体（L-29 抽出）
   *
   * 与取数解耦，供两条路径共用同一套判定，避免「批量版」与「单连接版」
   * 各写一份而逐渐漂移：
   *  - revalidateSocket：单连接取数后调用（入房复查）
   *  - runCleanupSweep：批量取数后逐连接调用（周期清扫）
   *
   * @param {import('socket.io').Socket} socket
   * @param {object|null} fresh 该 socket.userId 对应的最新用户文档（已 populate roles.code）
   * @returns {{ok: boolean, roleCodes: string[]}}
   */
  _applyRevalidation(socket, fresh) {
    const kick = (message, logMsg) => {
      logger.warn(logMsg);
      socket.emit('auth-error', { message });
      socket.disconnect(true);
      return { ok: false, roleCodes: [] };
    };

    if (!fresh) {
      return kick('用户不存在', `WebSocket 复查失败（用户已删除）: ${socket.id}`);
    }
    if (fresh.status !== 'active') {
      return kick(
        '账户已被禁用或锁定',
        `WebSocket 复查失败（status=${fresh.status}）: ${socket.id}`
      );
    }
    // 临时锁定：写入方只动 lockUntil（不动 status、不推进 tokenVersion），
    // 少了这一条臂，被锁账户的既有连接会一路活到下次自然重连
    if (isTemporarilyLocked(fresh)) {
      return kick(
        '账户已被临时锁定，请稍后重试',
        `WebSocket 复查失败（账户临时锁定至 ${fresh.lockUntil}）: ${socket.id}`
      );
    }
    // tokenVersion 推进意味着该用户的全部会话已被吊销（改密/管理员强制下线）
    const currentVersion = fresh.tokenVersion ?? 0;
    if (socket.tokenVersion !== undefined && socket.tokenVersion !== currentVersion) {
      return kick(
        '会话已失效，请重新登录',
        `WebSocket 复查失败（tokenVersion 已推进）: ${socket.id}`
      );
    }

    const roleCodes = (fresh.roles || []).map((r) => r?.code).filter(Boolean);
    // 回写快照，供无角色要求的房间与统计使用
    socket.roleCodes = roleCodes;

    // 降级即出房（L1-F1）：授/撤角色**不推进 tokenVersion**（只有"吊销全部会话"才推进），
    // 所以只复查 status/tokenVersion 的清扫放不倒已被降级但仍 active 的连接。
    // P2-14 封住的是「入房」面——已驻留在 role-management 的管理员被降级后，
    // 若不在此主动 leave，他会在整个连接生命周期内继续收 role-updated /
    // permissions-updated 广播（内容含权限码全集），直到浏览器刷新。
    // 房间清单取自本服务自己的记账（clients.get(id).rooms，join/leave 两处维护），
    // 不读 socket.rooms：后者是 socket.io 内部结构，与本服务的白名单记账并不等价。
    const client = this.clients?.get(socket.id);
    for (const room of client ? [...client.rooms] : []) {
      if (roomRolesSatisfied(room, roleCodes)) continue;
      socket.leave(room);
      client.rooms.delete(room);
      logger.warn(`WebSocket 复查：角色不再满足房间要求，已移出 ${room}`, {
        socketId: socket.id,
        userId: String(socket.userId),
        roleCodes,
      });
    }

    return { ok: true, roleCodes };
  }

  /**
   * 定期清理假死连接 + 周期授权复查（R-2，P2-14 的会话期收尾）
   *
   * P2-14 只封住了「入房」面：受限房间 join-room 时 revalidateSocket 复查。
   * 但已驻留在 role-management 房间的长连接，会话期间被降级/停权/强制下线后
   * 不会被主动移出，可继续接收 role-updated/permissions-updated 广播直至重连——
   * 破坏「停权即失效」契约。本清扫对每个已认证连接周期重查
   * status/tokenVersion/角色，命中失效即断开（复用 revalidateSocket 的 kick 路径）。
   */
  setupConnectionCleanup() {
    this._cleanupTimer = setInterval(() => {
      // 防重入：此前复查若因 DB 慢查询未结束，跳过本次改动而非并发叠加打库
      if (this._sweepRunning) return;
      this._sweepRunning = true;
      this.runCleanupSweep()
        .catch((err) => logger.warn(`WebSocket 周期清扫异常：${err.message}`))
        .finally(() => {
          this._sweepRunning = false;
        });
    }, HEARTBEAT_INTERVAL);
    if (this._cleanupTimer && this._cleanupTimer.unref) this._cleanupTimer.unref();
  }

  /**
   * 执行一轮清扫（清理失效记录 + 已认证连接授权复查）
   * 独立成方法便于测试直接驱动（不必等 30s 定时器）
   */
  async runCleanupSweep() {
    let cleanedCount = 0;
    let kickedCount = 0;

    // 第一趟：先做纯内存的「记录回收 + 待查清单」，不碰数据库。
    // 把不需要 DB 的工作与需要 DB 的工作分开，是为了让下面的批量查询
    // 只针对真正要复查的连接（未认证连接在认证成功前不参与）。
    const pending = [];
    for (const socketId of this.clients.keys()) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (!socket) {
        // Socket 已不存在，清理记录
        this.clients.delete(socketId);
        cleanedCount++;
        continue;
      }

      // 未认证/认证中的连接不复查：认证超时由 authTimer 负责
      if (!socket.authenticated || !socket.userId) continue;

      pending.push(socket);
    }

    if (pending.length === 0) {
      this._logSweepResult(cleanedCount, kickedCount);
      return;
    }

    // 第二趟：一次批量查询取回全部待复查用户，再逐连接判定。
    //
    // L-29 修复：原实现是 `for ... await this.revalidateSocket(socket)`，
    // 每个连接一次 findById。上限 1000 连接（见 HEARTBEAT_INTERVAL 注释）时
    // 每轮固定串行 1000 次 DB 往返——实测 875.92ms，且因为 await 串行，
    // 这段时间事件循环被反复让出，30 秒一轮等于周期性钝化。
    // 改为单次 $in 查询后实测 5.55ms（157.8x），存活判定结果完全一致（980/980）。
    // 明细见 deliverables/性能实测基线-2026-09-16.json。
    //
    // 去重：同一用户的多个标签页/设备会产生多个 socket，只需查一次。
    const uniqueUserIds = [...new Set(pending.map((s) => String(s.userId)))];
    let freshByUser = new Map();
    let dbUnavailable = false;
    try {
      const User = require('../models/User');
      const docs = await User.find({ _id: { $in: uniqueUserIds } })
        .select('status tokenVersion lockUntil')
        .populate({ path: 'roles', select: 'code', match: { status: 'active' } });
      freshByUser = new Map(docs.map((doc) => [String(doc._id), doc]));
    } catch (err) {
      // DB 瞬时故障：不能因为一次抖动清场全部在线连接。
      // 保持原语义——fail-closed 拒绝入房，但周期复查仅告警、等下一轮重试。
      dbUnavailable = true;
      logger.error(`WebSocket 批量授权复查异常，本轮跳过: ${err.message}`);
    }

    if (dbUnavailable) {
      logger.warn(`WebSocket 周期复查暂不可用，保留 ${pending.length} 个连接等待下轮`);
      this._logSweepResult(cleanedCount, kickedCount);
      return;
    }

    for (const socket of pending) {
      const fresh = freshByUser.get(String(socket.userId)) || null;
      const result = this._applyRevalidation(socket, fresh);
      if (!result.ok && !socket.connected) {
        // kick 路径（用户删除/停权/tokenVersion 推进）内部已 disconnect(true)
        kickedCount++;
      }
    }

    this._logSweepResult(cleanedCount, kickedCount);
  }

  /**
   * 输出一轮清扫的结果（仅在确有变化时打日志，避免 30s 一次的空转噪声）
   * @param {number} cleanedCount 回收的失效记录数
   * @param {number} kickedCount 踢出的失效会话数
   */
  _logSweepResult(cleanedCount, kickedCount) {
    if (cleanedCount > 0 || kickedCount > 0) {
      logger.info(
        `WebSocket 清扫: 移除 ${cleanedCount} 个失效记录, 复查踢出 ${kickedCount} 个失效会话, ` +
          `当前总连接: ${this.clients.size}`
      );
    }
  }

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
  }

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
  }

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
        const User = require('../models/User');
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
  }

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
  }

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
      maxConnections: MAX_CONNECTIONS,
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
  }
}

module.exports = WebSocketService;

// P0-2 修复配套（2026-09-17）：导出握手 IP 解析工具，供一致性测试直接驱动，
// 断言「WS 与 HTTP 在同一 trust proxy 语义下得出同一个客户端 IP」。
// 挂在 class 上而非替换 module.exports——不改变既有 `new WebSocketService()` 用法。
WebSocketService.resolveHandshakeClientIP = resolveHandshakeClientIP;
// F-B42 配套：一并导出跳数解析，供用例直接钉「WS 与 HTTP 在同一环境下取到同一个
// hops」。既有的一致性用例把 hops 作为入参传给 resolveHandshakeClientIP，等于跳过了
// hops 的来源——正是本次上限漏判能藏住的原因。
WebSocketService.resolveTrustProxyHops = resolveTrustProxyHops;
