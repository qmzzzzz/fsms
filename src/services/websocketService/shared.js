/**
 * WebSocket 连接管理共享原语
 *
 * 常量、房间白名单与纯谓词：无外部依赖，供 handshake / lifecycle / push 与门面 index.js 共用。对外导出面仍由 index.js 的 WebSocketService 承担，本模块不是公开 API。
 *
 * 纯数据与谓词收在这里（常量、房间白名单、纯谓词，无外部依赖），供 handshake / lifecycle / push 与门面 index.js 共用，避免循环依赖。
 */

// 连接管理常量

/**
 * 单**进程**的在线连接上限
 *
 * 原名 `MAX_CONNECTIONS`，读起来像"整个系统的连接上限"，实际数的是 `io.sockets.sockets.size`——本进程的 Socket.IO 连接数。多副本部署下每个实例各自都能到 1000，**整体没有统一上限**：
 *
 *     可承载连接总数 ≈ 实例数 × 本常量
 *
 * 改名不是洁癖：容量规划与告警阈值都按这个名字读，`MAX_CONNECTIONS=1000` 会让 Ingress/LB 的 `MaxConnections` 被照着设成 1000，而真实可用量是 3000。
 * 反向代理侧的总配额必须按乘积设置（见 docs/multi-instance-consistency.md §五）。
 *
 * 若要真正的**全局**配额，需要在网关层限流或引入共享计数（Redis INCR + TTL）；当前未实现，属已知缺口而非配置项——别把这个常量当成全局上限。
 */
const MAX_CONNECTIONS_PER_PROCESS = 1000;
const HEARTBEAT_INTERVAL = 30000; // 30秒心跳检测
const HEARTBEAT_TIMEOUT = 60000; // 60秒超时断开
const AUTH_TIMEOUT = 30000; // 连接后 30 秒内必须完成认证，否则强制断开

/**
 * 单个来源 IP 允许同时持有的**未认证**连接数（#9）
 *
 * 认证超时（30s）只保证未认证连接不会永久占用名额，挡不住的是"在超时前短时间灌入大量连接"：全局上限 1000 是单进程共享的，一个来源用 1000 条未认证连接就能把本进程配额打满，已登录用户的重连全部被拒——一条低成本的拒绝服务路径，且无需任何凭据。
 *
 * 上限按「IP + 未认证」计，认证成功即释放名额：NAT/代理出口后的多个正常用户只要完成认证就不受此闸影响；真正被限制的是"同时挂着一堆还没认证的连接"这一攻击形态。取值高于单用户正常并发（多标签页/多设备）一个量级。
 *
 * 地址取 resolveHandshakeIPForSecurityDecision（与 allowedIPs/黑名单同一把安全裁决尺）：公网直连者无法用伪造 XFF 把连接拆到任意"新 IP"上绕过配额。
 */
const MAX_UNAUTHENTICATED_PER_IP = 10;

/**
 * 入站事件令牌桶（P1，2026-10-24）
 *
 * 为什么需要：连接层那三个闸（进程总连接数 / 未认证 IP 配额 / 认证超时）都数的是
 * **连接**，对"一条已认证连接里的事件频率"完全无感。而 `join-room` 在
 * `ROOM_ROLE_REQUIREMENTS` 命中时会在**角色判定之前**先调 `revalidateSocket` （一次 User 查询 + 一次 UserSession 查询，见 push.js 的 join-room 分支）——
 * 于是任何已认证用户都能把 `join-room 'role-management'` 当成免费的库查询放大器：他不需要 admin 角色，因为在拿到"无权加入"之前，查询已经付过了。一条连接每秒发几千次，就是每秒几千次库查询，而这条路径不受任何限流约束。
 *
 * 为什么是令牌桶而不是固定窗口：固定窗口在窗口边界允许 2× 突发（上一窗口末尾一次、下一窗口开头一次），而这里要挡的正是"突发"。令牌桶的突发额度由 CAPACITY 明确给定，稳态由 REFILL 明确给定，两个数都可解释。
 *
 * 取值依据（正常客户端一生只发 1 次 auth + ≤4 次 join-room，房间加入后长期保持）：
 *   · CAPACITY 20  —— 重连抖动时连发几轮也够用（每轮 5 个事件）
 *   · REFILL 2/s   —— 远高于任何正常交互；同时把"1000 条连接同时超速"的
 *                     最坏库查询量压到 2000/s 量级
 *   · MAX_VIOLATIONS 30 —— 连续 30 次被拒（约 15 秒持续超速）才断开；
 *                     计数在成功消费一次后归零，所以偶发超速不会累积到断开
 */
const WS_INBOUND_BUCKET_CAPACITY = 20;
const WS_INBOUND_REFILL_PER_SEC = 2;
const WS_INBOUND_MAX_VIOLATIONS = 30;

/**
 * 账户是否处于「临时锁定」中（暴力破解阈值写入，10 分钟后自动失效）。
 *
 * 判据与 HTTP 侧同源：`src/middleware/auth.js` 的 `assertAccountUsable` 用 `lockUntil && lockUntil > new Date()` 返回 ACCOUNT_TEMP_LOCKED；
 * `authService.loginUser` 用同一判据拒绝登录。而写入方（authService 的失败计数）
 * **只写 lockUntil，不动 status、也不推进 tokenVersion**，所以
 * 「status==='active' 且已有 access 令牌」在临时锁定期间依然成立—— HTTP 面拒绝的令牌，若 WS 面只看 status 就会放行，等于给被锁定的账户留了一条实时推送通道（含 role-management 广播）。
 * @param {object} user 需已 select lockUntil
 * @returns {boolean}
 */
const isTemporarilyLocked = (user) => Boolean(user?.lockUntil) && user.lockUntil > new Date();

/**
 * 用户定向房间名（服务端内部房间，不经客户端 join 白名单）。挂载 Redis adapter 后，向该房间投递即可触达连接在**任一实例**上的该用户连接——跨实例权限同步的落点（R-3/收尾）。
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
 * 抽成一处而非两处各写 `requiredRoles.some(...)`：入房判定与复查后的清房判定必须是同一个谓词，否则会出现"入得来、却被清扫逻辑按另一套标准赶出去"（或反之）。
 * @param {string} room 房间名（须在 ROOM_ROLE_REQUIREMENTS 内）
 * @param {string[]} roleCodes 该连接当前生效的角色码
 * @returns {boolean}
 */
const roomRolesSatisfied = (room, roleCodes) => {
  const requiredRoles = ROOM_ROLE_REQUIREMENTS[room];
  if (!requiredRoles) return true;
  return requiredRoles.some((r) => roleCodes.includes(r));
};

module.exports = {
  MAX_CONNECTIONS_PER_PROCESS,
  MAX_UNAUTHENTICATED_PER_IP,
  HEARTBEAT_INTERVAL,
  HEARTBEAT_TIMEOUT,
  AUTH_TIMEOUT,
  WS_INBOUND_BUCKET_CAPACITY,
  WS_INBOUND_REFILL_PER_SEC,
  WS_INBOUND_MAX_VIOLATIONS,
  isTemporarilyLocked,
  userRoom,
  ALLOWED_ROOMS,
  ROOM_ROLE_REQUIREMENTS,
  roomRolesSatisfied,
};
