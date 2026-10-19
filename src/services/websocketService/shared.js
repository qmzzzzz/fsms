/**
 * WebSocket 连接管理共享原语（2026-10-18 自 services/websocketService.js 拆出）
 *
 * 常量、房间白名单与纯谓词：无外部依赖，供 handshake / lifecycle / push 与
 * 门面 index.js 共用。对外导出面仍由 index.js 的 WebSocketService 承担，
 * 本模块不是公开 API。
 *
 * 拆分动机：原文件 ESLint 计 739 代码行（max-lines 300），按「握手认证 /
 * 连接生命周期 / 事件分发」切三块，纯数据与谓词收在这里避免循环依赖。
 */

// 连接管理常量

/**
 * 单**进程**的在线连接上限（F-13，2026-10-17 改名）
 *
 * 原名 `MAX_CONNECTIONS`，读起来像"整个系统的连接上限"，实际数的是
 * `io.sockets.sockets.size`——本进程的 Socket.IO 连接数。多副本部署下
 * 每个实例各自都能到 1000，**整体没有统一上限**：
 *
 *     可承载连接总数 ≈ 实例数 × 本常量
 *
 * 改名不是洁癖：容量规划与告警阈值都按这个名字读，`MAX_CONNECTIONS=1000`
 * 会让 Ingress/LB 的 `MaxConnections` 被照着设成 1000，而真实可用量是 3000。
 * 反向代理侧的总配额必须按乘积设置（见 docs/multi-instance-consistency.md §五）。
 *
 * 若要真正的**全局**配额，需要在网关层限流或引入共享计数（Redis INCR + TTL）；
 * 当前未实现，属已知缺口而非配置项——别把这个常量当成全局上限。
 */
const MAX_CONNECTIONS_PER_PROCESS = 1000;
const HEARTBEAT_INTERVAL = 30000; // 30秒心跳检测
const HEARTBEAT_TIMEOUT = 60000; // 60秒超时断开
const AUTH_TIMEOUT = 30000; // 连接后 30 秒内必须完成认证，否则强制断开

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

module.exports = {
  MAX_CONNECTIONS_PER_PROCESS,
  HEARTBEAT_INTERVAL,
  HEARTBEAT_TIMEOUT,
  AUTH_TIMEOUT,
  isTemporarilyLocked,
  userRoom,
  ALLOWED_ROOMS,
  ROOM_ROLE_REQUIREMENTS,
  roomRolesSatisfied,
};
