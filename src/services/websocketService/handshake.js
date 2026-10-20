/**
 * WebSocket 握手认证（2026-10-18 自 services/websocketService.js 拆出）
 *
 * 握手取址（resolveHandshakeClientIP / resolveHandshakeIPForSecurityDecision /
 * resolveTrustProxyHops）、令牌提取与整条 authenticateSocket 校验链（含 _assert*
 * 家族与身份绑定）。方法是 mixin 形态：由 index.js 挂到 WebSocketService.prototype，
 * 对外只有门面可见（方法保持原样，`this` 语义不变）。
 *
 * 交叉引用：ip 白名单/封禁判据与 HTTP 侧同源，见 middleware/security/ipBlacklist.js；
 * skip 位置约束（在途断开复检）由 websocketAuthGhostConnection 测试按文本位置钉住。
 */

const logger = require('../../utils/logger');
const config = require('../../config');
const {
  MAX_TRUST_PROXY_HOPS,
  resolveTrustProxyHops: resolveTrustProxyHopsFromConfig,
} = require('../../config/validate');
const { parseCookies, ACCESS_COOKIE_NAME } = require('../../utils/cookie');
const { isIPAllowed } = require('../../utils/ipRange');
const { isPeerTrustedProxy } = require('../../utils/ipUtils');
const trustedProxies = require('../../config/trustedProxies');
const { isTemporarilyLocked, userRoom } = require('./shared');

/**
 * 解析握手来源 IP（修复，2026-09-17）
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
 * 安全裁决用的握手客户端 IP（F-B43，2026-10-01 第 5 轮）
 *
 * 缺陷形状（并行审计发现，独立复现成立）：HTTP 侧的 allowedIPs 判定在 auth.js 改用了
 * `utils/ipUtils.js` 的 `clientIpForSecurityDecision`——可信边界内取 req.ip，边界外
 * 退回**不可伪造的 socket 对端**；而 WS 侧仍直接用 `resolveHandshakeClientIP`
 * （= express 的 req.ip）。于是同一条伪造 XFF 在两侧得出相反结论：HTTP 拒、WS 放行，
 * 持有效令牌但真实地址不在允许范围内的人仍能从 WS 面进入 alarm / device-alert /
 * role-management 房间。把一个"两侧同样弱"的均匀缺陷修成"HTTP 强、WS 弱"的不均匀
 * 缺陷，比不修更危险——它会让读侧的收紧看起来已完成。
 *
 * 本函数不是新判据：它把 ipUtils 那把尺的三个输入换成 handshake 形态的同源值，
 * 逐条对应 HTTP 侧 `isClientIpIdentityTrustworthy` 的三种可信形态：
 *   trustProxyEnabled  ⇔  `req.app.get('trust proxy')`（WS 面的同一配置来源是
 *                          TRUST_PROXY_HOPS，hops>0 即开；见 resolveTrustProxyHops）
 *   xffPresent         ⇔  `req.get('x-forwarded-for') !== undefined`
 *                          （用 === undefined 而非真值判断：**存在但为空**的头在
 *                          express 里同样算"携带 XFF"，会走对端核查那一臂）
 *   isPeerTrustedProxy(peer, proxies) ⇔ 同一函数、同一份名单
 *
 * **F-01 收尾（2026-10-18）：第三臂不能只判私网。** 原实现写死
 * `isPrivateOrLoopback(peer)`，与 HTTP 侧「配了 TRUSTED_PROXY_CIDRS 就以名单为准」
 * 的收紧脱钩——HTTP 面把「私网但不在名单内」判成不可信，WS 面仍判可信，于是同一个
 * 伪造 XFF 在两侧再次得出相反结论。这正是本函数开头点名的「把均匀缺陷修成
 * 不均匀缺陷，比不修更危险」的复发形态，只是这次分界线从 HTTP/WS 换成了
 * 「HTTP 已收紧 / WS 没跟上」。现在三处（HTTP 准入、封禁分类、WS 握手）共用
 * `utils/ipUtils.isPeerTrustedProxy`，名单来源是 `config/trustedProxies`
 * 的同一份解析结果（与 app.js 注入 `app.set('trusted proxy cidrs', …)` 的是同一个对象）。
 * 未配置时退回私网/回环，行为与修复前逐字一致（兼容档）。
 * 退回侧的 `peer || declared` 也与 HTTP 的 `peer || req.ip` 同序，取不到对端时
 * 保持既有形态（不让夹具/替身把裁决变成空地址）。
 *
 * 一致性用例见 src/tests/services/websocketAllowedIpTrustBoundary.test.js：
 * 那里把**同一份输入**同时喂给 clientIpForSecurityDecision 与本函数，四种形态逐一
 * 比对。`resolveHandshakeClientIP` 与真实 express 的等价性已由
 * websocketAuthScope.test.js 用真实 HTTP 请求钉住，故本函数不再重复那一层。
 *
 * 封禁（黑名单）判定自 2026-10-10 #24 R1 起也走本函数：HTTP 侧 checkIPBlacklist 改用
 * clientIpForSecurityDecision（security.js:685），WS 封禁闸随之改用本函数——两侧仍同址，
 * 且同取安全裁决尺，由 websocketHandshakeIpBan.test.js / websocketAllowedIpTrustBoundary.test.js 钉。
 *
 * @param {object} handshake socket.handshake
 * @param {number} hops 信任的代理跳数（来自 resolveTrustProxyHops）
 * @returns {string|null} 可用作准入裁决的客户端地址；无任何可用地址时返回 null
 */
const resolveHandshakeIPForSecurityDecision = (handshake, hops) => {
  const declared = resolveHandshakeClientIP(handshake, hops);
  const peer = handshake?.address || '';
  const trustProxyEnabled = Number.isInteger(hops) && hops > 0;
  const xffHeader = handshake?.headers?.['x-forwarded-for'];
  // 边界判据与 HTTP 侧共用同一个函数（F-01 收尾，理由见上方 JSDoc 末段）；
  // 名单只在真需要判第三臂时才解析（前两臂已短路的情形不必碰配置）。
  const identityTrustworthy =
    !trustProxyEnabled ||
    xffHeader === undefined ||
    isPeerTrustedProxy(peer, trustedProxies.resolveTrustedProxies());
  if (identityTrustworthy) return declared || peer || null;
  return peer || declared || null;
};

/**
 * 信任的代理跳数（修复，2026-09-17；F-B42 起委托给 config/validate）
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

const methods = {
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
  },

  /**
   * 校验令牌并完成 socket 认证（握手路径与 'auth' 事件路径共用同一套校验逻辑）
   * @param {Object} socket - Socket.IO socket
   * @param {string} token - 待校验的 JWT
   * @param {number} authTimer - 认证超时计时器句柄，认证成功后清除
   */
  async authenticateSocket(socket, token, authTimer) {
    try {
      // 黑名单闸（2026-10-01 审计 D-1）：HTTP 侧 checkIPBlacklist 挂在 authenticate
      // **之前**（app.js:263），WS 侧此前全文 0 处引用 IPBlacklist ⇒ 被自动升级封禁
      // 或被人工拉黑的 IP，只要手里还有一枚未失效令牌就能建立推送通道并订阅
      // alarm / device-alert / role-management，封禁对它只关上了 HTTP 那扇门。
      // 放在令牌校验之前，与 HTTP 侧同序：被禁 IP 一律不消耗后续查库与解密开销。
      if (await this._assertHandshakeIpNotBanned(socket)) return false;

      const jwt = require('jsonwebtoken');
      // 限制算法防止 alg:none 攻击，使用统一配置而非直接读环境变量
      const decoded = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });

      if (this._assertHandshakeTokenPurpose(socket, decoded)) return false;
      if (await this._assertHandshakeTokenNotRevoked(socket, token)) return false;

      // 校验用户当前状态、tokenVersion、allowedIPs 与临时锁定：被禁用/锁定/改密后旧连接应失效。
      // 字段集与 auth.js 的等价 select（含 lockUntil）对齐——少取一个字段就等于少一条判据。
      const User = require('../../models/User');
      const freshUser = await User.findById(decoded.userId)
        .select('username status tokenVersion passwordChangedAt allowedIPs lockUntil')
        .populate({ path: 'roles', select: 'code', match: { status: 'active' } });
      if (this._assertHandshakeUserExists(socket, freshUser)) return false;
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
      if (this._assertHandshakeTokenVersion(socket, freshUser, decoded)) return false;
      if (this._assertHandshakePasswordFresh(socket, freshUser, decoded)) return false;

      // ============ 修复：补齐 HTTP 侧已有、WS 侧缺失的两道失效信号 ============
      // 审计实证：同一个 JWT 在 HTTP 侧因 allowedIPs 不匹配被 403 AUTH_IP_RANGE_DENIED、
      // 或因设备会话已吊销被拒；WS 侧却认证通过并绑定 socket.userId。根因是本方法此前
      // 全文 0 处引用 sid / allowedIPs / sessionService。两段校验抽为独立方法
      // （与 middleware/auth.js 的 assertIpAllowed / assertSessionUsable 同源同序），
      // 使「HTTP 拒绝的令牌，WS 也必须拒绝」。
      if (this._assertHandshakeIpAllowed(socket, freshUser)) return false;
      if (await this._assertHandshakeSessionUsable(socket, decoded)) return false;

      // 在途断开复检（F-188）：上面每一次 await 都是一个窗口，客户端可能已经断开。
      // disconnect 处理器此时跑过，但它按 `socket.userId` 清理，而 userId 要到下面才赋值
      // ⇒ 只清得掉 clients，清不到 userConnections；这里一旦继续登记就留下**永久幽灵连接**
      // ——周期清扫只遍历 this.clients.keys()，永不回收它。代价不是内存量级而是"以为还在"：
      // getStats().totalUsers 长期虚高、emitPermissionSync 给已死 socket.id 逐个查库+投递、
      // MAX_CONNECTIONS_PER_PROCESS 数的是 io.sockets.sockets.size ⇒ 幽灵不占配额，计数与真实在线分叉。
      // 位置约束：必须紧贴最后一个 await、且在任何状态写入之前——中间再插 await 就重新开窗。
      // 不抽成 _assert* 方法：websocketAuthGhostConnection 的接线闸按**文本位置**钉这两件事
      // （复检在最后一个 await 之后、this.userConnections 之前），抽走就只剩一句注释承诺。
      if (!socket.connected) {
        logger.warn(`WebSocket 认证在途断开，作废本次认证: ${socket.id}`);
        return false;
      }

      this._bindHandshakeIdentity(socket, decoded, freshUser);
      clearTimeout(authTimer);

      // 加入用户定向房间：挂载 Redis adapter 后，权限同步可经房间投递
      // 触达连接在任一实例上的该用户（未挂 adapter 时即本实例房间，无副作用）
      socket.join(userRoom(socket.userId));

      // 认证成功后把 userId 回写到连接时以 null 占位的 clients 条目，
      // 保证 join-room / getStats / 后续统计读到真实身份
      this._syncClientEntryUserId(socket);

      // 记录用户连接
      // 这一段**必须**留在本方法体内：websocketAuthGhostConnection 的接线闸按文本位置钉
      // 「复检在最后一个 await 之后、this.userConnections 之前」，搬进方法里那条判据就失效
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
  },

  /**
   * 把已认证的 userId 回写到 clients 条目（连接建立时该字段以 null 占位）。
   *
   * 与 userConnections 的登记分开：后者必须留在 authenticateSocket 体内（见那里的注释），
   * 前者只是一次字段回写，抽走不影响任何位置判据。
   *
   * @param {import('socket.io').Socket} socket
   */
  _syncClientEntryUserId(socket) {
    const clientEntry = this.clients.get(socket.id);
    if (clientEntry) clientEntry.userId = socket.userId;
  },

  /**
   * 认证通过后把身份写到 socket 上（原 authenticateSocket 的赋值段）。
   *
   * 只做赋值、不做登记：userConnections 的写入仍留在 authenticateSocket 体内，
   * 因为 websocketAuthGhostConnection 的接线闸按**文本位置**钉「复检在最后一个 await 之后、
   * this.userConnections 之前」——把登记一起搬走，那条判据就退化成一句注释承诺。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object} decoded 已验证的 JWT payload
   * @param {object} freshUser 已 populate roles 的用户文档
   */
  _bindHandshakeIdentity(socket, decoded, freshUser) {
    socket.userId = decoded.userId || decoded.id;
    socket.username = decoded.username;
    socket.roleCodes = freshUser.roles?.map((r) => r?.code).filter(Boolean) || [];
    // 记录令牌版本：受限房间入房时用 revalidateSocket 复查，
    // tokenVersion 被推进（改密/强制下线）即断开该长连接
    socket.tokenVersion = decoded.tokenVersion;
    socket.authenticated = true;
  },

  /**
   * 令牌用途闸：refresh 令牌不得建立推送通道。
   *
   * access/refresh 本是两把密钥，但 config 的"两把密钥不得相同"只在生产语义下强制；
   * 配成同值时 refresh（7 天有效、自带 userId/tokenVersion/sid）在这条路径上能过完全部
   * 校验，于是"access 短有效期 + 频繁换发"的窗口收缩机制对 WS 整体失效。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object} decoded 已验证的 JWT payload
   * @returns {boolean} true 表示已拒绝并断开连接
   */
  _assertHandshakeTokenPurpose(socket, decoded) {
    const { violatesAccessTokenPurpose } = require('../../utils/tokenPurpose');
    if (!violatesAccessTokenPurpose(decoded)) return false;
    logger.warn(`WebSocket 认证失败（令牌用途不符 type=${String(decoded.type)}）: ${socket.id}`);
    socket.emit('auth-error', { message: '认证令牌类型不合法' });
    socket.disconnect(true);
    return true;
  },

  /**
   * 令牌吊销闸：access 令牌进黑名单（登出 / 强制下线）后，WS 侧同样不得再建连。
   *
   * @param {import('socket.io').Socket} socket
   * @param {string} token 待校验的 JWT 原文（黑名单按原文为键）
   * @returns {Promise<boolean>} true 表示已拒绝并断开连接
   */
  async _assertHandshakeTokenNotRevoked(socket, token) {
    const { isTokenBlacklisted } = require('../../middleware/tokenBlacklist');
    if (!(await isTokenBlacklisted(token))) return false;
    logger.warn(`WebSocket 认证失败（token 已吊销）: ${socket.id}`);
    socket.emit('auth-error', { message: '认证令牌已失效' });
    socket.disconnect(true);
    return true;
  },

  /**
   * 用户存在闸。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object|null} freshUser 按 decoded.userId 查回的用户文档
   * @returns {boolean} true 表示已拒绝并断开连接
   */
  _assertHandshakeUserExists(socket, freshUser) {
    if (freshUser) return false;
    logger.warn(`WebSocket 认证失败（用户不存在）: ${socket.id}`);
    socket.emit('auth-error', { message: '用户不存在' });
    socket.disconnect(true);
    return true;
  },

  /**
   * tokenVersion 闸：必须携带且匹配。
   *
   * 省略字段或版本不匹配均说明令牌可疑 / 已被强制下线；历史文档可能缺少该字段，
   * 按 schema 默认值 0 参与比对（与 middleware/auth.js 同口径）。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object} freshUser 已 select tokenVersion 的用户文档
   * @param {object} decoded 已验证的 JWT payload
   * @returns {boolean} true 表示已拒绝并断开连接
   */
  _assertHandshakeTokenVersion(socket, freshUser, decoded) {
    const expected = freshUser.tokenVersion ?? 0;
    if (decoded.tokenVersion !== undefined && decoded.tokenVersion === expected) return false;
    logger.warn(`WebSocket 认证失败（tokenVersion 缺失或不匹配）: ${socket.id}`);
    socket.emit('auth-error', { message: '会话已失效，请重新登录' });
    socket.disconnect(true);
    return true;
  },

  /**
   * 改密闸：签发时间早于 passwordChangedAt 的令牌失效。
   *
   * 秒级比较（与 authenticate 中间件同口径）：iat 为秒、passwordChangedAt 为毫秒，
   * 直接毫秒比较会把「改密后同一秒内签发」的令牌误判为失效。
   *
   * @param {import('socket.io').Socket} socket
   * @param {object} freshUser 已 select passwordChangedAt 的用户文档
   * @param {object} decoded 已验证的 JWT payload
   * @returns {boolean} true 表示已拒绝并断开连接
   */
  _assertHandshakePasswordFresh(socket, freshUser, decoded) {
    if (!decoded.iat || !freshUser.passwordChangedAt) return false;
    const changedAtTs = Math.floor(new Date(freshUser.passwordChangedAt).getTime() / 1000);
    if (decoded.iat >= changedAtTs) return false;
    logger.warn(`WebSocket 认证失败（密码已修改）: ${socket.id}`);
    socket.emit('auth-error', { message: '密码已修改，请重新登录' });
    socket.disconnect(true);
    return true;
  },

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
  },

  /**
   * 握手 IP 访问范围校验（修复，2026-09-17）
   *
   * 与 middleware/auth.js 的 assertIpAllowed 同源（F-B43 起包含可信边界那一半）：
   * 规则为空时不限制；配置了规则但来源 IP 解析不出或不在范围内 → 拒绝。
   * 地址取 `resolveHandshakeIPForSecurityDecision`，与 HTTP 侧的
   * `clientIpForSecurityDecision` 逐条对应——两侧若各取一种地址，收紧只生效一半。
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
    const clientIP = resolveHandshakeIPForSecurityDecision(
      socket.handshake,
      resolveTrustProxyHops()
    );
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
  },

  /**
   * 握手 IP 黑名单校验（2026-10-01 审计 D-1）
   *
   * 缺陷：`checkIPBlacklist`（middleware/security.js）是 Express 中间件，而 socket.io
   * 挂在同一个 http server 上**自成一个入口**，不经 Express 中间件链。于是 IP 一旦被
   * 分级自动封禁（securityAlert / rateLimitEscalation 那两条升级链）或被管理员手工拉黑，
   * 该地址在 HTTP 侧吃 403 IP_BLOCKED，在 WS 侧却照常建连——它仍能以手中未失效的令牌
   * 订阅 alarm / device-alert / role-management 等实时房间。封禁是"处置"，
   * 只关一半的门等于没有关。
   *
   * 判据与 HTTP 侧同源，逐条对齐：
   *  - 地址取自 resolveHandshakeIPForSecurityDecision(handshake, resolveTrustProxyHops())——
   *    与 HTTP 侧 checkIPBlacklist 同一把安全裁决尺（2026-10-10 #24 R1）：可信边界内取
   *    req.ip 等价值，边界外（公网直连+伪造 XFF）退回不可伪造的 socket 对端；底层仍复用
   *    已与真实 express 比对过的 resolveHandshakeClientIP（见 websocketAuthScope / trustProxyHopsParity）。
   *    两侧不同尺会让"HTTP 侧封的 IP"与"WS 侧查的 IP"不是同一个值，闸形同虚设。
   *  - 白名单优先：与 checkIPBlacklist 一致，命中白名单即豁免黑名单。
   *  - 取不到地址 / 名单查询抛错 ⇒ fail-open 放行，与 HTTP 侧同口径
   *    （宁可不拦，也不因一次 DB 抖动把全部实时推送踢下线）；但 fail-open 必须留
   *    显式可观测信号（评价报告 #7 的同一条纪律），故复用 HTTP 侧的
   *    ip_blacklist_failopen 计数——同一根因、同一条时间序列，不新造恒真信号。
   *
   * 已闭合的部分（2026-10-01 第 4 轮补齐）：本闸只在建立连接时生效，而 HTTP 侧是
   * 逐请求复查——一条已建立的 socket 是长连接，封禁发生在建连之后时它会存活到自然断开。
   * 该运行期面由 `runCleanupSweep` → `_sweepBannedIps` 接上（同一个 IP 推导、
   * 同一份名单快照、同一条 fail-open 口径），两侧共用 resolveHandshakeIPForSecurityDecision，
   * 不存在"握手看的地址"与"清扫看的地址"两套判据。
   *
   * @param {import('socket.io').Socket} socket
   * @returns {Promise<boolean>} true 表示已拒绝并断开连接
   */
  async _assertHandshakeIpNotBanned(socket) {
    const clientIP = resolveHandshakeIPForSecurityDecision(
      socket.handshake,
      resolveTrustProxyHops()
    );
    if (!clientIP) return false;

    const IPBlacklist = require('../../models/IPBlacklist');
    let whitelisted = false;
    let blocked = false;
    try {
      // 与 HTTP 侧同样的并行查询：两者共用模型层的名单快照，一次加载即可两次匹配
      [whitelisted, blocked] = await Promise.all([
        IPBlacklist.isWhitelisted(clientIP),
        IPBlacklist.isBlocked(clientIP),
      ]);
    } catch (err) {
      logger.error(`WebSocket 握手名单查询失败，fail-open 放行：${socket.id} ${err.message}`);
      try {
        require('../../utils/metrics').incSecurityAlert('ip_blacklist_failopen', 'high');
      } catch (_) {
        /* 指标端不可用不影响放行主流程 */
      }
      return false;
    }

    if (whitelisted || !blocked) return false;
    logger.warn('WebSocket 认证失败（IP 命中黑名单）', {
      ip: clientIP,
      socketId: socket.id,
    });
    socket.emit('auth-error', { message: '当前网络已被封禁' });
    socket.disconnect(true);
    return true;
  },

  /**
   * 握手设备会话状态校验（修复，2026-09-17）
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
    const { validateSession } = require('../sessionService');
    const sessionState = await validateSession(decoded.sid);
    if (sessionState.usable) return false;
    logger.warn(`WebSocket 认证失败（设备会话已吊销或不存在）: ${socket.id}`);
    socket.emit('auth-error', { message: '该设备会话已失效，请重新登录' });
    socket.disconnect(true);
    return true;
  },
};

module.exports = {
  methods,
  resolveHandshakeClientIP,
  resolveTrustProxyHops,
  resolveHandshakeIPForSecurityDecision,
};
