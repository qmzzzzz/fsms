/**
 * WebSocket 握手必须吃 IP 黑名单（2026-10-01 审计 D-1）
 *
 * 缺陷形状：`checkIPBlacklist` 是 Express 中间件，而 socket.io 挂在同一个 http server
 * 上**自成一个入口**，不经过 Express 中间件链。于是 IP 被分级自动封禁
 * （securityAlert / rateLimitEscalation 两条升级链）或被管理员手工拉黑之后，
 * 该地址在 HTTP 侧吃 403 IP_BLOCKED，在 WS 侧却照常建连并订阅
 * alarm / device-alert / role-management —— 处置只关了一半的门。
 *
 * 本文件锁四件事：
 *  1. 被禁地址连不上（且**在任何查库之前**就被拒，见下）；
 *  2. 未列黑的地址照常认证成功 —— 反向保护，防止把闸做成恒拒绝；
 *  3. 白名单优先与 fail-open 口径和 HTTP 侧一致：名单查询抛错时放行，
 *     但必须留下可观测信号（复用同一条 ip_blacklist_failopen 计数）；
 *  4. 封禁判定与 allowedIPs 判定用的是**同一个客户端 IP**。这条最容易漂：
 *     两处各自取址时，HTTP 侧封的、WS 侧拦的、WS 侧放行判断的会是三个值。
 *     断言按 resolveTrustProxyHops() 的实际取值分支，两种形态都必须只由
 *     "同一个 IP"解释得通（复刻判据的写法被本仓明令禁止，故这里只把 hops
 *     当入参，与 websocketAuthScope.test.js 同法）。
 */

const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

describe('WebSocket 握手 IP 黑名单闸', () => {
  let WebSocketService;
  let User;
  let Role;
  let IPBlacklist;
  let metrics;
  let roleId;
  const stamp = `wsban${String(Date.now()).slice(-8)}`;
  let counter = 0;

  // TEST-NET-3：文档用地址，不会被真实客户端命中
  const BANNED_IP = '203.0.113.9';
  const PEER_IP = '10.0.0.1';
  const entryIds = [];

  /** 造一个用户：allowedIPs 为 null 表示不限制 */
  const makeUser = async (suffix, allowedIPs) => {
    const user = await User.create({
      username: `b${suffix}_${stamp}`,
      email: `b${suffix}-${stamp}@example.com`,
      password: `P@ssw0rd-${stamp}-${suffix}`,
      roles: [roleId],
      status: 'active',
      ...(allowedIPs ? { allowedIPs } : {}),
    });
    return user;
  };

  const signToken = (user) =>
    jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        tokenVersion: user.tokenVersion ?? 0,
        jti: `jti-ban-${++counter}`,
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' }
    );

  /** 最小服务实例：认证路径只用到 clients / userConnections 两张表 */
  const makeService = () => {
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map();
    return svc;
  };

  /** 假 socket：handshake 可注入直连对端地址与 X-Forwarded-For */
  const makeSocket = (token, { address = PEER_IP, xff = null } = {}) => {
    const socket = {
      id: `wsb-sock-${++counter}`,
      handshake: {
        auth: { token },
        address,
        headers: xff ? { 'x-forwarded-for': xff } : {},
      },
      authenticated: false,
      emitted: [],
      connected: true,
      rooms: new Set(),
      emit: (ev, data) => socket.emitted.push({ ev, data }),
      disconnect: () => {
        socket.connected = false;
      },
      join: (room) => socket.rooms.add(room),
    };
    return socket;
  };

  const authErrorOf = (socket) => socket.emitted.find((e) => e.ev === 'auth-error');

  /** 落一条名单（blockIP 会同步失效模型层的名单快照，无需等 TTL） */
  const putEntry = async (ip, type, source = 'auto') => {
    const entry = await IPBlacklist.blockIP(ip, {
      reason: stamp,
      durationMs: 60000,
      source,
      type,
    });
    if (entry && entry._id) entryIds.push(entry._id);
    return entry;
  };

  /** 本用例集内所有 fail-open 计数的总和（键由 label 拼成，故按子串取） */
  const failOpenTotal = () => {
    let sum = 0;
    for (const [key, value] of metrics._alertCounters.entries()) {
      if (key.includes('ip_blacklist_failopen')) sum += Number(value) || 0;
    }
    return sum;
  };

  /**
   * WS 侧此刻实际使用的信任跳数——照 websocketService.js:84 那一行原样调用，
   * 不在本文件里另写一份判据。
   *
   * 留一个坑位说明：config/validate 导出的 `resolveTrustProxyHops(raw, nodeEnv)`
   * 返回的是 **{hops, parsed, illegal, clamped} 对象**，而 websocketService 里
   * 同名的模块内包装返回的是**数字**。`resolveTrustProxyHops()` 空调用的结果是
   * `{hops: 0, parsed: NaN, …}`，拿它写 `> 0` 会恒为 false —— 于是"按 hops 分支"的
   * 用例会静默只跑一侧。这里必须带实参取 `.hops`。
   */
  const currentHops = (raw = process.env.TRUST_PROXY_HOPS) => {
    const { resolveTrustProxyHops } = require('../../config/validate');
    return resolveTrustProxyHops(raw, require('../../config').nodeEnv).hops;
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    IPBlacklist = require('../../models/IPBlacklist');
    metrics = require('../../utils/metrics');
    WebSocketService = require('../../services/websocketService');

    const role = await Role.findOneAndUpdate(
      { code: `WSBAN_${stamp.toUpperCase()}` },
      { $setOnInsert: { name: 'wsban-role', code: `WSBAN_${stamp.toUpperCase()}`, level: 5 } },
      { upsert: true, new: true }
    );
    roleId = role._id;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const users = await User.find({ username: new RegExp(`^b.*_${stamp}$`) }).select('_id');
      const ids = users.map((u) => u._id);
      await IPBlacklist.deleteMany({ _id: { $in: entryIds } }).catch(() => {});
      IPBlacklist.invalidateSnapshot();
      await User.deleteMany({ _id: { $in: ids } }).catch(() => {});
      await Role.deleteOne({ code: `WSBAN_${stamp.toUpperCase()}` }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('端到端：握手认证链上的黑名单闸', () => {
    test('被禁 IP + 有效令牌 → 拒绝并断开，且一次用户查库都不发生', async () => {
      const user = await makeUser('ban', null);
      await putEntry(BANNED_IP, 'black');
      const svc = makeService();
      // 无 XFF ⇒ resolveHandshakeClientIP 对任意 hops 都返回直连对端地址，
      // 这条用例因此与 TRUST_PROXY_HOPS 的配置无关。
      const socket = makeSocket(signToken(user), { address: BANNED_IP });

      // 闸必须排在查库之前：被处置的地址不该再消耗令牌校验/用户查询/会话校验
      const findById = jest.spyOn(User, 'findById');

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(false);
      expect(socket.connected).toBe(false);
      expect(socket.authenticated).toBe(false);
      expect(authErrorOf(socket).data.message).toContain('封禁');
      expect(findById).not.toHaveBeenCalled();
    });

    test('反向保护：未列黑的 IP 照常认证成功（闸不得恒拒绝）', async () => {
      const user = await makeUser('ok', null);
      const svc = makeService();
      const socket = makeSocket(signToken(user), { address: '203.0.113.77' });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(true);
      expect(socket.userId).toBe(String(user._id));
    });

    test('同 IP 既在白名单又在黑名单 → 白名单优先放行（与 HTTP 侧同判据）', async () => {
      const user = await makeUser('wl', null);
      const ip = '203.0.113.88';
      await putEntry(ip, 'white', 'manual');
      await putEntry(ip, 'black');
      const svc = makeService();
      const socket = makeSocket(signToken(user), { address: ip });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(true);
    });

    // 封禁判定与 allowedIPs 判定必须取同一个 IP：两处各自取址时，
    // 「HTTP 侧封的」「WS 侧拦的」「WS 侧放行判断的」会分裂成三个值。
    test('XFF 在场时封禁判定与 allowedIPs 判定同源（按实际 hops 分支，两侧只能有一个解释）', async () => {
      const hops = currentHops();
      await putEntry(BANNED_IP, 'black');
      const user = await makeUser('par', BANNED_IP); // 只允许 BANNED_IP 这个范围
      const svc = makeService();
      const socket = makeSocket(signToken(user), { address: PEER_IP, xff: BANNED_IP });

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      if (hops > 0) {
        // 信任代理 ⇒ 两处都看到 XFF 最右可信段 BANNED_IP：allowedIPs 会放过，
        // 而黑名单必须先把它拦下（否则"封了 IP 却还能收推送"）。
        expect(ok).toBe(false);
        expect(authErrorOf(socket).data.message).toContain('封禁');
      } else {
        // 不信任转发头 ⇒ 两处都只看到直连对端 PEER_IP：未被封禁（放行侧一致），
        // 但 PEER_IP 不在 allowedIPs 内，于是仍被拒 —— 关键是**拒绝来自范围闸
        // 而不是封禁闸**：若封禁闸自顾自地去读 XFF，这里就会以「封禁」的名义报错。
        expect(ok).toBe(false);
        expect(authErrorOf(socket).data.message).toContain('IP 范围');
      }
    });

    // 上一条按环境实际 hops 走单侧分支；测试环境 TRUST_PROXY_HOPS 实测为 0，
    // 于是"信任代理 ⇒ 用 XFF 段查封禁"这条**真正危险**的分支在本地从未跑过。
    // 这里把它单独钉死：伪造/透传的 XFF 命中黑名单时必须以「封禁」报错，
    // 且 allowedIPs 恰好放行该段——用来证明报错来自封禁闸而不是范围闸。
    test('TRUST_PROXY_HOPS>0 时封禁判定读的是 XFF 可信段（与 req.ip 同值）', async () => {
      const original = process.env.TRUST_PROXY_HOPS;
      process.env.TRUST_PROXY_HOPS = '1';
      try {
        // 前提自证：改环境后判据确实变了，否则这条用例是空跑
        expect(currentHops()).toBe(1);
        await putEntry(BANNED_IP, 'black');
        const user = await makeUser('hops', BANNED_IP);
        const svc = makeService();
        const socket = makeSocket(signToken(user), { address: PEER_IP, xff: BANNED_IP });

        const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

        expect(ok).toBe(false);
        expect(authErrorOf(socket).data.message).toContain('封禁');
      } finally {
        if (original === undefined) delete process.env.TRUST_PROXY_HOPS;
        else process.env.TRUST_PROXY_HOPS = original;
      }
    });
  });

  describe('_assertHandshakeIpNotBanned 本体：与 HTTP 侧对齐的两种降级', () => {
    const call = (socket) =>
      Object.create(WebSocketService.prototype)._assertHandshakeIpNotBanned(socket);

    test('名单查询抛错 → fail-open 放行，但必须计入 ip_blacklist_failopen', async () => {
      const before = failOpenTotal();
      jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
      jest.spyOn(IPBlacklist, 'isWhitelisted').mockResolvedValue(false);
      const socket = makeSocket('x', { address: BANNED_IP });

      const rejected = await call(socket);

      expect(rejected).toBe(false);
      expect(socket.connected).toBe(true);
      expect(socket.emitted).toHaveLength(0);
      // 放行不等于无声：评价报告 #7 的同一条纪律——fail-open 必须有显式信号。
      // 复用 HTTP 侧的计数类型（同一根因同一条时间序列），不新造恒真信号。
      expect(failOpenTotal()).toBeGreaterThan(before);
    });

    test('取不到任何地址 → 放行（与 checkIPBlacklist 的 clientIP 缺失同口径）', async () => {
      const socket = makeSocket('x', { address: null });
      expect(await call(socket)).toBe(false);
    });

    test('命中黑名单 → 断开并回执，返回 true 表示"已处理"', async () => {
      await putEntry('203.0.113.99', 'black');
      const socket = makeSocket('x', { address: '203.0.113.99' });
      expect(await call(socket)).toBe(true);
      expect(socket.connected).toBe(false);
      expect(authErrorOf(socket).data.message).toContain('封禁');
    });
  });

  /**
   * 会话面（2026-10-01 第 4 轮）：握手拦过之后不再复看，是上一组用例暴露出的
   * 「只关一半的门」的后半段——HTTP 侧逐请求复查，长连接没有"下一个请求"。
   *
   * 这里用**真实名单数据 + 真实清扫**（不 mock IPBlacklist 的判定结果，只 mock
   * 故障注入所需的抛错），于是断言覆盖的是"清扫与握手是否同一判据"，
   * 而不是"清扫是否照抄了我给它喂的返回值"。
   */
  describe('运行期封禁复查：清扫里的名单复查（建连之后才被拉黑的会话）', () => {
    const FRESH = (n) => `203.0.113.${n}`;

    /** 已认证驻留连接：handshake 决定清扫看到的地址，userId 决定授权批量查谁 */
    const makeLiveSocket = ({ address = PEER_IP, xff = null, userId = 'u', tokenVersion = 0 }) => {
      const socket = {
        id: `wsban-live-${++counter}`,
        userId,
        tokenVersion,
        authenticated: true,
        roleCodes: ['FIREFIGHTER'],
        handshake: { address, headers: xff ? { 'x-forwarded-for': xff } : {} },
        connected: true,
        emitted: [],
        emit: (ev, data) => socket.emitted.push({ ev, data }),
        disconnect: (force) => {
          socket.connected = false;
          socket.disconnectForced = force;
        },
        leave: () => {},
      };
      return socket;
    };

    /** 清扫用最小实例（与 websocketSweep.test.js 同形：两张表 + io 替身） */
    const makeSweepService = (sockets) => {
      const svc = Object.create(WebSocketService.prototype);
      svc.io = {
        sockets: { sockets: new Map(sockets.map((s) => [s.id, s])) },
        to: () => ({ emit: () => {} }),
        socketsAdapter: null,
      };
      svc.clients = new Map(
        sockets.map((s) => [
          s.id,
          { id: s.id, userId: s.userId, rooms: new Set(), connectedAt: new Date() },
        ])
      );
      return svc;
    };

    /** 直接驱动名单复查本体（不需要 io/clients） */
    const sweep = (sockets) => Object.create(WebSocketService.prototype)._sweepBannedIps(sockets);

    test('建连后被拉黑 ⇒ 清扫断开该连接（auth-error + disconnect(true)）', async () => {
      const user = await makeUser('swk', null);
      const ip = FRESH(131);
      await putEntry(ip, 'black');
      const banned = makeLiveSocket({ address: ip, userId: String(user._id) });
      const svc = makeSweepService([banned]);

      await svc.runCleanupSweep();

      expect(banned.connected).toBe(false);
      expect(banned.disconnectForced).toBe(true);
      expect(authErrorOf(banned).data.message).toContain('封禁');
    });

    // 正向对照：上面的"断开"必须来自名单而不是"清扫恒踢"，且被踢的那条不该
    // 再消耗授权查询——$in 只含存活连接，是"名单复查排在批量取数之前"的结构性证据。
    test('正向对照：未列黑的连接活着进入授权复查，$in 只含它（被拉黑的那条不再查库）', async () => {
      const okUser = await makeUser('swok', null);
      const badUser = await makeUser('swbad', null);
      const bannedIp = FRESH(132);
      await putEntry(bannedIp, 'black');
      const alive = makeLiveSocket({ address: FRESH(133), userId: String(okUser._id) });
      const banned = makeLiveSocket({ address: bannedIp, userId: String(badUser._id) });
      const find = jest.spyOn(User, 'find');
      const svc = makeSweepService([banned, alive]);

      await svc.runCleanupSweep();

      expect(alive.connected).toBe(true);
      expect(banned.connected).toBe(false);
      expect(find).toHaveBeenCalledTimes(1);
      expect(find.mock.calls[0][0]._id.$in.map(String)).toEqual([String(okUser._id)]);
    });

    test('同地址既白又黑 ⇒ 清扫放行（与握手面同一条白名单优先判据）', async () => {
      const ip = FRESH(134);
      await putEntry(ip, 'white', 'manual');
      await putEntry(ip, 'black');
      const socket = makeLiveSocket({ address: ip });

      const res = await sweep([socket]);

      expect(res).toEqual({ alive: [socket], kicked: 0 });
      expect(socket.connected).toBe(true);
    });

    test('按地址去重：同一出口 IP 的三条连接本轮只查一次名单，且三条都断开', async () => {
      const ip = FRESH(135);
      await putEntry(ip, 'black');
      const isBlocked = jest.spyOn(IPBlacklist, 'isBlocked');
      const isWhitelisted = jest.spyOn(IPBlacklist, 'isWhitelisted');
      const sockets = [1, 2, 3].map(() => makeLiveSocket({ address: ip }));

      const res = await sweep(sockets);

      // L-29 的教训在这一面上的形态：逐连接打库（这里是 3 次）就是周期性钝化。
      // 去重后同 IP 只查一次，但去重不得让"其余连接"漏网。
      expect(isBlocked).toHaveBeenCalledTimes(1);
      expect(isWhitelisted).toHaveBeenCalledTimes(1);
      expect(res.kicked).toBe(3);
      expect(res.alive).toHaveLength(0);
      expect(sockets.every((s) => !s.connected)).toBe(true);
    });

    test('名单查询抛错 ⇒ 本轮全部保留（fail-open），计数每轮只加 1（不随地址数放大）', async () => {
      const before = failOpenTotal();
      jest.spyOn(IPBlacklist, 'isBlocked').mockRejectedValue(new Error('db down'));
      const sockets = [141, 142, 143].map((n) => makeLiveSocket({ address: FRESH(n) }));

      const res = await sweep(sockets);

      expect(res).toEqual({ alive: sockets, kicked: 0 });
      expect(sockets.every((s) => s.connected)).toBe(true);
      // 一次库抖动会让全部待查地址同时失败：逐地址计数把一个根因放大成 N 倍告警量，
      // 时间序列失去意义（握手面是"一次请求一个根因"，所以那里逐请求计）。
      expect(failOpenTotal() - before).toBe(1);
    });

    test('取不到地址的连接不参与名单判定、也不断开（与握手面同口径）', async () => {
      const isBlocked = jest.spyOn(IPBlacklist, 'isBlocked');
      const socket = makeLiveSocket({ address: null });

      const res = await sweep([socket]);

      // 握手期"解析不出地址"是这次认证本身可疑（还没给过它任何信任），
      // 清扫期断开一条已在收数据的连接则是处置——无地址即无从判定封禁。
      expect(res).toEqual({ alive: [socket], kicked: 0 });
      expect(isBlocked).not.toHaveBeenCalled();
    });

    test('刻意排在授权批量查询之前：User.find 抛错的那一轮，封禁遏制照常完成', async () => {
      const user = await makeUser('sworder', null);
      const bannedIp = FRESH(145);
      await putEntry(bannedIp, 'black');
      const banned = makeLiveSocket({ address: bannedIp, userId: String(user._id) });
      const peer = makeLiveSocket({ address: FRESH(146), userId: String(user._id) });
      jest.spyOn(User, 'find').mockImplementation(() => {
        throw new Error('users collection down');
      });
      const svc = makeSweepService([banned, peer]);

      await svc.runCleanupSweep();

      // 一次与封禁无关的用户表故障不得推迟遏制
      expect(banned.connected).toBe(false);
      expect(authErrorOf(banned).data.message).toContain('封禁');
      // 原有语义保持不变：DB 抖动不踢健康连接（等下一轮重试）
      expect(peer.connected).toBe(true);
    });

    test('处置与通知解耦：auth-error 发送抛错不得推迟断开，也不中断其余连接复查', async () => {
      const ip = FRESH(147);
      await putEntry(ip, 'black');
      const throwing = makeLiveSocket({ address: ip });
      throwing.emit = () => {
        throw new Error('write after end');
      };
      const other = makeLiveSocket({ address: ip });

      const res = await sweep([throwing, other]);

      expect(throwing.connected).toBe(false);
      expect(throwing.disconnectForced).toBe(true);
      expect(other.connected).toBe(false);
      expect(res.kicked).toBe(2);
    });

    // 两侧必须用同一个地址推导：否则"握手看的"与"清扫看的"是两个值，
    // 换一条链就能让一侧的封禁对另一侧失效。这里只用一份名单数据，
    // 靠 hops 的两个取值让同一条 socket 得出相反结论——分歧只能由"同址"解释。
    test('与握手面同址：hops=0 查直连对端、hops=1 查 XFF 可信段（同一 socket 两种结论）', async () => {
      const original = process.env.TRUST_PROXY_HOPS;
      const bannedDirect = FRESH(148);
      const cleanXff = FRESH(149);
      await putEntry(bannedDirect, 'black');
      try {
        process.env.TRUST_PROXY_HOPS = '0';
        expect(currentHops('0')).toBe(0);
        const asPeer = makeLiveSocket({ address: bannedDirect, xff: cleanXff });
        expect((await sweep([asPeer])).kicked).toBe(1);
        expect(asPeer.connected).toBe(false);

        process.env.TRUST_PROXY_HOPS = '1';
        expect(currentHops('1')).toBe(1);
        const behindProxy = makeLiveSocket({ address: bannedDirect, xff: cleanXff });
        expect((await sweep([behindProxy])).kicked).toBe(0);
        expect(behindProxy.connected).toBe(true);
      } finally {
        if (original === undefined) delete process.env.TRUST_PROXY_HOPS;
        else process.env.TRUST_PROXY_HOPS = original;
      }
    });
  });
});
