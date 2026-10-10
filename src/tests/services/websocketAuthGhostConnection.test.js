/**
 * 认证在途断开不留幽灵连接（F-188）
 *
 * 【缺陷】authenticateSocket 在登记连接映射之前要 await 三处外部状态（令牌黑名单、
 * User 查询、设备会话校验）。客户端在这段时间里断开是常态（页面刷新、网络抖动、
 * 认证超时被服务端踢）：disconnect 处理器（websocketService.js:367-379）跑的时候
 * `socket.userId` 还没赋值，于是只从 `clients` 里摘掉这条连接，`userConnections`
 * 那支判据整段跳过；等 await 回来，:511-514 仍然把这个**已经死掉的 socketId** 登记进
 * userConnections。之后没有任何地方再清它（周期清扫只遍历 `this.clients.keys()`，
 * 除 dispose() 外没有路径再碰 userConnections）⇒ 一条永久幽灵。
 *
 * 【代价】userConnections 是「谁在线」的事实来源：
 *   - getStats().totalUsers 直接取它的 size ⇒ 在线用户数虚高且永不回落；
 *   - emitPermissionSync 按它判定在线 ⇒ 每次角色变更为死连接做一次查库 + 一次 emit；
 *   - MAX_CONNECTIONS 数的是 io.sockets.sockets.size，幽灵不占名额 ⇒ 上限挡不住它。
 *
 * 【修法】最后一个 await 之后、任何状态写入之前复检 `socket.connected`。
 * 为什么判 socket.connected 而不是判 `this.clients.has(socket.id)`：后者会让
 * 「直接调用 authenticateSocket、fake socket 从未进过 clients」的既有用例全部变红——
 * 那是把测试夹具的形态当成生产不变量。socket.io v4 在 connect/close 两侧维护
 * connected 布尔，是权威信号；仓内 7 处 WS 夹具本就都带 `connected: true`。
 *
 * 【可证伪结构】
 *   ① 对照组（不 Mock）：正常路径确实登记——没有它，「永远不登记」也能把 ② 跑绿。
 *   ② 两臂分别把断开压在**第一个**与**最后一个** await 上。为什么两臂就够：
 *      链路里的 await 只有这三处，「复检在所有 await 之后」这条性质由 ④ 的
 *      结构闸钉住（对整段方法体取最后一个 await 的位置）；②的两臂负责证明
 *      这个复检真的会作废认证（不是恒真的文本匹配）。中间的 await 被两端夹住，
 *      不需要第三个 mock——那需要替换 mongoose 继承来的静态方法，代价是夹具失真。
 *   ③ 后果闸：一条幽灵就足以让 totalUsers 虚高 ⇒ ② 挡的是真代价，不是洁癖。
 *   ④ 接线顺序闸，跑注释屏蔽后的代码视图（文本闸会被注释里那句"await"骗绿）。
 */

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

/** 与 utils/shutdownBudgetContract.test.js 同口径的注释屏蔽 */
function jsCodeOnly(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .map((l) => l.replace(/\/\/[^\n]*/g, ' '))
    .join('\n');
}

const WS_PATH = path.join(__dirname, '../../services/websocketService.js');

describe('WebSocket 认证在途断开不留幽灵连接（F-188）', () => {
  let WebSocketService;
  let User;
  let Role;
  let UserSession;
  let roleId;
  const stamp = `g${String(Date.now()).slice(-8)}`;
  const createdUserIds = [];
  let counter = 0;

  /** 最小服务实例：authenticateSocket 只用到 clients / userConnections 两张表 */
  const makeService = () => {
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map();
    return svc;
  };

  /** 假 socket：connected 可被中途翻掉（disconnect() 与生产语义一致） */
  const makeSocket = (token) => {
    const socket = {
      id: `gho-sock-${++counter}`,
      handshake: { auth: { token }, address: { address: '127.0.0.1' }, headers: {} },
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
    const svc = makeService();
    // 生产在 connection 回调里先登记 clients（userId 占位 null），认证成功才回填
    svc.clients.set(socket.id, { id: socket.id, userId: null, rooms: new Set() });
    return { socket, svc };
  };

  const makeUser = async () => {
    const user = await User.create({
      username: `wgho_${stamp}_${++counter}`,
      email: `wgho${counter}-${stamp}@example.com`,
      password: `P@ssw0rd-${stamp}-${counter}`,
      roles: [roleId],
      status: 'active',
    });
    createdUserIds.push(user._id);
    return user;
  };

  const signToken = (user, sid) =>
    jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        tokenVersion: user.tokenVersion ?? 0,
        jti: `jti-gho-${stamp}-${counter}`,
        ...(sid ? { sid } : {}),
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '24h' }
    );

  /**
   * 把「客户端在某个 await 期间断开」注入真实链路：只翻 liveness 标志，
   * 查询本身照旧执行 ⇒ 断言的仍是完整认证流程走到那一步，而不是被 mock 架空。
   */
  const dropDuring = (site, socket) => {
    if (site === 'first') {
      const bl = require('../../middleware/tokenBlacklist');
      const orig = bl.isTokenBlacklisted.bind(bl);
      const spy = jest.spyOn(bl, 'isTokenBlacklisted').mockImplementation(async (t) => {
        socket.connected = false;
        return orig(t);
      });
      return () => spy.mockRestore();
    }
    if (site === 'last') {
      const ss = require('../../services/sessionService');
      const spy = jest.spyOn(ss, 'validateSession').mockImplementation(async (sid) => {
        socket.connected = false;
        return { usable: true, sid };
      });
      return () => spy.mockRestore();
    }
    throw new Error(`未知的 await 站点：${site}`);
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    UserSession = require('../../models/UserSession');
    WebSocketService = require('../../services/websocketService');

    const role = await Role.findOneAndUpdate(
      { code: `WSGHO_${stamp.toUpperCase()}` },
      { $setOnInsert: { name: 'wsgho-role', code: `WSGHO_${stamp.toUpperCase()}`, level: 5 } },
      { upsert: true, new: true }
    );
    roleId = role._id;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await UserSession.deleteMany({ userId: { $in: createdUserIds } }).catch(() => {});
      await User.deleteMany({ _id: { $in: createdUserIds } }).catch(() => {});
      await Role.deleteOne({ _id: roleId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('① 对照（前提自证）：全程存活 ⇒ 正常登记，两张表都留下可寻址痕迹', async () => {
    const user = await makeUser();
    const { socket, svc } = makeSocket(signToken(user));

    const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

    expect(ok).toBe(true);
    expect(socket.connected).toBe(true);
    // ②的判据是"这里没有痕迹"，所以先证明正常路径确实留痕迹
    expect(svc.userConnections.get(String(user._id)).has(socket.id)).toBe(true);
    expect(svc.clients.get(socket.id).userId).toBe(String(user._id));
  });

  // first = middleware/tokenBlacklist.isTokenBlacklisted（链上第一个 await）
  // last  = sessionService.validateSession（链上最后一个 await，须经 sid 才会走到）
  test.each(['first', 'last'])(
    '② 断开发生在 %s 这次 await 期间 ⇒ 认证作废且不登记',
    async (site) => {
      const user = await makeUser();
      const token = signToken(user, site === 'last' ? `sid-gho-${stamp}` : undefined);
      const { socket, svc } = makeSocket(token);

      const restore = dropDuring(site, socket);
      let ok;
      try {
        ok = await svc.authenticateSocket(socket, token, null);
      } finally {
        restore();
      }

      expect(socket.connected).toBe(false); // 断开确实发生（否则这条臂只是正常路径重跑）
      expect(ok).toBe(false);
      expect(socket.authenticated).toBe(false);
      expect(socket.userId).toBeUndefined();
      // 幽灵的两种形态都不许出现：per-user 集合里不出现该 id，整个 userId 键也不该被造出来
      expect(svc.userConnections.size).toBe(0);
      expect(svc.userConnections.get(String(user._id))).toBeUndefined();
      // 且不是靠抛异常蒙过去的：认证链走到了业务判据全部通过的那一步才因 liveness 作废
      expect(socket.emitted.some((e) => e.ev === 'auth-error')).toBe(false);
    }
  );

  test('③ 后果闸：一条幽灵就足以让 totalUsers 虚高 ⇒ ② 挡的是真代价', () => {
    const svc = makeService();
    svc.io = { sockets: { adapter: { rooms: new Map() }, sockets: new Map() } };
    // 幽灵形态：userConnections 里有 id，clients 里没有
    // （正是 disconnect 摘掉 clients、而认证尾部又补登记 userConnections 的那种）
    svc.userConnections.set('ghost-user', new Set(['dead-socket']));
    expect(svc.getStats().totalUsers).toBe(1);
    expect(svc.getStats().totalClients).toBe(0);

    const clean = makeService();
    clean.io = svc.io;
    expect(clean.getStats().totalUsers).toBe(0);
  });

  /** authenticateSocket 的方法体（原始文本按边界截取后再剥注释：边界不许被注释挪动） */
  function methodBody(text) {
    const from = text.indexOf('async authenticateSocket(');
    const to = text.indexOf('\n  /**', from); // 下一个方法的 JSDoc 起 = 本方法体止
    expect(from).toBeGreaterThan(-1);
    expect(to).toBeGreaterThan(from); // 前提：真的截到单个方法，而不是整份文件
    return jsCodeOnly(text.slice(from, to));
  }

  test('④ 接线闸（代码视图）：复检位于最后一个 await 之后、登记之前', () => {
    const raw = fs.readFileSync(WS_PATH, 'utf8');
    const body = methodBody(raw);

    const GUARD = /if\s*\(\s*!\s*socket\.connected\s*\)/;
    const guard = body.search(GUARD);
    expect(guard).toBeGreaterThan(-1);
    expect(body.lastIndexOf('await ')).toBeLessThan(guard); // 在**所有** await 之后
    expect(body.indexOf('this.userConnections')).toBeGreaterThan(guard); // 在登记之前

    // 反例：把复检包进块注释 ⇒ 文本视图 token 数不变、代码视图归零（纯文本闸骗绿的形状）
    const ANCHOR = 'if (!socket.connected) {';
    expect(raw.split(ANCHOR)).toHaveLength(2); // 锚点唯一，否则 replace 打偏
    const commented = raw.replace(ANCHOR, '/* if (!socket.connected) */ {');
    expect((commented.match(/socket\.connected/g) || []).length).toBe(
      (raw.match(/socket\.connected/g) || []).length
    );
    expect(methodBody(commented).search(GUARD)).toBe(-1);
  });
});
