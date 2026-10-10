/**
 * WebSocket 的两条「会话期内失效」防线（临时锁定 + 降级出房）
 *
 * 审计实证的两个缺口：
 * 1) 账户被爆破阈值临时锁定时，HTTP 侧每个请求都被 assertAccountUsable 拒
 *    （middleware/auth.js 的 ACCOUNT_TEMP_LOCKED），但 WS 侧只看 status——
 *    而锁定写入方（services/authService.js）**只写 lockUntil，既不动 status
 *    也不推进 tokenVersion**，于是"status 仍是 active"在被锁期间恒成立，
 *    被锁账户的实时推送通道一条都不掉。根因是取数字段集比 HTTP 侧少一个
 *    lockUntil：少取一个字段就等于少一条判据。
 * 2) 授/撤角色不推进 tokenVersion（全仓只有 middleware/tokenBlacklist.js:161
 *    这一处 $inc），所以"降级但仍 active"的连接在只复查 status/tokenVersion
 *    的判定体里永远通过——已驻留 role-management 的降级管理员会在整个连接
 *    生命周期内继续收 role-updated / permissions-updated 广播。
 *
 * 因此本文件锁两件事：握手与复查两面对 lockUntil 同判据；
 * 复查判定体在角色变更后把不再满足要求的房间 leave 掉，且入房面与清房面
 * 用同一个谓词（roomRolesSatisfied）。
 *
 * F-144（投影不复制第二份）：本文件原先在"取数字段集含 lockUntil"那条用例里
 * **逐字抄了一遍**生产的 select 字符串。抄的这份不会随生产漂移——实测把
 * `websocketService.js:438` 投影里的 `lockUntil` 删掉，那条用例照旧绿（`-t` 单独跑
 * `Tests: 17 skipped, 1 passed`），名字承诺的防线并不存在。现在投影改为**从生产源码
 * 解析**，并补一条结构门禁：握手判定读到的每个 `freshUser.<字段>` 必须在
 * select 投影或 populate 填充集里——那正是本文件头说的根因（"少取一个字段就等于
 * 少一条判据"）的可执行形式。
 */

const fs = require('fs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const path = require('path');

const WS_SRC = path.join(__dirname, '../../services/websocketService.js');

/** 整行注释 + 行尾注释都剥掉：判据只能由代码满足，不能由注释满足 */
const codeOnly = (src) =>
  src
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .map((l) => l.replace(/\/\/[^\n]*/g, ' '))
    .join('\n');

const wsCode = () => codeOnly(fs.readFileSync(WS_SRC, 'utf8'));

/** 握手那一次查询的 select 投影（生产源码里 authenticateSocket 之后的第一个） */
const handshakeProjection = () => {
  const seg = wsCode().slice(wsCode().indexOf('async authenticateSocket('));
  const m = seg.match(/\.select\(\s*'([^']*)'\s*\)/);
  if (!m) throw new Error('未找到 authenticateSocket 的 select 投影');
  return m[1].trim();
};

/** 握手那一次查询 populate 的字段（roles 之类的关联字段不写在 select 里） */
const handshakePopulated = () => {
  const seg = wsCode().slice(wsCode().indexOf('async authenticateSocket('));
  const m = seg.match(/\.populate\(\s*\{\s*path:\s*'([^']*)'/);
  return m ? [m[1]] : [];
};

/** 握手链路上实际读出的 `freshUser.<字段>`（authenticateSocket + 其判定方法共用该形参名） */
const handshakeReadFields = () =>
  [...wsCode().matchAll(/freshUser\.([a-zA-Z_][a-zA-Z0-9_]*)/g)].map((m) => m[1]);

describe('WebSocket 临时锁定与降级出房', () => {
  let WebSocketService;
  let User;
  let Role;
  let UserSession;
  let superAdminRoleId;
  let securityAdminRoleId;
  let plainRoleId;
  const stamp = `y${String(Date.now()).slice(-8)}`;
  let counter = 0;

  const FUTURE = () => new Date(Date.now() + 15 * 60 * 1000);
  const PAST = () => new Date(Date.now() - 60 * 1000);

  /** 造用户：默认不带 allowedIPs / lockUntil，按用例覆盖 */
  const makeUser = async (suffix, extra = {}) => {
    const user = await User.create({
      username: `q${suffix}_${stamp}`,
      email: `q${suffix}-${stamp}@example.com`,
      password: `P@ssw0rd-${stamp}-${suffix}`,
      roles: [plainRoleId],
      status: 'active',
      ...extra,
    });
    return user;
  };

  /** 签发 access 形态令牌（不带 type，与既有 WS 测试同一形态） */
  const signToken = (user) =>
    jwt.sign(
      {
        userId: String(user._id),
        username: user.username,
        tokenVersion: user.tokenVersion ?? 0,
        jti: `jti-${++counter}`,
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '24h' }
    );

  /** 最小服务实例：authenticateSocket / revalidateSocket 只用这两张表 */
  const makeService = () => {
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map();
    return svc;
  };

  /**
   * 假 socket。rooms / left / joined 与真实 socket.io 同形，
   * 但被测代码读的房间清单是本服务的 clients 记账，不是 socket.rooms，
   * 所以两者分开断言才能证明「记账与 socket.io 状态一起收敛」。
   */
  const makeSocket = (user, { rooms = [] } = {}) => {
    const socket = {
      id: `wsc-sock-${++counter}`,
      handshake: {
        auth: { token: user ? signToken(user) : null },
        address: '127.0.0.1',
        headers: {},
      },
      authenticated: false,
      // 令牌主体就是该用户：socket.userId 由脚手架预置（复查面需要它已绑定身份），
      // 因此握手拒绝用例断言的是"服务侧不留下任何该连接的授权痕迹"，
      // 而不是这个脚手架字段有没有被写过
      userId: user ? String(user._id) : undefined,
      tokenVersion: user ? (user.tokenVersion ?? 0) : undefined,
      emitted: [],
      connected: true,
      rooms: new Set(rooms),
      joined: [],
      left: [],
      emit: (ev, data) => socket.emitted.push({ ev, data }),
      disconnect: () => {
        socket.connected = false;
      },
      join: (room) => {
        socket.rooms.add(room);
        socket.joined.push(room);
      },
      leave: (room) => {
        socket.rooms.delete(room);
        socket.left.push(room);
      },
    };
    return socket;
  };

  /** 把连接按「已认证并驻留若干房间」的形态登记进服务记账 */
  const attach = (svc, socket, rooms) => {
    svc.clients.set(socket.id, { userId: socket.userId, rooms: new Set(rooms) });
    socket.authenticated = true;
    return svc.clients.get(socket.id);
  };

  const authErrorOf = (socket) => socket.emitted.find((e) => e.ev === 'auth-error');

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    User = require('../../models/User');
    Role = require('../../models/Role');
    UserSession = require('../../models/UserSession');
    WebSocketService = require('../../services/websocketService');

    // 房间准入按 code 判定，这里按 code upsert 取回（内置角色可能已由启动播种创建）
    const ensureRole = async (code, level) =>
      Role.findOneAndUpdate(
        { code },
        { $setOnInsert: { name: `ws-${code.toLowerCase()}`, code, level } },
        { upsert: true, new: true }
      );
    superAdminRoleId = (await ensureRole('SUPER_ADMIN', 100))._id;
    securityAdminRoleId = (await ensureRole('SECURITY_ADMIN', 90))._id;
    plainRoleId = (await ensureRole(`WSY_PLAIN_${stamp.toUpperCase()}`, 5))._id;
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      const users = await User.find({ username: new RegExp(`^q.*_${stamp}$`) }).select('_id');
      const ids = users.map((u) => u._id);
      await UserSession.deleteMany({ userId: { $in: ids } }).catch(() => {});
      await User.deleteMany({ _id: { $in: ids } }).catch(() => {});
      await Role.deleteOne({ _id: plainRoleId }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  describe('握手期临时锁定（与 HTTP 侧 ACCOUNT_TEMP_LOCKED 同判据）', () => {
    test('锁定中的 active 账户：认证拒绝、断开、且不绑定身份', async () => {
      const user = await makeUser('lk', { lockUntil: FUTURE() });
      const svc = makeService();
      const socket = makeSocket(user);

      const ok = await svc.authenticateSocket(socket, socket.handshake.auth.token, null);

      expect(ok).toBe(false);
      expect(socket.authenticated).toBe(false);
      expect(socket.connected).toBe(false);
      expect(authErrorOf(socket).data.message).toContain('临时锁定');
      // 认证不通过时不得在服务侧留下任何可寻址痕迹：userConnections / clients 是
      // 定向推送（userRoom）与统计的连接来源
      expect(svc.userConnections.size).toBe(0);
      expect(svc.clients.size).toBe(0);
      expect(socket.joined).toEqual([]);
    });

    test('判定只看时间不看存在：lockUntil 已过期 → 正常认证通过', async () => {
      const user = await makeUser('exp', { lockUntil: PAST() });
      const svc = makeService();
      const socket = makeSocket(user);

      expect(await svc.authenticateSocket(socket, socket.handshake.auth.token, null)).toBe(true);
      expect(socket.userId).toBe(String(user._id));
    });

    test('从未锁定（lockUntil 为 null）→ 认证通过（对照组，排除“有字段就拒”）', async () => {
      const user = await makeUser('none', { lockUntil: null });
      const svc = makeService();
      const socket = makeSocket(user);

      expect(await svc.authenticateSocket(socket, socket.handshake.auth.token, null)).toBe(true);
    });

    test('取数字段集含 lockUntil：select 少一个字段即判据失效（反向锁定）', async () => {
      // 直接证明"读到字段"这件事：把同一份用户文档交给判定方法，
      // 只有 select 带出 lockUntil 时，DB 取回的文档才会让认证失败。
      // 投影取自生产源码（F-144）：本文件不再抄第二份，抄的那份不会随生产漂移。
      const projection = handshakeProjection();
      expect(projection.split(/\s+/)).toContain('lockUntil');

      const user = await makeUser('sel', { lockUntil: FUTURE() });
      const doc = await User.findById(user._id)
        .select(projection)
        .populate({ path: 'roles', select: 'code', match: { status: 'active' } });
      expect(doc.lockUntil).toBeInstanceOf(Date);
      expect(doc.lockUntil.getTime()).toBeGreaterThan(Date.now());

      const svc = makeService();
      const socket = makeSocket(user);
      expect(svc._assertHandshakeAccountLocked(socket, doc)).toBe(true);

      // 同名用户但字段被投影掉（复现"select 漏字段"）→ 判定必须放行，
      // 这说明本用例真正在测的是"字段有没有被取到"，而不是恒定拒绝
      const stripped = { username: doc.username, status: doc.status, tokenVersion: 0 };
      expect(svc._assertHandshakeAccountLocked(makeSocket(user), stripped)).toBe(false);
    });

    test('握手判定读到的每个 freshUser 字段都在投影/填充集里（F-144 结构门禁）', () => {
      const covered = new Set([
        ...handshakeProjection().split(/\s+/).filter(Boolean),
        ...handshakePopulated(),
      ]);
      const read = [...new Set(handshakeReadFields())].sort();
      // 前提自证：这条判据不是空集恒真——握手链路确实读了这 7 个字段
      expect(read.length).toBeGreaterThanOrEqual(7);
      expect(read.filter((f) => !covered.has(f))).toEqual([]);
      // 反向对照：把生产投影里的 lockUntil 删掉，本行必须红（用例注释里的那次实测）
      expect(covered.has('lockUntil')).toBe(true);
    });
  });

  describe('_assertHandshakeAccountLocked 真值表', () => {
    const svc = () => makeService();

    test.each([
      { label: 'lockUntil 为 null → 放行', lockUntil: null, rejected: false },
      { label: 'lockUntil 为过去 → 放行', lockUntil: PAST(), rejected: false },
      { label: 'lockUntil 为未来 → 拒绝', lockUntil: FUTURE(), rejected: true },
    ])('$label', ({ lockUntil, rejected }) => {
      const socket = makeSocket(null);
      const result = svc()._assertHandshakeAccountLocked(socket, {
        username: 'anyone',
        lockUntil,
      });
      expect(result).toBe(rejected);
      expect(socket.connected).toBe(!rejected);
      if (rejected) {
        expect(authErrorOf(socket).data.message).toContain('临时锁定');
      } else {
        expect(socket.emitted).toHaveLength(0);
      }
    });

    test('缺少字段的用户文档不抛异常（判定为未锁定）', () => {
      const socket = makeSocket(null);
      expect(svc()._assertHandshakeAccountLocked(socket, {})).toBe(false);
      expect(svc()._assertHandshakeAccountLocked(socket, undefined)).toBe(false);
      expect(socket.connected).toBe(true);
    });
  });

  describe('复查期临时锁定（revalidateSocket 的 select 同样必须带 lockUntil）', () => {
    test('在线期间被临时锁定 → 复查断开该连接', async () => {
      const user = await makeUser('rlk', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management'] });
      attach(svc, socket, ['role-management']);

      await User.updateOne({ _id: user._id }, { lockUntil: FUTURE() });

      const result = await svc.revalidateSocket(socket);
      expect(result.ok).toBe(false);
      expect(result.roleCodes).toEqual([]);
      expect(socket.connected).toBe(false);
      expect(authErrorOf(socket).data.message).toContain('临时锁定');
    });

    test('同一用户取消锁定 → 复查放行（锁定是唯一变量）', async () => {
      const user = await makeUser('rxl', { lockUntil: FUTURE(), roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management'] });
      attach(svc, socket, ['role-management']);

      expect((await svc.revalidateSocket(socket)).ok).toBe(false);

      await User.updateOne({ _id: user._id }, { lockUntil: null });
      socket.connected = true;
      socket.emitted.length = 0;

      const result = await svc.revalidateSocket(socket);
      expect(result.ok).toBe(true);
      expect(result.roleCodes).toContain('SUPER_ADMIN');
      expect(socket.connected).toBe(true);
    });

    test('批量清扫路径与单连接路径同判据（runCleanupSweep 走同一判定体）', async () => {
      const user = await makeUser('sweep', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management'] });
      attach(svc, socket, ['role-management']);
      svc.io = { sockets: { sockets: new Map([[socket.id, socket]]) } };

      await User.updateOne({ _id: user._id }, { lockUntil: FUTURE() });
      await svc.runCleanupSweep();

      expect(socket.connected).toBe(false);
      expect(authErrorOf(socket).data.message).toContain('临时锁定');
    });
  });

  describe('降级即出房（角色变更不推进 tokenVersion，只能靠清房收敛）', () => {
    test('撤销管理员角色 → 连接保留但 role-management 被移出（含记账同步）', async () => {
      const user = await makeUser('demo', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management', 'alarm'] });
      const client = attach(svc, socket, ['role-management', 'alarm']);

      // 降级：只改 roles，不动 status、不动 tokenVersion（这正是漏洞成立的前提）
      user.roles = [plainRoleId];
      await user.save();
      const after = await User.findById(user._id).select('tokenVersion status');
      expect(after.tokenVersion).toBe(user.tokenVersion ?? 0);
      expect(after.status).toBe('active');

      const result = await svc.revalidateSocket(socket);

      expect(result.ok).toBe(true); // 未失效：不应断开
      expect(socket.connected).toBe(true);
      expect(result.roleCodes).toEqual(['WSY_PLAIN_' + stamp.toUpperCase()]);
      // socket.io 层与本服务记账层都必须收敛，只改一处等于另一处继续投递
      expect(socket.left).toEqual(['role-management']);
      expect(client.rooms.has('role-management')).toBe(false);
      expect(client.rooms.has('alarm')).toBe(true);
      expect(socket.rooms.has('role-management')).toBe(false);
    });

    test('换成 SECURITY_ADMIN 仍满足房间要求 → 一间都不移出', async () => {
      const user = await makeUser('keep', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management'] });
      const client = attach(svc, socket, ['role-management']);

      user.roles = [securityAdminRoleId];
      await user.save();

      const result = await svc.revalidateSocket(socket);
      expect(result.ok).toBe(true);
      expect(result.roleCodes).toContain('SECURITY_ADMIN');
      expect(socket.left).toEqual([]);
      expect(client.rooms.has('role-management')).toBe(true);
    });

    test('无角色要求的房间不因清房逻辑被误伤（谓词与入房面同源）', async () => {
      const user = await makeUser('free', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['device-alert', 'notification', 'alarm'] });
      const client = attach(svc, socket, ['device-alert', 'notification', 'alarm']);

      user.roles = [];
      await user.save();

      expect((await svc.revalidateSocket(socket)).ok).toBe(true);
      expect(socket.left).toEqual([]);
      expect([...client.rooms].sort()).toEqual(['alarm', 'device-alert', 'notification']);
    });

    test('角色只剩停用/无 code 的残项 → 移出（判定体不看成员关系，只看生效角色码）', async () => {
      // 说明：populate 已按 match:{status:'active'} 过滤停用角色（该语义由
      // inactiveRoleAuthorization 覆盖）。本用例刻意不动内置角色的 status
      // ——改共享文档会污染并发跑的其它套件——而是直接给出"过滤后"的判定体输入。
      const user = await makeUser('dis', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management'] });
      const client = attach(svc, socket, ['role-management']);

      const fresh = {
        _id: user._id,
        status: 'active',
        tokenVersion: user.tokenVersion ?? 0,
        roles: [{ code: undefined }, {}], // 停用后被过滤掉、只剩取不到 code 的残项
      };
      const result = svc._applyRevalidation(socket, fresh);

      expect(result.ok).toBe(true);
      expect(result.roleCodes).toEqual([]);
      expect(socket.left).toEqual(['role-management']);
      expect(client.rooms.size).toBe(0);
    });

    test('记账缺失（连接已被 disconnect 回收）→ 不抛异常、不影响判定', async () => {
      const user = await makeUser('nomap', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management'] });
      // 故意不调用 attach：clients 里没有该条目

      user.roles = [plainRoleId];
      await user.save();

      const result = await svc.revalidateSocket(socket);
      expect(result.ok).toBe(true);
      expect(socket.left).toEqual([]); // 无记账即无从清房，但绝不能抛
    });

    test('批量清扫对降级连接执行同一清房（两路共用判定体的直接证据）', async () => {
      const user = await makeUser('sw2', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management', 'alarm'] });
      const client = attach(svc, socket, ['role-management', 'alarm']);
      svc.io = { sockets: { sockets: new Map([[socket.id, socket]]) } };

      user.roles = [plainRoleId];
      await user.save();

      await svc.runCleanupSweep();

      expect(socket.connected).toBe(true); // 降级不等于失效：只清房不断线
      expect(socket.left).toEqual(['role-management']);
      expect(client.rooms.has('alarm')).toBe(true);
      expect(client.rooms.has('role-management')).toBe(false);
    });

    test('反复复查不产生重复 leave（幂等，避免记账 drift）', async () => {
      const user = await makeUser('idem', { roles: [superAdminRoleId] });
      const svc = makeService();
      const socket = makeSocket(user, { rooms: ['role-management'] });
      const client = attach(svc, socket, ['role-management']);

      user.roles = [plainRoleId];
      await user.save();

      await svc.revalidateSocket(socket);
      await svc.revalidateSocket(socket);
      await svc.revalidateSocket(socket);

      expect(socket.left).toEqual(['role-management']);
      expect(client.rooms.size).toBe(0);
    });
  });
});
