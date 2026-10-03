/**
 * WebSocket 事件监听器的「拒绝臂」（2026-10-03 审计线 R11-C #1）
 *
 * 缺陷形状：socket.io 4.8.3 派发监听器时**丢弃返回值**
 * （node_modules/socket.io/dist/socket.js:697 的 `super.emitUntyped.apply(this, event)`
 * 是 process.nextTick 回调里的一条裸语句，既不赋值也不 return），所以
 * `socket.on('x', async …)` 里 reject 掉的 promise 是一个没人持有的孤儿 promise
 * ⇒ Node 判为 unhandledRejection。而本仓在 src/index.js:446-463 的口径是
 * 「任何未处理拒绝 ⇒ flush 审计后 process.exit(1)」，且该处理器在所有环境都注册。
 * 两条既定事实合起来：一条长连接上的一次 promise 拒绝 = 整个进程下线。
 *
 * 同文件握手路径写了 `authenticateSocket(...).catch(() => {})`（:353），
 * 作者已经承认这条 promise 会 reject，只是兜底没覆盖事件监听器形态——
 * 'auth' 的 try/finally 没有 catch，'join-room' 连 try 都没有。
 *
 * 检测手段为什么是「持柄直测」而不是 process 监听器（本文件先前版本的写法，已推翻）：
 * jest 沙箱里的 `process` 是 `Object.create(真实 process)`，测试里
 * `process.on('unhandledRejection', …)` 把监听器登记在**沙箱副本**上，真实派发
 * 打不到它（实测 rejections 恒为空 ⇒ 那种断言是恒真的假绿）。沙箱里唯一可靠的
 * 观测方式是自己接住 promise：`await expect(listener(...)).resolves/rejects`。
 * 所以每条保护用例都自己去拿 `socket.__listeners` 里注册的**真实**监听器的返回值。
 *
 * 双保险：孤儿 promise 在 jest 里也会被归因成用例失败（实测可见），
 * 因此摘掉保护的变异会同时打红「持柄直测」和「真跑」两组用例。
 */

const fs = require('fs');
const path = require('path');
const logger = require('../../utils/logger');
const WebSocketService = require('../../services/websocketService');

/** 去掉整行注释（JSDoc 里写着 `socket.on('x', async …)` 的例子，会被扫成注册点） */
const stripCommentLines = (src) =>
  src
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith('//') || t.startsWith('/*') || t.startsWith('*'));
    })
    .join('\n');

const WS_SRC = stripCommentLines(
  fs.readFileSync(path.join(__dirname, '..', '..', 'services', 'websocketService.js'), 'utf8')
);

describe('WebSocket async 监听器的未处理拒绝', () => {
  let counter;
  let errorSpy;

  beforeEach(() => {
    counter = 0;
    errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  /**
   * 复刻 socket.io 的派发语义：调用监听器并丢弃返回值（返回 undefined）。
   * 下一条用例把「真实代码确实是丢弃」钉住；本文件用它驱动真实注册点的成功/失败路径。
   */
  const dispatch = (socket, event, ...args) => {
    for (const listener of socket.__listeners[event] || []) {
      listener(...args);
    }
    return undefined;
  };

  /** 持柄：取出真实注册的监听器并 await 它返回的 promise（沙箱内唯一可靠的观测口） */
  const callRegistered = (socket, event, ...args) => socket.__listeners[event][0](...args);

  const makeSocket = (token = null) => {
    const socket = {
      id: `ws-rej-${++counter}`,
      handshake: { auth: token ? { token } : {}, headers: {} },
      authenticated: false,
      authing: false,
      connected: true,
      userId: null,
      rooms: new Set(),
      emitted: [],
      __listeners: {},
      emit: (ev, data) => socket.emitted.push({ ev, data }),
      disconnect: () => {
        socket.connected = false;
      },
      on: (ev, cb) => {
        socket.__listeners[ev] = socket.__listeners[ev] || [];
        socket.__listeners[ev].push(cb);
      },
      join: (room) => socket.rooms.add(room),
      leave: (room) => socket.rooms.delete(room),
    };
    return socket;
  };

  /** 最小服务实例：只喂 setupEventHandlers 需要的字段，其余走真实原型方法 */
  const makeService = () => {
    const svc = Object.create(WebSocketService.prototype);
    svc.clients = new Map();
    svc.userConnections = new Map();
    svc._sweepRunning = false;
    svc.io = {
      on: (ev, cb) => {
        if (ev === 'connection') svc.__connectionCb = cb;
      },
      sockets: { sockets: new Map(), adapter: { rooms: new Map() } },
      to: () => ({ emit: () => {} }),
    };
    svc.setupEventHandlers();
    return svc;
  };

  /** 走真实 connection 回调：注册点、clients 登记、authTimer 全部按生产形态建立 */
  const connect = (svc, socket) => {
    svc.io.sockets.sockets.set(socket.id, socket);
    svc.__connectionCb(socket);
    return socket;
  };

  // ── 前提与探针自证（缺任何一条，下面的 not.rejects 都是空的）────────
  test('前提自证：socket.io 4.8.3 真的丢弃监听器返回值（裸语句调用，无赋值无 return）', () => {
    const socketIoSrc = fs.readFileSync(
      path.join(__dirname, '..', '..', '..', 'node_modules', 'socket.io', 'dist', 'socket.js'),
      'utf8'
    );
    const line = socketIoSrc
      .split(/\r?\n/)
      .find((l) => l.includes('emitUntyped.apply(this, event)'));
    expect(line).toBeDefined();
    // trimmed 后直接以「接收者.方法.方法(」开头 ⇒ 既没 `const x =`，也没 `return`
    expect(line.trim()).toMatch(/^super\.emitUntyped\.apply\(/);
  });

  test('探针自证：没有保护时，reject 确实 observable（本文件的 rejects 断言不是恒真）', async () => {
    // 修复前的形状：监听器本身 reject
    const rawHandler = async () => {
      throw new Error('探针拒绝');
    };
    await expect(rawHandler()).rejects.toThrow('探针拒绝');

    // 派发方拿不到这个 promise ⇒ 只看 dispatch 的返回值。此处经 dispatch 走的是
    // 一个**正常 resolve** 的探针：实测让探针真的 reject 会被 jest 归因成
    // 下一条用例失败（与生产里打死服务的是同一机制），作为夹具会污染无关用例。
    const socket = makeSocket();
    let called = 0;
    socket.on('probe', async () => {
      called += 1;
    });
    expect(dispatch(socket, 'probe', 'x')).toBeUndefined();
    // 反向对照：dispatch 确实调到了监听器（否则 undefined 是空断言）
    await new Promise((resolve) => setImmediate(resolve));
    expect(called).toBe(1);
  });

  // ── 'auth' ───────────────────────────────────────────────────────
  test('auth：认证依赖 reject 时，注册的监听器不再向外 reject（保护生效）', async () => {
    const svc = makeService();
    const socket = connect(svc, makeSocket()); // 无握手令牌 ⇒ 走 'auth' 兑底路径

    svc.authenticateSocket = jest.fn().mockRejectedValue(new Error('数据库连接中断'));

    await expect(callRegistered(socket, 'auth', 'some-token')).resolves.toBeUndefined();

    // 正向对照：保护不是「把处理器短路掉」——真实依赖确实被调用过一次
    expect(svc.authenticateSocket).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('auth'));
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('数据库连接中断'));
  });

  test('auth：真跑派发路径，防重入标志仍被复位（try/finally 与保护叠加不互相吞）', async () => {
    const svc = makeService();
    const socket = connect(svc, makeSocket());
    svc.authenticateSocket = jest.fn().mockRejectedValue(new Error('数据库连接中断'));

    dispatch(socket, 'auth', 'some-token');
    // 监听器内部是 await 链，让微任务排空后再读复位状态
    await new Promise((resolve) => setImmediate(resolve));

    expect(socket.authing).toBe(false);
    expect(socket.authenticated).toBe(false);
  });

  test('auth：防重入前置判断在保护之后仍然生效（被忽略的请求不得顺手复位别人的进行中状态）', async () => {
    const svc = makeService();
    const socket = connect(svc, makeSocket());
    svc.authenticateSocket = jest.fn().mockRejectedValue(new Error('不应被调用'));

    socket.authing = true;
    await callRegistered(socket, 'auth', 't');

    expect(svc.authenticateSocket).not.toHaveBeenCalled();
    expect(socket.authing).toBe(true);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  // ── 'join-room' ──────────────────────────────────────────────────
  test('join-room：受限房间复查 reject 时不向外 reject，且不得入房（该监听器原本连 try 都没有）', async () => {
    const svc = makeService();
    const socket = connect(svc, makeSocket());
    socket.authenticated = true;
    socket.userId = 'u-rej-1';

    svc.revalidateSocket = jest.fn().mockRejectedValue(new Error('复查失败'));

    await expect(callRegistered(socket, 'join-room', 'role-management')).resolves.toBeUndefined();

    expect(svc.revalidateSocket).toHaveBeenCalledTimes(1);
    expect(socket.rooms.has('role-management')).toBe(false);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('join-room'));
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('复查失败'));
  });

  test('join-room：无角色要求的房间仍正常入房（保护没有改变成功路径）', async () => {
    const svc = makeService();
    const socket = connect(svc, makeSocket());
    socket.authenticated = true;
    socket.userId = 'u-rej-2';
    svc.revalidateSocket = jest.fn().mockRejectedValue(new Error('不该被调用'));

    dispatch(socket, 'join-room', 'alarm');
    await new Promise((resolve) => setImmediate(resolve));

    expect(svc.revalidateSocket).not.toHaveBeenCalled();
    expect(socket.rooms.has('alarm')).toBe(true);
    expect(svc.clients.get(socket.id).rooms.has('alarm')).toBe(true);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  // ── 源码文本闸：钉住「所有 async 监听器都被保护」这个整体形状 ────────
  /**
   * 逐个 socket.on(...) 注册点判定：异步监听器必须由 guardSocketHandler 包裹。
   * 窗口取「到下一个注册点为止」，与 AlarmService 读投影闸同一手法（保护包裹
   * 与被包裹的表达式在同一次调用实参内，不会跨窗口）。
   */
  const classifyRegistrations = (src) => {
    const starts = [...src.matchAll(/socket\.on\(/g)].map((m) => m.index);
    return starts.map((start, i) => {
      const chunk = src.slice(start, i + 1 < starts.length ? starts[i + 1] : start + 1200);
      const event = (chunk.match(/socket\.on\(\s*'([^']+)'/) || [])[1];
      const isAsync = /async\s*\(/.test(chunk);
      const guarded = /guardSocketHandler\(/.test(chunk);
      return { event, isAsync, guarded };
    });
  };

  test('源码文本闸：websocketService 每个 async socket 监听器都必须由 guardSocketHandler 包裹', () => {
    const regs = classifyRegistrations(WS_SRC);
    // 基线自证：2 个 async（auth/join-room）+ 2 个同步（leave-room/disconnect）= 4。
    // 零命中或命中数下跌会先被这条拦住，不会出现「正则没匹配到 ⇒ 全绿」。
    expect(regs.length).toBe(4);
    expect(regs.filter((r) => r.isAsync).map((r) => r.event)).toEqual(['auth', 'join-room']);

    expect(regs.filter((r) => r.isAsync && !r.guarded).map((r) => r.event)).toEqual([]);
    // 反向自查：这套匹配确实读到了被保护的那两个注册点，而不是空数组蒙对
    expect(regs.filter((r) => r.guarded).map((r) => r.event)).toEqual(['auth', 'join-room']);
  });

  test('静态闸自证：把包裹摘掉（修复前的写法）闸必须变红', () => {
    const before = `
      socket.on('auth', async (token) => {
        await this.authenticateSocket(socket, token, authTimer);
      });
      socket.on('leave-room', (room) => { socket.leave(room); });
    `;
    const after = `
      socket.on(
        'auth',
        guardSocketHandler('auth', async (token) => {
          await this.authenticateSocket(socket, token, authTimer);
        })
      );
      socket.on('leave-room', (room) => { socket.leave(room); });
    `;
    const flagged = (src) => classifyRegistrations(src).filter((r) => r.isAsync && !r.guarded);

    expect(flagged(before).map((r) => r.event)).toEqual(['auth']);
    expect(flagged(after)).toEqual([]);
    // 同步监听器不该被要求包裹（否则闸会把 leave-room/disconnect 误报成缺陷）
    expect(flagged(before).some((r) => r.event === 'leave-room')).toBe(false);
  });
});
