/**
 * WebSocket 入站事件限流（P1，2026-10-24）
 *
 * 缺陷形状：连接层的三个闸（进程总连接数 / 未认证 IP 配额 / 认证超时）都数**连接**，
 * 对"一条已认证连接里的事件频率"无感。而 `join-room` 命中
 * `ROOM_ROLE_REQUIREMENTS` 时会在**角色判定之前**先 `revalidateSocket`（查库），
 * 于是任何已认证用户都能把 `join-room 'role-management'` 当成免费库查询放大器：
 * 他不需要 admin 角色——在拿到"无权加入"之前，查询已经付过了。
 *
 * 本文件钉三件事：
 *   ① 桶本身的行为（容量、补充、违规归零、断开阈值）；
 *   ② 装上之后，**库查询次数被真的限住**（这是判据，不是形状）；
 *   ③ 可证伪——把限流摘掉，同一条用例必须红。
 */

const metrics = require('../../utils/metrics');
const logger = require('../../utils/logger');
const {
  takeInboundSlot,
  installInboundThrottle,
  _peekState,
} = require('../../services/websocketService/inboundThrottle');
const {
  WS_INBOUND_BUCKET_CAPACITY,
  WS_INBOUND_REFILL_PER_SEC,
  WS_INBOUND_MAX_VIOLATIONS,
} = require('../../services/websocketService/shared');

/**
 * 假 socket：实现 `use` 与 socket.io 的派发语义
 * （dispatch → run(fns) → emitUntyped；中间件不调 next 则监听器不执行）。
 */
function makeSocket(id = 'ws-throttle-1') {
  const middlewares = [];
  const listeners = {};
  const socket = {
    id,
    userId: null,
    connected: true,
    emitted: [],
    use(fn) {
      middlewares.push(fn);
      return socket;
    },
    on(ev, cb) {
      listeners[ev] = listeners[ev] || [];
      listeners[ev].push(cb);
      return socket;
    },
    emit(ev, data) {
      socket.emitted.push({ ev, data });
      return true;
    },
    disconnect() {
      socket.connected = false;
    },
    /** 复刻 socket.io 的派发：逐个跑中间件，全部 next() 才触发监听器 */
    deliver(event, ...args) {
      let i = 0;
      const runListeners = () => {
        for (const cb of listeners[event] || []) cb(...args);
      };
      if (middlewares.length === 0) {
        runListeners();
        return;
      }
      const next = () => {
        i += 1;
        if (i < middlewares.length) return middlewares[i]([event, ...args], next);
        return runListeners();
      };
      middlewares[0]([event, ...args], next);
    },
  };
  return socket;
}

describe('WebSocket 入站事件限流', () => {
  let warnSpy;
  let alertSpy;

  beforeEach(() => {
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    alertSpy = jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    alertSpy.mockRestore();
  });

  // ── 前提自证 ─────────────────────────────────────────────────────
  test('前提：真实 Socket.IO 连接对象上有 use()（生产不会走进"没装"的分支）', () => {
    // 顶层导出即可：深路径 socket.io/dist/socket 被 package.json 的 exports 挡住
    const { Socket } = require('socket.io');
    expect(typeof Socket.prototype.use).toBe('function');

    // 反向对照：installInboundThrottle 的兼容性闸确实认得这个能力位，
    // 而不是恒返回 false（那样生产上等于没装，测试却全绿）
    const real = makeSocket('probe-real');
    expect(installInboundThrottle(real)).toBe(true);
    expect(installInboundThrottle({ id: 'no-use' })).toBe(false);
  });

  // ── 桶行为 ───────────────────────────────────────────────────────
  test('容量内全部放行，第 CAPACITY+1 个被拒（同一毫秒内）', () => {
    const socket = makeSocket();
    const now = 1_700_000_000_000;

    for (let i = 0; i < WS_INBOUND_BUCKET_CAPACITY; i += 1) {
      expect(takeInboundSlot(socket, 'join-room', now).allowed).toBe(true);
    }
    const rejected = takeInboundSlot(socket, 'join-room', now);
    expect(rejected.allowed).toBe(false);
    expect(rejected.disconnect).toBe(false);
    expect(rejected.retryAfterMs).toBeGreaterThan(0);
  });

  test('按稳态速率补充：经过 1/REFILL 秒后恰好能再放行一个', () => {
    const socket = makeSocket();
    const t0 = 1_700_000_000_000;
    for (let i = 0; i < WS_INBOUND_BUCKET_CAPACITY; i += 1) takeInboundSlot(socket, 'x', t0);
    expect(takeInboundSlot(socket, 'x', t0).allowed).toBe(false);

    // 补一个令牌所需时间 = 1000 / REFILL 毫秒
    const needMs = 1000 / WS_INBOUND_REFILL_PER_SEC;
    expect(takeInboundSlot(socket, 'x', t0 + needMs + 1).allowed).toBe(true);
  });

  test('补充不会超过容量上限（长时间空闲后不会攒出无限突发）', () => {
    const socket = makeSocket();
    const t0 = 1_700_000_000_000;
    takeInboundSlot(socket, 'x', t0);
    // 空闲一整天
    const later = t0 + 24 * 60 * 60 * 1000;
    let allowed = 0;
    for (let i = 0; i < WS_INBOUND_BUCKET_CAPACITY + 5; i += 1) {
      if (takeInboundSlot(socket, 'x', later).allowed) allowed += 1;
    }
    expect(allowed).toBe(WS_INBOUND_BUCKET_CAPACITY);
  });

  test('成功消费一次即把连续违规计数归零（偶发超速不累积到断开）', () => {
    const socket = makeSocket();
    const t0 = 1_700_000_000_000;
    for (let i = 0; i < WS_INBOUND_BUCKET_CAPACITY; i += 1) takeInboundSlot(socket, 'x', t0);

    // 攒 29 次违规（差 1 次到阈值）
    for (let i = 0; i < WS_INBOUND_MAX_VIOLATIONS - 1; i += 1) {
      expect(takeInboundSlot(socket, 'x', t0).disconnect).toBe(false);
    }
    // 补满一个令牌并消费掉 ⇒ violations 归零
    const later = t0 + (1000 / WS_INBOUND_REFILL_PER_SEC) * (WS_INBOUND_BUCKET_CAPACITY + 1);
    expect(takeInboundSlot(socket, 'x', later).allowed).toBe(true);
    expect(_peekState(socket).violations).toBe(0);

    // 归零后再攒 29 次仍不断开（若没归零，这里会立刻断）
    for (let i = 0; i < WS_INBOUND_MAX_VIOLATIONS - 1; i += 1) {
      expect(takeInboundSlot(socket, 'x', later).disconnect).toBe(false);
    }
  });

  test('连续违规达到阈值即要求断开', () => {
    const socket = makeSocket();
    const t0 = 1_700_000_000_000;
    for (let i = 0; i < WS_INBOUND_BUCKET_CAPACITY; i += 1) takeInboundSlot(socket, 'x', t0);

    let disconnectAt = null;
    for (let i = 1; i <= WS_INBOUND_MAX_VIOLATIONS; i += 1) {
      if (takeInboundSlot(socket, 'x', t0).disconnect) {
        disconnectAt = i;
        break;
      }
    }
    expect(disconnectAt).toBe(WS_INBOUND_MAX_VIOLATIONS);
  });

  // ── 判据：库查询次数被真的限住 ────────────────────────────────────
  test('装上之后：60 次 join-room 只有 CAPACITY 次进入处理器（库查询被限住）', () => {
    const socket = makeSocket();
    installInboundThrottle(socket);

    let handlerCalls = 0;
    socket.on('join-room', () => {
      handlerCalls += 1; // 真实处理器里这里是一次 revalidateSocket → 两次查库
    });

    for (let i = 0; i < 60; i += 1) socket.deliver('join-room', 'role-management');

    expect(handlerCalls).toBe(WS_INBOUND_BUCKET_CAPACITY);
    expect(socket.connected).toBe(false); // 第 50 个事件触发断开
    // 断开后的 10 个在途包**不再计数**（见下一条用例）：throttled 停在阈值处
    expect(_peekState(socket).throttled).toBe(WS_INBOUND_MAX_VIOLATIONS);
  });

  test('断开判定之后到达的包静默丢弃：不重复计数、不重复记指标与日志', () => {
    // 断开是异步生效的（transport close 要等事件循环），期间排队中的包会继续
    // 流进中间件。若这些包继续走"超限"分支，一次攻击会产出 N 条指标 + N 条日志
    // —— 处置动作自己变成放大器。实测未修时 60 个包 → 11 条 ws_inbound_throttled。
    const socket = makeSocket();
    installInboundThrottle(socket);
    socket.on('join-room', () => {});

    for (let i = 0; i < 60; i += 1) socket.deliver('join-room', 'role-management');

    expect(socket.connected).toBe(false);
    expect(_peekState(socket).throttled).toBe(WS_INBOUND_MAX_VIOLATIONS);
    expect(alertSpy.mock.calls.filter((c) => c[0] === 'ws_inbound_throttled')).toHaveLength(1);
    expect(warnSpy.mock.calls.filter((c) => String(c[0]).includes('已断开连接'))).toHaveLength(1);
  });

  test('可证伪：不装限流时同一个攻击串把处理器打满 60 次（上一条的判据不是恒真）', () => {
    const socket = makeSocket();
    let handlerCalls = 0;
    socket.on('join-room', () => {
      handlerCalls += 1;
    });

    for (let i = 0; i < 60; i += 1) socket.deliver('join-room', 'role-management');

    expect(handlerCalls).toBe(60);
  });

  test('超速连击只回一条 error（不是每个被丢的包回一条，否则等于把入站洪水换成出站洪水）', () => {
    const socket = makeSocket();
    installInboundThrottle(socket);
    socket.on('join-room', () => {});

    for (let i = 0; i < 40; i += 1) socket.deliver('join-room', 'alarm');

    const errors = socket.emitted.filter((e) => e.ev === 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0].data.code).toBe('WS_RATE_LIMITED');
    expect(errors[0].data.retryAfterMs).toBeGreaterThan(0);
  });

  test('指标按连接计一次（断开时），不按被丢的包计', () => {
    const socket = makeSocket();
    installInboundThrottle(socket);
    socket.on('join-room', () => {});

    for (let i = 0; i < 60; i += 1) socket.deliver('join-room', 'role-management');

    const throttleAlerts = alertSpy.mock.calls.filter((c) => c[0] === 'ws_inbound_throttled');
    expect(throttleAlerts).toHaveLength(1);
    expect(throttleAlerts[0][1]).toBe('medium');
    // 反向对照：断开确实发生了，不是"没断所以没计数"
    expect(socket.connected).toBe(false);
  });

  test('每条连接一个独立桶：新连接不受上一条连接超速的影响', () => {
    const a = makeSocket('a');
    const b = makeSocket('b');
    installInboundThrottle(a);
    installInboundThrottle(b);
    for (let i = 0; i < 60; i += 1) a.deliver('join-room', 'alarm');

    let bCalls = 0;
    b.on('join-room', () => {
      bCalls += 1;
    });
    b.deliver('join-room', 'alarm');
    expect(bCalls).toBe(1);
  });

  test('正常交互不受影响：1 次 auth + 4 次 join-room 全部放行', () => {
    const socket = makeSocket();
    installInboundThrottle(socket);
    const seen = [];
    socket.on('auth', () => seen.push('auth'));
    socket.on('join-room', (room) => seen.push(room));

    socket.deliver('auth', 'token');
    for (const room of ['role-management', 'device-alert', 'alarm', 'notification']) {
      socket.deliver('join-room', room);
    }

    expect(seen).toEqual(['auth', 'role-management', 'device-alert', 'alarm', 'notification']);
    expect(socket.emitted).toHaveLength(0);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
