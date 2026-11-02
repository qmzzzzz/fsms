/**
 * WebSocket 服务门面（2026-10-18 自 services/websocketService.js 拆分）
 *
 * 对外形态固定为：`module.exports = WebSocketService`（class），
 * `new WebSocketService(server)` 用法不变，静态工具仍挂在类上：
 *   · WebSocketService.resolveHandshakeClientIP
 *   · WebSocketService.resolveTrustProxyHops
 *   · WebSocketService.resolveHandshakeIPForSecurityDecision
 * 实现分布：shared（常量/谓词）、handshake（握手认证）、lifecycle（连接生命周期
 * 与周期复查）、sessionRevocation（设备会话吊销处置）、push（事件分发）——
 * 方法以 mixin 挂回 prototype，`this` 语义不变。
 */

const socketIo = require('socket.io');
const logger = require('../../utils/logger');
const config = require('../../config');
const { HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT } = require('./shared');
const handshake = require('./handshake');
const lifecycle = require('./lifecycle');
const sessionRevocation = require('./sessionRevocation');
const push = require('./push');
const realtimeNotifier = require('../realtimeNotifier');

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
    // O-2：连接数是**拉取式** gauge —— 把取值函数注册给指标层，抓取时现算。
    // 不用"在 set/delete/clear 处各推一次"：连接表的增删有 4 处（push.js 的
    // set/delete、lifecycle.js 的清扫与 dispose 的 clear），漏掉任何一处都会让
    // gauge 永久偏移，而且不会有任何测试变红。注册取值函数则天然无漂移。
    require('../../utils/metricsRuntime').registerWsConnectionSource(() => this.clients.size);
    // #9：来源 IP -> 尚未认证的连接数（认证成功或断开即归还）
    this.unauthConnectionsByIp = new Map();
    this._cleanupTimer = null;
    this._sweepRunning = false; // R-2 周期复查防重入标志
    this._adapterClients = []; // Redis adapter 专用连接（dispose 时回收）
    // #2：设备会话吊销后立即断开对应长连接。跨实例吊销由周期清扫兜底
    // （revokeSession 的广播只承载缓存失效语义，订阅方不应据此推断吊销成立）。
    // 惰性 require：sessionService 在模块加载期会向 sharedCache 注册失效处理器，
    // 顶层引入会让「只使用原型方法的单元测试」连带产生这条模块级副作用。
    const sessionService = require('../sessionService');
    this._offSessionRevoked = sessionService.onSessionRevoked((event) =>
      this._handleSessionRevoked(event)
    );
    this.setupEventHandlers();
    this.setupConnectionCleanup();

    // 业务层（AlarmService/DeviceService）经 realtimeNotifier 向本实例推送。
    // 绑定由实例自身持有：构造即生效、dispose 即解绑，启动/关闭流程都不必再记得调用，
    // 也不存在「服务已销毁但入口仍指向它」的窗口。
    realtimeNotifier.setWebSocketService(this);

    logger.info('WebSocket 服务已初始化');
  }
}

Object.assign(
  WebSocketService.prototype,
  handshake.methods,
  lifecycle.methods,
  sessionRevocation.methods,
  push.methods
);

module.exports = WebSocketService;

// 修复配套：导出握手 IP 解析工具，供一致性测试直接驱动，
// 断言「WS 与 HTTP 在同一 trust proxy 语义下得出同一个客户端 IP」。
// 挂在 class 上而非替换 module.exports——不改变既有 `new WebSocketService()` 用法。
WebSocketService.resolveHandshakeClientIP = handshake.resolveHandshakeClientIP;
// F-B42 配套：一并导出跳数解析，供用例直接钉「WS 与 HTTP 在同一环境下取到同一个
// hops」。既有的一致性用例把 hops 作为入参传给 resolveHandshakeClientIP，等于跳过了
// hops 的来源——正是本次上限漏判能藏住的原因。
WebSocketService.resolveTrustProxyHops = handshake.resolveTrustProxyHops;
// F-B43 配套：导出「安全裁决形态」的握手取址，供跨通道一致性用例与 HTTP 侧的
// clientIpForSecurityDecision 逐形态比对（见 websocketAllowedIpTrustBoundary.test.js）。
WebSocketService.resolveHandshakeIPForSecurityDecision =
  handshake.resolveHandshakeIPForSecurityDecision;
