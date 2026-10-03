/**
 * 消防管理系统 - 服务器启动入口
 * 职责：连接数据库 → 初始化数据 → 启动 HTTP/WS 服务 → 注册信号处理
 * Express 应用配置见 app.js（app/server 分离，便于测试）
 */

// 注意：dotenv 在 config/index.js 模块加载时已完成初始化，
// 入口不再重复 require('dotenv').config()

// 生产环境配置校验（在数据库连接之前执行）
const config = require('./config');
config.validateProductionConfig();

const mongoose = require('mongoose');
const connectDB = require('./config/database');
const logger = require('./utils/logger');
const { exitAfterFlush, bestEffortDrain } = require('./utils/loggerFlush');

// P3-48：密钥文件注入的结果在 config 加载期产生（早于 logger 可用），
// 此处补记日志。只记变量名不记值。
if (config.secretHydration) {
  const { loaded, warnings } = config.secretHydration;
  if (loaded.length > 0) {
    logger.info(`已从挂载文件注入密钥：${loaded.join(', ')}（值不出现在容器环境变量中）`);
  }
  warnings.forEach((w) => logger.warn(`密钥配置告警：${w}`));
}

const { createApp } = require('./app');
const { initializeSystem } = require('./services/initData');
const { startReminderScheduler, stopReminderScheduler } = require('./services/deviceReminder');
const { startAlertCleanup, stopAlertCleanup } = require('./services/securityAlert');
const { startCaptchaCleanup, stopCaptchaCleanup } = require('./services/captchaService');
const auditBuffer = require('./services/auditBuffer');
const auditMonitor = require('./services/auditMonitor');
// 审计链周期自检（2026-09-30）：补上"链完整性由定时任务守护"这一方，
// 与 auditMonitor（异常行为检测）分工，见该模块文件头
const auditChainMonitor = require('./services/auditChainMonitor');
// M-09：启动期重同步审计链链尾（清除崩溃遗留的幻影链尾）
const { resyncChainTail } = require('./utils/auditChain');
// F-103：关停链的总预算（每一步向它要自己的超时，见 gracefulShutdown 内的注释）
const shutdownBudget = require('./utils/shutdownBudget');
const statsCache = require('./services/statsCache');
const userPermissionService = require('./services/userPermissionService');
const sharedCache = require('./services/sharedCache');
const WebSocketService = require('./services/websocketService');
const { captureException } = require('./middleware/sentry');
const { assertSingleProcessAssumptions } = require('./constants/runtime');

const PORT = config.port || 3000;

// 模块级引用，供优雅关闭使用
let httpServer = null;
let wsServiceInstance = null;
let reminderScheduler = null;
// 优雅关闭幂等守卫：防止信号重复触发导致清理流程重入
let shuttingDown = false;

/**
 * 执行一个清理步骤，失败不中断后续步骤
 *
 * 第三个参数 `capMs` 是**这一步最多等多久**的硬闸（F-202）：缺省＝不设闸，
 * 由步骤自己负责超时（HTTP/调度器/审计排空/SIEM 排空就是这一类，它们本就在向
 * `stepAllowMs` 要额度）。凡是自己不管超时、又确实要 await 一个网络 I/O 的步骤，
 * **必须**传 capMs —— 否则那一步能把整条关停链楔死（判据见
 * `src/tests/utils/shutdownBudgetContract.test.js` 的"每一步要么自带额度、要么带硬闸"）。
 *
 * 放在模块作用域而不是 gracefulShutdown 体内：它不读关停链的任何闭包状态，
 * 而 gracefulShutdown 的函数体长度已是要消化的存量债（`npm run lint:ratchet` 只许降不许升）。
 *
 * @param {string} name 步骤名（用于日志定位）
 * @param {Function} fn 步骤实现（可 async）
 * @param {number} [capMs] 本步最多等待的毫秒数（不传＝信任步骤自带超时）
 */
const runStep = async (name, fn, capMs) => {
  let task;
  try {
    task = Promise.resolve(fn());
  } catch (e) {
    task = Promise.reject(e);
  }
  const { timedOut, error, elapsedMs } = await shutdownBudget.guardStep(task, capMs);
  if (timedOut) {
    logger.error(
      `优雅关闭步骤「${name}」等待超过 ${capMs}ms（实际 ${elapsedMs}ms），` +
        '放弃等待并继续后续清理：该步的 I/O 可能仍未完成，进程退出时由系统回收。' +
        '反复出现说明对端（Redis/Mongo）已不可达，本次关停只剩兜底路径'
    );
    return;
  }
  if (error) {
    logger.error(
      `优雅关闭步骤「${name}」失败，继续执行后续清理：${error && error.message ? error.message : error}`
    );
  }
};

/**
 * 优雅关闭：关闭 WS → 停止接收新 HTTP 连接 → 停止调度器 → 关闭 DB → 退出
 *
 * P3-33 异常隔离：原实现把各步骤直接写在一条 async 流程里，任一步抛错
 * 即中断整条清理链——例如 wsServiceInstance.dispose() 抛错会导致
 * 审计缓冲永不 flush（最后一批审计彻底丢失）、DB 连接不正常关闭。
 * 现在每步用 runStep 包裹：单步失败只记录并继续，保证「审计落库」与
 * 「DB 关闭」这两个有持久化后果的步骤一定被执行到。
 */
const gracefulShutdown = async (signal) => {
  // 幂等守卫（二次信号强制退出）：优雅关闭流程只执行一次；
  // 清理进行中再次收到信号视为「不再等待」的强制退出诉求，
  // 直接以非零码终止，避免卡死的清理步骤无限拖住进程
  if (shuttingDown) {
    logger.warn(`收到重复 ${signal} 信号，跳过剩余清理并强制退出`);
    // P1-13：强制退出路径同样需要留痕（这条日志解释了为何「跳过清理」）
    return exitAfterFlush(1);
  }
  shuttingDown = true;
  // F-103：从这一刻起，链上每一步的超时都受总预算约束（预算小于部署侧 stop_grace_period，
  // 见 src/utils/shutdownBudget.js 与 docker-compose.yml 的注释）
  shutdownBudget.beginShutdownBudget();

  logger.info(`收到 ${signal} 信号，正在优雅关闭服务器...`);

  // 1. 先关闭 WebSocket：WS 连接挂在同一 httpServer 上，
  //    若先调 httpServer.close()，Node 会等待全部存量连接（含 WS 长连接）断开，
  //    必然拖满 10 秒超时；先 dispose WS，后续 close 才能立即完成
  await runStep('关闭 WebSocket', () => {
    if (wsServiceInstance) {
      wsServiceInstance.dispose();
      logger.info('WebSocket 服务已关闭');
    }
  });

  // 2. 停止 HTTP 服务器（不再接受新连接，最多等 10 秒让存量请求处理完）
  await runStep('关闭 HTTP 服务器', async () => {
    if (!httpServer) return;
    await new Promise((resolve) => {
      // B-L3：立即关闭空闲 keep-alive 连接——浏览器长连接会让 close() 回调
      // 拖满 10s 超时（Node ≥18.2 提供；活跃请求不受影响）。WS 已在步骤 1 断开
      if (typeof httpServer.closeIdleConnections === 'function') {
        httpServer.closeIdleConnections();
      }
      // F-103：10 s 只是**硬上限**，实际取"总预算减去尾部保留时间"。否则在途请求会
      // 永久优先于"审计落盘"——排空与关库排在链尾，10 s 被这里吃光后它们就没机会跑了。
      const httpAllowMs = Math.min(
        10000,
        shutdownBudget.stepAllowMs(shutdownBudget.TAIL_RESERVE_MS)
      );
      const forceTimeout = setTimeout(() => {
        logger.warn(`HTTP 服务器优雅关闭超时（${httpAllowMs}ms），强制关闭剩余连接`);
        // 超时兜底：仍存活的连接（含极端情况下仍在写的响应）强制断开
        if (typeof httpServer.closeAllConnections === 'function') {
          httpServer.closeAllConnections();
        }
        resolve();
      }, httpAllowMs);
      httpServer.close((err) => {
        clearTimeout(forceTimeout);
        // io.close()（dispose 内）会连带关闭挂载的 HTTP server，
        // 此处再 close 必然收到 ERR_SERVER_NOT_RUNNING——属预期路径，降噪为 debug
        if (err && err.code !== 'ERR_SERVER_NOT_RUNNING') {
          logger.error(`HTTP 服务器关闭出错：${err.message}`);
        } else {
          logger.info('HTTP 服务器已关闭');
        }
        resolve();
      });
    });
  });

  // 3. 停止调度器
  await runStep('停止提醒调度器', async () => {
    if (reminderScheduler) {
      // 30 s 同样是硬上限（F-103）：一次设备扫描跑完与否，不该决定审计能不能落盘
      await stopReminderScheduler(reminderScheduler, {
        maxWaitMs: Math.min(30000, shutdownBudget.stepAllowMs(shutdownBudget.TAIL_RESERVE_MS)),
      });
      logger.info('设备到期提醒调度已停止');
    }
  });
  await runStep('停止告警清理定时器', () => stopAlertCleanup());
  await runStep('停止验证码清理定时器', () => stopCaptchaCleanup());
  await runStep('停止统计缓存清理定时器', () => statsCache.stopCleanup());
  await runStep('停止权限缓存清理定时器', () => userPermissionService.stopCleanup());

  // 3.5 审计日志缓冲清空落库 + 异常监控停止（必须在数据库连接关闭前完成）。
  // 顺序关键：flush（walEnabled 仍为 true，落库后按本批文档的 __walSeq 精确裁剪 WAL，
  // F-97 之前这里是"按条数裁剪"——WAL 有行缺序号或已被回收时会误删未落库行）→ 等待
  // walChain 排空（裁剪的原子 rename 落盘）→ stop。此前「await flush(); stop()」
  // 不等裁剪，500ms 强制退出截断 rename → 重启重放把已落库批次重复插入（B-L2）
  await runStep('停止审计监控', () => auditMonitor.stop());
  // 审计链核验与 auditMonitor 同为"只读扫描 + 告警"的后台任务，关停口径一致：
  // 只清定时器（停掉新一轮），在途那一轮由 runStep 的超时预算兜底，不阻塞关停
  await runStep('停止审计链核验', () => auditChainMonitor.stop());
  await runStep('清空审计缓冲', async () => {
    // F-101：这一句以前无条件打「已清空」。flush 在有在途批次时会直接 return，
    // 于是"定时 flush 正跑到一半时关停"这种常见时序下，日志说清空了、缓冲里其实还压着记录，
    // 而运维正看着这条日志决定可以强退 ⇒ 谎报本身就是审计缺失的直接证据。
    // F-103：2500 ms 是"排空之后还要跑完的步骤"的保留（关 Redis + 关 Mongo +
    // 日志 transport 落盘 500 ms）。预算已经耗尽时这里拿到 0 ⇒ 排空立刻返回并**如实**
    // 报 residual（走下面的 error 分支），而不是静默跳过——谎报已被 F-101 关掉了。
    const { drained, residual } = await auditBuffer.flushAndStop(shutdownBudget.stepAllowMs(2500));
    if (drained) {
      logger.info('审计日志缓冲已清空');
    } else {
      logger.error(
        `审计日志缓冲未排空：仍有 ${residual} 条待落库（排空预算用尽，通常是数据库不可达）。` +
          '这些记录的 WAL 行仍在磁盘上，进程重启后由 start() 重放；本次退出前不会落库'
      );
    }
  });

  // 3.6 关闭共享缓存门面（断开 Redis 连接与失效广播订阅）。
  // 放在审计落库之后、数据库关闭之前，与其它资源清理同一阶段。
  // F-202：这是一次网络往返。Redis socket 卡在半开时 `await` 永不返回 ⇒ 后面的关库、
  // SIEM 排空、exit 一个都跑不到，进程只在 stop_grace_period 后吃 SIGKILL 且无线索。
  // 硬闸＝"给后面留 1s"与 2s 的较小值；预算用尽时拿到 0 ⇒ 一帧不等，但**如实**打 error。
  await runStep(
    '关闭共享缓存',
    () => sharedCache.shutdownSharedCache(),
    Math.min(2000, shutdownBudget.stepAllowMs(1000))
  );

  // 4. 关闭数据库
  await runStep(
    '关闭 MongoDB 连接',
    async () => {
      await mongoose.connection.close(false);
      logger.info('MongoDB 连接已关闭');
    },
    // F-202：`close(false)` 会等在途操作排空，Mongo 不可达时同样是不落地的 promise。
    // 保留 500ms 给链尾的 SIEM 排空与 exitAfterFlush 的 transport 落盘。
    Math.min(2000, shutdownBudget.stepAllowMs(500))
  );

  // 4.5 排空 SIEM 转发缓冲（F-186）。放在链尾是**有意的**：上面每一步自己写的日志
  // （"MongoDB 连接已关闭"、审计未排空的 error）都还压在这个缓冲里，越早排就越少送到。
  // 必须是最后一步，所以它的保留额度取 0（后面没有要保住的步骤了）。
  // 为什么需要这一步：logShipper 的 close() 在 F-186 之前**没有任何生产调用点**。
  // 但机制不是"end() 够不到 close()"——两支探针实测：end() 确实会经 transport 'finish' →
  // pipe 收尾的 'unpipe' 触发 close()，只是①**触发而不等待**（end() 后立刻 exit 实测只送达
  // 5/25，100ms 后 15/25，200ms 才全量，且丢了没人报），②F-187 又删掉了生产里唯一的
  // end() 调用点 ⇒ 今天的树上 close() 压根不会被触发。判据与源码位置见 loggerFlush 的 JSDoc。
  await runStep('排空 SIEM 日志转发缓冲', async () => {
    await bestEffortDrain({
      allowMs: shutdownBudget.stepAllowMs(0),
      tag: '优雅关闭',
      reportDrained: true,
    });
  });

  // P1-13：正常关闭路径同样要让日志落地——延时 500ms 让 winston 的异步 transport
  // 把队列写完再 exit。这里**不调用** logger.end()（F-187：end() 对落盘零收益，
  // 却会让这 500ms 窗口内的任何一条日志同步抛 ERR_STREAM_WRITE_AFTER_END）；
  // SIEM 缓冲的排空也不靠它，由上一步显式 await close() 完成。
  // 500ms 与原先一致，给审计 WAL 裁剪的原子 rename 留出余量。
  return exitAfterFlush(0, { delayMs: 500 });
};

/**
 * 启动服务器
 */
const startServer = async () => {
  try {
    // 初始化共享缓存门面（R-3 基础设施）：配置 REDIS_URL 时建立连接，
    // 使限流/验证码/权限缓存失效广播（L-4）与审计链分布式锁（A-1）在启动即就绪。
    // 未配置或连接失败时内部降级为进程内内存态并告警，不阻断启动。
    // 先于运行时拓扑校验执行，使校验能据 Redis 是否就绪区分已外置/仍单进程的机制。
    await sharedCache.initSharedCache();

    // 运行时拓扑校验（P3-19）：本服务十余处机制依赖单进程假设
    // （审计哈希链、审计 WAL、限流计数、用户缓存等），
    // 检测到多进程迹象时在启动日志里列出确切的失效清单
    assertSingleProcessAssumptions();

    await connectDB();
    await initializeSystem();

    // WB-1：生产密钥强度审计留痕。弱密钥已在 config/validate.js 以阻断级拦截，
    // 这里把「本次启动用的密钥通过了强度校验」落审计，供事后证明密钥治理持续有效；
    // 审计写入失败只告警不阻断（审计不可用不应反过来让服务起不来）
    // 判据统一走 config/validate 的环境归一：字面量比较会让 NODE_ENV=prod 的部署
    // 静默少一条"密钥强度审计"留痕，而它正是事后证明密钥治理持续有效的证据。
    if (require('./config/validate').requiresProductionSemantics()) {
      try {
        const AuditLog = require('./models/AuditLog');
        await AuditLog.record({
          action: 'security_key_strength_audit',
          category: 'security',
          username: 'system',
          ip: '127.0.0.1',
          success: true,
          riskLevel: 'low',
          reason: '启动配置校验通过：JWT/JWT_REFRESH/AES/HMAC 密钥均满足强度要求',
        });
      } catch (auditErr) {
        logger.warn(`密钥强度审计留痕写入失败：${auditErr.message}`);
      }
    }

    const app = createApp();

    // ===== 可选 HTTPS（ENABLE_HTTPS=true）=====
    // 生产环境强烈建议在 Nginx 等反向代理做 TLS 终结（见 deployment/nginx.conf.example），
    // 此处仅用于内网/本地开发自测 TLS 行为。证书路径通过 TLS_CERT_PATH / TLS_KEY_PATH 指定，
    // 可用 scripts/generate-dev-cert.sh 生成自签名证书。
    let server;
    if (process.env.ENABLE_HTTPS === 'true') {
      const fs = require('fs');
      const https = require('https');
      const tlsCert = process.env.TLS_CERT_PATH || './certs/server.crt';
      const tlsKey = process.env.TLS_KEY_PATH || './certs/server.key';
      try {
        server = https.createServer(
          {
            cert: fs.readFileSync(tlsCert),
            key: fs.readFileSync(tlsKey),
          },
          app
        );
        logger.info(`TLS 已启用（cert=${tlsCert}）`);
      } catch (tlsErr) {
        // 显式要求 HTTPS（ENABLE_HTTPS=true）却加载失败时，禁止静默降级为明文 HTTP：
        // 降级会让令牌/Cookie 以明文传输，属于安全策略失效，直接非零退出交由运维介入
        logger.error(`TLS 证书加载失败（cert=${tlsCert}, key=${tlsKey}）：${tlsErr.message}`);
        // P1-13：启动期致命错误最需要取证，等日志落盘后再退出
        return exitAfterFlush(1);
      }
    } else {
      server = require('http').createServer(app);
    }

    // 监听错误兜底（如 EADDRINUSE 端口占用）：listen 的错误不会抛异常，
    // 不监听会让进程静默挂死、容器编排误判为健康；记录后以非零码退出
    server.on('error', (err) => {
      if (err && err.code === 'EADDRINUSE') {
        logger.error(`端口 ${PORT} 已被占用（EADDRINUSE），请更换 PORT 或释放端口后重试`);
      } else {
        logger.error(`HTTP 服务器监听出错：${err ? err.message : err}`);
      }
      // P1-13：端口占用等监听错误必须留痕，等日志落盘后再退出
      return exitAfterFlush(1);
    });

    // 【M-09】启动期从 DB 重同步审计链链尾，清除可能的「幻影链尾」。
    //
    // 成因：链尾推进发生在 ODM 的 pre('save') 钩子内（见 models/auditLogHooks.js），
    // 而文档落库在钩子之后。若进程恰在「已推进链尾、尚未完成 insert」之间被强杀
    //（SIGKILL / OOM / 容器驱逐），链尾就指向一条从未入库的 hash。其后所有记录的
    // prevHash 都会指向不存在的 hash，完整性校验产生**持续性假阳性** chain_break，
    // 运维在反复确认"是误报"后倾向忽略该告警，从而在真正篡改发生时失去检测能力。
    //
    // 为什么不在 post('save') 里推进链尾：链尾推进与哈希计算必须处于同一把
    // withChainLock 临界区内，否则并发写入会读到相同链尾、算出相同 prevHash，
    // 造成**真实分叉**——那比幻影链尾（仅假阳性）严重得多。跨 pre/post 两个
    // 钩子持锁则会引入"钩子未触发即锁泄漏、审计整体停摆"的新失效模式。
    // 故保持原推进位置，改在启动期做一次自愈：从 DB 重建真实链尾。
    //
    // 位置：必须在 listen 回调**之外**（该回调非 async），且早于任何审计写入。
    await resyncChainTail();

    httpServer = server.listen(PORT, () => {
      // 初始化 WebSocket（挂载到同一 HTTP server）
      wsServiceInstance = new WebSocketService(httpServer);
      app.set('wsService', wsServiceInstance);
      // REDIS_URL 就绪时为推送挂 Redis adapter（跨实例触达）；内部吞错降级，
      // 不阻塞启动——此处不 await，挂载完成前的推送至多回退单实例语义。
      // 但**必须持有返回的 promise**：initSharedAdapter 是 async，它自己那条
      // catch 一旦再抛（例如 logger 侧异常、或收到非 Error 形态的拒绝时读
      // err.message），拒绝就没人接住 ⇒ 撞上本文件下方的 unhandledRejection
      // 兜底 ⇒ 刚 listen 成功就 process.exit(1)。调用点兜一道比改对方文件更便宜，
      // 且"降级不阻断启动"这条注释承诺由此变成机器判据（见
      // src/tests/services/observabilityWritesNeverReject.test.js 的调用点闸）。
      wsServiceInstance.initSharedAdapter().catch((err) => {
        logger.warn(
          `WebSocket Redis adapter 挂载异常（推送降级为单实例语义）：${err?.message ?? err}`
        );
      });

      // 启动后台清理任务
      startAlertCleanup();
      startCaptchaCleanup();
      // 统计缓存定时清理（P3-23：原为模块加载期自启动，现与其余后台任务口径一致）
      statsCache.startCleanup();
      // 权限缓存定时清理（报告 O-4：与其余后台任务 start*/stop* 口径一致）
      userPermissionService.startCleanup();
      // 启动审计日志缓冲定时落库（配合 gracefulShutdown 中的 stop + flush）
      auditBuffer.start();
      // 启动审计异常检测定时监控（配合 gracefulShutdown 中的 stop）
      auditMonitor.start();
      // 启动审计链周期自检（2026-09-30）：此前链核验只在被手动调用时发生，
      // "篡改会留痕"成立而"痕迹会被发现"不成立；本定时器把发现从人工动作
      // 变成自动循环。窗口取最近 N 条（默认 2000），发现新断裂/缺口即告警。
      auditChainMonitor.start();
      reminderScheduler = startReminderScheduler(24 * 60 * 60 * 1000);

      const scheme = process.env.ENABLE_HTTPS === 'true' ? 'https' : 'http';
      const wsScheme = process.env.ENABLE_HTTPS === 'true' ? 'wss' : 'ws';
      logger.info(`================================`);
      logger.info(`消防管理系统启动成功`);
      logger.info(`环境：${config.nodeEnv}`);
      logger.info(`端口：${PORT}`);
      logger.info(`API 地址：${scheme}://localhost:${PORT}/api`);
      logger.info(`WebSocket 地址：${wsScheme}://localhost:${PORT}`);
      logger.info(`================================`);

      if (config.nodeEnv === 'production') {
        logger.warn('生产环境运行中，请确保已配置强密钥和 CORS 白名单！');
      }
    });

    // 优雅关闭信号
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  } catch (error) {
    logger.error(`服务器启动失败：${error.message}`);
    // P1-13：等日志落盘后再退出。原为紧接 process.exit(1)，而 winston 的
    // 文件 transport 是异步的——「服务器启动失败」这条最关键的日志实测会丢。
    return exitAfterFlush(1);
  }
};

// 未捕获异常
//
// F-186b：崩溃路径同样要排空 SIEM 转发缓冲——gracefulShutdown 里的那一步管不到这里，
// 而按取证价值排序恰好是反的：进程崩掉那一刻的日志最需要进 SIEM，它们此时全压在
// logShipper 的内存缓冲里（默认 100 行/批、串行发送）。
// 预算硬顶 500ms：这两条链后面还要 setTimeout(1s) 才 exit，超出即放弃并如实报——
// 绝不为"送日志"把一个已经崩溃的进程再拖长（helper 内的计时器已 unref）。
// helper 永不 reject：崩溃链的 finally 之后没有 catch，一次 reject 就是新的
// unhandledRejection（见 utils/loggerFlush.js 的 bestEffortDrain 注释）。
const CRASH_DRAIN_BUDGET_MS = 500;

// P3-33：进程即将退出前必须 flush 审计缓冲——内存里可能有上百条已确认
// 响应给客户端、但尚未落库的审计记录，直接 exit 会让它们随进程消失
// （WAL 能在下次启动重放，但重放依赖进程能正常再启动，不能作为唯一保障）。
process.on('uncaughtException', (error) => {
  if (config.nodeEnv === 'development') {
    logger.error(`未捕获的异常：${error.message}`);
    logger.error(error.stack);
  } else {
    logger.error(`未捕获的异常：${error.message} (${error.name})`);
  }
  try {
    captureException(error, { type: 'uncaughtException' });
  } catch (e) {
    /* ignore */
  }
  // flush 失败不阻断退出：进程已处于不可信状态，尽力而为
  Promise.resolve()
    .then(() => auditBuffer.flush())
    .catch((e) => logger.error(`退出前审计缓冲落库失败：${e && e.message ? e.message : e}`))
    .then(() => bestEffortDrain({ allowMs: CRASH_DRAIN_BUDGET_MS, tag: 'uncaughtException' }))
    .finally(() => setTimeout(() => process.exit(1), 1000));
});

process.on('unhandledRejection', (reason, promise) => {
  if (config.nodeEnv === 'development') {
    logger.error(`未处理的 Promise 拒绝：${reason}`);
  } else {
    const err = reason instanceof Error ? reason : new Error(String(reason));
    logger.error(`未处理的 Promise 拒绝：${err.message} (${err.name})`);
  }
  try {
    const err = reason instanceof Error ? reason : new Error(String(reason));
    captureException(err, { type: 'unhandledRejection', promise });
  } catch (e) {
    /* ignore */
  }
  Promise.resolve()
    .then(() => auditBuffer.flush())
    .catch((e) => logger.error(`退出前审计缓冲落库失败：${e && e.message ? e.message : e}`))
    .then(() => bestEffortDrain({ allowMs: CRASH_DRAIN_BUDGET_MS, tag: 'unhandledRejection' }))
    .finally(() => setTimeout(() => process.exit(1), 1000));
});

startServer();
