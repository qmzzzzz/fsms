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
    process.exit(1);
  }
  shuttingDown = true;

  logger.info(`收到 ${signal} 信号，正在优雅关闭服务器...`);

  /**
   * 执行一个清理步骤，失败不中断后续步骤
   * @param {string} name 步骤名（用于日志定位）
   * @param {Function} fn 步骤实现（可 async）
   */
  const runStep = async (name, fn) => {
    try {
      await fn();
    } catch (e) {
      logger.error(
        `优雅关闭步骤「${name}」失败，继续执行后续清理：${e && e.message ? e.message : e}`
      );
    }
  };

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
      const forceTimeout = setTimeout(() => {
        logger.warn('HTTP 服务器优雅关闭超时（10s），强制关闭剩余连接');
        // 超时兜底：仍存活的连接（含极端情况下仍在写的响应）强制断开
        if (typeof httpServer.closeAllConnections === 'function') {
          httpServer.closeAllConnections();
        }
        resolve();
      }, 10000);
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
      await stopReminderScheduler(reminderScheduler);
      logger.info('设备到期提醒调度已停止');
    }
  });
  await runStep('停止告警清理定时器', () => stopAlertCleanup());
  await runStep('停止验证码清理定时器', () => stopCaptchaCleanup());
  await runStep('停止统计缓存清理定时器', () => statsCache.stopCleanup());
  await runStep('停止权限缓存清理定时器', () => userPermissionService.stopCleanup());

  // 3.5 审计日志缓冲清空落库 + 异常监控停止（必须在数据库连接关闭前完成）。
  // 顺序关键：flush（walEnabled 仍为 true，落库后按条数裁剪 WAL）→ 等待
  // walChain 排空（裁剪的原子 rename 落盘）→ stop。此前「await flush(); stop()」
  // 不等裁剪，500ms 强制退出截断 rename → 重启重放把已落库批次重复插入（B-L2）
  await runStep('停止审计监控', () => auditMonitor.stop());
  await runStep('清空审计缓冲', async () => {
    await auditBuffer.flushAndStop();
    logger.info('审计日志缓冲已清空');
  });

  // 3.6 关闭共享缓存门面（断开 Redis 连接与失效广播订阅）。
  // 放在审计落库之后、数据库关闭之前，与其它资源清理同一阶段。
  await runStep('关闭共享缓存', () => sharedCache.shutdownSharedCache());

  // 4. 关闭数据库
  await runStep('关闭 MongoDB 连接', async () => {
    await mongoose.connection.close(false);
    logger.info('MongoDB 连接已关闭');
  });

  setTimeout(() => process.exit(0), 500);
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
    if (process.env.NODE_ENV === 'production') {
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
        process.exit(1);
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
      process.exit(1);
    });

    httpServer = server.listen(PORT, () => {
      // 初始化 WebSocket（挂载到同一 HTTP server）
      wsServiceInstance = new WebSocketService(httpServer);
      app.set('wsService', wsServiceInstance);
      // REDIS_URL 就绪时为推送挂 Redis adapter（跨实例触达）；内部吞错降级，
      // 不阻塞启动——此处不 await，挂载完成前的推送至多回退单实例语义
      wsServiceInstance.initSharedAdapter();

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
    process.exit(1);
  }
};

// 未捕获异常
//
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
    .finally(() => setTimeout(() => process.exit(1), 1000));
});

startServer();
