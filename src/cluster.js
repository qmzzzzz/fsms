'use strict';

/**
 * Node 原生 cluster 多进程入口（可选，默认不启用）
 *
 * 何时使用：单机 CPU 多核、已外置 Redis（REDIS_URL）且希望把 HTTP 吞吐
 * 按核数扩展时。设 CLUSTER_WORKERS=N（N>1）后，用本文件代替 src/index.js
 * 启动（例如 `node src/cluster.js`），primary 进程 fork N 个 worker，
 * 每个监听同一端口（内核负载均衡）。
 *
 * 何时**不要**使用：
 * - 未外置 Redis：审计哈希链写序、限流计数、权限缓存失效等机制依赖单进程
 *   假设（清单见 constants/runtime.js 的 SINGLE_PROCESS_DEPENDENCIES）。
 *   detectMultiProcess 会识别 cluster worker 并触发 assertSingleProcessAssumptions
 *   的 error 级清单告警；/readyz 侧 multiInstanceReadinessBlocker 在 Redis
 *   未就绪时会直接不就绪（这是刻意的：多进程 + 无分布式锁的审计链必分叉）。
 * - 容器化部署：直接加副本数（K8s replicas / compose 实例数）更干净，
 *   本文件面向的是"单机跑满多核"这一中间形态。
 *
 * 与 PM2 的关系：PM2 cluster 模式（pm2 start src/index.js -i max）等效，
 * 且 detectMultiProcess 同样认得 NODE_APP_INSTANCE。本文件是零额外依赖
 * 的原生等价物。
 *
 * 稳定性语义：
 * - worker 异常退出：primary 记 error 并补 fork（exit 非 0 / 非显式 kill）；
 * - SIGTERM/SIGINT：primary 先停 fork 循环，再向所有 worker 转发信号，
 *   worker 内 index.js 已有的 gracefulShutdown 负责真正的排空关闭；
 * - worker 的启动失败（如 Mongo 不可达）走 index.js 自身的非零退出，
 *   primary 据退出码补拉，日志里可见完整脉络。
 */

const cluster = require('cluster');

const resolveWorkerCount = () => {
  const configured = parseInt(process.env.CLUSTER_WORKERS, 10);
  if (Number.isFinite(configured) && configured > 1) return Math.min(configured, 16);
  return 1;
};

const workerCount = resolveWorkerCount();

if (workerCount === 1) {
  // 未开启多进程：直接走单进程入口，行为与 `node src/index.js` 完全一致
  require('./index');
} else if (cluster.isPrimary) {
  loggerBanner(workerCount);

  let shuttingDown = false;

  cluster.setupPrimary({ exec: require.resolve('./index.js') });

  for (let i = 0; i < workerCount; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    if (shuttingDown) return;
    const label = `worker#${worker.id}(pid=${worker.process.pid})`;
    if (signal) {
      console.error(`[cluster] ${label} 收到信号 ${signal} 退出，将补 fork`);
    } else {
      console.error(`[cluster] ${label} 以退出码 ${code} 退出，将补 fork`);
    }
    cluster.fork();
  });

  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(
      `[cluster] 收到 ${signal}，向 ${Object.keys(cluster.workers).length} 个 worker 转发`
    );
    for (const worker of Object.values(cluster.workers)) {
      worker.kill(signal);
    }
    // primary 自身不等 worker 排空完成（worker 的 gracefulShutdown 各自决定退出时机；
    // 等全部退出再退 primary 会把总关停时间拖成最慢 worker 的尾巴，且容器编排器
    // 的宽限期只看进程树是否结束）。留一个兜底定时器，防止个别 worker 卡死时
    // primary 永久驻留。
    const graceMs = parseInt(process.env.CLUSTER_SHUTDOWN_GRACE_MS, 10);
    setTimeout(
      () => process.exit(0),
      Number.isFinite(graceMs) && graceMs > 0 ? graceMs : 10000
    ).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
} else {
  // worker：正常加载应用入口（index.js 内含 listen 与优雅关闭）
  require('./index');
}

function loggerBanner(count) {
  // primary 不加载 winston（避免多进程日志文件争抢），只用 stdout 摘要；
  // worker 各自的 logger 在 index.js 内初始化。
  console.log(`[cluster] primary pid=${process.pid} fork ${count} workers`);
  if (!process.env.REDIS_URL) {
    console.error(
      '[cluster] 警告：未配置 REDIS_URL，多进程下审计哈希链/限流计数/缓存失效将降级（见启动日志的失效清单）'
    );
  }
}
