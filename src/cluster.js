'use strict';

/**
 * 可选的多进程入口：CLUSTER_WORKERS>1 时 primary fork N 个 worker，否则透传单进程。前提是已外置 Redis——审计哈希链写序、限流计数、权限缓存失效假定单进程（见 constants/runtime.js），detectMultiProcess 会告警、/readyz 会不就绪。多副本部署（K8s replicas / compose 实例数）优于本文件；PM2 cluster 等效。
 * worker 异常退出由 primary 补 fork；SIGTERM/SIGINT 先停 fork 再转发，worker 的 gracefulShutdown 负责排空，primary 以 CLUSTER_SHUTDOWN_GRACE_MS 兜底。
 */

const cluster = require('cluster');
const { hydrateSecretsFromFiles } = require('./config/secrets');

hydrateSecretsFromFiles();

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

  // 崩溃循环退避：worker 活过 CRASH_STABLE_MS 视为稳定，连发计数清零；短命连发按指数退避补 fork（1s 起步、封顶 30s）。没有这一层时，一段必崩的启动代码或坏配置会把 fork/die 打成全速空转（每秒数次的进程创建 + 日志风暴），而退避只是把同样的"持续补 fork"契约放慢——永不清零重试次数，也不放弃。
  const CRASH_STABLE_MS = 10000;
  const BACKOFF_BASE_MS = 1000;
  const BACKOFF_MAX_MS = 30000;
  let crashStreak = 0;
  const forkedAt = new Map(); // worker.id → fork 时刻（算存活时长用）

  cluster.on('fork', (worker) => {
    forkedAt.set(worker.id, Date.now());
  });

  cluster.on('exit', (worker, code, signal) => {
    // 退避判定只看存活时长：活过稳定窗说明是偶发崩溃（清零）；短命退出计连发。先算 uptime 再清 Map——顺序反了就永远查不到 fork 时刻，退避整个失效。
    const forkTime = forkedAt.get(worker.id);
    forkedAt.delete(worker.id);
    if (shuttingDown) return;
    const label = `worker#${worker.id}(pid=${worker.process.pid})`;
    if (signal) {
      console.error(`[cluster] ${label} 收到信号 ${signal} 退出，将补 fork`);
    } else {
      console.error(`[cluster] ${label} 以退出码 ${code} 退出，将补 fork`);
    }
    const uptime = Number.isFinite(forkTime) ? Date.now() - forkTime : CRASH_STABLE_MS;
    crashStreak = uptime >= CRASH_STABLE_MS ? 0 : crashStreak + 1;
    const delayMs = Math.min(BACKOFF_BASE_MS * 2 ** (crashStreak - 1), BACKOFF_MAX_MS);
    if (delayMs <= 0) {
      cluster.fork();
      return;
    }
    console.error(
      `[cluster] 短命连发 ×${crashStreak}（存活 ${uptime}ms < 稳定窗 ${CRASH_STABLE_MS}ms），` +
        `${delayMs}ms 后补 fork`
    );
    setTimeout(() => {
      // 等待期间可能收到关停信号——不检查的话退避定时器会逆着 shutdown 再 fork 一个
      if (!shuttingDown) cluster.fork();
    }, delayMs);
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
    // primary 自身不等 worker 排空完成（worker 的 gracefulShutdown 各自决定退出时机；等全部退出再退 primary 会把总关停时间拖成最慢 worker 的尾巴，且容器编排器的宽限期只看进程树是否结束）。留一个兜底定时器，防止个别 worker 卡死时 primary 永久驻留。
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
