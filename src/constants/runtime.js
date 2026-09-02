/**
 * 运行时拓扑假设的集中声明（P3-19）
 *
 * 背景：仓库里十余处实现隐含「本服务只有一个 Node 进程」这一前提，
 * 却分散在各文件的注释里，没有任何集中声明与启动期校验。一旦有人
 * 加上 `pm2 -i 4` 或把副本数调到 2，下列机制会**静默**失效：
 *
 *   1. 审计哈希链（utils/auditChain.js）
 *      进程内互斥锁 + 内存链尾指针。多进程各自维护链尾 → 必然分叉，
 *      append-only 防篡改整体失效（最严重，且校验脚本才能发现）。
 *   2. 审计缓冲（services/auditBuffer.js）
 *      内存队列 + 本地 WAL 文件。多进程写同一 WAL 路径 → 行交错、
 *      前缀裁剪按各自条数进行 → 账目错乱、可能丢行。
 *   3. 限流（middleware/rateLimit.js，express-rate-limit 默认 MemoryStore）
 *      每进程独立计数 → 实际配额被放大 N 倍，暴力破解防护按比例削弱。
 *   4. 用户/权限缓存（middleware/auth.js invalidateUserCache）
 *      失效只作用于当前进程 → 禁用用户/改权限后其余进程最长 60s 仍放行。
 *   5. 验证码存储（captchaStore）、统计缓存（statsCache）、
 *      告警频控（securityAlert alertRateLimit Map）、
 *      MFA 重放计数、WebSocket 客户端表（websocketService）
 *      均为进程内 Map → 跨进程不可见，一次性消费/风暴抑制不成立。
 *
 * 本模块把这些假设写成可执行的断言：启动期检测多进程迹象并给出
 * 明确的失效清单，而不是让运维在数据不一致时才发现。
 *
 * 要真正支持多实例，需把上述状态外置（Redis/Mongo），逐项迁移；
 * 在完成之前，部署拓扑必须保持单进程。
 */

const logger = require('../utils/logger');

/** 依赖单进程假设的机制清单（供日志与文档引用，避免再次散落）
 *
 * `redisExternalized: true` 表示该机制在配置 REDIS_URL（共享缓存就绪）后
 * 已外置为跨实例一致：审计链锁与链尾（A-1）、限流计数（R-3 rate-limit-redis）、
 * 用户/权限缓存失效广播（L-4）、验证码存储。启动校验据此把它们与「仍单进程」
 * 的机制区分开，避免 Redis 已就绪时仍误报这些项会失效。
 */
const SINGLE_PROCESS_DEPENDENCIES = Object.freeze([
  {
    module: 'utils/auditChain.js',
    mechanism: '哈希链互斥锁 + 内存链尾',
    impact: '多进程必然链分叉，append-only 防篡改失效',
    redisExternalized: true,
  },
  {
    module: 'services/auditBuffer.js',
    mechanism: '内存缓冲 + 本地 WAL',
    impact: '多进程写同一 WAL，前缀裁剪账目错乱可能丢行',
  },
  {
    module: 'middleware/rateLimit.js',
    mechanism: 'express-rate-limit MemoryStore',
    impact: '每进程独立计数，实际配额被放大 N 倍',
    redisExternalized: true,
  },
  {
    module: 'middleware/auth.js',
    mechanism: '用户缓存 invalidateUserCache',
    impact: '缓存失效不跨进程，禁用/改权限最长延迟 60s',
    redisExternalized: true,
  },
  {
    module: 'utils/captchaStore',
    mechanism: '验证码内存表',
    impact: '一次性消费不成立（换进程可复用同一验证码）',
    redisExternalized: true,
  },
  {
    module: 'services/statsCache.js',
    mechanism: '统计缓存 Map',
    impact: '各进程数据不一致（仅表现为数字抖动）',
  },
  {
    module: 'services/securityAlert.js',
    mechanism: 'alertRateLimit Map',
    impact: '风暴抑制按进程计，告警量被放大',
  },
  {
    module: 'services/websocketService.js',
    mechanism: '客户端连接表',
    impact: '跨进程无法向指定用户推送（需 socket.io adapter）',
    redisExternalized: true,
  },
]);

/**
 * 检测是否存在多进程运行迹象
 *
 * 判据（任一命中即视为可疑）：
 *   - PM2 注入的 instances / NODE_APP_INSTANCE
 *   - Node 原生 cluster 的 worker 标记
 *   - 显式声明的 WEB_CONCURRENCY / CLUSTER_WORKERS > 1
 * @returns {{suspected: boolean, reasons: string[]}}
 */
function detectMultiProcess() {
  const reasons = [];

  // PM2 cluster 模式会注入 NODE_APP_INSTANCE（0..N-1）与 instances
  const pm2Instances = Number(process.env.instances);
  if (Number.isFinite(pm2Instances) && pm2Instances > 1) {
    reasons.push(`PM2 instances=${pm2Instances}`);
  }
  if (process.env.NODE_APP_INSTANCE !== undefined && process.env.NODE_APP_INSTANCE !== '0') {
    reasons.push(`NODE_APP_INSTANCE=${process.env.NODE_APP_INSTANCE}（非首实例）`);
  }

  // Node 原生 cluster：worker 进程的 isPrimary 为 false
  try {
    const cluster = require('cluster');
    if (cluster.isWorker) reasons.push('运行于 cluster worker 进程');
  } catch (_) {
    /* 环境不支持 cluster，忽略 */
  }

  for (const key of ['WEB_CONCURRENCY', 'CLUSTER_WORKERS']) {
    const n = Number(process.env[key]);
    if (Number.isFinite(n) && n > 1) reasons.push(`${key}=${n}`);
  }

  return { suspected: reasons.length > 0, reasons };
}

/**
 * 启动期校验单进程假设
 *
 * 不阻断启动：多实例部署下服务本身可用，只是上述机制降级；
 * 强行退出反而可能让运维在不知情时失去服务。因此以 error 级日志
 * 列出确切的失效清单，让问题在启动日志里就无法被忽略。
 *
 * 若共享缓存（Redis）已就绪，标记为 redisExternalized 的机制已外置为
 * 跨实例一致，不再列入失效清单，只单列说明；仍单进程的机制照常告警。
 *
 * @returns {{suspected: boolean, reasons: string[]}}
 */
function assertSingleProcessAssumptions() {
  const result = detectMultiProcess();
  if (!result.suspected) {
    logger.debug('运行时拓扑检查：未检测到多进程迹象，单进程假设成立');
    return result;
  }

  // 懒加载：避免在模块加载期耦合共享缓存（其初始化在启动流程中显式完成）
  let redisReady = false;
  try {
    redisReady = require('../services/sharedCache').isRedisEnabled();
  } catch (_) {
    /* 共享缓存不可用时按未就绪处理 */
  }

  const stillSingle = SINGLE_PROCESS_DEPENDENCIES.filter(
    (d) => !(redisReady && d.redisExternalized)
  );
  const externalized = redisReady
    ? SINGLE_PROCESS_DEPENDENCIES.filter((d) => d.redisExternalized)
    : [];

  let message = `检测到多进程/多实例运行迹象（${result.reasons.join('；')}），`;
  if (stillSingle.length > 0) {
    message +=
      '但本服务的以下机制依赖单进程假设，将静默降级：\n' +
      stillSingle
        .map((d, i) => `  ${i + 1}. ${d.module} —— ${d.mechanism} → ${d.impact}`)
        .join('\n');
  } else {
    message += '且共享缓存（Redis）已就绪，相关状态均已外置：';
  }
  if (externalized.length > 0) {
    message +=
      '\n以下机制已通过共享缓存外置，跨实例一致：' + externalized.map((d) => d.module).join('、');
  }
  if (stillSingle.length > 0) {
    message +=
      '\n请改为单进程部署（水平扩展用多容器 + 外置状态），' +
      '或先完成上述状态的外置改造（Redis/Mongo）。';
  }

  logger.error(message);
  return result;
}

module.exports = {
  SINGLE_PROCESS_DEPENDENCIES,
  detectMultiProcess,
  assertSingleProcessAssumptions,
};
