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
 * 解析 Pod 序号（K8s StatefulSet 的 hostname 约定：<name>-<ordinal>）
 *
 * 为什么需要这条判据：Deployment 的 `replicas > 1` 由 ReplicaSet 命名 Pod
 * （形如 `<deployment>-<rs-hash>-<5位随机>`），**不注入任何环境变量**，
 * 因此上方 6 条判据（PM2 / cluster / WEB_CONCURRENCY / INSTANCE_COUNT /
 * REPLICAS / NODE_APP_INSTANCE）在纯 K8s 单容器多副本场景下**全部落空**，
 * 检测静默失效——而这正是审计哈希链分叉、限流配额放大最可能的生产形态。
 *
 * 判据分两档，避免把普通单副本 Pod 误判：
 *   - 强信号：StatefulSet 序号 > 0（`app-0` / `app-1` …）。同一 StatefulSet
 *     的序号互不相同，序号非 0 即可确定存在同族其他 Pod。
 *   - 弱信号：Deployment 形态的 `<name>-<rsHash>-<5位>`。这个形态在**单副本**
 *     时也成立，故本身不能证明多副本，只能说明「像是由编排器管理的 Pod」。
 *     调用方按需决定是否上报（见 detectMultiProcess 的 k8sPodLike 字段）。
 *
 * 为何读 `os.hostname()` 而不是 `process.env.HOSTNAME`：容器内两者通常相同，
 * 但 hostname 在本地/裸机也能拿到真实值，且不依赖编排器是否导出该变量——
 * 本判据必须在「编排器什么都没导出」时仍能工作。
 *
 * @param {string} [hostname] 待解析的 hostname，默认取 os.hostname()
 * @returns {{podLike: boolean, ordinal: number|null, strong: boolean}}
 */
function parsePodOrdinal(hostname) {
  let host = hostname;
  if (host === undefined) {
    try {
      host = require('os').hostname();
    } catch (_) {
      return { podLike: false, ordinal: null, strong: false };
    }
  }
  if (typeof host !== 'string' || host.length === 0) {
    return { podLike: false, ordinal: null, strong: false };
  }

  const lower = host.toLowerCase();

  // 强信号：StatefulSet 序号（末段为纯数字，且非 0 才算多副本）
  const sts = /-([0-9]+)$/.exec(lower);
  if (sts) {
    const ordinal = Number(sts[1]);
    // 序号 0 是首个 Pod，单副本时同样成立，不构成多副本证据
    return { podLike: true, ordinal, strong: ordinal > 0 };
  }

  // 弱信号：Deployment 形态 <name>-<rsHash>-<5位随机>
  // rsHash 为 8~10 位字母数字，末段为 5 位字母数字
  const dep = /-[a-z0-9]{8,10}-[a-z0-9]{5}$/.exec(lower);
  if (dep) return { podLike: true, ordinal: null, strong: false };

  return { podLike: false, ordinal: null, strong: false };
}

/**
 * 检测是否存在多进程运行迹象
 *
 * 判据（任一命中即视为可疑）：
 *   - PM2 注入的 instances / NODE_APP_INSTANCE
 *   - Node 原生 cluster 的 worker 标记
 *   - 显式声明的 WEB_CONCURRENCY / CLUSTER_WORKERS > 1
 *   - INSTANCE_COUNT / REPLICAS > 1（编排器显式声明的副本数）
 *   - K8s StatefulSet Pod 序号 > 0（见 parsePodOrdinal；Deployment 形态
 *     属弱信号，仅置 k8sPodLike 提示，不计入 suspected）
 *
 * @param {{hostname?: string}} [opts] 仅测试使用：注入 hostname 以验证判据
 * @returns {{suspected: boolean, reasons: string[], k8sPodLike: boolean}}
 */
function detectMultiProcess(opts = {}) {
  const reasons = [];

  for (const key of ['INSTANCE_COUNT', 'REPLICAS']) {
    const declared = Number(process.env[key]);
    if (Number.isFinite(declared) && declared > 1) {
      reasons.push(`${key}=${declared}`);
    }
  }

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

  // K8s 兜底判据：Deployment 的 replicas>1 不注入任何环境变量，
  // 只能从 Pod 名推断（见 parsePodOrdinal 的两档说明）
  const pod = parsePodOrdinal(opts.hostname);
  if (pod.strong) {
    reasons.push(`K8s Pod 序号=${pod.ordinal}（StatefulSet 非首副本）`);
  }

  return { suspected: reasons.length > 0, reasons, k8sPodLike: pod.podLike };
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
  parsePodOrdinal,
  detectMultiProcess,
  assertSingleProcessAssumptions,
};
