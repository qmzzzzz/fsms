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
 *   5. 验证码存储（services/captchaService.js）、统计缓存（services/statsCache.js）、
 *      告警频控（services/securityAlert.js 的 alertRateLimit Map）、
 *      WebSocket 客户端表（services/websocketService.js）
 *      均为进程内 Map → 跨进程不可见，一次性消费/风暴抑制不成立。
 *   6. 安全与数据面的进程内缓存（无失效广播者，多实例下各自为政到一个 TTL）：
 *      IP 封禁缓存（middleware/security.js）、部门成员缓存（services/auditScopeFilter.js）、
 *      配置读取缓存（models/SystemConfig.js，TTL 30s）、名单快照（models/IPBlacklist.js，TTL 10s）、
 *      告警去重表（services/auditMonitor.js，多实例会重复告警）。
 *      前两项直接影响**鉴权与数据范围判定**，不是"数字抖动"那么轻。
 *
 * 刻意**不在**本清单：MFA 重放计数。它一度被写进本注释，属名实不符——
 * 现由 `User.mfaLastCounter` + `mfaService.claimTotpWindow` 的 Mongo 原子认领实现
 * （状态在库、跨进程天然一致），不是进程内 Map。把它列进来会让运维在
 * 多实例部署时误以为"重放防护会失效"，从而漏掉真正失效的那几项。
 *
 * 本清单的唯一事实来源是下方 SINGLE_PROCESS_DEPENDENCIES 数组（本注释只是导读）。
 * 完整性由 src/tests/constants/singleProcessInventoryCompleteness.test.js 钉住：
 * 新增进程内状态而忘记登记，会在该用例变红。
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
    module: 'services/captchaService.js',
    mechanism: '验证码内存表（localStore Map）',
    impact: '一次性消费不成立（换进程可复用同一验证码）',
    redisExternalized: true,
  },
  {
    module: 'services/statsCache.js',
    mechanism: '统计缓存 Map',
    impact: '各进程数据不一致（仅表现为数字抖动）',
    // 与 middleware/auth.js 的 userCache 同一模式：缓存本体在进程内，
    // 失效经 sharedCache 广播（statsCache.js:114 publishInvalidate / :124 onInvalidate）。
    // 此前漏标 ⇒ Redis 就绪时仍被报成"将静默降级"，属假警报
    // （假警报会训练运维忽略真信号，见文件头第 3 条判据的同类教训）。
    redisExternalized: true,
  },
  {
    module: 'services/securityAlert.js',
    mechanism: 'alertRateLimit Map',
    impact: '风暴抑制按进程计，告警量被放大',
  },
  {
    module: 'services/rateLimitEscalation.js',
    mechanism: '限流升级触发计数（令牌桶 Map，压力升序淘汰）',
    // 计数留在进程内是**刻意的**（见该文件头「仍保留的既定取舍」）：多实例下各实例只
    // 统计自己分到的 429，实际封禁阈值 = 配置阈值 × 实例数 —— 少封不误封；
    // 429 拦截本身由限流器自己的共享存储跨实例保证，不受此影响。
    // 被容量淘汰掉的条目同理只影响本实例的判定。
    impact: '多实例下升级封禁阈值按实例数摊薄（少封不误封，by design）',
  },
  {
    module: 'services/ipLocationService.js',
    mechanism: '归属地结果缓存（resultCache Map，FIFO 上限 2048）',
    impact: '纯派生缓存、无失效语义，各进程独立仅为性能，不影响正确性',
  },
  {
    module: 'constants/timezone.js',
    mechanism: 'Intl formatter 时区缓存（dayPartsFmtCache Map，上限 32）',
    impact: '纯派生缓存（按时区构造 formatter），无跨进程语义',
  },
  {
    module: 'utils/metricsRuntime.js',
    mechanism: 'readyz 判定计数（readyzChecks Map）',
    impact: '各进程独立计数（/metrics 的 readyz 观测值按进程呈现）',
  },
  {
    module: 'middleware/security.js',
    mechanism: 'IP 封禁缓存（ipBlockCache Map）',
    impact: 'A 实例封禁的 IP 在 B 实例仍放行，直到 B 自己的 TTL 到期',
  },
  {
    module: 'services/auditScopeFilter.js',
    mechanism: '部门成员缓存（deptMembersCache Map）',
    impact: '数据范围过滤按各进程缓存判定，改部门成员后其余进程延迟生效',
  },
  {
    module: 'models/SystemConfig.js',
    mechanism: '配置读取缓存（getCache Map + 注册开关布尔缓存，TTL 30s）',
    impact: '改配置后各进程最长 30s 仍按旧值判定（如关闭公开注册后仍可注册）',
  },
  {
    module: 'models/IPBlacklist.js',
    mechanism: '名单快照缓存（snapshotCache Map，TTL 10s）',
    impact: 'A 实例封禁的 IP 在 B 实例最长 10s 内仍放行，封禁存在时间窗',
  },
  {
    module: 'services/userPermissionService.js',
    mechanism: '权限缓存（permCache Map，配失效广播）',
    impact: '缓存本体在进程内，靠 sharedCache 广播失效；Redis 未就绪时不跨进程',
    redisExternalized: true,
  },
  {
    module: 'services/sessionService.js',
    mechanism: '会话缓存 Map（sessionCache，配 `sesscache:` 失效广播）',
    impact: '缓存本体在进程内，靠 sharedCache 广播失效；Redis 未就绪时不跨进程',
    redisExternalized: true,
  },
  {
    module: 'services/reportDashboardService.js',
    mechanism: '仪表盘缓存（dashboardCache Map，配失效广播）',
    impact: '缓存本体在进程内，靠 sharedCache 广播失效；Redis 未就绪时不跨进程',
    redisExternalized: true,
  },
  {
    module: 'services/auditMonitor.js',
    mechanism: '告警去重表（notifiedDayByDimension Map）',
    impact: '各进程各自去重，同一事件按实例数重复告警',
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

  // 先判 Deployment 形态：<name>-<rsHash 8~10>-<5 位随机>。
  // 必须**先于**下面的「末段纯数字」规则，否则会把单副本 Deployment 误判成多副本：
  // K8s 的 Pod 名随机后缀取自元音回避字母表 `bcdfghjklmnpqrstvwxz23456789`，
  // **含数字**，所以 `api-7d9f8c7b6-23459` 的末段是 5 位纯数字，若先跑序号规则
  // 就会得出 ordinal=23459 > 0 ⇒ strong ⇒ 每次启动打一条 error 级「检测到多实例」
  // 并列出失效清单，而实际只有一个副本（假警报会训练运维忽略真信号）。
  // 反向误伤可忽略：StatefulSet 的 ordinal 从 0 连续编号，能凑成
  // `-<8~10>-<5>` 形态要求上万副本，且其 Pod 名末段不会是 5 位以上数字。
  const dep = /-[a-z0-9]{8,10}-[a-z0-9]{5}$/.exec(lower);
  if (dep) return { podLike: true, ordinal: null, strong: false };

  // 强信号：StatefulSet 序号（末段为纯数字，且非 0 才算多副本）
  const sts = /-([0-9]+)$/.exec(lower);
  if (sts) {
    const ordinal = Number(sts[1]);
    // 序号 0 是首个 Pod，单副本时同样成立，不构成多副本证据。
    // 且"主机名以 -数字 结尾"太常见（CI runner 编号 `runner-14`/`ci-agent-3`、
    // EC2 私有 DNS 名 `ip-10-0-1-23`、`host-2024`），只看形状会让单实例机器
    // 每次启动都报一条 error 级"检测到多实例运行迹象"+整页失效清单——正是本文件
    // 开头警告的"假警报训练运维忽略真信号"。
    // 故形状之外再要一个集群事实判据：kubelet 会给每个 Pod 注入
    // KUBERNETES_SERVICE_HOST（它与"编排器没导出模板变量"那条顾虑无关，不是模板变量）。
    // 不存在形状规则能救这件事：`ci-agent-3` 与 `app-1` 形状完全同构。
    const inCluster = Boolean(process.env.KUBERNETES_SERVICE_HOST);
    return { podLike: true, ordinal, strong: inCluster && ordinal > 0 };
  }

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
