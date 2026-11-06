const crypto = require('crypto');
const logger = require('./logger');
const { readPositiveNumberEnv } = require('./envNumber');

// 共享缓存门面（A-1）：提供跨实例分布式锁与共享链尾指针的存取。
// 仅依赖 logger，无循环依赖，可顶层引入。未配置 REDIS_URL 时
// isRedisEnabled() 恒为 false，下列分布式路径全部回退为原进程内语义。
const sharedCache = require('../services/sharedCache');
const fence = require('./auditChainFence');
const {
  PAYLOAD_FIELDS_V1,
  PAYLOAD_FIELDS_V2,
  PAYLOAD_FIELDS_V3,
  PAYLOAD_FIELDS_V4,
  PAYLOAD_FIELDS_V5,
  PAYLOAD_FIELDS_V6,
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
  computeHash,
} = require('./auditChainPayload');
// method 的取值全集与降级规则只有一份（constants/audit.js）：schema 的 set 与这里的
// 批量哈希用同一个函数，否则「被哈希的形态」与「落库的形态」会在铸造那一步分叉。
// ip / userAgent / username 同族（上界 + 控制字符中和），见各自的 gate 注释。
const {
  auditMethodOrUndefined,
  auditIpOrUndefined,
  auditUserAgentOrUndefined,
  cleanAuditUsername,
} = require('../constants/audit');

// A-1 共享态键名：配置 REDIS_URL 时，链尾与互斥锁外置到共享缓存，
// 多实例在分布式锁内读写同一链尾，消除「各实例独立链尾 → 必然分叉」；
// 未配置时全部回退进程内语义（与历史行为一致）
const CHAIN_TAIL_KEY = 'audit:chain-tail';
const CHAIN_LOCK_KEY = 'audit:chain-lock';
// 链尾为空（null）时的哨兵值：用于区分「共享缓存键不存在（未初始化，需回 DB 读）」
// 与「链尾已被确认初始化为 null（尚无任何审计记录）」。sharedCache.get 对这两种
// 情况都返回 null，必须用 sentinel 区分，否则首条记录后每次 get 都会误判为未初始化。
const EMPTY_SENTINEL = sharedCache.EMPTY_SENTINEL;

/**
 * 哈希链 payload 版本化：
 *  v1（历史）：仅覆盖 9 个核心字段 —— 存量数据必须继续用 v1 口径校验，否则全部误报断链；
 *  v2（历史）：全量业务字段纳入哈希保护，堵住「篡改 success/riskLevel/userAgent 等
 *             未覆盖字段不触发 hash_mismatch」的旁路。
 *             **已知缺陷**：批量路径（auditBuffer → chainBatch → insertMany）在
 *             计算 hash 时未补 schema 默认值，落库后 riskLevel/riskFactors 由
 *             Mongoose 填成 'low'/[]，重算必然失配（实测 4182/4407 条）。
 *             逐条 create 路径（pre-save，默认值已填充）不受影响——
 *             因此 v2 这个版本号本身是歧义的，同一版本号下存在两种 payload 口径。
 *  v3：与 v2 字段集完全相同，但**语义上保证**默认值在算 hash 前已补齐
 *             （见 PAYLOAD_SCHEMA_DEFAULTS）。版本号的唯一作用是消除 v2 的歧义：
 *             校验端见到 v3 即可施加严格单一口径，不再需要「试两种」。
 *  v4（历史）：在 v3 的 25 字段上补进 targetType / targetId / dataType /
 *             description。这四个字段是加到 schema 的（举报对象、被查看的
 *             敏感数据类型、操作描述），当时未同步进 payload 白名单——落库后可被
 *             任意改写而 hash/hmac/链接三层都不会红。校验端按 doc.hashVersion
 *             选择口径，v1~v3 的复算方式逐字保持不变（旧数据不会因新增版本而集体报断链）。
 *  v5/v6：refusalReason（4xx 归因证据）与请求/响应头、响应正文取证材料的增量
 *             及冻结理由见 auditChainPayload.js 的对应版本段——此处不复述，
 *             避免第三次出现「三处各说各话」的漂移载体。
 * 新写入一律带 hashVersion=CURRENT_PAYLOAD_VERSION（当前值见 auditChainPayload.js，
 * 不在此复述）；校验端按 doc.hashVersion 选择口径。
 * 存量 v1~v3 记录的这四字段**无法追认**（重签只能对当前值重新摘要，不能证明历史值未被改）；
 * 需要把它们升到 v4 时用 scripts/resign-audit-chain-v3.js（该脚本按当前版本常量重签）。
 */

function getHmacSecret() {
  try {
    return require('../config').hmacSecret || '';
  } catch {
    return process.env.HMAC_SECRET || '';
  }
}

function computeHmac(hash) {
  const secret = getHmacSecret();
  if (!secret) return null;
  return crypto.createHmac('sha256', secret).update(hash, 'utf8').digest('hex');
}

/** 是否配置了 HMAC 密钥（校验脚本据此决定是否执行 hmac 校验） */
const isHmacConfigured = () => !!getHmacSecret();

// 链尾初始化口径（谁是尾、窗口反查、兜底）抽到 utils/auditChainTail.js：
// 本文件顶 max-lines 棘轮阈值，而那块是纯读侧判据，与链尾指针/分布式锁无关。
const { getLatestHash } = require('./auditChainTail');

// ================= 哈希链并发防护 =================
// pre-save（逐条 create）与 auditBuffer.flush（批量 insertMany）原先各自
// "读 DB 链尾 → 计算 → 写入"，两步之间可交错，导致两条记录引用同一 prevHash
// 形成分叉，削弱防篡改验证可信度。以下用「进程内互斥 + 内存链尾指针」串行化
// 链尾推进：读尾→计算→推进尾 原子化，落库异步跟上即可。
//
// A-1：配置 REDIS_URL 时，上面的互斥与链尾进一步外置为跨实例分布式锁 +
// 共享链尾（见 withChainLock / getChainTail），消除多实例/多 worker 各自维护
// 独立链尾导致的必然分叉。未配置时仍为单进程语义，该假设在
// constants/runtime.js 集中声明，启动期由 assertSingleProcessAssumptions() 校验。

let chainTail = null; // 内存中最新链尾 hash（含尚未落库的追加）
let chainTailLoaded = false; // 是否已从 DB 初始化过链尾
let chainLock = Promise.resolve();
// B-L4/B-L5（改后审计）：链尾代际——锁超时（持有超时/前驱等待超时）递增代际，
// 超时的「僵尸 fn」稍后调用 advanceChainTail 时因代际过期被跳过，
// 不再用过期 hash 覆写已重同步的链尾；代价是下一次操作从 DB 重同步
let chainGeneration = 0;
// 僵尸写入冻结窗口的状态机在 auditChainFence（本文件受体积棘轮约束）：
// 超时后本地拒绝新写入、跨实例保持并续租锁，僵尸落定重同步后再解冻。
/**
 * F-184b：共享链尾是否**不可信**（上一次推进只写进了本进程内存、Redis 没收）。
 *
 * 为什么必须是显式状态而不是"记一条日志就完事"：`sharedCache.set` 在 Redis 抛错时
 * 回退写本地内存，对本进程自洽；但共享层那个键仍是**旧值**。Redis 恢复后
 * `getChainTail` 会优先读共享层 ⇒ 拿到旧尾 ⇒ 在旧尾上另起一条链 ⇒ "一父两子"的分叉。
 * 而链接性判据原本只做成员测试，这种分叉当场仍报 `intact:true`（已由 F-184a 补上检测）。
 * 置位后本进程改为**每批从 DB 读权威链尾**（DB 里就是真实尾部），直到某次写入确认落到 Redis。
 */
let sharedTailUntrusted = false;

/** 非法数值配置的告警（本变量只在模块加载期读一次，无需去重） */
function invalidEnvWarning(name, raw, fallback) {
  logger.error(
    `${name}=${JSON.stringify(raw)} 非法（须为正的毫秒数），已按默认 ${fallback}ms 处理；负值或零会让审计链锁立即判定超时 ⇒ 链尾永不推进、全部审计降级为无哈希落库`
  );
}

// 锁持有超时（毫秒）：fn 悬挂时不能让整条审计链永久排队
//
// 原为 `Number(process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS) || 15000`，而**负值是真值**
// ——`-1` 会原样生效，于是 `Promise.race([prev, timeout])` 与 `race([fn, timeout])`
// 双双立即超时：每次 withChainLock 都「标记链尾失效 + 抛错」，链尾永不推进，
// 所有审计记录降级为 legacy（无 hash）落库——防篡改承诺整体失效，
// 而日志里只会看到一条条"锁持有超时"，看不出根因是配置笔误。
// 现与 swagger/config/retention 同一口径：只接受有限正数，否则回落默认并告警。
// 读取为每次现读（2026-11-07）：模块常量会让先 require 者定值钉死后续套件（31337 实测）。
const chainLockTimeoutMs = () =>
  readPositiveNumberEnv('AUDIT_CHAIN_LOCK_TIMEOUT_MS', 15000, {
    onInvalid: invalidEnvWarning,
  });

/**
 * 互斥执行临界区（fn 内为「读链尾→计算→推进链尾」）：fn 完成前，后续
 * withChainLock 调用者排队等待，保证追加不交错。
 *
 * A-1 接线：先持有**进程内锁**（Promise 队列，单进程兜底），再在
 * `sharedCache.isRedisEnabled()` 时叠加**跨实例分布式锁**（Redis NX）。
 * 未配置 REDIS_URL 时 `isRedisEnabled()` 为 false，完全走进程内语义，
 * 行为与历史一致。
 *
 * 分布式锁拿不到（超时/Redis 抖动）时**绝不无锁推进链尾**——那必然造成
 * 链分叉。改为标记链尾失效并抛错，由调用方按既有超时路径处理：
 * auditBuffer.flush 回退缓冲重试（WAL 兜底），AuditLog.create 降级为
 * legacy（无 hash）落库。审计不丢、链不分叉。
 *
 * 超时保护：原实现无超时——一旦 fn 因网络挂起（Mongo 无响应且驱动
 * 未超时）永不 settle，chainLock 永远不释放，其后**所有**审计写入无限排队，
 * 表现为「服务正常但审计彻底停摆」，且无任何日志线索。
 * 现在超时即释放**进程内排队**并让本批以错误回退（缓冲重试 / legacy 落库），
 * 不让审计链整体死锁；但 fn 本身无法取消，超时后它仍是「僵尸写入」。
 * 因此超时同时冻结后续链写入，直到僵尸 fn 落定并完成 DB 重同步
 * （本地 chainFrozen + 跨实例保持并续租分布式锁），否则后一批会与僵尸
 * 从同一父哈希各写一条 —— 链分叉不可自动修复，比一次降级严重得多。
 */
function withChainLock(fn) {
  const prev = chainLock;
  let release;
  chainLock = new Promise((r) => {
    release = r;
  });

  // 上一持有者也受超时约束：prev 挂起时不能拖住本次调用
  //
  // F-192：这枚定时器必须在前驱正常放行时被 clear——Promise.race 只决定谁的结果被采用，
  // 不会取消输掉的那一支。原实现于是把下面注释承诺的"前驱超时放行时"才做的失效标记，
  // 变成了"每一次 withChainLock 都在 CHAIN_LOCK_TIMEOUT_MS 后无条件执行一次"：
  // 内存链尾自我作废（每批都回库重读尾），代际凭空递增，B-L4 的僵尸守卫因此
  // 把合法批次的 advanceChainTail 判成僵尸并跳过（实测：无争用两次调用后静置，
  // 告警"审计链尾推进被跳过（代际 0 已过期，当前 1）"）。
  let waitTimer = null;
  const clearWaitTimer = () => {
    if (waitTimer) clearTimeout(waitTimer);
  };
  const waitPrev = Promise.race([
    prev,
    new Promise((resolve) => {
      waitTimer = setTimeout(() => {
        // B-L5：前驱超时放行时同样标记链尾失效并递增代际——
        // 重叠的后继与挂起的前驱，其 advanceChainTail 均因代际过期被跳过，
        // 直到任一操作从 DB 重同步；代价是一次额外重同步。
        // 前驱的 fn 可能仍在飞（它就是挂起本身）：冻结后继写入，等前驱落定。
        // 通常情况下前驱自己的持锁超时先触发并负责解冻；这里兜住定时器调度乱序。
        chainTailLoaded = false;
        chainTail = null;
        chainGeneration += 1;
        fence.freeze();
        resolve();
      }, chainLockTimeoutMs());
      if (waitTimer.unref) waitTimer.unref();
    }),
  ]);
  // 两个分支都 clear：prev 先 settle 是常见路径（这条修复的正文），定时器自己跑完时
  // clear 是空操作。用 then(fn, fn) 而不是 finally——finally 派生的那支没人接 reject，
  // prev 一旦异常就冒出 unhandledRejection。
  waitPrev.then(clearWaitTimer, clearWaitTimer);

  return waitPrev
    .then(async () => {
      // 僵尸冻结窗口：上一持有者超时后 fn 仍在飞行，链尾状态未知。
      // 此时进入临界区会与僵尸共享同一父哈希 ⇒ 分叉，直接失败让调用方回退。
      fence.check();

      // A-1：进程内锁已就绪后叠加跨实例分布式锁
      let distLock = null;
      if (sharedCache.isRedisEnabled()) {
        distLock = await sharedCache.acquireLockBlocking(
          CHAIN_LOCK_KEY,
          chainLockTimeoutMs(),
          chainLockTimeoutMs()
        );
        if (!distLock) {
          // 拿不到跨实例锁：标记链尾失效 + 抛错走降级，绝不无锁推进链尾。
          // resyncChainTail 永不 reject（内部吞错），fire-and-forget 即可
          resyncChainTail();
          chainTailLoaded = false;
          chainTail = null;
          throw new Error(
            `审计链分布式锁获取超时（${chainLockTimeoutMs()}ms），本批回退，链尾已标记失效待重同步`
          );
        }
      }

      let timer = null;
      let timedOut = false;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          // 链尾可能已被 fn 部分推进，无法判断其状态 → 标记失效，下次从 DB 重同步；
          // B-L4：同时递增代际——fn 的 advanceChainTail 因代际过期被跳过
          chainTailLoaded = false;
          chainTail = null;
          chainGeneration += 1;
          // 冻结下一批，直到僵尸 fn 真正落定（见 auditChainFence）
          timedOut = true;
          fence.freeze();
          if (sharedCache.isRedisEnabled()) {
            resyncChainTail(); // 永不 reject（内部吞错），尽力而为地清除共享链尾
          }
          const reason = `审计链锁持有超时（${chainLockTimeoutMs()}ms），已冻结后续链写入并等待僵尸任务落定`;
          reject(new Error(reason));
        }, chainLockTimeoutMs());
        if (timer.unref) timer.unref();
      });

      // B-L4：fn 以当前代际调用——持锁超时递增代际后，僵尸 fn 稍后的
      // advanceChainTail 因代际过期被跳过
      const gen = chainGeneration;
      const work = Promise.resolve().then(() => fn(gen));

      try {
        return await Promise.race([work, timeout]);
      } finally {
        if (timer) clearTimeout(timer);
        if (!timedOut) {
          if (distLock) {
            try {
              await distLock.release();
            } catch (_) {
              /* 锁会随 PX 到期，释放失败不致命 */
            }
          }
        } else {
          // 超时的是锁，不是 fn：work 仍在后台跑且随时可能提交。
          // 分布式锁不释放并续租，直到僵尸落定；重同步必须先于解冻。
          fence.waitForZombie(work, distLock, {
            ttlMs: chainLockTimeoutMs(),
            resync: async () => {
              if (sharedCache.isRedisEnabled()) sharedTailUntrusted = true;
              await resyncChainTail();
            },
          });
        }
      }
    })
    .finally(() => release());
}

/**
 * 链尾写共享缓存的**唯一入口**（三条写路径共用同一套落地判据）。
 *
 * 返回 sharedCache.set 的落地判据；顺带维护「共享尾是否可信」：
 *  - false ⇒ 值只在**本进程内存**里，共享层仍是旧尾：置不可信，此后一律从 DB 读权威尾。
 *  - 其他（含 undefined，旧桩）⇒ 按已落到 Redis 处理：解除不可信，
 *    并抹掉本地副本——「本地内存里存在链尾副本 ⇒ 共享尾不可信」这条不变量必须在这里成立，
 *    否则一次失败写入留下的本地值会在之后任意一次 GET 抖动时被顶回（F-204 的残留缺口：
 *    只清标记不清副本，而 Redis 成功路径根本不碰内存层），
 *    把一个早已死掉的父哈希当成链尾续下去 ⇒ chain_fork（误判篡改）。
 * 调用方失败分支若还需兜内存指针/告警，自行按返回值处理（本函数不越权做）。
 */
async function writeSharedTail(value) {
  const landed = await sharedCache.set(CHAIN_TAIL_KEY, value === null ? EMPTY_SENTINEL : value);
  if (landed === false) {
    sharedTailUntrusted = true;
  } else {
    sharedTailUntrusted = false;
    sharedCache.dropLocalCopy(CHAIN_TAIL_KEY);
  }
  return landed;
}

/**
 * 取当前链尾：优先指针（内存或共享缓存）；未初始化时从 DB 读一次。
 *
 * Redis 就绪时链尾外置（CHAIN_TAIL_KEY）；键不存在 = 未初始化，EMPTY_SENTINEL = 「写入那一刻
 * 链尾为 null」——两者都回 DB 读一次并回写：哨兵是历史事实而非当前事实（多实例 set 未落地、
 * 运维直写库只写 hash 都会让它陈旧），按 null 续链即落成第二条链首。未配置时走进程内指针。
 */
async function getChainTail(model) {
  if (sharedCache.isRedisEnabled() && !sharedTailUntrusted) {
    const shared = await sharedCache.get(CHAIN_TAIL_KEY);
    if (shared !== null && shared !== undefined && shared !== EMPTY_SENTINEL) return shared;
    // 键不存在（未初始化）与哨兵都回 DB 读一次：哨兵只证明「写入那一刻」链为空（见函数头）
    const latest = await getLatestHash(model);
    if (shared === EMPTY_SENTINEL && latest === null) return null; // 库真为空：结论与改前逐字相同（代价是多一次 find）
    // F-204：这条"回写"路径必须和 advanceChainTail 一样吃 set() 的落地判据。
    // 写没进 Redis 时，sharedCache.set 会把值落进**本进程内存**并返回 false；此后任何
    // 一次共享读命令失败（Redis 抖动/主从切换）都会让 get() 从内存顶回这份副本，
    // 而这个键在共享层里早已被其他实例推进过 ⇒ 既不回 DB 重同步也不告警，
    // 本实例就在一个已死的父哈希上续链 ⇒ 链分叉（实测见 auditChainDistributed.test.js）。
    // 只标记不可信，不改本轮返回值：latest 本就来自 DB（权威）。
    await writeSharedTail(latest);
    return latest;
  }
  if (sharedCache.isRedisEnabled()) {
    // F-184b：共享尾不可信 ⇒ 读 DB（权威），并顺手尝试修复共享键；
    // 只有确认写入落到 Redis 才解除不可信状态（写回失败时保持降级，不会"以为修好了"）。
    const latest = await getLatestHash(model);
    await writeSharedTail(latest);
    return latest;
  }
  if (!chainTailLoaded) {
    chainTail = await getLatestHash(model);
    chainTailLoaded = true;
  }
  return chainTail;
}

/**
 * 推进链尾（仅供锁内的追加路径调用）。
 * Redis 就绪时写共享缓存（链尾是长期状态，不带 TTL）；否则推进内存指针。
 * 写入未落到 Redis 时不抛错（审计不丢优先），而是置「共享尾不可信」标记，
 * 此后 getChainTail 一律从 DB 读权威尾 —— 见 sharedTailUntrusted 注释。
 */
async function advanceChainTail(hash, gen = chainGeneration) {
  // B-L4：代际守卫——持锁/前驱等待超时递增代际后，超时的「僵尸 fn」稍后
  // 完成时的推进被跳过，避免用过期 hash 覆写已重同步的链尾（正常路径
  // fn 运行期间无超时发生，gen 恒等于当前代际）
  if (gen !== chainGeneration) {
    logger.warn(
      `审计链尾推进被跳过（代际 ${gen} 已过期，当前 ${chainGeneration}）：该批次的链尾状态不确定，已由 DB 重同步兜底`
    );
    return;
  }
  if (sharedCache.isRedisEnabled()) {
    const landed = await writeSharedTail(hash);
    if (landed === false) {
      // Redis 没收下：值只在本地内存，共享层仍是旧尾 ⇒ 本进程此后一律从 DB 读尾（见 getChainTail）。
      // 同时把内存尾写成本批结果：Redis 若整体不可用（isRedisEnabled() 转 false），
      // 进程内语义接手时指针已经是正确的，不会退化成"从空尾重开"。
      chainTail = hash;
      chainTailLoaded = true;
      logger.error(
        '审计链共享链尾未能写入 Redis（只落到本进程内存），此后每批改从 DB 重读链尾：继续信任共享层旧尾会让本实例与其他实例在同一父哈希上各写一条 ⇒ 链分叉（F-184a 起分叉会计入 chain_fork）'
      );
    }
    return;
  }
  chainTail = hash;
}

/**
 * 回滚链尾（落库失败时消除「幻影链尾」）。
 * 仅当链尾仍停在本次写入产生的 hash 时才回滚；
 * 若后续记录已接续该尾（无法挽回的分叉），返回 false 由调用方告警。
 * Redis 就绪时用 casSet 原子回滚——回滚发生在锁外（post('save') 错误钩子），
 * 直接 SET 可能覆盖其他实例刚推进的链尾；CAS 保证「仍是期望尾才回滚」。
 */
async function rollbackChainTail(expectedCurrent, restoreTo) {
  if (sharedCache.isRedisEnabled()) {
    return sharedCache.casSet(
      CHAIN_TAIL_KEY,
      expectedCurrent === null ? EMPTY_SENTINEL : expectedCurrent,
      restoreTo === null ? EMPTY_SENTINEL : restoreTo
    );
  }
  if (!chainTailLoaded || chainTail === expectedCurrent) {
    chainTail = restoreTo;
    return true;
  }
  return false;
}

/**
 * 标记链尾失效：下次 getChainTail 强制从 DB 重读（部分落库成功后的自愈入口）。
 * 进程内 loaded 标记在所有分支都清；Redis 就绪时额外删除共享链尾键
 * （下次 getChainTail 因键缺失回 DB 重读并回写）。
 */
async function resyncChainTail() {
  // F-194：进程内链尾必须无条件清。Redis 在线时 getChainTail 不读它，看似无害；
  // 但 advanceChainTail 明确承诺"Redis 若整体不可用，进程内语义接手"——那时接手的
  // 就是这枚幻影尾，而调用方（auditBuffer 的部分落库自愈入口）只调本函数、不再手工清。
  chainTail = null;
  chainTailLoaded = false;
  // 删除失败：共享链尾残留属降级，但「链尾失效」本就是尽力而为的自愈入口，
  // 吞错避免 fire-and-forget 路径产生 unhandled rejection
  if (sharedCache.isRedisEnabled()) await sharedCache.del(CHAIN_TAIL_KEY).catch(() => {});
  else if (sharedCache.isRedisConfigured())
    logger.warn('链尾自愈未执行：Redis 已配置但未就绪，共享链尾键未清理（本进程内不再尝试）'); // 与 G-01 同形：空转必须留信号；本函数无重试点
}

/**
 * schema 默认值对齐表（批量串链路径专用）
 *
 * 背景（AUX-02 断链根因）：auditBuffer 走 insertMany，chainBatch 在**入库前**
 * 对纯 JS 对象算 hash，而 Mongoose 在**入库时**才补 schema 默认值
 * （riskLevel='low'、riskFactors=[]、params/query/body={}）。于是：
 *   算 hash 时 riskLevel=undefined → payload 里是 null
 *   落库后        riskLevel='low'   → 校验时重算得到不同 hash
 * 结果 hashVersion=2 的记录几乎全部 hash_mismatch（实测 4182/4776），
 * 「防篡改」承诺不成立——而这与并发无关（实测 chain_break 仅 12 条，
 * 且无一发生在同毫秒，说明进程内互斥锁本身是有效的）。
 *
 * 逐条 create 路径不受影响：pre('save') 在默认值已填充后取 this.toObject()。
 *
 * 维护约束：AuditLog schema 中任何**参与 payload 的字段**新增 default 时，
 * 必须同步登记到此表，否则同类断链会再次出现。
 * 单测 auditChain.test.js 会对照 schema 校验本表完整性。
 */
const PAYLOAD_SCHEMA_DEFAULTS = {
  timestamp: () => new Date(),
  params: () => ({}),
  query: () => ({}),
  body: () => ({}),
  riskLevel: () => 'low',
  riskFactors: () => [],
};

// 子文档的 schema 字段集（与 AuditLog.js 的 clientInfo / location 声明同步）。
// 批量路径先算哈希、insertMany 才铸造：未声明的子键会被 Mongoose 剥掉，
// 若被哈希的对象仍带着它，落库读回重算必然 hash_mismatch（永久假篡改）。
// 因此必须在算哈希前把子对象投影成 schema 会保留的形态——未知子键删除，
// 已知但值为 undefined 的键也删除（stableStringify 会把 undefined 写成 null，
// 而 Mongoose 会丢弃该键，两侧同样分叉）。
const AUDIT_CLIENT_INFO_FIELDS = Object.freeze([
  'browser',
  'os',
  'device',
  'reportedIp',
  'socketPeer',
]);
const AUDIT_LOCATION_FIELDS = Object.freeze(['country', 'province', 'city']);

function projectSubdocument(source, allowedFields) {
  const projected = {};
  for (const field of allowedFields) {
    if (source[field] !== undefined) projected[field] = source[field];
  }
  return projected;
}

/**
 * 批量串链：为 docs 按序计算 prevHash/hash/hmac 并标记 payload 版本。
 *
 * 计算前先补齐 schema 默认值（见 PAYLOAD_SCHEMA_DEFAULTS），
 * 保证「串链时的 payload」与「落库后的文档」逐字节一致。
 */
function chainBatch(docs, startPrevHash) {
  let prevHash = startPrevHash || null;
  for (const doc of docs) {
    // 与 Mongoose 落库行为对齐：undefined 字段由 schema default 填充，
    // 必须在算 hash 前写回文档本身（而非仅在 payload 里临时补），
    // 否则 insertMany 存进去的是默认值、hash 却基于 undefined 计算。
    // timestamp 额外容忍 null（调用方可能显式传 null）
    for (const [field, makeDefault] of Object.entries(PAYLOAD_SCHEMA_DEFAULTS)) {
      if (doc[field] === undefined || (field === 'timestamp' && doc[field] === null)) {
        doc[field] = makeDefault();
      }
    }
    // method 的降级闸必须与 AuditLog.js 的 schema set 同一份实现，而且必须发生在算哈希**之前**：
    // 逐条路径先铸造后算哈希（两侧天然同源），批量路径先算哈希、insertMany 才铸造。
    // 少了这一行，`curl -X FOO` 这类枚举外动词的记录就带着 method='FOO' 进了哈希、
    // 落库时又被 set 抹成「不记 method」⇒ 该记录从此永久 hash_mismatch（假篡改），
    // 且它自身的完整性保护静默失效（已经是红的，再被真改也照样红）。
    doc.method = auditMethodOrUndefined(doc.method);
    // ip 与 method 同规：闸本体在 constants/audit.js，schema 的 set 会再跑一次（幂等），
    // 所以两侧形态必然一致。少了这一行，一条超长 XFF 派生值就会带着 4011 字符进哈希、
    // 落库时被剪到 64 ⇒ 该记录永久 hash_mismatch，且它的完整性保护静默失效。
    doc.ip = auditIpOrUndefined(doc.ip);
    // userAgent 同理（它也在 payload 字段集里）：21 个写入点传裸 `req.get('user-agent')`，
    // 一条 16KB 的 UA 会带着原样进哈希、落库时被剪到 512。
    doc.userAgent = auditUserAgentOrUndefined(doc.userAgent);
    // username 也在 payload 字段集里，且它是**唯一由未认证请求方直接决定**的那一维
    // （登录失败审计传 `req.body.username`）。少了这一行，请求体里一个 JSON 转义
    // `"\ud800"` 就带着孤立代理项进哈希（内存 61 d800 62），BSON 落盘时被驱动改写成
    // U+FFFD（61 fffd 62）⇒ 读回复算必然 hash_mismatch。实测形态见
    // tests/services/auditUsernameCastGate.test.js（闸前后各一条，反向对照）。
    doc.username = cleanAuditUsername(doc.username);
    // clientInfo 整对象在 payload V2+ 里，其 ip 子字段与顶层 ip 同族：
    // 必须在这里做与 schema set 相同的清洗，否则超长/带控制字符的 XFF
    // 会带着原样进哈希、落库时被剪到 64 ⇒ 永久 hash_mismatch。
    // undefined 键要删掉而不是留着：canonicalPayload 的 stableStringify
    // 把 undefined 序列化为 null，Mongoose 却会丢弃该键，两侧形态不一致。
    // 先按 schema 字段集投影：未声明子键（如 gps）必须在这里删除，
    // 否则被哈希的形态带着它、insertMany 铸造时被剥掉，读回复算必然失配。
    if (doc.clientInfo && typeof doc.clientInfo === 'object') {
      const clientInfo = projectSubdocument(doc.clientInfo, AUDIT_CLIENT_INFO_FIELDS);
      for (const key of ['reportedIp', 'socketPeer']) {
        const cleaned = auditIpOrUndefined(clientInfo[key]);
        if (cleaned === undefined) delete clientInfo[key];
        else clientInfo[key] = cleaned;
      }
      doc.clientInfo = clientInfo;
    }
    // location 同理：schema 只声明 country/province/city，多余子键会在铸造时消失。
    if (doc.location && typeof doc.location === 'object') {
      doc.location = projectSubdocument(doc.location, AUDIT_LOCATION_FIELDS);
    }

    doc.prevHash = prevHash;
    const payload = canonicalPayload(doc, CURRENT_PAYLOAD_VERSION);
    const hash = computeHash(prevHash, payload);
    doc.hash = hash;
    doc.hmac = computeHmac(hash);
    doc.hashVersion = CURRENT_PAYLOAD_VERSION;
    prevHash = hash;
  }
  return prevHash;
}

/**
 * 仅供测试重置内部状态（生产不调用）——与 auditBuffer.__resetForTest 同惯例。
 * 不重置 chainLock：它与在飞的持有者同生死，单独清零会让上一个用例遗留的
 * release() 去 resolve 本用例新装的锁，反而制造串扰。
 */
function __resetForTest() {
  chainTail = null;
  chainTailLoaded = false;
  chainGeneration = 0;
  fence.reset();
  sharedTailUntrusted = false;
}

module.exports = {
  PAYLOAD_FIELDS_V1,
  PAYLOAD_FIELDS_V2,
  PAYLOAD_FIELDS_V3,
  PAYLOAD_FIELDS_V4,
  PAYLOAD_FIELDS_V5,
  PAYLOAD_FIELDS_V6,
  PAYLOAD_SCHEMA_DEFAULTS,
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
  computeHash,
  computeHmac,
  getHmacSecret,
  isHmacConfigured,
  getLatestHash,
  chainBatch,
  withChainLock,
  getChainTail,
  advanceChainTail,
  rollbackChainTail,
  resyncChainTail,
  isChainFrozen: fence.isFrozen,
  __resetForTest,
};
