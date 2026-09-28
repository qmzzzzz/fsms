const crypto = require('crypto');
const logger = require('./logger');
const { readPositiveNumberEnv } = require('./envNumber');

// 共享缓存门面（A-1）：提供跨实例分布式锁与共享链尾指针的存取。
// 仅依赖 logger，无循环依赖，可顶层引入。未配置 REDIS_URL 时
// isRedisEnabled() 恒为 false，下列分布式路径全部回退为原进程内语义。
const sharedCache = require('../services/sharedCache');
const {
  PAYLOAD_FIELDS_V1,
  PAYLOAD_FIELDS_V2,
  PAYLOAD_FIELDS_V3,
  PAYLOAD_FIELDS_V4,
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
  computeHash,
} = require('./auditChainPayload');
// method 的取值全集与降级规则只有一份（constants/audit.js）：schema 的 set 与这里的
// 批量哈希用同一个函数，否则「被哈希的形态」与「落库的形态」会在铸造那一步分叉。
const { auditMethodOrUndefined } = require('../constants/audit');

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
 *  v4（当前）：在 v3 的 25 字段上补进 targetType / targetId / dataType /
 *             description。这四个字段是 P1-12 加到 schema 的（举报对象、被查看的
 *             敏感数据类型、操作描述），当时未同步进 payload 白名单——落库后可被
 *             任意改写而 hash/hmac/链接三层都不会红。校验端按 doc.hashVersion
 *             选择口径，v1~v3 的复算方式逐字保持不变（旧数据不会因新增版本而集体报断链）。
 * 新写入一律带 hashVersion=CURRENT_PAYLOAD_VERSION(4)；校验端按 doc.hashVersion 选择口径。
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
function isHmacConfigured() {
  return !!getHmacSecret();
}

/**
 * 取最新链尾（仅用于首次初始化链尾，见 getChainTail）。
 *
 * 按 `_id` 降序近似写入顺序——ObjectId 内嵌毫秒时间戳，单实例下与追加顺序一致。
 * 多实例场景下本函数**只**在共享链尾未初始化时被调用一次（且在分布式锁内），
 * 链尾推进由 A-1 分布式锁保证串行，不存在「各实例各自读旧尾」的分叉问题，
 * 故不为此引入额外写放大。
 */
async function getLatestHash(model) {
  const latest = await model
    .findOne({ hash: { $ne: null } }, { hash: 1, _id: 1 })
    .sort({ _id: -1 })
    .lean();
  return latest && latest.hash ? latest.hash : null;
}

// ================= 哈希链并发防护（M-3 + A-1） =================
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
    `${name}=${JSON.stringify(raw)} 非法（须为正的毫秒数），已按默认 ${fallback}ms 处理；` +
      '负值或零会让审计链锁立即判定超时 ⇒ 链尾永不推进、全部审计降级为无哈希落库'
  );
}

// 锁持有超时（毫秒）：fn 悬挂时不能让整条审计链永久排队
//
// 原为 `Number(process.env.AUDIT_CHAIN_LOCK_TIMEOUT_MS) || 15000`，而**负值是真值**
// ——`-1` 会原样生效，于是 `Promise.race([prev, timeout])` 与 `race([fn, timeout])`
// 双双立即超时：每次 withChainLock 都「标记链尾失效 + 抛错」，链尾永不推进，
// 所有审计记录降级为 legacy（无 hash）落库——防篡改承诺整体失效，
// 而日志里只会看到一条条"锁持有超时"，看不出根因是配置笔误。
// 现与 swagger(P2-37)/config(P2-39)/retention 同一口径：只接受有限正数，否则回落默认并告警。
// 读取时机仍是模块加载期（测试按需在 require 之前设值，语义未变）。
const CHAIN_LOCK_TIMEOUT_MS = readPositiveNumberEnv('AUDIT_CHAIN_LOCK_TIMEOUT_MS', 15000, {
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
 * P3-19 超时保护：原实现无超时——一旦 fn 因网络挂起（Mongo 无响应且驱动
 * 未超时）永不 settle，chainLock 永远不释放，其后**所有**审计写入无限排队，
 * 表现为「服务正常但审计彻底停摆」，且无任何日志线索。
 * 现在超时即强制释放锁并标记链尾失效（下次从 DB 重新同步），
 * 宁可让该批次以 legacy 形式落库，也不能让审计链整体死锁。
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
        // 直到任一操作从 DB 重同步；代价是一次额外重同步
        chainTailLoaded = false;
        chainTail = null;
        chainGeneration += 1;
        resolve();
      }, CHAIN_LOCK_TIMEOUT_MS);
      if (waitTimer.unref) waitTimer.unref();
    }),
  ]);
  // 两个分支都 clear：prev 先 settle 是常见路径（这条修复的正文），定时器自己跑完时
  // clear 是空操作。用 then(fn, fn) 而不是 finally——finally 派生的那支没人接 reject，
  // prev 一旦异常就冒出 unhandledRejection。
  waitPrev.then(clearWaitTimer, clearWaitTimer);

  return waitPrev
    .then(async () => {
      // A-1：进程内锁已就绪后叠加跨实例分布式锁
      let distLock = null;
      if (sharedCache.isRedisEnabled()) {
        distLock = await sharedCache.acquireLockBlocking(
          CHAIN_LOCK_KEY,
          CHAIN_LOCK_TIMEOUT_MS,
          CHAIN_LOCK_TIMEOUT_MS
        );
        if (!distLock) {
          // 拿不到跨实例锁：标记链尾失效 + 抛错走降级，绝不无锁推进链尾。
          // resyncChainTail 永不 reject（内部吞错），fire-and-forget 即可
          resyncChainTail();
          chainTailLoaded = false;
          chainTail = null;
          throw new Error(
            `审计链分布式锁获取超时（${CHAIN_LOCK_TIMEOUT_MS}ms），本批回退，链尾已标记失效待重同步`
          );
        }
      }

      let timer = null;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          // 链尾可能已被 fn 部分推进，无法判断其状态 → 标记失效，下次从 DB 重同步；
          // B-L4：同时递增代际——fn 的 advanceChainTail 因代际过期被跳过
          chainTailLoaded = false;
          chainTail = null;
          chainGeneration += 1;
          if (sharedCache.isRedisEnabled()) {
            resyncChainTail(); // 永不 reject（内部吞错），尽力而为地清除共享链尾
          }
          reject(
            new Error(`审计链锁持有超时（${CHAIN_LOCK_TIMEOUT_MS}ms），已强制释放并标记链尾失效`)
          );
        }, CHAIN_LOCK_TIMEOUT_MS);
        if (timer.unref) timer.unref();
      });

      // B-L4：fn 以当前代际调用——持锁超时递增代际后，僵尸 fn 稍后的
      // advanceChainTail 因代际过期被跳过
      const gen = chainGeneration;

      try {
        return await Promise.race([Promise.resolve().then(() => fn(gen)), timeout]);
      } finally {
        if (timer) clearTimeout(timer);
        if (distLock) {
          try {
            await distLock.release();
          } catch (_) {
            /* 锁会随 PX 到期，释放失败不致命 */
          }
        }
      }
    })
    .then(
      (v) => {
        release();
        return v;
      },
      (e) => {
        release();
        throw e;
      }
    );
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
 * Redis 就绪时链尾外置到共享缓存（CHAIN_TAIL_KEY），多实例共享同一链尾；
 * 键不存在表示「未初始化」→ 从 DB 读一次并回写；值为 EMPTY_SENTINEL 表示
 * 链尾已初始化为 null（尚无任何记录）。未配置 Redis 时走进程内内存指针。
 */
async function getChainTail(model) {
  if (sharedCache.isRedisEnabled() && !sharedTailUntrusted) {
    const shared = await sharedCache.get(CHAIN_TAIL_KEY);
    if (shared === EMPTY_SENTINEL) return null;
    if (shared !== null && shared !== undefined) return shared;
    // 键不存在（未初始化）：从 DB 读并回写共享缓存，供本实例及他实例复用
    const latest = await getLatestHash(model);
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
        '审计链共享链尾未能写入 Redis（只落到本进程内存），此后每批改从 DB 重读链尾：' +
          '继续信任共享层旧尾会让本实例与其他实例在同一父哈希上各写一条 ⇒ 链分叉（F-184a 起分叉会计入 chain_fork）'
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
  if (sharedCache.isRedisEnabled()) {
    try {
      await sharedCache.del(CHAIN_TAIL_KEY);
    } catch (_) {
      // 删除失败：共享链尾残留，下次 getChainTail 不会从 DB 重读——属降级，
      // 但「链尾失效」本就是自愈入口的尽力而为语义，吞错避免 fire-and-forget
      // 路径产生 unhandled rejection
    }
  }
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
  sharedTailUntrusted = false;
}

module.exports = {
  PAYLOAD_FIELDS_V1,
  PAYLOAD_FIELDS_V2,
  PAYLOAD_FIELDS_V3,
  PAYLOAD_FIELDS_V4,
  PAYLOAD_SCHEMA_DEFAULTS,
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
  computeHash,
  computeHmac,
  isHmacConfigured,
  getLatestHash,
  chainBatch,
  withChainLock,
  getChainTail,
  advanceChainTail,
  rollbackChainTail,
  resyncChainTail,
  __resetForTest,
};
