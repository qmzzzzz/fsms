/**
 * 审计哈希链完整性校验服务
 *
 * 单一实现，供三方复用：运维脚本（scripts/verify-audit-chain.js 与
 * scripts/resign-audit-chain-v3.js 的改写前/后核验）、管理接口
 * GET /api/security/audit-logs/verify（见 controllers/auditController.verifyAuditChainIntegrity）。
 * 没有"周期性自检"这一方：链核验至今只在被调用时执行，未接入任何定时任务。
 *
 * 三层校验，强度递减但互补：
 *
 * 1. hash 重算（内容防篡改）—— 逐条 SHA256(prevHash|canonicalPayload) 比对。
 *    payload 口径按记录自带的 hashVersion 选择（null 视为 v1 存量口径）。
 *    任何字段被改写都会在此暴露，与记录顺序无关，是最强的一层。
 *
 * 2. hmac 校验（密钥防篡改）—— hash 是无密钥 SHA-256，拿到 DB 写权限者可
 *    整条链重算；hmac = HMAC-SHA256(HMAC_SECRET, hash) 是唯一真正的防线。
 *    缺失或失配均计入断裂。未配置 HMAC_SECRET 时降级并显式声明。
 *
 * 3. 链接性校验（删除检测）—— 每条记录的 prevHash 必须命中「近期已见
 *    hash 的滑动窗口」。用窗口而非「严格等于上一条的 hash」，是因为 _id 顺序
 *    与实际串链顺序存在小幅错位：AuditLog.create 在构造文档时就分配了 _id，
 *    而 auditBuffer 走 insertMany 的批次要等 2s 定时器才拿到 _id——两者在
 *    链锁上的先后可能与 _id 大小相反。这种错位不是完整性问题（哈希链本身连续），
 *    严格逐对比较会产出大量假阳性断链，反而掩盖真实篡改。
 *    窗口足够小（LINK_WINDOW_SIZE），**删除**记录会立即暴露。注意别把它读成
 *    "插入也覆盖"——插入伪造在本层不可检出，成因与修法见下方「已知检出上限」段。
 *
 * 无哈希记录不再一律算 legacy（P2 级修正）：哈希链自启用起就是**连续**的，
 * 因此「无 hash」出现在带 hash 记录之前 = 存量 legacy（不计断裂），出现在之后 =
 * 完整性无法追认，计入 breaks（type=hash_stripped）。原先两种都只累加 legacy 且
 * `intact: breaks===0`，等于把某条记录整组 $unset 掉 hash/prevHash/hmac 就能把它
 * 改写过的内容洗白——顺带还把"其后第一条不再校验链接"的窗口重置一并利用。
 * 注：$unset 只能由绕过 mongoose 中间件的写入完成（直连驱动 / mongosh），
 * 而这正是本服务要防的威胁模型（持有 DB 写权限的内部人）。
 *
 * **2026-09-30 归因细分（hashFailure 标记）**：出现在带哈希记录之后的无哈希记录，
 * 有两种成因、且数据形态完全相同——① 人为 $unset（篡改灭迹）；② auditBuffer 算 hash
 * 抛错后照常落库（write-side 异常）。后者是**良性**的、且会**持续**产生，若与①同样
 * 计入 breaks，每轮核验都报断裂 ⇒ 真实篡改告警被常态噪声淹没（M-09「幻影链尾」的
 * 同一条演化路径：反复确认是误报后，人开始忽略它）。
 * 故 ② 在写入侧被显式打上 `AuditLog.hashFailure` 标记（该字段**不参与哈希**——
 * 不在 PAYLOAD_FIELDS_V4 里），核验端据此归入独立计数 `hash_compute_failed`：
 * 不计 breaks，但 > 0 时 `computeChainVerdict` 拒绝给出 code 0（"链完整"）。
 * 即缺口仍然可见、仍然告警，只是不再伪装成篡改。
 *
 * 标记的威胁模型边界（如实记录）：能写 hashFailure 的攻击者已经有 DB 写权限——
 * 那种情况下他直接 $unset hash 更省事。而本字段不参与哈希 ⇒ **无法洗白内容篡改**
 * （改过内容的记录仍被 hash_mismatch 抓）；它能把"篡改告警"降级成"缺口告警"，
 * 但不能让篡改消失（降级后仍有计数与告警）。这条降级路径是刻意的取舍：
 * 代价是攻击者多写一个字段可以把一处 code 1 变成 code 2，收益是良性缺口不再
 * 制造假篡改、保住了"篡改告警一响就有人看"这个前提。
 *
 * 「legacy 段之后第一条」不属免检档（同一族的另一头）：链接检查只对**窗口的第一条**免检
 * ——它的父记录确实可能在窗口之外（maxRecords 截断、TTL 把头一批删掉）。legacy 段之后的
 * 那条不是这一档：它声称的父哈希就落在它前面那条记录的位置上，而那条没有哈希。
 * 诚实形态照样过得去——链启用时库里读不到任何带哈希的记录，启用后的第一条 prevHash 为 null，
 * 而 prevHash=null 本就是链首。早先的实现让 legacy 也重置这道免检，实测
 * 「整窗 $unset 但留最新一条」= intact true、判据 code 0（等于为灭迹背书"链完整"），
 * 而「整窗抹光」反而被下面的 nothingHashed 挡在 code 2 ⇒ 留一条比抹光更好用。
 * 判据与四种诚实/攻击形态的对照见
 * `src/tests/services/auditChainLegacyPrefixWash.test.js`。
 *
 * 已知检出上限（不得当作已修好）：**插入**一条 prevHash 指向链中已有 hash 的
 * 伪造记录，在本设计下不可检出——滑动窗口只要求 prevHash 命中近期任一 hash。
 * 要堵住它需要给链上每条记录一个参与哈希的序号（chainIndex），使"父子关系"
 * 变成严格线性；那是一次需要全量重签的格式升级，不在本次改动范围。
 *
 * 存量数据的已知限制（必须如实告知，不得当作「已修好」）：
 * - hashVersion=null（legacy，本机 1137 条）：写入时无哈希链，完全无保护。
 * - hashVersion=2（本机 4419 条）：批量路径算 hash 时未补 schema 默认值，
 *   校验端用 canonicalPayloadV2LegacyBatch 宽容该已知漂移（计入
 *   legacyV2BatchTolerated 而非 breaks）。代价是这批记录的
 *   riskLevel/riskFactors **从未受哈希保护**，事后无法追认。
 *   宽容后仍有少量 v2 记录失配（本机 19 条），成因未能归因到任何单/双字段
 *   变换——可能是当时并发写入下 payload 与落库文档存在其它差异。
 *   这些条目保留在 breaks 中，不做进一步宽容：宁可留下待查告警，
 *   也不为了「报告干净」而扩大宽容面。
 * - hashVersion=3（修复后写入）：实测 hash/hmac/链接三层全绿。
 * 结论：**新写入的链已可信；存量 v1/v2 记录的完整性不可追认**。
 */

const {
  canonicalPayload,
  canonicalPayloadV2LegacyBatch,
  computeHash,
  computeHmac,
  isHmacConfigured,
} = require('../utils/auditChain');

// 链接性校验的滑动窗口大小：容纳 _id 与串链顺序的正常错位，
// 远小于任何有意义的删除批量 ⇒ 删除可检出；插入伪造不可检，见文件头「已知检出上限」
const LINK_WINDOW_SIZE = 256;

// 单次校验的记录上限：审计集合可达千万级，全量校验必须由离线脚本分段执行。
// 接口侧默认只校验最近一段，避免长事务与内存膨胀。
const DEFAULT_MAX_RECORDS = 20000;
const HARD_MAX_RECORDS = 200000;

// 断裂样本上限（响应体大小保护）
const MAX_SAMPLES = 20;

/**
 * 校验审计哈希链
 *
 * @param {import('mongoose').Model} AuditLog 审计日志模型
 * @param {Object} [options]
 * @param {number} [options.maxRecords] 最多校验多少条（从最新往前取，再按时序校验）
 * @param {boolean} [options.fromLatest=true] true=校验最近 maxRecords 条；false=从最早开始
 * @param {Object} [options.filter] 附加查询条件，用于只校验某个子集（如单条测试自己的
 *   造数）。**仅限离线/测试作用域**：在线自检接口与运维脚本一律不传，否则
 *   「挑一个没有断链的子集」就能把真实断裂藏起来——报告里会把 filter 原样回显，
 *   便于消费方识别这是一次局部校验。
 * @param {number} [options.maxTimeMS=0] 服务端单查询时间预算（毫秒），**0=不限**（HTTP 接口与
 *   离线脚本的原行为，保持不带该参数时的结论与耗时特征完全不变）。
 *   取值口径：有限正数才生效，且**向下取整**（真库对小数报 FailedToParse）；
 *   0 / 负数 / NaN / Infinity / 非数字一律按"不限"，见实现处的实测说明。
 *   为什么只有定时器侧必须传：`auditChainMonitor` 用 `verificationRunning` 做单轮闸门，
 *   一条挂死的 find 会让之后每一轮都判"上一轮未结束"而跳过，且**永不恢复**——
 *   带预算时最坏情况由服务端中断本轮、走 catch 释放闸门（与 auditMonitor 的 roundBudgetMs 同法）。
 * @returns {Promise<Object>} 校验报告
 */
const verifyAuditChain = async (AuditLog, options = {}) => {
  const maxRecords = Math.max(
    1,
    Math.min(Number(options.maxRecords) || DEFAULT_MAX_RECORDS, HARD_MAX_RECORDS)
  );
  const fromLatest = options.fromLatest !== false;
  const filter = options.filter && Object.keys(options.filter).length > 0 ? options.filter : {};
  // 预算归一：只接受**有限正数**，并向下取整。
  // 取整不是洁癖——真库实测小数一律被拒（文案随 mongod 版本而变：本机报
  // FailedToParse「Expected an integer: maxTimeMS」，测试用的内存 mongod 报
  // 「maxTimeMS has non-integral value」），负数报 BadValue「value must be >= 0」。
  // 两种都是**抛错**形态，若留给调用方传（间隔来自 env，`AUDIT_*_INTERVAL_MS=1.5`
  // 完全可能）就会让每一轮核验都在服务端失败，而闸门侧看到的是 failures 恒增——
  // 比没预算更难查。0 / 未设置 / NaN / Infinity / 非数字一律落回"不限"（原行为）。
  const rawBudget = Number(options.maxTimeMS);
  const maxTimeMS = Number.isFinite(rawBudget) && rawBudget > 0 ? Math.floor(rawBudget) : 0;

  const hmacChecked = isHmacConfigured();

  let total = 0;
  let legacy = 0;
  let breaks = 0;
  const byType = {
    hash_mismatch: 0,
    hmac_missing: 0,
    hmac_mismatch: 0,
    chain_break: 0,
    // F-184a：同一个父哈希被两条记录认领（链在此处分叉成 DAG）。原判据是成员测试，
    // 一个父节点挂两个子节点照样通过 ⇒ 「防篡改」的链接性在最关键的一种形态上是静默的。
    chain_fork: 0,
    hash_stripped: 0,
    // 2026-09-30：带 AuditLog.hashFailure 标记的无哈希记录（auditBuffer 算 hash 抛错后
    // 照常落库的那批）。与 hash_stripped 数据形态相同（无 hash、位于带哈希记录之后），
    // 但成因是良性的、且会**持续**产生 ⇒ 单列一类、**不计入 breaks**，否则每轮核验都
    // 报断裂，真实篡改告警被常态噪声淹没（M-09「幻影链尾」的同一条演化路径）。
    // 仍计入告警面：它代表链上有一段无法追认的记录，是完整性缺口的直接信号。
    hash_compute_failed: 0,
  };
  // v2 批量路径的历史默认值漂移：不是篡改，单独计数不计入 breaks
  let legacyV2BatchTolerated = 0;
  // hashFailure 标记的无哈希记录数（不计 breaks，但要在报告里可见、可告警）
  let hashComputeFailed = 0;
  const samples = [];

  const pushBreak = (sample) => {
    breaks += 1;
    byType[sample.type] = (byType[sample.type] || 0) + 1;
    if (samples.length < MAX_SAMPLES) samples.push(sample);
  };

  // 取最近 maxRecords 条：先按 _id 降序取窗口，再反转为升序校验
  // （链接性校验依赖时序，必须升序推进）
  //
  // 预算走 find 的**第三参**而不是链式 `.maxTimeMS()`，三条理由：
  // ① 与模型侧既有先例同法（models/auditLogQueryStatics.js 的 aggregateWithBudget
  //    就是「不带预算走单参、带预算走 options 袋」）；
  // ② 不带预算时必须走**逐字不变**的单参形态：HTTP 接口与离线脚本的调用面、
  //    以及消费方对 `find` 的既有断言都不该因为一个"默认不生效"的参数而漂移
  //    （`maxTimeMS: 0` 在服务端本就是"不限"，实测接受，所以发 0 只是多一个签名）；
  // ③ 第二参是 projection，写成 `find(filter, { maxTimeMS })` 会被当成投影而不是选项，
  //    是个静默失效的经典坑，故必须 `find(filter, null, { maxTimeMS })` 显式占位。
  // 实测 mongoose 8.24.1：`find(f, null, {maxTimeMS:2500}).options.maxTimeMS === 2500`，
  // 与链式 `.maxTimeMS()` 落进同一个 options 袋（到驱动层等价）。
  const windowOptions = maxTimeMS > 0 ? { maxTimeMS } : undefined;
  const window = await AuditLog.find(filter, null, windowOptions)
    .sort({ _id: fromLatest ? -1 : 1 })
    .limit(maxRecords)
    .lean();
  const docs = fromLatest ? window.reverse() : window;

  // 近期已见 hash 的滑动窗口（Set 用于命中判断，数组用于按序淘汰）
  const seen = new Set();
  const seenOrder = [];
  /**
   * F-184a：`prevHash → 第一个认领它的记录`。
   *
   * 链接性原本只做**成员测试**（`seen.has(doc.prevHash)`），而分叉的形态恰恰是
   * "一个父节点挂了两个子节点"：两条记录的 prevHash 都在窗口内（无 chain_break）、
   * 各自的 hash 也都算得回来（无 hash_mismatch）⇒ 整链其实已经是 DAG，而报告仍然
   * `intact: true`。分叉不需要攻击者才能造出来：共享链尾写入失败后各实例读到的
   * 尾不同（见 utils/auditChain 的 advanceChainTail）、锁超时后的僵尸推进、
   * 或 WAL 重放挑错链尾，都会产出同父两子。
   * 与 `seen` 同生同灭：淘汰/重置必须同步，否则会拿窗口外的旧子报假分叉。
   */
  const firstChildOf = new Map();
  const forgetOldest = () => {
    const oldest = seenOrder.shift();
    if (oldest !== undefined) firstChildOf.delete(oldest);
  };
  const resetWindow = () => {
    seen.clear();
    seenOrder.length = 0;
    firstChildOf.clear();
  };
  const remember = (hash) => {
    seen.add(hash);
    seenOrder.push(hash);
    if (seenOrder.length > LINK_WINDOW_SIZE) forgetOldest();
  };

  // 免检范围严格等于「本窗口的第一条」：它的父记录可能落在窗口之外。
  // legacy 段之后的那条不在这一档里（那里置 isFirst=false），见文件头的说明。
  let isFirst = true;
  // 是否已经见过「带哈希」的记录。用于区分两种形态完全不同的无哈希记录：
  // - 出现在带哈希记录**之前**：存量 legacy（写入时尚无哈希链），不属篡改；
  // - 出现在带哈希记录**之后**：要么有人把 hash/prevHash/hmac 整组 $unset 掉
  //   （mongoose 中间件拦不住直连驱动/mongosh 的改写），要么哈希计算失败后
  //   仍落库（见 auditBuffer 的「批次将无哈希落库」分支）。两种情况都意味着
  //   「这条记录的完整性无法追认」，必须计入断裂而不是被 legacy 吸收。
  let seenHashed = false;

  for (const doc of docs) {
    total += 1;

    // 定期让出事件循环：本循环对每条记录做 SHA-256 + 规范 JSON 序列化，是纯 CPU 工作，
    // 不 yield 时整个扫描期间该进程无法服务任何其他请求（心跳/健康检查也会超时）。
    // 2000 条一批是折中：yield 太频繁会放大调度开销，太稀则单段阻塞仍然过长。
    if (total % 2000 === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    // 无 hash 的存量记录：计为 legacy。这里的 resetWindow 是防御性的——走到这条分支说明
    // 还没见过带哈希的记录，窗口本来就是空的（变异自检里有一臂专门证它删不掉任何结论）。
    // 清空窗口 ≠ 免检：其后那条要不要验链接，取决于"它是不是窗口的第一条"，见下面 isFirst。
    if (!doc.hash) {
      if (seenHashed) {
        // 2026-09-30：带 hashFailure 标记 ⇒ 归因明确是「算 hash 抛错后照常落库」，
        // 不是人为抹除。单列计数、**不计 breaks**——但**仍然重置窗口、仍然不置 isFirst**，
        // 与 hash_stripped 同处理：这段的哈希本来就没了，其后的记录链接必然失联，
        // 是真实结论而不是噪声（两条一起报才完整）。
        //
        // 为什么绕不过这个标记（威胁模型）：能写 hashFailure 的攻击者已经有 DB 写权限，
        // 那种情况下直接 $unset hash 更省事、更彻底；而本字段**不参与哈希**
        // （不在 PAYLOAD_FIELDS_V4 里），所以它无法洗白一条被改过内容的记录——
        // 内容篡改仍由 hash_mismatch 抓。它唯一的作用是把"无哈希"的归因从硬篡改
        // 降级为待查，且降级后**仍有独立计数与告警**（hashComputeFailed > 0 使
        // computeChainVerdict 不走「全绿」结论，见该函数）。即攻击者用这个标记能做的
        // 最坏事情是"把一处篡改告警换成一处缺口告警"，不是"让篡改消失"。
        if (doc.hashFailure) {
          hashComputeFailed += 1;
          byType.hash_compute_failed += 1;
          if (samples.length < MAX_SAMPLES) {
            samples.push({
              _id: String(doc._id),
              index: total,
              type: 'hash_compute_failed',
              reason: doc.hashFailure,
              action: doc.action,
              timestamp: doc.timestamp,
            });
          }
        } else {
          pushBreak({
            _id: String(doc._id),
            index: total,
            type: 'hash_stripped',
            action: doc.action,
            timestamp: doc.timestamp,
          });
        }
        // 这里**不**重置 isFirst：抹掉哈希正是为了让自己和后继之间的链接失联，
        // 沿用 legacy 的「跳过其后第一条」宽容等于替篡改者收尾。父哈希已不存在，
        // 后继必然 chain_break —— 两条一起报才是完整结论。
        resetWindow();
        continue;
      }
      legacy += 1;
      resetWindow();
      // 「窗口第一条免检」只给窗口的第一条，不给「legacy 段之后的第一条」：
      // 后者的父哈希不是落在窗口外，而是就在它前面那条记录的位置上——而那条没有哈希。
      // 诚实形态不受影响：链启用时 getChainTail 在库里读不到任何带哈希的记录，
      // 启用后的第一条 prevHash 为 null，而 prevHash=null 本来就是链首（见上面的链接检查）。
      // 原写法在这里置 isFirst=true，把「整窗抹哈希但留最新一条」洗成 intact=true、code=0，
      // 而「整窗抹光」反而被 nothingHashed 挡住在 code=2 —— 留一条比抹光更好用。
      isFirst = false;
      continue;
    }
    seenHashed = true;

    const version = doc.hashVersion || 1;
    const expectedHash = computeHash(doc.prevHash, canonicalPayload(doc, version));
    if (expectedHash !== doc.hash) {
      // v2 记录额外尝试「批量路径历史口径」：v2 时期 chainBatch 未补 schema
      // 默认值，riskLevel/riskFactors 落库后被 Mongoose 填充，重算必然失配。
      // 这是已知的实现缺陷而非篡改，不应计入 breaks 淹没真实告警。
      // v1/v3 不做此宽容：v1 的 payload 不含这两个字段，v3 已保证算前补齐。
      const toleratedByLegacyBatch =
        version === 2 && computeHash(doc.prevHash, canonicalPayloadV2LegacyBatch(doc)) === doc.hash;

      if (toleratedByLegacyBatch) {
        legacyV2BatchTolerated += 1;
      } else {
        pushBreak({
          _id: String(doc._id),
          index: total,
          type: 'hash_mismatch',
          hashVersion: version,
          action: doc.action,
          timestamp: doc.timestamp,
        });
      }
    }

    if (hmacChecked) {
      if (!doc.hmac) {
        pushBreak({ _id: String(doc._id), index: total, type: 'hmac_missing', action: doc.action });
      } else if (doc.hmac !== computeHmac(doc.hash)) {
        pushBreak({
          _id: String(doc._id),
          index: total,
          type: 'hmac_mismatch',
          action: doc.action,
        });
      }
    }

    // 链接性：prevHash=null 是链首，合法
    if (!isFirst && doc.prevHash) {
      if (!seen.has(doc.prevHash)) {
        pushBreak({
          _id: String(doc._id),
          index: total,
          type: 'chain_break',
          action: doc.action,
          actualPrevHash: doc.prevHash,
          timestamp: doc.timestamp,
        });
      } else if (firstChildOf.has(doc.prevHash)) {
        // 同一个父哈希的第二个孩子 ⇒ 分叉。两条记录自身都算得回来，所以只有这里能看见。
        pushBreak({
          _id: String(doc._id),
          index: total,
          type: 'chain_fork',
          action: doc.action,
          parentHash: doc.prevHash,
          forkedWithId: firstChildOf.get(doc.prevHash),
          timestamp: doc.timestamp,
        });
      } else {
        firstChildOf.set(doc.prevHash, String(doc._id));
      }
    }

    remember(doc.hash);
    isFirst = false;
  }

  return {
    intact: breaks === 0,
    total,
    legacy,
    breaks,
    byType,
    // v2 时期批量写入路径的默认值漂移条数（已知实现缺陷，非篡改）。
    // 这些记录的 riskLevel/riskFactors 从未受哈希保护，事后无法追认；
    // 数值应随存量记录过期（TTL）而归零，若持续增长说明仍有 v2 写入路径存活。
    legacyV2BatchTolerated,
    // hashFailure 标记的无哈希记录数（auditBuffer 算 hash 失败后落库）。
    // 不计 breaks，但 > 0 表示链上有一段无法追认——消费方必须看得见，
    // 且 computeChainVerdict 据此不让报告拿 code 0（见该函数的 hashComputeFailed 段）。
    hashComputeFailed,
    hmacChecked,
    scanned: { maxRecords, fromLatest, filter },
    chainTailHash: seenOrder.length ? seenOrder[seenOrder.length - 1] : null,
    samples,
    verifiedAt: new Date().toISOString(),
  };
};

/**
 * 扫描口径是否"局部"：缺 scanned 或带 filter 都算。
 *
 * 单独成函数有两个理由：① 判据主体要同时摆 5 条否决 + 6 段文案，
 * 全挤进一个箭头函数就是 complexity 27，会被 lint:ratchet（只许降不许升）挡下——
 * 拆分在这里不是审美，是让"再加一条否决"仍然便宜；② 这一条判据本身有细节
 * （服务层对无过滤的扫描回显 `filter: {}`，空对象不算子集），值得有名字。
 */
const isPartialScan = (scanned) => {
  if (!scanned) return true; // 口径未知 ⇒ 按局部处理（fail-closed）
  const filter = scanned.filter;
  return Boolean(filter && Object.keys(filter).length > 0);
};

/** 六条否决的文案，顺序即判据的优先级顺序（断裂在最前：最可行动的那条先读到） */
const chainVetoReasons = (v) => {
  const reasons = [];
  if (v.breaks > 0) reasons.push(`发现 ${v.breaks} 处断裂/失配`);
  if (v.truncated) {
    reasons.push(
      `仅覆盖 ${v.total}/${v.collectionTotal} 条即达 maxRecords=${v.maxRecords} 上限，剩余未校验` +
        (v.collectionTotal < v.total
          ? `（元数据估算 ${v.collectionTotal} 条低于实际扫到的 ${v.total} 条，估算与扫描互相矛盾，不以估算撤销截断判定）`
          : '')
    );
  }
  if (v.hmacSkipped) {
    reasons.push('未配置 HMAC_SECRET，hmac 层未参与校验（无密钥 SHA-256 可被整条链重算）');
  }
  if (v.emptyWaived) {
    reasons.push('审计集合为空（0 条）：无记录可验，"无断裂"不等于"链完好"');
  }
  if (v.nothingVerified) {
    reasons.push(
      `本次实际扫到并核验 0 条（元数据估算集合有 ${v.collectionTotal} 条）：` +
        '一条都没验过的链不具备完整性背书，且估算与扫描已不一致（不受 --allow-empty 豁免）'
    );
  }
  if (v.nothingHashed) {
    reasons.push(
      `本次扫到 ${v.total} 条，但全部无哈希（legacy=${v.legacy}）：一条都没有经过哈希校验，` +
        '不得宣称链完整——"链启用前的存量集合"与"整表 $unset 掉 hash/prevHash/hmac"在数据上不可区分'
    );
  }
  // 缺口理由排在"截断/子集"之前：它比核验口径问题更具体——是数据里真的有东西无法追认。
  // （2026-09-30 新增，见 computeChainVerdict 的 hashComputeFailed 段）
  if (v.hasUnattestableGap) {
    reasons.push(
      `发现 ${v.hashComputeFailed} 条哈希计算失败的无哈希记录（write-side 异常，非篡改）：` +
        '这些记录的内容未被哈希保护，链在该处不可追认，不得宣称完整'
    );
  }
  if (v.scoped) {
    reasons.push(
      v.scopeUnknown
        ? '调用方未回传 scanned 扫描口径，无从判断这是全量还是子集（按局部校验处理）'
        : `带 filter 的子集校验 ${JSON.stringify(v.scanned.filter)}：子集内无断裂不等于全链无断裂`
    );
  }
  return reasons;
};

/**
 * 带 hashFailure 标记的无哈希记录数 → 是否构成"不可追认的缺口"。
 *
 * 单独成函数（与 isPartialScan 同理）有两条理由：
 * ① computeChainVerdict 的 complexity 已贴着棘轮上限，正负两句判据再进主体就超；
 * ② 这条判据有一处**方向与邻居相反**的约定（缺省按 0 而非按"未知"），值得有名字。
 *
 * 缺省为何按 0（与 legacy/scanned 的"缺省按未知、偏保守"相反）：
 * 该字段的"未知"没有保守侧可言——把每次正常核验都判 INCOMPLETE 会让判据失去区分力，
 * 而那比漏报更糟（运维会开始忽略 code 2）。它由 verifyAuditChain 恒回填，
 * 唯一漏传路径是旧调用方，而旧调用方根本不可能产生带 hashFailure 标记的记录。
 */
const hasUnattestableGapOf = (hashComputeFailed) =>
  Number.isFinite(hashComputeFailed) ? hashComputeFailed > 0 : false;

/**
 * 「能不能宣称审计链完整」的唯一判据（CLI 与在线接口共用）
 *
 * 为什么要在服务层而不是脚本里：这个判据此前有两份实现——
 * `scripts/verify-audit-chain.js` 纳入了 truncated/empty/hmac 三类"不完整"，
 * 而在线的 `GET /api/security/audit-logs/verify` 只看 `intact && hmacChecked`，
 * 于是同一个事实在两处给出不同结论：脚本退 2 说"不得当作链完整"，
 * 接口却回答「审计链完整」并把核验审计记成 riskLevel=low。
 * 在线侧是 UI 与运维实际读的那一个，错得更贵。
 *
 * 不完整理由彼此独立，且**豁免不得越界**：allowNoHmac 只豁免 hmac，
 * allowEmpty 只豁免"集合本来就是空的"（首次部署）；"扫到 0 条"和截断、子集校验
 * 一样没有任何豁免口子——前者是估算与扫描互相矛盾的异常现场，不是一句"我知道是空的"
 * 能盖过去的；后者根本不该由判据的调用方自行声明（见下面 scanned 一段）。
 *
 * 为什么"扫过的条数"要单独否决一遍（total === 0 与 collectionTotal === 0 不是一回事）：
 * collectionTotal 来自 `estimatedDocumentCount()`，是**元数据估算**；total 是游标真的读回来
 * 并逐条重算过哈希的条数。两者不同源，就可以各说各话：
 * - 在线侧 scan 与估算之间隔着一个 await，清空集合与并发写入交错 ⇒ total=0 而估算>0；
 * - 脚本侧估算在 scan **之前**取（verify-audit-chain.js），扫描期间被清空 ⇒ 同一现场。
 * 旧判据只看 `collectionTotal === 0`，于是"0 条被验过 + 估算非 0"直接得 code 0，
 * 接口答「审计链完整」、脚本打 `PASS（全量、无断裂、hmac 已校验）`——
 * 为一条都没核验过的链签了合格证明，正是 auditController 里
 * 「等于为灭迹签发合格证明」那段注释声称要防的事。
 *
 * 为什么窗口打满时估算**低于**扫描数也要否决（`total !== collectionTotal` 而非 `<`）：
 * 旧式 `total < collectionTotal` 把估算当作"库里还有更多"的唯一证据，估算滞后偏低时
 * 条件为假 ⇒ 截断否决被一个不可信的数撤销。反过来（估算偏高）本来就判截断，
 * 不受影响。残留上限：估算恰好等于窗口大小时无从分辨"真就这么多条"与"估算滞后"，
 * 要分辨只能实打实 countDocuments({})（千万级集合上是全索引扫，代价不该由核验请求付）；
 * 判据在此选择保守一侧的方向是"宁可 INCOMPLETE，也不给局部结论盖章"。
 *
 * 为什么"整窗无哈希"要单独否决（`nothingHashed`）：`legacy` 是"无 hash 的记录数"，
 * 它同时容纳两种成因——链启用前的存量集合，与"整表 `$unset` 掉 hash/prevHash/hmac"
 * 的彻底灭迹。旧判据只把 legacy 当计数回显，**没有任何否决基于它**，于是实测出现
 * 这个反向激励：只抹链尾 ⇒ code=1（断裂）；整表全抹 ⇒ code=0（**"链完整"**、
 * 核验审计记 riskLevel=low）。抹得越彻底、结论反而越好，防御对更强的攻击失效。
 * `legacy` 缺省（调用方漏传）按"未知"处理、视同整窗无哈希，方向与缺 `scanned` 一致：
 * 偏保守，不产生假 PASS。确要在"链从未启用"的存量库上放行，显式传
 * `allowAllLegacy: true`（脚本侧对应 `--allow-all-legacy`）——与另两个豁免彼此独立，
 * 不得互相顶替。
 *
 * @param {Object} [params.scanned] 报告自带的扫描口径 verifyAuditChain 的 scanned 字段。
 *   判据据此识别"这只是一次子集校验"：带 filter 的扫描即使没撞上限也不是全量，
 *   旧判据对此毫无察觉（total=5 / maxRecords=20000 / collectionTotal=5000 ⇒ code 0「完整」），
 *   而服务层的 JSDoc 只是"建议"消费方自己看 filter 回显。**缺 scanned 一律按局部校验处理**：
 *   调用方漏传只会得到偏保守的 INCOMPLETE（响亮），不会得到一个假的 PASS（静默）。
 * @param {number} [params.legacy] 报告自带的"无 hash 记录数"（verifyAuditChain 的 legacy 字段）。
 *   缺省按"未知"处理并视同整窗无哈希（偏保守），见上面 `nothingHashed` 一段。
 * @param {number} [params.hashComputeFailed] 报告自带的"哈希计算失败的无哈希记录数"
 *   （verifyAuditChain 的 hashComputeFailed 字段）。> 0 时判据否决 code 0——
 *   这些记录的内容未被哈希保护，链在该处不可追认。缺省按 0 处理（与 legacy 方向相反，
 *   理由见实现内注释）。**不计入 breaks**：那是硬篡改信号，良性缺口不该淹没它。
 * @param {boolean} [params.allowAllLegacy=false] 唯一豁免 `nothingHashed` 的开关，
 *   仅供"链从未启用"的存量库在知情前提下放行；与 allowNoHmac / allowEmpty 彼此独立。
 *
 * @returns {{code:number, canAttestIntact:boolean, reasons:string[], truncated:boolean, hmacSkipped:boolean, empty:boolean, nothingVerified:boolean, nothingHashed:boolean, hasUnattestableGap:boolean, scoped:boolean}}
 *          code：0=全量且无断裂且各层都真跑过；1=发现断裂；2=不完整（不得宣称完整）
 */
const computeChainVerdict = ({
  breaks,
  total,
  maxRecords,
  collectionTotal,
  hmacChecked,
  legacy,
  hashComputeFailed: hashComputeFailedIn,
  scanned,
  allowNoHmac = false,
  allowEmpty = false,
  allowAllLegacy = false,
}) => {
  const truncated = total >= maxRecords && total !== collectionTotal;
  const hmacSkipped = !hmacChecked && !allowNoHmac;
  const emptyCollection = collectionTotal === 0;
  // 唯一可豁免的一条："我知道集合是空的"（首次部署）
  const emptyWaived = emptyCollection && !allowEmpty;
  const nothingVerified = total === 0 && collectionTotal > 0;
  // 扫到了记录，却**一条都没有经过哈希校验**（整窗无 hash ⇒ 全被 legacy 吸收）。
  //
  // 为什么必须单独否决：两种成因在数据上不可区分——①链启用前的存量集合；
  // ②有人把 hash/prevHash/hmac 整组 $unset（直连驱动 / mongosh 可绕过模型中间件）。
  // ②是**彻底灭迹**，而旧判据下它比"只抹链尾"**更容易拿到 intact**：legacy 把整窗
  // 全数吸收、breaks 恒为 0，于是"抹得越干净"反而"判得越干净"——防御对更彻底的
  // 攻击失效。这与 auditController 里"等于为灭迹签发合格证明"要防的是同一件事，
  // 只是触发形态从"0 条可验"变成"N 条全不可验"。
  //
  // legacy 缺省按"未知"处理、视同整窗无哈希：与 isPartialScan 对缺 scanned 的方向
  // 一致（**漏传只得到偏保守的 INCOMPLETE，不会得到假 PASS**）。
  //
  // 这条闸只管到"N 条全不可验"为止，**不要**把它改成比例阈值：覆盖率不足 X% 在数据上
  // 与"链刚启用"无法区分，改了就是给每个新库发一张不合格证明。"抹光但留一条"这一档
  // 由链接性那一层抓（legacy 段之后的第一条 prevHash 非空 ⇒ 父失联 ⇒ chain_break ⇒ code=1），
  // 见 verifyAuditChain 的 legacy 分支与文件头。
  const legacyCount = Number.isFinite(legacy) ? legacy : total;
  const nothingHashed = total > 0 && legacyCount >= total && !allowAllLegacy;
  // 2026-09-30：带 hashFailure 标记的无哈希记录 ⇒ 链上有无法追认的缺口。
  // **不计入 breaks**（那是硬篡改信号，会被良性缺口淹没），但**不能给 code 0**：
  // 一条记录缺失哈希就是"这段内容未被证明未被改"，无论成因是人为抹除还是算 hash 抛错。
  // 这道闸与 nothingHashed 的区别：nothingHashed 管"整窗一条都没哈希"（彻底灭迹形态），
  // 这里管"窗口里混进了若干条无哈希"（部分缺口）——旧实现下后者会让 intact=true、
  // 且 breaks=0 ⇒ code 0「审计链完整」，等于对缺口一字不提。
  // 判据与缺省方向见 hasUnattestableGapOf。
  const hasUnattestableGap = hasUnattestableGapOf(hashComputeFailedIn);
  const scopeUnknown = !scanned;
  const scoped = isPartialScan(scanned);
  const reasons = chainVetoReasons({
    breaks,
    total,
    maxRecords,
    collectionTotal,
    legacy: legacyCount,
    truncated,
    hmacSkipped,
    emptyWaived,
    nothingVerified,
    nothingHashed,
    hasUnattestableGap,
    hashComputeFailed: hashComputeFailedIn,
    scoped,
    scopeUnknown,
    scanned,
  });
  const vetoes = [
    truncated,
    hmacSkipped,
    emptyWaived,
    nothingVerified,
    nothingHashed,
    hasUnattestableGap,
    scoped,
  ];
  const code = breaks > 0 ? 1 : vetoes.some(Boolean) ? 2 : 0;
  return {
    code,
    canAttestIntact: code === 0,
    reasons,
    truncated,
    hmacSkipped,
    empty: emptyCollection || nothingVerified,
    nothingVerified,
    nothingHashed,
    hasUnattestableGap,
    scoped,
  };
};

module.exports = {
  verifyAuditChain,
  computeChainVerdict,
  LINK_WINDOW_SIZE,
  DEFAULT_MAX_RECORDS,
  HARD_MAX_RECORDS,
};
