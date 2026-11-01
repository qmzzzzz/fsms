/**
 * 审计哈希链完整性校验服务
 *
 * 单一实现，供**四个**调用方复用：
 *   1. 运维脚本 scripts/verify-audit-chain.js（人工核查）；
 *   2. 运维脚本 scripts/resign-audit-chain-v3.js（改写前/后核验）；
 *   3. 管理接口 GET /api/security/audit-logs/verify
 *      （见 controllers/auditController.verifyAuditChainIntegrity）；
 *   4. 周期自检 services/auditChainMonitor.js（`auditChainMonitor.start()`，
 *      在 src/index.js 的启动流程里注册，窗口默认最近 2000 条）。
 *
 * 第 4 条是 2026-09-30 补的：此前链核验**只在被调用时**发生，"篡改会留痕"成立
 * 而"痕迹会被发现"不成立，于是把发现从人工动作变成自动循环。本文件此前的注释
 * 写的是"没有周期性自检这一方"，在 monitor 上线后已成反向描述（F-14，2026-10-17
 * 审计指出：过期注释会让维护者误判系统没有自动检测）。
 *
 * 注意 monitor 只**读**链、不写链：它调用本文件的 verifyAuditChain 拿报告，
 * 断裂/缺口交给 securityAlert 告警；任何补链/改写动作仍只能走上面的脚本。
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
 * 3. 链接性校验（删除检测）—— 每条记录的 prevHash 必须命中「窗口哈希集合」：已扫过的
 *    最近 256 条哈希（滑动窗口），或**未扫到**的 ≤ LINK_WINDOW_SIZE 个位次内的前瞻窗口
 *    （`auditBuffer.push` 在 push 时就分配 `_id`、串链要等链锁 ⇒ 子可能先于父被扫到，
 *    p6-d 实测形态）。判据**不依赖「谁先被扫到」**；中间隔着无哈希记录（分隔段边界）
 *    一律 chain_break，窗口外同样回落 chain_break（不静默、不假红）。窗口足够小
 *    ⇒ **删除**记录会立即暴露；插入伪造在本层不可检出，成因与修法见「已知检出上限」段。
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
 * 计入 breaks，每轮核验都报断裂 ⇒ 真实篡改告警被常态噪声淹没（「幻影链尾」的
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

// 链接性窗口：父可在**已扫侧最近 256 条哈希**里，或**未扫侧 ≤ 该值个位次**的前瞻里；
// 远小于任何有意义的删除批量 ⇒ 删除可检出；插入伪造不可检，见文件头「已知检出上限」
const LINK_WINDOW_SIZE = 256;

// 单次校验的记录上限：审计集合可达千万级，全量校验必须由离线脚本分段执行。
// 接口侧默认只校验最近一段，避免长事务与内存膨胀。
const DEFAULT_MAX_RECORDS = 20000;
const HARD_MAX_RECORDS = 200000;

// 断裂样本上限（响应体大小保护）
const MAX_SAMPLES = 20;

// 单批让出的条数（见 verifyAuditChain 循环内的说明）
const YIELD_EVERY = 2000;

/** 断裂/缺口样本的统一形状（_id 转字符串：样本会进 JSON 响应体） */
const sampleOf = (doc, index, type, extra = {}) => ({
  _id: String(doc._id),
  index,
  type,
  ...extra,
  action: doc.action,
  timestamp: doc.timestamp,
});

/**
 * 扫描状态：计数、样本、链接窗口与两个游标。一个可变对象串起下面全部具名步骤。
 *
 * 为什么不是"每步返回新状态"的纯函数：本循环是千万级记录的纯 CPU 路径，
 * 每条约 3 次分支都要复制一个含 Set/Map/数组的状态对象，代价全在分配上。
 * 可变状态 + 单一写入点（pushBreak / countUnattestableGap / rememberHash）换来的是
 * 「谁改了计数」只有三处可查，这是本文件能保持可维护的实际理由。
 */
const newChainState = () => ({
  byType: {
    hash_mismatch: 0,
    hmac_missing: 0,
    hmac_mismatch: 0,
    chain_break: 0,
    // F-184a：同一个父哈希被两条记录认领（链在此处分叉成 DAG）。原判据是成员测试，
    // 一个父节点挂两个子节点照样通过 ⇒「防篡改」的链接性在最关键的一种形态上是静默的。
    chain_fork: 0,
    hash_stripped: 0,
    // 2026-09-30：带 AuditLog.hashFailure 标记的无哈希记录（auditBuffer 算 hash 抛错后
    // 照常落库的那批）。与 hash_stripped 数据形态相同，但成因是良性的、且会**持续**产生
    // ⇒ 单列一类、**不计入 breaks**，否则每轮核验都报断裂，真实篡改告警被常态噪声淹没。
    // 仍计入告警面：它代表链上有一段无法追认的记录，是完整性缺口的直接信号。
    hash_compute_failed: 0,
  },
  samples: [],
  breaks: 0,
  legacy: 0,
  legacyV2BatchTolerated: 0,
  hashComputeFailed: 0,
  hmacChecked: isHmacConfigured(),
  // 链接窗口：`seen` 判「父在不在窗口内」，`firstChildOf` 判「父是否已被别的孩子认领」
  // （F-184a 分叉）。两者必须**同生同灭**（见 rememberHash）——原先 forgetOldest 只删
  // firstChildOf 而 seen 一路涨到整窗，实测同父两子的分叉在父哈希落后 ≥256 条时
  // **两头都不报**（无 chain_break、无 chain_fork，报告 intact: true），且第二条伪造记录
  // 会把同胞指认覆盖成第一条伪造记录。诚实链不因此多出断裂：一条链若没有任何断裂，它的
  // 读入顺序就是串链顺序，每个父哈希恰好落在前 1 个位置上，256 的窗口挡不住它。
  seen: new Set(),
  seenOrder: [],
  firstChildOf: new Map(),
  // 免检范围严格等于「本窗口的第一条」：它的父记录可能落在窗口之外（maxRecords 截断、
  // TTL 把头一批删掉）。legacy 段之后的那条**不在**这一档里（recordHashlessRecord 不置
  // isFirst），见文件头。
  isFirst: true,
  // 是否已经见过「带哈希」的记录。用于区分两种形态完全不同的无哈希记录：
  // 出现在带哈希记录**之前** = 存量 legacy（写入时尚无哈希链），不属篡改；
  // 出现在**之后** = 完整性无法追认（人为 $unset 灭迹，或算 hash 抛错后仍落库）。
  seenHashed: false,
});

/** 记一处断裂：计 breaks + byType + 样本（三者的唯一写入点之一） */
const pushBreak = (state, sample) => {
  state.breaks += 1;
  state.byType[sample.type] = (state.byType[sample.type] || 0) + 1;
  if (state.samples.length < MAX_SAMPLES) state.samples.push(sample);
};

/**
 * 记一处缺口（带 hashFailure 标记的无哈希记录）。
 *
 * **不计 breaks**：那是硬篡改信号，良性缺口不该淹没它。但计数与样本都要有，
 * 否则「链上有段无法追认」在报告里不可见（computeChainVerdict 据此拒绝给出 code 0）。
 */
const countUnattestableGap = (state, doc, index) => {
  state.hashComputeFailed += 1;
  state.byType.hash_compute_failed += 1;
  if (state.samples.length < MAX_SAMPLES) {
    state.samples.push(sampleOf(doc, index, 'hash_compute_failed', { reason: doc.hashFailure }));
  }
};

/** 记住一条哈希；超出窗口则淘汰最旧的那条（seen 与 firstChildOf 同步淘汰） */
const rememberHash = (state, hash) => {
  state.seen.add(hash);
  state.seenOrder.push(hash);
  if (state.seenOrder.length <= LINK_WINDOW_SIZE) return;
  const oldest = state.seenOrder.shift();
  state.seen.delete(oldest);
  state.firstChildOf.delete(oldest);
};

/**
 * 清空链接窗口。清空 ≠ 免检：其后那条要不要验链接，取决于"它是不是窗口的第一条"，
 * 见 isFirst。这里的清空是防御性的——走到 legacy 分支说明还没见过带哈希的记录，
 * 窗口本来就是空的（变异自检里有一臂专门证它删不掉任何结论）。
 */
const resetLinkWindow = (state) => {
  state.seen.clear();
  state.seenOrder.length = 0;
  state.firstChildOf.clear();
};

/** 链尾 = 窗口里最后记住的那个哈希（空窗口为 null） */
const tailHashOf = (state) =>
  state.seenOrder.length ? state.seenOrder[state.seenOrder.length - 1] : null;

/**
 * 无哈希记录的处置（三档）。
 *
 * 出现在带哈希记录**之前** = 存量 legacy（不计断裂），但「其后第一条」不再免检：
 * 后者的父哈希不是落在窗口外，而是就在它前面那条记录的位置上——而那条没有哈希。
 * 诚实形态不受影响：链启用时库里读不到任何带哈希的记录，启用后第一条 prevHash 为 null，
 * 而 prevHash=null 本来就是链首。
 *
 * 出现在**之后** = 完整性无法追认：带 hashFailure 标记的是良性 write-side 异常
 * （单列缺口、不计 breaks），没有标记的按 hash_stripped 计入断裂。两档都**重置窗口且
 * 不置 isFirst**——抹掉哈希正是为了让自己和后继之间的链接失联，沿用 legacy 的「跳过其后
 * 第一条」宽容等于替篡改者收尾。父哈希已不存在，后继必然 chain_break，两条一起报才完整。
 */
const recordHashlessRecord = (state, doc, index) => {
  if (!state.seenHashed) {
    state.legacy += 1;
    resetLinkWindow(state);
    state.isFirst = false;
    return;
  }
  if (doc.hashFailure) {
    countUnattestableGap(state, doc, index);
  } else {
    pushBreak(state, sampleOf(doc, index, 'hash_stripped'));
  }
  resetLinkWindow(state);
};

/** v2 批量路径的历史默认值漂移：不是篡改，单独计数不计入 breaks */
const toleratedByLegacyBatch = (doc, version) =>
  version === 2 && computeHash(doc.prevHash, canonicalPayloadV2LegacyBatch(doc)) === doc.hash;

/**
 * 内容层：hash 重算（内容防篡改）+ hmac（密钥防篡改）。hmac 未配置时整层跳过，
 * 报告里由 hmacChecked 显式声明（无密钥 SHA-256 可被整条链重算）。
 *
 * v2 记录额外尝试「批量路径历史口径」：v2 时期 chainBatch 未补 schema 默认值，
 * riskLevel/riskFactors 落库后被 Mongoose 填充，重算必然失配。这是已知的实现缺陷而非
 * 篡改，不应计入 breaks 淹没真实告警。v1/v3 不做此宽容：v1 的 payload 不含这两个字段，
 * v3 已保证算前补齐。
 */
const checkContentHash = (state, doc, index) => {
  const version = doc.hashVersion || 1;
  if (computeHash(doc.prevHash, canonicalPayload(doc, version)) !== doc.hash) {
    if (toleratedByLegacyBatch(doc, version)) {
      state.legacyV2BatchTolerated += 1;
    } else {
      pushBreak(state, sampleOf(doc, index, 'hash_mismatch', { hashVersion: version }));
    }
  }
  if (!state.hmacChecked) return;
  if (!doc.hmac) {
    pushBreak(state, sampleOf(doc, index, 'hmac_missing'));
    return;
  }
  if (doc.hmac !== computeHmac(doc.hash)) {
    pushBreak(state, sampleOf(doc, index, 'hmac_mismatch'));
  }
};

/** 前瞻窗口（见文件头第 3 条）：父哈希在**尚未扫到**的 ≤ LINK_WINDOW_SIZE 个位次内吗？
 *  量的是位次而不是 _id；遇无哈希记录（分隔段边界）即否定——抹掉哈希正是为了让前后失联。 */
const parentAhead = (docs, index, prevHash) => {
  const ahead = docs.slice(index, index + LINK_WINDOW_SIZE);
  const stop = ahead.findIndex((d) => !d.hash || d.hash === prevHash);
  return stop >= 0 && ahead[stop].hash === prevHash;
};

/**
 * 链接性层：prevHash=null 是链首（合法）；父不在窗口内 = chain_break（删除检测）；
 * 父已被别的孩子认领 = chain_fork（分叉检测）。
 *
 * 父在不在由两个窗口共同回答：已扫侧是最近 256 条哈希的滑动窗口，未扫侧是位次 ≤
 * LINK_WINDOW_SIZE 的前瞻（见 parentAhead），**不再**是"扫描顺序里出现过没有"：
 * `AuditLog.create` 在构造文档时分配 `_id`、auditBuffer 批次要等链锁 ⇒ 子先于父被扫到
 * 是诚实形态，按出现先后判会产出假阳性断链（p6 实测），反而掩盖真实篡改。
 */
const checkLinkage = (state, doc, index, docs) => {
  if (state.isFirst || !doc.prevHash) return;
  if (!state.seen.has(doc.prevHash) && !parentAhead(docs, index, doc.prevHash)) {
    pushBreak(state, sampleOf(doc, index, 'chain_break', { actualPrevHash: doc.prevHash }));
    return;
  }
  // 同一个父哈希的第二个孩子 ⇒ 分叉。两条记录自身都算得回来，所以只有这里能看见。
  if (state.firstChildOf.has(doc.prevHash)) {
    pushBreak(
      state,
      sampleOf(doc, index, 'chain_fork', {
        parentHash: doc.prevHash,
        forkedWithId: state.firstChildOf.get(doc.prevHash),
      })
    );
    return;
  }
  state.firstChildOf.set(doc.prevHash, String(doc._id));
};

/** 扫描口径归一：三处默认值 + 预算取整的唯一来源（理由见 verifyAuditChain 的 JSDoc） */
const normalizeScanOptions = (options) => {
  // 预算归一：只接受**有限正数**，并向下取整。取整不是洁癖——真库实测小数一律被拒
  // （文案随 mongod 版本而变：本机报 FailedToParse「Expected an integer: maxTimeMS」，
  // 测试用的内存 mongod 报「maxTimeMS has non-integral value」），负数报 BadValue。
  // 两种都是**抛错**形态，若留给调用方传（间隔来自 env，`AUDIT_*_INTERVAL_MS=1.5`
  // 完全可能）就会让每一轮核验都在服务端失败，而闸门侧看到的是 failures 恒增——
  // 比没预算更难查。0 / 未设置 / NaN / Infinity / 非数字一律落回"不限"（原行为）。
  const budget = Number(options.maxTimeMS);
  const maxRecords = Number(options.maxRecords) || DEFAULT_MAX_RECORDS;
  return {
    maxRecords: Math.max(1, Math.min(maxRecords, HARD_MAX_RECORDS)),
    fromLatest: options.fromLatest !== false,
    filter: options.filter && Object.keys(options.filter).length > 0 ? options.filter : {},
    maxTimeMS: Number.isFinite(budget) && budget > 0 ? Math.floor(budget) : 0,
  };
};

/** 取窗口：按 _id 取最近（或最早）maxRecords 条，再反转成升序供链接性校验 */
const fetchChainWindow = async (AuditLog, scan) => {
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
  const windowOptions = scan.maxTimeMS > 0 ? { maxTimeMS: scan.maxTimeMS } : undefined;
  const window = await AuditLog.find(scan.filter, null, windowOptions)
    .sort({ _id: scan.fromLatest ? -1 : 1 })
    .limit(scan.maxRecords)
    .lean();
  return scan.fromLatest ? window.reverse() : window;
};

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
  const scan = normalizeScanOptions(options);
  const state = newChainState();
  const docs = await fetchChainWindow(AuditLog, scan);

  let total = 0;
  for (const doc of docs) {
    total += 1;

    // 定期让出事件循环：本循环对每条记录做 SHA-256 + 规范 JSON 序列化，是纯 CPU 工作，
    // 不 yield 时整个扫描期间该进程无法服务任何其他请求（心跳/健康检查也会超时）。
    // YIELD_EVERY 条一批是折中：yield 太频繁会放大调度开销，太稀则单段阻塞仍然过长。
    if (total % YIELD_EVERY === 0) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    if (doc.hash) {
      // seenHashed 必须在处理前置位：recordHashlessRecord 靠它区分「链启用前的存量」
      // 与「启用后被抹掉」，置晚了第一条无哈希记录会被误判成 legacy
      state.seenHashed = true;
      checkContentHash(state, doc, total);
      checkLinkage(state, doc, total, docs);
      rememberHash(state, doc.hash);
      state.isFirst = false;
    } else {
      recordHashlessRecord(state, doc, total);
    }
  }

  return {
    intact: state.breaks === 0,
    total,
    legacy: state.legacy,
    breaks: state.breaks,
    byType: state.byType,
    // v2 时期批量写入路径的默认值漂移条数（已知实现缺陷，非篡改）。
    // 这些记录的 riskLevel/riskFactors 从未受哈希保护，事后无法追认；
    // 数值应随存量记录过期（TTL）而归零，若持续增长说明仍有 v2 写入路径存活。
    legacyV2BatchTolerated: state.legacyV2BatchTolerated,
    // hashFailure 标记的无哈希记录数（auditBuffer 算 hash 失败后落库）。
    // 不计 breaks，但 > 0 表示链上有一段无法追认——消费方必须看得见，
    // 且 computeChainVerdict 据此不让报告拿 code 0（见该函数的 hashComputeFailed 段）。
    hashComputeFailed: state.hashComputeFailed,
    hmacChecked: state.hmacChecked,
    scanned: { maxRecords: scan.maxRecords, fromLatest: scan.fromLatest, filter: scan.filter },
    chainTailHash: tailHashOf(state),
    samples: state.samples,
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
 * 而那比漏报更糟（运维会开始忽略 code 2）。
 *
 * 漏传的实际后果（实测）：链尾一条 hashFailure 记录 ⇒ hashComputeFailed=1、breaks=0 ⇒
 * 旧 CLI 打「PASS」并退 0。修的是**调用方**，不是把缺省翻成 fail-closed——翻转会让判据对
 * 任何不带该字段的调用报 INCOMPLETE。逐调用点门禁见 src/tests/verifyChainExitCode.test.js。
 */
const hasUnattestableGapOf = (hashComputeFailed) =>
  Number.isFinite(hashComputeFailed) ? hashComputeFailed > 0 : false;

/**
 * 「能不能宣称审计链完整」的唯一判据（CLI 与在线接口共用）
 *
 * 此前脚本与在线接口各一份实现（同一事实两处结论不同，在线侧错得更贵），故收敛到服务层。
 *
 * 四条否决臂，**豁免不得越界**：① nothingVerified（扫到 0 条，与估算互相矛盾）——
 * 无豁免口子；② truncated（`total !== collectionTotal`，不用 `<`：估算滞后偏低会把
 * 截断否决撤销）；③ scoped（缺 `scanned` 一律按局部校验，漏传只得到偏保守的
 * INCOMPLETE，不会得到假 PASS）；④ nothingHashed（`legacy` 缺省按未知、视同整窗无
 * 哈希）——否则「只抹链尾 ⇒ 断裂；整表全抹 ⇒ 完整」形成反向激励。
 * allowNoHmac 只豁免 hmac、allowEmpty 只豁免首次部署的空集合、allowAllLegacy 只豁免
 * nothingHashed，三者彼此独立、不得互相顶替。取舍的实测成因见
 * `src/tests/services/auditChainVerdict.test.js`（每条否决臂都有反向用例）。
 *
 * @param {Object} [params.scanned] 报告自带的扫描口径；缺省按局部校验处理。
 * @param {number} [params.legacy] 无 hash 记录数；缺省按未知（偏保守）。
 * @param {number} [params.hashComputeFailed] 哈希计算失败的无哈希记录数；> 0 否决 code 0。
 *   **不计入 breaks**：那是硬篡改信号，良性缺口不该淹没它。
 * @param {boolean} [params.allowAllLegacy=false] 唯一豁免 nothingHashed 的开关。
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
