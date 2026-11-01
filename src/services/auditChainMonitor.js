/**
 * 审计哈希链的**周期自检**监控：定时核验 + 发现异常经 securityAlert 告警——核验此前只在被调用时执行，
 * 等于「防篡改」只是一件**可被查询**的装饰，不是**被守护**的不变量。
 *
 * 【与 auditMonitor 的分工】后者跑 `AuditLog.detectAnomalies()`（异常行为），**不碰哈希链**；本模块跑
 * `verifyAuditChain()`（逐条 SHA-256 重算）。成本差一个量级、失败含义完全不同（异常行为 ≠ 完整性断裂），
 * 合并只会让一个拖累另一个 ⇒ 独立定时器、独立间隔、独立健康计数。
 *
 * 【资源闸：两道】① CPU 闸 = 窗口条数（默认 2000，远小于接口侧 20000）：每条要做 SHA-256 + 规范 JSON
 * 序列化，调大到数万会让单轮占住事件循环数十秒、连带拖垮心跳与健康检查（接口侧有 HTTP 超时兜底，这里没有）。
 * ② 服务端闸 = maxTimeMS（`roundBudgetMs()`，取 `max(60s, 生效间隔)`）：窗口只管"扫到之后算多少条"，
 * **管不到取数本身**——`find` 在服务端挂死时 `await` 永不返回 ⇒ `verificationRunning` **永久停在 true**，
 * 此后每轮都判"上一轮未结束"而跳过、`finally` 轮不到执行，监控静默停摆而 `isRunning()` 仍回答 true。
 * 带预算后最坏情况由**服务端**中断本轮 → 抛错进 catch（计 failures、写 lastFailureMessage）→ `finally` 释放闸门。
 * 与 auditMonitor 的 roundBudgetMs 同法（见该文件 :73-75）。
 *
 * 【噪声治理：本模块最要紧的设计约束】断裂**每一轮都会被重新发现**，每轮都告警会让告警面变成常态噪声、
 * 真实篡改告警被淹没。故按**断裂指纹**（结论码 + 断裂总数 + 逐类型计数 + 缺口数的规范化串）去重：
 * 只有指纹**变化**时才推送（及每次跨日后的首次）——存量问题只响一次，新增问题立刻响。
 *
 * 生命周期：由 index.js 启动时 start()、优雅关闭时 stop()；定时器 unref，不阻塞进程退出。
 */
const AuditLog = require('../models/AuditLog');
const securityAlert = require('./securityAlert');
const logger = require('../utils/logger');
const { businessDateParts } = require('../constants/timezone');
const { readPositiveNumberEnv } = require('../utils/envNumber');

// 核验间隔（毫秒），默认 10 分钟——比 auditMonitor 的 5 分钟长：
// 完整性核验比异常检测重（逐条重算哈希），且篡改检测对"晚 10 分钟发现"不敏感。
const DEFAULT_INTERVAL_MS = 10 * 60 * 1000;
/** 最小间隔：低于此值会与 auditMonitor 抢库（两条扫描都打满集合） */
const MIN_INTERVAL_MS = 60 * 1000;
const MAX_INTERVAL_MS = 24 * 60 * 60 * 1000; // 上限远低于 2^31-1：超界的 setInterval 被 Node 静默压成 1ms，面板却照报配置值（理由见 ADR-013「间隔上界」）
/**
 * 单轮服务端预算的下限（毫秒）。与 auditMonitor 的 MIN_ROUND_BUDGET_MS 同值同义：预算取 `max(本下限, 生效间隔)`，间隔被配得再小也不给服务端发一个"比一轮还短"的上限（那样每一轮都会被自己的预算掐死，failure 恒增）。
 */
const MIN_ROUND_BUDGET_MS = 60 * 1000;
/**
 * 单轮扫描窗口（条）：限制**单轮 CPU 量**的那道闸（见文件头「资源闸」）。2000 条足以覆盖"最近一段时间"的写入，从而使**新发生的**篡改/缺口在下一轮就被看到；历史更早的篡改由离线全量脚本负责（接口/脚本仍有 20000 / 200000 的上限）。
 */
const DEFAULT_WINDOW_RECORDS = 2000;
/** 窗口硬上限：即使配置也不能突破（调度器里跑数十万条会占死事件循环） */
const MAX_WINDOW_RECORDS = 20000;
/** 连续失败到第 2 轮才占告警通道：单轮可能是抖动（maxTimeMS 掐断），连续两轮才不是偶发；之后按业务日频控 */
const FAILURE_ALERT_THRESHOLD = 2;

let monitorTimer = null;
/** 生效间隔（env 非法回落与下限钳制**之后**的值），与 auditMonitor 同口径 */
let effectiveIntervalMs = DEFAULT_INTERVAL_MS;
/** 单轮闸门：上一轮未结束时本轮跳过（扫描是纯 CPU + 遍历，一轮跑不完会叠加） */
let verificationRunning = false;

/** 健康计数（isRunning 只说定时器挂着，不说核验在成功跑——见 auditMonitor 的同款注释） */
const health = {
  runs: 0,
  failures: 0,
  consecutiveFailures: 0,
  skippedOverlaps: 0,
  lastRunAt: null,
  lastSuccessAt: null, // 整轮（含告警投递）无异常才算成功：与 lastRunAt 配对判「跑完了还是一半就断了」
  lastFailureAt: null,
  lastFailureMessage: null,
  lastVerdictCode: null,
};

/**
 * 单轮服务端预算：一轮最多占一个周期，但不低于下限（与 auditMonitor 同式）。读的是**钳制后**的 `effectiveIntervalMs`，所以 `AUDIT_CHAIN_MONITOR_INTERVAL_MS`
 * 配成 30s 时预算取 30s，配成非法值回落 10min 时预算跟着取 10min—— 两个旋钮不会互相打架（写死常量的话，间隔调小后预算就大于间隔，闸门形同不存在）。
 *
 * **必须取整**：`AUDIT_CHAIN_MONITOR_INTERVAL_MS` 的读取没有 `integer: true`
 * （只要求"正数"），所以 90000.5 是完全可能的配置值。而服务端对小数 maxTimeMS 是
 * **拒绝**的——真库实测 `estimatedDocumentCount({maxTimeMS: 1.5})` 抛错
 * （文案随 mongod 版本而变：FailedToParse「Expected an integer」或「non-integral value」）。核验侧（verifyAuditChain）自己会把预算向下取整，所以只有估算这一次调用会漏：
 * 不取整的后果是"find 每次都成功、count 每次都抛错"，本轮仍进 catch 释放闸门，于是表现为 failures 每轮 +1 而链核验看起来正常——比没有预算更难归因。
 */
function roundBudgetMs() {
  return Math.floor(Math.max(MIN_ROUND_BUDGET_MS, effectiveIntervalMs));
}

/**
 * 上次推送时的断裂指纹。只在**指纹变化**时推送（存量断裂不重复刷），见文件头「噪声治理」。
 */
let lastAlertFingerprint = null;
/** 上次推送所属业务日期：跨日后强制重推一次（当日一次的上限由它兜底） */
let lastAlertDay = null;
/** 上次**投递失败**的指纹：指纹不得因投递失败而被记成已处理，下一轮必须重投（且不被频控挡住） */
let pendingRetryFingerprint = null;

/** 断裂指纹的规范化串（键排序，保证同一现象恒定同串） */
const fingerprintOf = (verdict, report) => {
  const byType = report.byType || {};
  const parts = Object.keys(byType)
    .sort()
    .filter((k) => byType[k] > 0)
    .map((k) => `${k}:${byType[k]}`);
  return `code${verdict.code}|breaks${report.breaks}|gap${report.hashComputeFailed || 0}|${parts.join(',')}`;
};

/**
 * 本轮结论是否值得占用告警通道。
 *
 * 单独成函数有两个理由：① runVerification 的 complexity 贴着棘轮上限；② 这里有一条**反直觉的取舍**必须写在有名字的地方——`code 2`（核验不完整）
 *    **不**单独告警。截断/子集/无 hmac 在每轮定时窗口下都是**必然**的
 *    （窗口 2000 几乎一定小于集合），把它们纳入告警会让每轮都响，
 *    正是本模块存在的意义（降噪）的反面。这类信息由 getHealth().lastVerdictCode
 *    暴露给合规面板，不占告警通道。
 *
 * 只对"内容层面真的有问题"的两种情形告警：
 *   - breaks > 0：硬断裂（hash_mismatch / hash_stripped / chain_break / chain_fork）
 *   - hashComputeFailed > 0：链上有无法追认的缺口（write-side 异常，非篡改）
 *
 * @returns {{alert:boolean, hasBreaks:boolean, gapCount:number}}
 */
const alertWorthinessOf = (verdict, report) => {
  const hasBreaks = report.breaks > 0;
  const gapCount = report.hashComputeFailed || 0;
  return {
    alert: verdict.code !== 0 && (hasBreaks || gapCount > 0),
    hasBreaks,
    gapCount,
  };
};

/**
 * 投递审计链告警（档位/类型静态分派）。
 *
 * 抽为独立函数的两个理由：
 *   ① `runVerification` 的行数贴着 max-lines-per-function（100）上限，抽走这 15 行
 *      才能留在闸内——拆函数是本仓对体积债的既定处置方式；
 *   ② 档位/类型**不得写成三元表达式**这条约束（见函数内注释）值得有独立的注释位，
 *      写在内联代码块里容易被后来的重构顺手"简化"掉。
 *
 * @param {boolean} hasBreaks 断裂（true）还是仅哈希计算失败缺口（false）
 * @param {string} message 已渲染好的告警文案
 * @param {object} report verifyAuditChain 的原始报告
 * @param {number} gapCount 缺口计数
 */
async function dispatchChainAlert(hasBreaks, message, report, gapCount) {
  // 与 auditMonitor 一致：await 投递结果（它需要据此做自己的记账）。sendNotification 内部已重试并降级，不改变业务语义。
  //
  // 档位/类型**不得写成三元表达式**：出站告警契约闸（tests/services/outboundAlertContract
  // 的 D1/D2）按文本解析前两个实参，只认 `ALERT_LEVELS.<键>` 与 `ALERT_TYPES.<键>` 两种
  // 静态形态。写成 `hasBreaks ? A : B` 会被判为"既不是键也不是字面量"，把两条调用点闸
  // 一起打红（实测：2026-09-30）。这里改成 if/else 分派——静态形态保住，语义逐字不变。
  const noticeData = {
    breaks: report.breaks,
    byType: report.byType,
    hashComputeFailed: gapCount,
    total: report.total,
    legacy: report.legacy,
    // 样本已由服务层截断到 MAX_SAMPLES，含 _id/action 便于核查
    samples: report.samples,
  };
  if (hasBreaks) {
    await securityAlert.sendNotification(
      securityAlert.ALERT_TYPES.AUDIT_CHAIN_BREAK_DETECTED,
      securityAlert.ALERT_LEVELS.CRITICAL,
      message,
      noticeData
    );
  } else {
    await securityAlert.sendNotification(
      securityAlert.ALERT_TYPES.AUDIT_HASH_COMPUTE_FAILED,
      securityAlert.ALERT_LEVELS.HIGH,
      message,
      noticeData
    );
  }
}
/**
 * hash_stripped 的运维面指认（待裁定 #19 选项②：只改告警文案，不动 `intact` 判定）。
 *
 * 为什么值得单独一句：`hash_stripped` 与「链锁降级窗口」**数据形态相同**—— 分布式锁拿不到时该批同样无哈希落库、同样位于带哈希记录之后（utils/auditChain.js:220 抛错走降级 ⇒ auditBuffer 回退重试）。告警原文只报
 * `type=hash_stripped=N`，读者按字面读成"有人抹了哈希"，而这两类的运维动作完全不同。
 *
 * 为什么**不加可判别标记**（选项①）：标记与 `hash` 同层、同一个 DB 写权限可达，能 `$unset` hash 的内部人同样能伪造/抹掉标记，区分度是假的。
 * 为什么**不改 `intact` 判定**：§21.2「误报是 fail-closed 的定价，不是缺陷」—— 把降级窗口判成 intact 会让真篡改披着降级外衣过关，方向更危险。
 *
 * @param {object} report verifyAuditChain 的原始报告
 * @returns {string} 需追加的指认文案；无 hash_stripped 时为空串
 */
const hashStrippedOpsHint = (report) => {
  if (!(report.byType || {}).hash_stripped) return '';
  return (
    '；其中 hash_stripped 也可能是链锁降级窗口的产物（无哈希落库），不是篡改的充分证据，' +
    '请先核对同时间窗的链锁降级日志（"锁持有超时"/"AUDIT_CHAIN_LOCK_TIMEOUT_MS 非法"/' +
    '"共享链尾未能写入 Redis"）再定性'
  );
};

/**
 * 核验「连续失败」的告警出口（失败路径此前只有 health + 一行日志，getHealth 无生产读取方）。
 *
 * 与断裂告警同一条通道、同一频控实现（shouldSendAlert 的业务日键）：
 * 阈值以下只是一次抖动；投递层自身失败只记日志，不得再被记成一轮核验失败（否则自我放大）。
 */
async function dispatchFailureAlert() {
  if (health.consecutiveFailures < FAILURE_ALERT_THRESHOLD) return;
  const alertKey = `audit_chain_verify_failed_${businessDateParts().dateStr}`;
  if (!securityAlert.shouldSendAlert(alertKey)) {
    logger.warn('审计链核验失败告警处于频控窗口内，本轮仅记录不推送');
    return;
  }
  const detail = String(health.lastFailureMessage || '').slice(0, 200);
  const message =
    `审计链周期核验连续 ${health.consecutiveFailures} 轮执行失败（累计 ${health.failures} 轮，` +
    `最近一次：${detail}）——核验恢复之前，链完整性无人守护，篡改不会被告警发现`;
  try {
    await securityAlert.sendNotification(
      securityAlert.ALERT_TYPES.AUDIT_CHAIN_VERIFY_FAILED,
      securityAlert.ALERT_LEVELS.HIGH,
      message,
      {
        consecutiveFailures: health.consecutiveFailures,
        failures: health.failures,
        lastFailureMessage: detail,
        lastVerdictCode: health.lastVerdictCode,
      }
    );
  } catch (err) {
    logger.error(
      `审计链核验失败告警投递未能执行：${err && err.message ? err.message : String(err)}`
    );
  }
}

function settleRound(failed) {
  if (failed) return; // 成功判据是「整轮没抛」：连败归零与成功时间同处落笔（旧归零点早于投递，投递持续故障时连续计数永远只有 1）
  health.consecutiveFailures = 0;
  health.lastSuccessAt = new Date().toISOString();
}

/**
 * 执行一次链完整性核验，按需推送告警
 *
 * 与 auditMonitor.runDetection 同构：单轮闸门 → 扫描 → 判定 → 频控 → 推送 → 记账。
 */
async function runVerification() {
  if (verificationRunning) {
    health.skippedOverlaps += 1;
    logger.warn(
      `审计链核验上一轮未结束，本轮跳过（累计跳过 ${health.skippedOverlaps} 轮）；` +
        `跳过持续增长说明单轮耗时已超过间隔 ${effectiveIntervalMs / 1000}s`
    );
    return;
  }
  verificationRunning = true;
  health.runs += 1;
  health.lastRunAt = new Date().toISOString();
  let roundFailed = false; // 成功判据是「整轮没抛」：告警投递的 reject 同样落进 catch，投递每轮都断的那一轮不是成功轮
  try {
    // 延迟 require：与 auditChainVerify 的其余消费方同惯例，避免启动期把
    // 整个链模块（含 canonicalPayload 的字段清单冻结）拉进配置校验路径。
    const { verifyAuditChain, computeChainVerdict } = require('./auditChainVerify');
    const windowRecords = Math.min(
      readPositiveNumberEnv('AUDIT_CHAIN_MONITOR_WINDOW', DEFAULT_WINDOW_RECORDS, {
        integer: true,
      }),
      MAX_WINDOW_RECORDS
    );

    // 一道预算同时覆盖本轮两次取数（核验的 find + 截断判据用的估算），
    // 与文件头「资源闸 ②」是同一条承诺：闸门释放只取决于"这一轮有没有结束"，
    // 而本轮的任何一次 await 都不允许无上限地挂着。
    const budgetMs = roundBudgetMs();

    const report = await verifyAuditChain(AuditLog, {
      maxRecords: windowRecords,
      fromLatest: true,
      maxTimeMS: budgetMs,
    });
    // collectionTotal 只用于判据的"截断"识别。这里刻意用 estimatedDocumentCount
    // （元数据估算，不扫集合）：定时器每轮都实数 countDocuments 会在千万级集合上
    // 变成固定开销，而窗口本来就取"最近 N 条"——截断与否只是判据的一个否决项。
    // 带 maxTimeMS 的入参会由 mongoose setOptions 转给驱动（实测 8.24.1：
    // Query.prototype.estimatedDocumentCount(options) → this.setOptions(options)）。
    const collectionTotal = await AuditLog.estimatedDocumentCount({ maxTimeMS: budgetMs });

    const verdict = computeChainVerdict({
      breaks: report.breaks,
      total: report.total,
      maxRecords: windowRecords,
      collectionTotal,
      hmacChecked: report.hmacChecked,
      legacy: report.legacy,
      hashComputeFailed: report.hashComputeFailed,
      scanned: report.scanned,
    });

    health.lastVerdictCode = verdict.code;

    const worth = alertWorthinessOf(verdict, report);
    if (!worth.alert) {
      // 完全干净（code 0）时清空指纹，让下一轮即使"看起来一样"也重新判一次——
      // 否则「断裂修好后又复发成同样指纹」会被上一轮的指纹挡住（静默）。
      if (verdict.code === 0) lastAlertFingerprint = null;
      return;
    }
    const { hasBreaks, gapCount } = worth;

    const fingerprint = fingerprintOf(verdict, report);
    const dayWindow = businessDateParts().dateStr;
    const isNewDay = lastAlertDay !== dayWindow;
    // 顺序有意：**先查指纹、再问频控**。
    // 反过来（先 shouldSendAlert、再查指纹）会造成两个问题：① 指纹命中而 return 时，
    // 频控表项已被消耗——一次纯判断留下了副作用；② 存量断裂每轮都吃掉一次频控额度，
    // 于是当**新的**断裂出现时可能正落在额度耗尽的窗口里、被无声挡掉。
    // 指纹检查是纯内存比较（零成本、无副作用），放最前面把噪声挡在最便宜的关口。
    if (fingerprint === lastAlertFingerprint && !isNewDay) {
      logger.info('审计链核验结果与上次告警指纹一致（存量问题），本轮仅记录不重复推送');
      return;
    }

    // 频控：与 auditMonitor 同口径。键含"断裂/缺口"两档，各自独立限流。
    // 重投位**越过频控**：上一轮投递失败时额度已被消耗，再让频控挡住就等于永久静默。
    const alertKeyPart = hasBreaks ? 'break' : 'gap';
    const isRetryOfFailedDelivery = pendingRetryFingerprint === fingerprint;
    const allowedByThrottle =
      isRetryOfFailedDelivery ||
      securityAlert.shouldSendAlert(`audit_chain_${alertKeyPart}_${dayWindow}`);
    if (!allowedByThrottle) {
      logger.info('审计链告警处于频控窗口内，本轮仅记录不推送');
      return;
    }

    const breakdown = Object.entries(report.byType || {})
      .filter(([, count]) => count > 0)
      .map(([type, count]) => `${type}=${count}`)
      .join(' ');
    const message = hasBreaks
      ? `审计链周期核验发现 ${report.breaks} 处断裂（${breakdown}），扫描 ${report.total} 条${hashStrippedOpsHint(report)}`
      : `审计链周期核验发现 ${gapCount} 条哈希计算失败的无哈希记录（链上缺口，非篡改）`;

    logger[hasBreaks ? 'error' : 'warn'](message);

    // 指纹只在**送达成功后**落成水位线：投递抛错也记成「已处理」会让该断裂在告警面上永久静默。
    pendingRetryFingerprint = fingerprint;
    await dispatchChainAlert(hasBreaks, message, report, gapCount);
    lastAlertFingerprint = fingerprint;
    lastAlertDay = dayWindow;
    pendingRetryFingerprint = null;
  } catch (err) {
    roundFailed = true;
    health.failures += 1;
    health.consecutiveFailures += 1;
    health.lastFailureAt = new Date().toISOString();
    health.lastFailureMessage = err && err.message ? err.message : String(err);
    logger.error(`审计链核验监控执行失败：${health.lastFailureMessage}`);
    await dispatchFailureAlert();
  } finally {
    settleRound(roundFailed);
    verificationRunning = false;
  }
}

/**
 * 启动定时核验。重复调用安全（幂等），与 auditMonitor.start 同惯例。
 */
function start() {
  if (monitorTimer) return;

  let intervalMs = readPositiveNumberEnv('AUDIT_CHAIN_MONITOR_INTERVAL_MS', DEFAULT_INTERVAL_MS, {
    onInvalid: (name, raw, d) =>
      logger.warn(
        `${name}=${JSON.stringify(raw)} 非法（须为正数），已按默认 ${d}ms 处理；` +
          '负值会被 setInterval 抬成 1ms，形成每毫秒一轮全量链核验的忙轮询'
      ),
  });
  if (intervalMs < MIN_INTERVAL_MS) {
    logger.warn(
      `AUDIT_CHAIN_MONITOR_INTERVAL_MS=${intervalMs} 低于最小间隔 ${MIN_INTERVAL_MS}ms，` +
        `已抬升到最小值（防止与 auditMonitor 抢库、打满事件循环）`
    );
    intervalMs = MIN_INTERVAL_MS;
  }
  if (intervalMs > MAX_INTERVAL_MS) {
    logger.warn(
      `AUDIT_CHAIN_MONITOR_INTERVAL_MS=${intervalMs} 高于最大间隔 ${MAX_INTERVAL_MS}ms，` +
        `已压到最大值（超过 2^31-1ms 的 setInterval 会被静默改成 1ms，等于忙轮询）`
    );
    intervalMs = MAX_INTERVAL_MS; // 上限钳制与下限同一个缺口类：抬升/下压都必须留痕
  }
  effectiveIntervalMs = intervalMs;

  monitorTimer = setInterval(() => {
    runVerification().catch((err) => {
      logger.error(`审计链核验定时任务异常：${err.message}`);
    });
  }, intervalMs);

  if (monitorTimer && monitorTimer.unref) monitorTimer.unref();

  logger.info(`审计链周期核验已启动（间隔 ${intervalMs / 1000}s）`);
}

/** 停止定时核验（供优雅关闭调用） */
function stop() {
  if (monitorTimer) {
    clearInterval(monitorTimer);
    monitorTimer = null;
    logger.info('审计链周期核验已停止');
  }
}

/** 定时器是否在运行（合规面板指标）。与 getHealth() 成对读，见 auditMonitor 同款注释。 */
function isRunning() {
  return !!monitorTimer;
}

/** 运行状态快照（返回副本） */
function getHealth() {
  return { ...health, intervalMs: effectiveIntervalMs, running: !!monitorTimer };
}

/**
 * 测试钩子（与 auditMonitor.__resetForTest 同惯例）：模块级 state 必须在每条用例前重置，否则随机顺序门禁下会出现假红/假绿。
 */
function __resetForTest() {
  verificationRunning = false;
  effectiveIntervalMs = DEFAULT_INTERVAL_MS;
  lastAlertFingerprint = null;
  lastAlertDay = null;
  pendingRetryFingerprint = null;
  health.runs = 0;
  health.failures = 0;
  health.consecutiveFailures = 0;
  health.skippedOverlaps = 0;
  health.lastRunAt = null;
  health.lastSuccessAt = null;
  health.lastFailureAt = null;
  health.lastFailureMessage = null;
  health.lastVerdictCode = null;
}

module.exports = {
  start,
  stop,
  runVerification,
  isRunning,
  getHealth,
  __resetForTest,
  __MIN_INTERVAL_MS: MIN_INTERVAL_MS,
  __MIN_ROUND_BUDGET_MS: MIN_ROUND_BUDGET_MS,
};
