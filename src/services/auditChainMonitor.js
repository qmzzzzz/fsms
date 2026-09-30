/**
 * 审计哈希链的**周期自检**监控（2026-09-30）
 *
 * 存在的理由：在此之前，「篡改会留下痕迹」成立，但「痕迹会被发现」不成立——
 * 核验只在有人手动调 `GET /api/security/audit-logs/verify` 或跑离线脚本时发生
 * （services/auditChainVerify.js 文件头原话：「没有"周期性自检"这一方：链核验
 * 至今只在被调用时执行，未接入任何定时任务」）。发现依赖有人想起来查，
 * 等于"防篡改"只是一件**可被查询**的装饰，不是**被守护**的不变量。
 * 本模块补上那一方：定时核验 + 发现异常即经 securityAlert 告警。
 *
 * 【和 auditMonitor 的分工，为什么必须是两个定时器】
 * auditMonitor 每 5 分钟跑 `AuditLog.detectAnomalies()`（高频失败/非常规时间），
 * **不碰哈希链**；本模块跑 `verifyAuditChain()`（逐条 SHA-256 重算），二者
 * 成本差一个量级、失败含义也完全不同（异常行为 ≠ 完整性断裂），合并只会让
 * 一个拖累另一个。故独立定时器、独立间隔、独立健康计数。
 *
 * 【资源闸：窗口就是唯一的闸】
 * `verifyAuditChain` 内部**不接受 maxTimeMS**（它的 find 是裸的），所以
 * "一轮最多扫多少条"是唯一能限制单轮耗时的旋钮——默认 2000 条，
 * 远小于接口侧默认的 20000（那个是单次请求、有 HTTP 超时兜底；这里是定时器，
 * CPU 占住事件循环会连带拖垮心跳/健康检查）。每条做 SHA-256 + 规范 JSON 序列化，
 * 2000 条在本机是百毫秒级；调大到数万会让单轮占住事件循环数十秒。
 *
 * 【噪声治理：这是本模块最要紧的设计约束】
 * 链条一旦出现断裂（例如历史遗留的 v2 记录失配、或若干条 hash_stripped），
 * 它会**每一轮都被重新发现**——如果每轮都告警，告警面立刻变成常态噪声，
 * 真实篡改告警被淹没（M-09「幻影链尾」的同一条演化路径：反复确认是误报后，
 * 人开始忽略它）。故本模块按**断裂指纹**去重：
 *   指纹 = { 结论码, 断裂总数, 逐类型计数, 缺口数 } 的规范化串。
 * 只有指纹**变化**时才推送（及每次跨日后的首次）。存量问题只响一次，
 * 新增问题立刻响——这正是"发现依赖有人想起来查"要解决的那个洞。
 *
 * 生命周期：由 index.js 在启动时 start()、优雅关闭时 stop()，与 auditMonitor 同惯例。
 * 定时器 unref，不阻塞进程退出。
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
/**
 * 单轮扫描窗口（条）。**这是本模块唯一的资源闸**（见文件头「资源闸」）。
 * 2000 条足以覆盖"最近一段时间"的写入，从而使**新发生的**篡改/缺口在下一轮就被看到；
 * 历史更早的篡改由离线全量脚本负责（接口/脚本仍有 20000 / 200000 的上限）。
 */
const DEFAULT_WINDOW_RECORDS = 2000;
/** 窗口硬上限：即使配置也不能突破（调度器里跑数十万条会占死事件循环） */
const MAX_WINDOW_RECORDS = 20000;

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
  lastFailureAt: null,
  lastFailureMessage: null,
  lastVerdictCode: null,
};

/**
 * 上次推送时的断裂指纹。
 * 只在**指纹变化**时推送（存量断裂不重复刷），见文件头「噪声治理」。
 */
let lastAlertFingerprint = null;
/** 上次推送所属业务日期：跨日后强制重推一次（当日一次的上限由它兜底） */
let lastAlertDay = null;

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
 * 单独成函数有两个理由：① runVerification 的 complexity 贴着棘轮上限；
 * ② 这里有一条**反直觉的取舍**必须写在有名字的地方——`code 2`（核验不完整）
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
  // 与 auditMonitor 一致：await 投递结果（它需要据此做自己的记账）。
  // sendNotification 内部已重试并降级，不改变业务语义。
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

    const report = await verifyAuditChain(AuditLog, {
      maxRecords: windowRecords,
      fromLatest: true,
    });
    // collectionTotal 只用于判据的"截断"识别。这里刻意用 estimatedDocumentCount
    // （元数据估算，不扫集合）：定时器每轮都实数 countDocuments 会在千万级集合上
    // 变成固定开销，而窗口本来就取"最近 N 条"——截断与否只是判据的一个否决项。
    const collectionTotal = await AuditLog.estimatedDocumentCount();

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
    health.consecutiveFailures = 0;

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
    const alertKeyPart = hasBreaks ? 'break' : 'gap';
    const allowedByThrottle = securityAlert.shouldSendAlert(
      `audit_chain_${alertKeyPart}_${dayWindow}`
    );
    if (!allowedByThrottle) {
      logger.info('审计链告警处于频控窗口内，本轮仅记录不推送');
      return;
    }

    const breakdown = Object.entries(report.byType || {})
      .filter(([, count]) => count > 0)
      .map(([type, count]) => `${type}=${count}`)
      .join(' ');
    const message = hasBreaks
      ? `审计链周期核验发现 ${report.breaks} 处断裂（${breakdown}），扫描 ${report.total} 条`
      : `审计链周期核验发现 ${gapCount} 条哈希计算失败的无哈希记录（链上缺口，非篡改）`;

    lastAlertFingerprint = fingerprint;
    lastAlertDay = dayWindow;

    logger[hasBreaks ? 'error' : 'warn'](message);

    await dispatchChainAlert(hasBreaks, message, report, gapCount);
  } catch (err) {
    health.failures += 1;
    health.consecutiveFailures += 1;
    health.lastFailureAt = new Date().toISOString();
    health.lastFailureMessage = err.message;
    logger.error(`审计链核验监控执行失败：${err.message}`);
  } finally {
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
 * 测试钩子（与 auditMonitor.__resetForTest 同惯例）：
 * 模块级 state 必须在每条用例前重置，否则随机顺序门禁下会出现假红/假绿。
 */
function __resetForTest() {
  verificationRunning = false;
  effectiveIntervalMs = DEFAULT_INTERVAL_MS;
  lastAlertFingerprint = null;
  lastAlertDay = null;
  health.runs = 0;
  health.failures = 0;
  health.consecutiveFailures = 0;
  health.skippedOverlaps = 0;
  health.lastRunAt = null;
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
  __DEFAULT_INTERVAL_MS: DEFAULT_INTERVAL_MS,
  __MIN_INTERVAL_MS: MIN_INTERVAL_MS,
  __MAX_WINDOW_RECORDS: MAX_WINDOW_RECORDS,
};
