/**
 * 扫描探测检测器 —— 路径指纹证据行 + 404 风暴计数（攻击检测面 2026-11-05，W2）。
 *
 * 解决的问题：非 /api 路径（/.env、wp-login、actuator…）此前零审计零计数（auditLog
 * 只挂 /api/，404 兜底无任何安全动作）；更隐蔽的是 **SPA fallback 会把 GET+HTML 的
 * 探测吞成 200 index.html**——扫描器最常见的目录爆破形态在留存里完全不存在。
 * 本模块把两类信号升级为结构化事件（attackEvents 注册表 `scan` 分类的事件源）：
 *
 *  1) `noteUnmatchedRequest(req)` —— 每个"未命中任何路由/静态文件"的请求都计数：
 *     命中 SCANNER_PATH_RE（单源自 constants/attackProfile.js，命中路径本身即证据）
 *     写 scan_probe_detected 行；累计达阈值（env SCAN_404_*，默认 40 次/5 分钟）写
 *     scan_probe_storm 行（high）并 markForensicTarget——取证捕获该 IP 的后续全站请求。
 *     封禁不在本模块：命中指纹的未匹配请求由同一挂载点的 unmatchedRequestLimiter 计数，
 *     接 ANON_ABUSE 升级阶梯（rateLimit.js）；不含指纹的普通未知路径只留痕不封禁——
 *     坏部署会让整个 NAT 出口的构建产物集体 404，按未匹配数封 IP 等于封掉一间办公室。
 *  2) forensicTrigger 文件头 v1b 待办清单的「扫描探测风暴」族由本模块销账。
 *
 * 三条纪律（与 injectionDetector 同族）：
 *  1) fire-and-forget：全部入口在 404/SPA 兜底热路径上，计数 O(1)，写行 setImmediate；
 *  2) 风暴行每固定时间窗口只写一次（保留已报告标记直到过期），证据行按 IP+path 60s 去重；
 *  3) 计数器有界（压力淘汰 + 写前清扫），绝不整体清空——轮换 IP 不能一键重置他人窗口。
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { guardDetection } = require('../utils/auditWriteFailure');
const { computeFingerprint } = require('../utils/fingerprint');
const { stripControlChars } = require('../utils/helpers');
const { auditPath } = require('../utils/auditMeta');
const { auditClientAddress } = require('../utils/ipUtils');
const { incSecurityAlert } = require('../utils/metrics');
const { SCANNER_PATH_RE } = require('../constants/attackProfile');
const { readPositiveNumberEnv } = require('../utils/envNumber');

// 扫描器 UA 指纹：只做留痕因子不做拦截（UA 可伪造、易误伤合法工具），命中说明
// 攻击者连伪装都懒得做——证据价值高
const KNOWN_SCANNER_UA_RE =
  /(?:sqlmap|nmap|masscan|nikto|wpscan|hydra|dirb|dirbuster|gobuster|wfuzz|ffuf|acunetix|nessus|openvas|zgrab|whatweb|w3af|arachni|metasploit|burp)/i;

// 风暴阈值：40 次/5 分钟（env 可覆盖，非法值 error 后回落——readPositiveNumberEnv 惯例）
const SCAN_404_WINDOW_MS = readPositiveNumberEnv('SCAN_404_WINDOW_MS', 5 * 60 * 1000, {
  onInvalid: (name, raw, fallback) =>
    logger.error(`扫描探测窗口配置非法（${name}=${raw}），回落 ${fallback}ms`),
});
const SCAN_404_THRESHOLD = readPositiveNumberEnv('SCAN_404_THRESHOLD', 40, {
  integer: true,
  onInvalid: (name, raw, fallback) =>
    logger.error(`扫描探测阈值配置非法（${name}=${raw}），回落 ${fallback}`),
});
// 计数器容量：攻击者轮换 IP 的上限封顶；LRU 按窗口起点淘汰（最久未活跃先出）
const STORM_TRACKER_MAX_ENTRIES = 10000;

/** 证据行去重：IP+path 60s 一行 */
const EVIDENCE_DEDUP_WINDOW_MS = 60 * 1000;
const EVIDENCE_DEDUP_MAX_ENTRIES = 4096;
const recentEvidenceByFingerprint = new Map();

/** 风暴计数保留 reported 到窗口过期，证据去重不影响累计。 */
const stormCounters = new Map();

const pruneMap = (map, maxEntries) => {
  if (map.size < maxEntries) return;
  for (const [key, value] of map.entries()) {
    const expiresAt = typeof value === 'number' ? value : value?.expiresAt;
    if (typeof expiresAt === 'number' && expiresAt <= Date.now()) map.delete(key);
  }
  while (map.size >= maxEntries) {
    map.delete(map.keys().next().value);
  }
};

const clientIpOf = (req) => auditClientAddress(req).ip;
const userAgentOf = (req) => stripControlChars(req.get('user-agent'), 512);

const recordScanProbeRow = guardDetection(
  '扫描探测留痕',
  async ({ req, kind, sample, riskLevel, riskFactors }) => {
    // type 必须是字面量实参：incSecurityAlert 的采集器按字面量锚定站点（failOpenSites
    // 台账双向对账），动态 type 只能进 PASS_THROUGH 且丢掉精确对账能力
    if (kind === 'scan_probe_storm') incSecurityAlert('scan_probe_storm', 'high');
    else incSecurityAlert('scan_probe_detected', 'medium');
    AuditLog.record({
      action: kind === 'scan_probe_storm' ? 'scan_probe_storm' : 'scan_probe_detected',
      category: 'security',
      userId: req.user?.userId,
      username: req.user?.username || 'anonymous',
      sessionId: req.user?.sessionId || null,
      fingerprint: computeFingerprint(req),
      method: req.method,
      path: auditPath(req),
      ...auditClientAddress(req),
      userAgent: userAgentOf(req),
      success: false,
      riskLevel,
      riskFactors,
      reason: stripControlChars(sample, 512),
    });
  }
);

const markForensics = (req, evidence) => {
  try {
    // 惰性 require：取证标记是叶子模块，标记失败吞错计数（fail-visible），绝不影响主流程
    require('./forensicTrigger').markForensicTarget(clientIpOf(req), {
      reason: evidence.reason,
      source: 'scanProbeDetector',
      evidence: evidence.data,
    });
  } catch (_) {
    /* require 期异常同样吞掉：检测不改变 404 兜底的响应行为 */
  }
};

/**
 * 未命中请求的统一入口：404 兜底与 SPA fallback 吞没分支都调它。
 * 内部两件事：① path 命中扫描器指纹 → 证据行（IP+path 60s 去重）+ 取证标记；
 * ② 无条件计入该 IP 的风暴窗口 → 达阈值写 storm 行（high）+ 取证标记。
 * @returns {void} 永不抛
 */
const noteUnmatchedRequest = (req) => {
  try {
    if (!req || typeof req.path !== 'string') return;
    const ip = clientIpOf(req);
    const now = Date.now();
    const uaFactor = KNOWN_SCANNER_UA_RE.test(userAgentOf(req)) ? ['scanner_user_agent'] : [];

    // ① 路径指纹证据：命中即证据（attackProfile 同一口径），与响应码无关
    if (SCANNER_PATH_RE.test(req.path)) {
      const fingerprint = `${ip}|${req.path}`;
      if ((recentEvidenceByFingerprint.get(fingerprint) ?? 0) <= now) {
        if (!recentEvidenceByFingerprint.has(fingerprint)) {
          pruneMap(recentEvidenceByFingerprint, EVIDENCE_DEDUP_MAX_ENTRIES);
        }
        recentEvidenceByFingerprint.set(fingerprint, now + EVIDENCE_DEDUP_WINDOW_MS);
        setImmediate(() =>
          recordScanProbeRow({
            req,
            kind: 'scan_probe_detected',
            sample: `扫描器路径探测：${stripControlChars(req.path, 200)}`,
            riskLevel: 'medium',
            riskFactors: ['scanner_path', ...uaFactor],
          })
        );
        markForensics(req, {
          reason: 'scan_probe',
          data: { path: stripControlChars(req.path, 200) },
        });
      }
    }

    let counter = stormCounters.get(ip);
    if (!counter || counter.expiresAt <= now) {
      if (!counter) pruneMap(stormCounters, STORM_TRACKER_MAX_ENTRIES);
      counter = { count: 0, expiresAt: now + SCAN_404_WINDOW_MS, reported: false };
      stormCounters.set(ip, counter);
    }
    if (counter.reported) return;
    counter.count += 1;
    if (counter.count < SCAN_404_THRESHOLD) return;
    counter.reported = true;
    setImmediate(() =>
      recordScanProbeRow({
        req,
        kind: 'scan_probe_storm',
        sample: `404 风暴：${SCAN_404_THRESHOLD} 次/${Math.round(
          SCAN_404_WINDOW_MS / 60000
        )} 分钟（最新 ${stripControlChars(req.path, 200)}）`,
        riskLevel: 'high',
        riskFactors: ['unmatched_path_storm', ...uaFactor],
      })
    );
    markForensics(req, {
      reason: 'scan_probe_storm',
      data: { threshold: SCAN_404_THRESHOLD, windowMs: SCAN_404_WINDOW_MS },
    });
  } catch (error) {
    // 计数/判定的任何异常都不许影响 404 兜底本身（fail-open，但留下痕迹）
    logger.error(`扫描探测检测异常（已跳过本轮）: ${error.message}`);
  }
};

/** 测试与运维自检：计数器规模与生效阈值 */
const getScanProbeDetectorStats = () => ({
  trackedIps: stormCounters.size,
  threshold: SCAN_404_THRESHOLD,
  windowMs: SCAN_404_WINDOW_MS,
  maxTracked: STORM_TRACKER_MAX_ENTRIES,
});

/** 测试钩子：清空进程内计数器（jest 隔离用例间状态） */
const resetScanProbeDetector = () => {
  stormCounters.clear();
  recentEvidenceByFingerprint.clear();
};

module.exports = {
  noteUnmatchedRequest,
  getScanProbeDetectorStats,
  resetScanProbeDetector,
  KNOWN_SCANNER_UA_RE,
};
