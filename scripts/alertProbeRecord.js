#!/usr/bin/env node
/**
 * 告警投递探针的**判据**（F-09，2026-10-17）—— 纯函数，无 IO
 *
 * 审计事实：仓库态下 Alertmanager 的 webhook 接收端是 `hooks.example.com` 占位，
 * `ALERT_WEBHOOK_CHECK=production` 能判出"还是占位"，但**没有任何东西证明
 * 真实通道收到过东西**。`scripts/deploy.js` 的 preflight 也只检查配置文件里
 * 有没有占位串——一个写对了 URL 但打不通的通道，与一个真能叫醒人的通道，
 * 在所有这些判据里长得一模一样。
 *
 * 本模块把"告警链路到底验没验过"变成可判定的三档状态，供合规检查消费：
 *   - `missing`：从未跑过探针（没有任何证据）
 *   - `stale`  ：跑过，但超过窗口（默认 7 天）——通道可能已经改坏
 *   - `failed` ：最近一次探针失败（Alertmanager 拒收 / 不可达）
 *   - `ok`     ：窗口内有一次成功
 *
 * ⚠ **探针能证明什么、不能证明什么，必须写清楚**（否则就是新一轮的"看起来有防护"）：
 *   能证明：Alertmanager 进程活着、`/api/v2/alerts` 接受写入、这条告警**匹配到了某个
 *           receiver**（返回的 200 只代表入队成功）。
 *   不能证明：receiver 背后的 webhook 真的把消息送到了人手上——那取决于钉钉/企微
 *           的 access_token 是否有效、适配器是否在跑、群是否还在。
 *   所以记录里同时留 `correlationId`，由值班在探针后按该 id 到接收端核对，
 *   并把核对结果写进 `acknowledgedBy` / `acknowledgedAt`。
 *   合规检查对"已入队但未人工确认"给出的是**不同**的文案，不会混成一句"已验证"。
 */

/** 探针时效窗口：7 天。理由见 evaluateProbeRecord 的注释。 */
const PROBE_WINDOW_HOURS = 168;

/** 探针记录里必须存在的字段（缺一即视为记录损坏，不是"通过"） */
const REQUIRED_RECORD_FIELDS = ['probedAt', 'target', 'ok', 'correlationId'];

/**
 * 校验并判定一份探针记录。
 *
 * 窗口取 7 天而不是 24 小时：探针是人工/定时触发的动作，一天一次太频繁（每次都会在
 * 值班群里留一条测试告警）；而"一个月没验过"又太松——期间换过 access_token、
 * 改过 alertmanager 配置都不会被发现。7 天是"每周巡检顺手跑一次"的自然节奏。
 *
 * @param {{record: object|null, now?: number, windowHours?: number}} input
 * @returns {{state: 'missing'|'invalid'|'stale'|'failed'|'ok'|'queued-unacked',
 *   ok: boolean, ageHours: number|null, detail: string}}
 */
function evaluateProbeRecord({ record = null, now = Date.now(), windowHours = PROBE_WINDOW_HOURS } = {}) {
  if (!record) {
    return {
      state: 'missing',
      ok: false,
      ageHours: null,
      detail:
        '从未执行过告警投递探针：告警链路**没有任何实证**（配置里有 URL 不等于通道能通）。' +
        '执行 node scripts/alert-delivery-probe.js 后重跑本检查',
    };
  }
  const missing = REQUIRED_RECORD_FIELDS.filter((f) => record[f] === undefined || record[f] === null);
  if (missing.length > 0) {
    return {
      state: 'invalid',
      ok: false,
      ageHours: null,
      detail: `探针记录损坏（缺字段 ${missing.join('/')}）：不能当成"验过"`,
    };
  }
  const ts = Date.parse(record.probedAt);
  if (!Number.isFinite(ts)) {
    return {
      state: 'invalid',
      ok: false,
      ageHours: null,
      detail: `探针记录的 probedAt 不是合法时间：${JSON.stringify(record.probedAt)}`,
    };
  }
  const ageHours = (now - ts) / 3600000;
  if (record.ok !== true) {
    return {
      state: 'failed',
      ok: false,
      ageHours,
      detail:
        `最近一次探针（${record.probedAt}，${Math.round(ageHours)}h 前）**失败**：` +
        `${record.error || `HTTP ${record.statusCode || '?'}`}。告警可能根本发不出去`,
    };
  }
  if (ageHours > windowHours) {
    return {
      state: 'stale',
      ok: false,
      ageHours,
      detail:
        `最近一次成功探针在 ${Math.round(ageHours)}h 前，超过 ${windowHours}h 窗口：` +
        '期间换过 access_token 或改过 alertmanager 配置都不会被发现',
    };
  }
  if (!record.acknowledgedAt) {
    return {
      state: 'queued-unacked',
      // 入队成功但没人核对过接收端 ⇒ 不算"已验证"，但也不判成失败：
      // 它是"证据不足"，由 notReady 表达，而不是 passed=false（那会被读成"链路坏了"）。
      ok: false,
      ageHours,
      detail:
        `探针 ${record.probedAt} 已被 Alertmanager 接受（correlationId=${record.correlationId}），` +
        '但**未在接收端人工核对**：入队成功 ≠ 有人收到。请按 correlationId 到群里确认后，' +
        '在记录里补 acknowledgedBy / acknowledgedAt',
    };
  }
  return {
    state: 'ok',
    ok: true,
    ageHours,
    detail:
      `探针 ${record.probedAt} 通过且已由 ${record.acknowledgedBy} 在接收端核对` +
      `（correlationId=${record.correlationId}，${Math.round(ageHours)}h 前）`,
  };
}

/**
 * SIEM 转发就绪度（审计建议第 4 条：「LOG_SHIPPING_URL 在生产环境未配置时
 * 应成为 P1 阻断或明确的书面豁免，而不是普通通过」）。
 *
 * 三档，与告警探针同构：
 *   - `unconfigured`：没配 ⇒ 生产态是 notReady（不是"关闭状态、不算缺陷"）
 *   - `misconfigured`：配了但 transport 不可用 ⇒ 红（配置与实现不符）
 *   - `ready`：配了且可用
 *
 * 豁免口沿用既有风格（`ALLOW_*` 字面量 'true'）：没有 SIEM 的部署是真实存在的形态
 * （单机、离线环境），但豁免必须**显形**——豁免时降级为 notReady 并写明"已豁免"，
 * 而不是判绿。
 *
 * @param {{urlConfigured: boolean, transportAvailable: boolean,
 *   allowUnconfigured?: boolean}} input
 * @returns {{state: 'ready'|'unconfigured'|'misconfigured', passed: boolean,
 *   notReady: boolean, detail: string}}
 */
function evaluateSiemShipping({ urlConfigured, transportAvailable, allowUnconfigured = false } = {}) {
  if (urlConfigured && transportAvailable) {
    return {
      state: 'ready',
      passed: true,
      notReady: false,
      detail: '已配置 LOG_SHIPPING_URL 且 HttpShipperTransport 可用（启用中）',
    };
  }
  if (urlConfigured && !transportAvailable) {
    return {
      state: 'misconfigured',
      passed: false,
      notReady: true,
      detail: '已配置 LOG_SHIPPING_URL，但 HttpShipperTransport 不可用（配置与实现不符）',
    };
  }
  const exempt = allowUnconfigured ? '（已显式豁免：ALLOW_UNCONFIGURED_LOG_SHIPPING=true）' : '';
  return {
    state: 'unconfigured',
    passed: true, // 仓库态/开发态没有 SIEM 是正常的，不判红
    // 但"没配"必须是 notReady：生产部署门禁（COMPLIANCE_STRICT=1）会因此阻断，
    // 而不是像修前那样"关闭状态、不计为缺陷"。
    notReady: true,
    detail:
      '未配置 LOG_SHIPPING_URL：审计日志只落在本地文件与容器日志，**外部 SIEM 不可见**' +
      `（进程崩溃/磁盘写满即失去外部副本）${exempt}`,
  };
}

module.exports = {
  PROBE_WINDOW_HOURS,
  REQUIRED_RECORD_FIELDS,
  evaluateProbeRecord,
  evaluateSiemShipping,
};
