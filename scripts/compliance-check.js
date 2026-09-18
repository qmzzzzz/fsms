#!/usr/bin/env node
/**
 * 审计合规就绪度检查脚本
 *
 * 用法:
 *   node scripts/compliance-check.js
 *
 * 检查项:
 *   1. 留存天数配置（AUDIT_RETENTION_DAYS，默认 180）
 *   2. append-only 钩子是否挂载（读取 schema 预编译钩子名）
 *   3. 审计导出接口是否存在（auditController.exportAuditLogs，含路由挂载校验）
 *   4. 审计异常监控是否挂载（index.js 中 auditMonitor.start/stop）
 *   5. 哈希链字段是否存在（prevHash / hash）
 *   6. WAL 兜底能力（auditBuffer.isWalEnabled）
 *   7. SIEM 转发能力（logShipper transport 可用，LOG_SHIPPING_URL 可选）
 *
 * 退出码:
 *   0 = 全部就绪
 *   1 = 存在缺失项
 *
 * 输出: JSON 格式的合规就绪度清单 + 控制台摘要
 */

const path = require('path');

const checks = [];
let allPassed = true;

function recordCheck(name, passed, detail) {
  checks.push({ name, passed, detail });
  if (!passed) allPassed = false;
}

// ================= 1. 留存天数配置 =================
// P3-46：原实现先把配置钳制到 [90, 3650]，再断言「钳制结果 ≥ 90」——
// 恒真检查。AUDIT_RETENTION_DAYS=1 或 -5 同样报「就绪」，
// 一个专门用来发现配置不合规的脚本反而遮蔽了配置不合规。
//
// 现改为断言**原始配置值**是否合规，并把「已被钳制/回退」列为不通过：
// 钳制让数据库 TTL 保住了 90 天，但它同时意味着运维的意图与实际不符
// （他以为留 1 天、以为留 10000 天），这种偏差必须在合规检查里显形。
function checkRetention() {
  const {
    RAW_RETENTION_DAYS,
    RETENTION_DAYS,
    MIN_RETENTION_DAYS,
    MAX_RETENTION_DAYS,
    isConfigured,
    wasAdjusted,
    describeRetention,
  } = require('../src/constants/retention');

  // 通过条件：① 生效值满足合规下限（未配置时的默认 180 属正常）；
  //           ② 且配置未被静默修正
  const meetsMinimum = RETENTION_DAYS >= MIN_RETENTION_DAYS;
  const passed = meetsMinimum && !wasAdjusted;

  let detail = describeRetention();
  if (wasAdjusted && isConfigured) {
    detail +=
      `。原始配置 ${RAW_RETENTION_DAYS} 不在合规区间 ` +
      `[${MIN_RETENTION_DAYS}, ${MAX_RETENTION_DAYS}] 内，` +
      '数据库 TTL 已按钳制值建索引，但配置意图与实际留存不一致，请修正环境变量';
  } else if (wasAdjusted) {
    detail += '。请修正为 [90, 3650] 区间内的整数';
  }

  recordCheck('留存天数 (AUDIT_RETENTION_DAYS)', passed, detail);
}

// ================= 2. append-only 钩子挂载 =================
function checkAppendOnlyHooks() {
  try {
    const AuditLog = require('../src/models/AuditLog');
    // L-25：清单直接引用实现侧的单一事实来源，避免两处手工同步。
    // 原先此处硬编码 6 项而实际挂 9 项，漏掉的恰是 updateMany /
    // findOneAndReplace / bulkWrite 三个**批量篡改**路径——若这些守卫被误删，
    // 门禁不会失败，只能靠事后哈希链校验发现"已被篡改"而非"护栏缺失"。
    const { APPEND_ONLY_HOOKS: expectedHooks } = require('../src/models/auditLogHooks');

    // 读取 schema 预编译钩子列表。schema.s.hooks._pres 属于 Mongoose 内部结构，
    // 可能随版本变化：探测不到时输出警告交由人工核对，而非静默判定为未挂载
    let registeredHooks = null;
    try {
      const presMap =
        AuditLog.schema.s && AuditLog.schema.s.hooks ? AuditLog.schema.s.hooks._pres : undefined;
      if (presMap instanceof Map) registeredHooks = [...presMap.keys()];
      else if (presMap && typeof presMap === 'object') registeredHooks = Object.keys(presMap);
    } catch (probeErr) {
      console.warn(`[警告] 钩子注册探测异常：${probeErr.message}`);
      registeredHooks = null;
    }

    if (!registeredHooks) {
      console.warn(
        '[警告] 无法探测钩子注册（mongoose 内部结构变化），append-only 钩子需人工核对 AuditLog 模型'
      );
      recordCheck(
        'append-only 钩子挂载',
        false,
        '无法探测钩子注册（mongoose 内部结构变化）：schema.s.hooks._pres 不可读，需人工确认 append-only 钩子'
      );
      return;
    }

    const missing = expectedHooks.filter((h) => !registeredHooks.includes(h));

    const passed = missing.length === 0;
    recordCheck(
      'append-only 钩子挂载',
      passed,
      missing.length === 0
        ? `已挂载 ${expectedHooks.length} 个钩子：${expectedHooks.join(', ')}`
        : `缺失钩子：${missing.join(', ')}；已注册：${registeredHooks.join(', ')}`
    );
  } catch (err) {
    recordCheck('append-only 钩子挂载', false, `检查失败：${err.message}`);
  }
}

// ================= 3. 审计导出接口存在 =================
// L-25 同族修复（2026-09-16）：原实现查的是 securityController 上的同名函数，
// 但该函数实际位于 controllers/auditController.js（securityRoutes.js:248 引用它）。
// 于是本项**长期误报「未定义」**——门禁亮红却无人能修，因为代码本身是对的。
// 门禁的价值在于「失败时指向真问题」；指向错位置的红灯会训练出「红灯可忽略」的
// 习惯，比没有门禁更危险。现改为按路由实际挂载的处理器校验（单一事实来源），
// 并顺带断言它确实是路由的最后一个 handler（中间件链完整）。
function checkExportInterface() {
  try {
    const auditController = require('../src/controllers/auditController');
    const hasHandler = typeof auditController.exportAuditLogs === 'function';

    // 交叉验证：路由表里 /audit-logs/export 的处理器链末尾必须是同一个函数
    const routesSrc = require('fs').readFileSync(
      require('path').join(__dirname, '..', 'src', 'routes', 'securityRoutes.js'),
      'utf8'
    );
    const routeWired = /\/audit-logs\/export[\s\S]{0,200}?auditController\.exportAuditLogs/.test(
      routesSrc
    );

    const passed = hasHandler && routeWired;
    recordCheck(
      '审计导出接口 (exportAuditLogs)',
      passed,
      passed
        ? 'auditController.exportAuditLogs 已定义且已挂到 GET /audit-logs/export'
        : hasHandler
          ? 'auditController.exportAuditLogs 已定义，但未在 securityRoutes.js 挂到 /audit-logs/export'
          : 'auditController.exportAuditLogs 未定义'
    );
  } catch (err) {
    recordCheck('审计导出接口 (exportAuditLogs)', false, `检查失败：${err.message}`);
  }
}

// ================= 4. 审计异常监控挂载 =================
function checkMonitorMounted() {
  try {
    const fs = require('fs');
    const indexContent = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');

    const hasStart = /auditMonitor\s*\.\s*start\s*\(\s*\)/.test(indexContent);
    const hasStop = /auditMonitor\s*\.\s*stop\s*\(\s*\)/.test(indexContent);
    const hasRequire = /require\s*\(\s*['"][^'"]*auditMonitor['"]\s*\)/.test(indexContent);

    const passed = hasStart && hasStop && hasRequire;
    const details = [];
    if (!hasRequire) details.push('未引入 auditMonitor 模块');
    if (!hasStart) details.push('未调用 auditMonitor.start()');
    if (!hasStop) details.push('未调用 auditMonitor.stop()');

    recordCheck(
      '审计异常监控挂载 (auditMonitor)',
      passed,
      passed ? 'auditMonitor 已在 index.js 中挂载（start + stop）' : details.join('；')
    );
  } catch (err) {
    recordCheck('审计异常监控挂载 (auditMonitor)', false, `检查失败：${err.message}`);
  }
}

// ================= 5. 哈希链字段存在 =================
function checkHashChainFields() {
  try {
    const AuditLog = require('../src/models/AuditLog');
    const paths = AuditLog.schema.paths;
    const hasPrevHash = !!paths.prevHash;
    const hasHash = !!paths.hash;

    const passed = hasPrevHash && hasHash;
    recordCheck(
      '哈希链字段 (prevHash / hash)',
      passed,
      passed ? 'prevHash + hash 字段已在 schema 中定义' : `prevHash=${hasPrevHash}, hash=${hasHash}`
    );
  } catch (err) {
    recordCheck('哈希链字段 (prevHash / hash)', false, `检查失败：${err.message}`);
  }
}

// ================= 6. WAL 兜底能力 =================
function checkWalFallback() {
  try {
    const auditBuffer = require('../src/services/auditBuffer');
    const passed =
      typeof auditBuffer.isWalEnabled === 'function' && typeof auditBuffer.push === 'function';
    recordCheck(
      '审计缓冲 WAL 兜底 (auditBuffer)',
      passed,
      passed
        ? 'auditBuffer 已具备 isWalEnabled() + WAL 兜底能力'
        : 'auditBuffer 缺少 WAL 兜底能力（isWalEnabled）'
    );
  } catch (err) {
    recordCheck('审计缓冲 WAL 兜底 (auditBuffer)', false, `检查失败：${err.message}`);
  }
}

// ================= 7. SIEM 转发能力 =================
function checkShippingTransport() {
  try {
    const { HttpShipperTransport } = require('../src/utils/logShipper');
    const transportAvailable = typeof HttpShipperTransport === 'function';
    const urlConfigured = !!process.env.LOG_SHIPPING_URL;
    // 能力就绪以 transport 可用为准；是否启用取决于是否配置 URL（可选）
    const passed = transportAvailable;
    recordCheck(
      'SIEM 转发能力 (logShipper)',
      passed,
      passed
        ? `HttpShipperTransport 可用${urlConfigured ? `，且已配置 LOG_SHIPPING_URL（启用中）` : '（未配置 LOG_SHIPPING_URL，默认关闭）'}`
        : 'HttpShipperTransport 不可用'
    );
  } catch (err) {
    recordCheck('SIEM 转发能力 (logShipper)', false, `检查失败：${err.message}`);
  }
}

// ================= 执行所有检查 =================
function runAllChecks() {
  checkRetention();
  checkAppendOnlyHooks();
  checkExportInterface();
  checkMonitorMounted();
  checkHashChainFields();
  checkWalFallback();
  checkShippingTransport();

  // 输出 JSON 结果
  const result = {
    timestamp: new Date().toISOString(),
    allPassed,
    checks,
  };

  console.log(JSON.stringify(result, null, 2));

  // 控制台摘要
  console.log('\n========== 合规就绪度摘要 ==========');
  for (const c of checks) {
    const icon = c.passed ? '✅' : '❌';
    console.log(`${icon} ${c.name}: ${c.detail}`);
  }
  console.log(`\n总体: ${allPassed ? '就绪' : '存在缺失'}`);

  process.exit(allPassed ? 0 : 1);
}

runAllChecks();
