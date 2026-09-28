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
 *   8. 告警投递端点就绪度（alertmanager webhook；仓库态允许占位，
 *      ALERT_WEBHOOK_CHECK=production 时占位即红——2026-09-26 审计 Top2 的
 *      "占位 URL 无接入防线"由此闭合：生产就绪声明必须先过本闸）
 *
 * 退出码:
 *   0 = 全部就绪
 *   1 = 存在缺失项（含"某条检查器没交出结论"这一类，见 runRegisteredChecks 的注释）
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

// ================= 源码形态判定的共用底座 =================
// 「某功能是否在源码里挂载」这类检查只能靠读源码，而**直接对原文跑正则**会被注释满足：
// 把 `auditMonitor.start();` 前面加两个斜杠，检查项仍然报「已挂载」——
// 门禁绿、代码里那个调用已经不存在。与本仓 nginx 契约门禁同一先例
// （deployment 侧的门禁先在"去注释后的代码视图"上判，再断言原文与视图同结论），
// 也与我此前修掉的 P3-46「恒真检查」是同一族：门禁的价值只在失败时指向真问题。
/**
 * 把 JS 源码里的注释剥掉，只留真正会执行的文本（保留行数，便于 diff 与人工核对）。
 *
 * 一条全局 alternation 从左到右扫：字符串/模板字面量优先匹配（所以 `'https://x'` 里的
 * `//` 不会被当成注释），随后才是行注释与块注释。因为扫描是按位置推进的，
 * 注释体里的撇号永远轮不到"字符串"那一支，不会引发跨行误吞；
 * 引号分支额外禁止裸换行（JS 的单双引号字符串本来就不允许），
 * 兜住"代码里出现落单撇号"这种会把后面整段吞掉的形态。
 *
 * 已知不覆盖：正则字面量里成对的斜杠（`/^https:\/\//`）。
 * 这类过度剥离的表现是**门禁误报红灯**（把在用的功能判成没挂载），不是静默放行，
 * 且被检文件本身在 complianceGate.test.js 里有一条"代码视图下仍判绿"的断言兜着。
 */
const TEXT_OR_COMMENT =
  /(['"])((?:\\.|(?!\1)[^\\\r\n])*)\1|(`(?:\\.|[^`\\])*`)|\/\/[^\n]*|\/\*[\s\S]*?\*\//g;

/** 第二遍只针对字符串/模板字面量（第一遍已把真注释抹掉，剩下的引号才是定界符） */
const TEXT_OR_TEMPLATE = /(['"])((?:\\.|(?!\1)[^\\\r\n])*)\1|(`(?:\\.|[^`\\])*`)/g;

/** 注释 ⇒ 用其中的换行占位（行数不变）；字符串 ⇒ 原样保留 */
const blankComment = (m) => (/^['"`]/.test(m) ? m : m.replace(/[^\n]/g, ''));

/** 字符串/模板 ⇒ 保留定界符与内部换行，其余字符**等长**打点（不改变任何位置索引） */
const blankStringBody = (m) => {
  const quote = m[0];
  return quote + m.slice(1, -1).replace(/[^\n]/g, '·') + quote;
};

function stripJsComments(source) {
  return source.replace(TEXT_OR_COMMENT, blankComment);
}

/**
 * 两份视图：
 *  - `text`：只剥注释，字符串内容还在 ⇒ 供必须读字面量的判据使用（`require('./x')` 的模块路径本身就是字符串）；
 *  - `code`：在 `text` 之上再把字符串内容等长打点 ⇒ 只剩真正会执行的语法。
 *
 * 为什么两份都要：只剥注释的话，一行 `logger.error('auditMonitor.start() 未执行')`
 * 就能满足 hasStart——与注释同族的静默放行（2026-09-25 审计指出）；只抹字符串又会把
 * 模块路径一起抹掉，判据在真实代码上恒假。
 *
 * 对齐口径（这里唯一需要的位置性质）：**text 与 code 逐位等长**——打点不删除字符，
 * 于是"路径在 text 的下标 + code 同区间内必须有真处理器引用"这类跨视图距离判据成立。
 * 两份视图与**原文**都不等长（注释整段删掉，只保行数），所以任何"视图下标 ↔ 原文下标"
 * 的设想都是错的；complianceGate.test.js 有一条用例分别钉住"等长"与"不等长"两侧，
 * 免得后来人拿视图下标去报原始行号。
 */
function codeViews(source) {
  const text = stripJsComments(source);
  return { text, code: text.replace(TEXT_OR_TEMPLATE, blankStringBody) };
}

/** index.js 里审计监控的挂载信号（start/stop 只认代码，不认注释与字符串） */
function mountSignals(indexSrc) {
  const { text, code } = codeViews(indexSrc);
  return {
    // hasRequire 只能活在 text 视图（模块路径就是字符串）。它不是承重信号：
    // 把 require 与调用一起删掉时 hasStart/hasStop 必红，而在字符串里仿写一条
    // require 却不留任何真调用，同样被 hasStart/hasStop 判住。
    hasRequire: /require\s*\(\s*['"][^'"]*auditMonitor['"]\s*\)/.test(text),
    hasStart: /auditMonitor\s*\.\s*start\s*\(\s*\)/.test(code),
    hasStop: /auditMonitor\s*\.\s*stop\s*\(\s*\)/.test(code),
  };
}

/**
 * securityRoutes.js 里审计导出接口的挂载信号。
 * 路径 `/audit-logs/export` 必然写在字符串里 ⇒ 在 text 视图定位；
 * 处理器引用 `auditController.exportAuditLogs` 必然是代码 ⇒ 在同一位置的后续窗口内
 * 用 code 视图判定。于是"一整行路由说明文字"不再能满足本检查。
 */
function exportRouteWired(routesSrc) {
  const { text, code } = codeViews(routesSrc);
  const PATH = /\/audit-logs\/export/g;
  let hit;
  while ((hit = PATH.exec(text)) !== null) {
    const window = code.slice(hit.index, hit.index + hit[0].length + 200);
    if (/auditController\s*\.\s*exportAuditLogs/.test(window)) return true;
  }
  return false;
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

    // expectedHooks 与被守护的注册同源于 auditLogHooks——若有人从清单里删掉某个高危写钩子，
    // 注册与"期望"会同步缩水，本门禁照样绿（自我认证）。补一份**独立低限**：这几个能批量改写/删除
    // 审计记录、最利于灭迹的钩子，任何时候都必须在清单里；删之即红，与是否仍"注册一致"无关。
    const REQUIRED_APPEND_ONLY_GUARDS = [
      'updateMany',
      'deleteMany',
      'bulkWrite',
      'findOneAndReplace',
      'findOneAndUpdate',
    ];
    const missingRequired = REQUIRED_APPEND_ONLY_GUARDS.filter((h) => !expectedHooks.includes(h));

    const passed = missing.length === 0 && missingRequired.length === 0;
    recordCheck(
      'append-only 钩子挂载',
      passed,
      passed
        ? `已挂载 ${expectedHooks.length} 个钩子：${expectedHooks.join(', ')}`
        : [
            missing.length ? `未注册钩子：${missing.join(', ')}` : '',
            missingRequired.length ? `清单缺失高危钩子（低限）：${missingRequired.join(', ')}` : '',
            `已注册：${registeredHooks.join(', ')}`,
          ]
            .filter(Boolean)
            .join('；')
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
    const routeWired = exportRouteWired(routesSrc);

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

    const { hasStart, hasStop, hasRequire } = mountSignals(indexContent);

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
    // 这条是"接线检查"，不是"能力已生效"：walEnabled 由启动流程调用 startup() 才置真，
    // 本脚本没有启动缓冲，读它的实时值只会得到 false。措辞必须与实测范围一致，
    // 否则合规报告里"已具备 WAL 兜底"又是一处"没验却报成验过"。
    recordCheck(
      '审计缓冲 WAL 兜底 (auditBuffer)',
      passed,
      passed
        ? 'WAL 入口已接线（push + isWalEnabled）；运行期是否启用需看启动流程是否调用 startup()，本静态检查不覆盖'
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
    // 原判据 `passed = transportAvailable` 在 require 成功时恒真 ⇒ 这条检查永远不会红，
    // 属于"把没验的报成验过"。改成三态：未配置=转发关闭（如实标注，既不算缺陷也不算已具备）；
    // 已配置且 transport 可用=启用中；已配置但 transport 不可用=配置与实现不符 ⇒ 红。
    const passed = !urlConfigured || transportAvailable;
    recordCheck(
      'SIEM 转发能力 (logShipper)',
      passed,
      passed
        ? urlConfigured
          ? '已配置 LOG_SHIPPING_URL 且 transport 可用（启用中）'
          : '未配置 LOG_SHIPPING_URL：SIEM 转发处于关闭状态（不计为缺陷，也不计为已具备）'
        : '已配置 LOG_SHIPPING_URL，但 HttpShipperTransport 不可用（配置与实现不符）'
    );
  } catch (err) {
    recordCheck('SIEM 转发能力 (logShipper)', false, `检查失败：${err.message}`);
  }
}

// ================= 8. 告警投递端点就绪度（2026-09-26 审计 Top2） =================
// 判据本体在 scripts/compliance-alerting.js：仓库态放行占位 URL（模板形态）、
// ALERT_WEBHOOK_CHECK=production 生产闸下占位即红、明文 http/残缺值任何模式都红。
// 独立成模块便于测试直调纯判据，也避免本文件越过体积棘轮红线。
function checkAlertingDeliveryEndpoint() {
  try {
    const { evaluateAlertingDelivery } = require('./compliance-alerting');
    const fs = require('fs');
    const file = path.join(__dirname, '..', 'deployment', 'observability', 'alertmanager.yml');
    const source = fs.readFileSync(file, 'utf8');
    const gateMode = process.env.ALERT_WEBHOOK_CHECK === 'production' ? 'production' : 'repo';
    const { passed, detail } = evaluateAlertingDelivery(source, gateMode);
    recordCheck('告警投递端点就绪度 (alertmanager webhook)', passed, detail);
  } catch (err) {
    recordCheck('告警投递端点就绪度 (alertmanager webhook)', false, `检查失败：${err.message}`);
  }
}

// ================= 执行所有检查 =================
/**
 * 每条合规要求的唯一登记处。函数名就是它的身份，"登记 = 真跑过"由本文件自己保证。
 *
 * 为什么不能留原来那份手写调用列表：`runAllChecks()` 里删掉一行 `checkWalFallback();`
 * 的后果是 checks 少一条、`allPassed` 仍为真 ⇒ 退出码 0、CI 全绿，而那条合规要求
 * **从未被评估**。这正是本仓给门禁立过的规矩要拦的形状（"删掉门禁不会让任何东西变红"，
 * 见 F-161 的 CI 四件套对账、F-149 的私有拷贝对账）。现在两层各拦一种删法：
 *   - 本文件的 runRegisteredChecks：登记表内部——检查器抛出或早退而没交结论 ⇒ 补一条失败；
 *   - complianceGate.test.js：登记表与源码里全部 `function check*` 对账 ⇒ 少登记一条即红。
 */
const COMPLIANCE_CHECKS = [
  checkRetention,
  checkAppendOnlyHooks,
  checkExportInterface,
  checkMonitorMounted,
  checkHashChainFields,
  checkWalFallback,
  checkShippingTransport,
  checkAlertingDeliveryEndpoint,
];

/**
 * 跑完一张登记表，返回**本次**产出的结论（便于用例直接断言，不必猜模块内部状态）。
 *
 * 两种"检查器没交出结论"的形态都必须留下失败记录，而不是让总体继续算就绪：
 *   - 抛出：`checkRetention` 这类不带 try 的检查器一旦 require 失败，整个进程被掀掉，
 *     其余六条的结论跟着一起丢——CI 只看到一个栈回溯，看不出哪条坏了、也看不到 JSON 报告；
 *   - 跑完却一条 recordCheck 都没调（未来新增的早退分支）。
 * 两者都是把"没验"报成"验过"的通道，补记的失败行使退出码照常变红。
 */
function runRegisteredChecks(registry = COMPLIANCE_CHECKS) {
  const start = checks.length;
  for (const check of registry) {
    const before = checks.length;
    try {
      check();
    } catch (err) {
      recordCheck(`${check.name} 自身抛出`, false, `检查器异常，本条结论缺失：${err.message}`);
      continue;
    }
    if (checks.length === before) {
      recordCheck(
        `${check.name} 未产出结论`,
        false,
        '检查函数跑完却没有调用 recordCheck——不能视作已就绪'
      );
    }
  }
  return checks.slice(start);
}

function runAllChecks() {
  runRegisteredChecks();

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

// 作为脚本运行 ⇒ 立即出结论并退出；被 require（测试要复用判定函数）⇒ 不执行、只导出。
// 不这样分叉的话，require 会连带跑完门禁并 process.exit，测试既拿不到函数也活不下来。
if (require.main === module) {
  runAllChecks();
} else {
  module.exports = {
    stripJsComments,
    codeViews,
    mountSignals,
    exportRouteWired,
    COMPLIANCE_CHECKS,
    runRegisteredChecks,
    // 检查器写结论的唯一出口。测试要构造"跑完不记结论"的检查器来验证上一条注释里的不变量，
    // 只能借用这个 sink——不导出的话，那条不变量就只能靠改源码做变异来证明（用例无法自建）。
    recordCheck,
  };
}
