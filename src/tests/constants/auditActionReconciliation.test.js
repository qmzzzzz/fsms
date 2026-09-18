/**
 * 审计 action 自动对账（P1-11 / P3-61）
 *
 * 缺陷（P1-11）：\`authService.js\` 写入 action=\`account_temp_locked\` 的审计记录，
 * 但 \`constants/audit.js\` 的 AUDIT_LOG_ACTIONS 白名单缺此条 —— 记录在库里，
 * 而 \`utils/auditQuery.js\` 的 validateEnum(action, AUDIT_LOG_ACTIONS) 会让
 * **按该 action 筛选的查询直接 400**（"审计留痕形同虚设"：写了却查不出来）。
 * 同类漂移在 P3-11 已发生过一次（路由派生 action 滞后），本次以自动对账防复发。
 *
 * 本测试**不手写 action 列表**（手写等于把"对账"退化成"复制"）：它扫描 src/
 * 下所有审计写入调用点，从源码里**解析出实际写入的 action 字符串**，
 * 再断言该集合 ⊆ AUDIT_LOG_ACTIONS。
 *
 * ===== 扫描口径（重要，改动前请先读）=====
 *
 * 1. 识别四类写入调用（与 models/auditLogWriteStatics.js 的静态方法一一对应）：
 *      - AuditLog.record({ ... })          事件型/安全告警
 *      - AuditLog.create({ ... })          直写（控制器/服务）
 *      - AuditLog.recordSensitiveAction(uid, uname, ACTION, category, ...)  第 3 参
 *      - auditBuffer.push({ ... })         全局中间件批量写
 *    匹配用「括号配平」而不是正则行匹配：调用实参跨多行、字符串内含 ')' 都不影响。
 *
 * 2. action 取值表达式只解析以下四种形态（其余一律**报错**而不是静默跳过，
 *    避免新写法悄悄逃出对账范围）：
 *      - 字符串字面量：              action: 'mfa_disable'
 *      - 三元两个字面量：            action: locked ? 'user_locked' : 'user_unlocked'
 *      - ALERT_TYPES 常量：          action: ALERT_TYPES.BRUTE_FORCE
 *                                    （常量表从 securityAlert.js 实际导出读取，不复制字面量）
 *      - meta.action（早于 auditLog 中间件的 403 转发）：
 *                                    middleware/security.js 的 recordEarlyRejection（2026-09-17 时为 :359），
 *                                    是唯一写入方，其 action 由调用方传入。此处扫描
 *                                    全仓 recordEarlyRejection( 调用点取出字面量 action。
 *
 * 3. 排除项及原因：
 *      - 查询/过滤上下文（如 securityController 最近登录记录查询里的 action: { $in: [...] }）：
 *        不是写入调用，自然不在四类调用的实参扫描范围内。
 *      - 子文档 action（FireAlarm/Inspection 的 processLog、AlarmService 的
 *        executionLog、roleController/userController/rolePermissionController 的
 *        WebSocket payload）：不是 AuditLog 写入，同上不匹配。
 *      - middleware/security.js 的 auditBuffer.push（2026-09-17 时为 :689）用 deriveAuditMeta(req)
 *        派生 action（路由派生型），其覆盖面由 src/tests/utils/auditMeta.test.js
 *        的「路由派生 action ⊆ 白名单」用例负责，本文件不重复断言。
 *      - 动态拼接/变量型 action：本扫描会解析失败并**抛出**（见上条 2），
 *        新增此类写法时必须同步扩展本扫描器，而不是放宽断言。
 *
 * 4. 记录型静态方法 AuditLog.recordLogin（内部固定 login_success / login_failed）
 *    与 recordSensitiveAction 的字面量第 3 参：前者 action 由方法自身决定，
 *    在 writeStatics 源码里以字面量出现，天然被上面第 2 条覆盖。
 */

const fs = require('fs');
const path = require('path');

const SRC_DIR = path.resolve(__dirname, '../..');

/** 扫描目标：src/ 下全部生产代码（跳过 tests，测试自身的探针 action 不属生产写入） */
function listSourceFiles(dir = SRC_DIR, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listSourceFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/**
 * 从 src 文本中取出 openIdx（指向 '('）起配平括号的实参文本。
 * 配平期间正确跳过字符串/模板串与转义，避免实参里的括号造成提前截断。
 */
function readCallArgs(src, openIdx) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let i = openIdx; i < src.length; i += 1) {
    const ch = src[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return src.slice(openIdx + 1, i);
    }
  }
  return null;
}

/** 顶层（不在任何括号/字符串内）逗号切分实参 */
function splitTopLevelArgs(argsText) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let escaped = false;
  let buf = '';
  for (const ch of argsText) {
    if (escaped) {
      buf += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      buf += ch;
      escaped = true;
      continue;
    }
    if (quote) {
      buf += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      buf += ch;
      continue;
    }
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) depth -= 1;
    if (ch === ',' && depth === 0) {
      parts.push(buf);
      buf = '';
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) parts.push(buf);
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** 从 openIdx（指向 open 字符）起找配对的 close 字符位置；未闭合返回 -1 */
function findBalancedEnd(text, openIdx, open, close) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let i = openIdx; i < text.length; i += 1) {
    const ch = text[i];
    if (escaped) {
      escaped = false;
    } else if (ch === '\\') {
      escaped = true;
    } else if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
    } else if (ch === open) {
      depth += 1;
    } else if (ch === close) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** 取实参中第一个顶层对象字面量的内部文本（跳过嵌套括号与字符串） */
function firstObjectLiteral(argsText) {
  const openIdx = argsText.indexOf('{');
  if (openIdx === -1) return null;
  const endIdx = findBalancedEnd(argsText, openIdx, '{', '}');
  return endIdx === -1 ? null : argsText.slice(openIdx + 1, endIdx);
}
/** 顶层属性切分（按逗号），并取出名为 action 的属性值表达式 */
function extractActionExpr(argsText, mode) {
  if (mode === 'positional-2') return splitTopLevelArgs(argsText)[2] ?? null;
  const inner = firstObjectLiteral(argsText);
  if (inner == null) return null;
  for (const prop of splitTopLevelArgs(inner)) {
    const m = /^action\s*:\s*([\s\S]+)$/.exec(prop);
    if (m) return m[1].trim();
  }
  return null;
}

/** 解析 action 取值表达式 → 字面量数组；无法解析返回 null（调用方报错） */
function resolveActionExpr(expr, ctx) {
  if (expr == null) return null;
  const literal = /^'([^']*)'$/.exec(expr) || /^"([^"]*)"$/.exec(expr);
  if (literal) return [literal[1]];
  const ternary = /\?\s*'([^']+)'\s*:\s*'([^']+)'/.exec(expr);
  if (ternary) return [ternary[1], ternary[2]];
  const alertConst = /^ALERT_TYPES\.([A-Z_]+)$/.exec(expr);
  if (alertConst) {
    const value = ctx.ALERT_TYPES[alertConst[1]];
    return value ? [value] : null;
  }
  if (expr === 'meta.action') return [...ctx.earlyRejectionActions];
  return null;
}

/** 从 src 目录静态收集 recordEarlyRejection 各调用点传入的 action 字面量 */
function collectEarlyRejectionActions() {
  const actions = new Set();
  for (const file of listSourceFiles()) {
    const src = fs.readFileSync(file, 'utf8');
    let from = 0;
    let idx = src.indexOf('recordEarlyRejection(');
    while (idx !== -1) {
      from = idx + 1;
      const args = readCallArgs(src, idx + 'recordEarlyRejection'.length);
      const expr = args == null ? null : extractActionExpr(args, 'object');
      const literal = expr && /^'([^']*)'$/.exec(expr);
      if (literal) actions.add(literal[1]);
      idx = src.indexOf('recordEarlyRejection(', from);
    }
  }
  return actions;
}

const WRITE_CALLS = [
  { token: 'AuditLog.record(', mode: 'object' },
  { token: 'AuditLog.create(', mode: 'object' },
  { token: 'AuditLog.recordSensitiveAction(', mode: 'positional-2' },
  { token: 'auditBuffer.push(', mode: 'object' },
];

describe('审计 action 白名单对账（P1-11 / P3-61）', () => {
  test('src/ 实际写入的 audit action 全部在 AUDIT_LOG_ACTIONS 白名单内', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    // ALERT_TYPES 从实际导出读取，避免把常量值复制进测试造成二次漂移
    const { ALERT_TYPES } = require('../../services/securityAlert');
    const whitelist = new Set(AUDIT_LOG_ACTIONS);
    const ctx = { ALERT_TYPES, earlyRejectionActions: collectEarlyRejectionActions() };

    const unresolved = [];
    const written = new Map(); // action -> [调用点]
    for (const file of listSourceFiles()) {
      const src = fs.readFileSync(file, 'utf8');
      const rel = path.relative(path.resolve(__dirname, '../../..'), file).replace(/\\/g, '/');
      for (const { token, mode } of WRITE_CALLS) {
        let from = 0;
        let idx = src.indexOf(token, from);
        while (idx !== -1) {
          from = idx + token.length;
          const line = src.slice(0, idx).split('\n').length;
          const args = readCallArgs(src, idx + token.length - 1);
          const expr = args == null ? null : extractActionExpr(args, mode);
          const values = resolveActionExpr(expr, ctx);
          if (values == null) {
            // 路由派生型批量写（middleware/security.js 的 auditBuffer.push 用
            // deriveAuditMeta(req) 派生 action）不在本对账范围，见文件头排除说明
            if (token === 'auditBuffer.push(' && /deriveAuditMeta/.test(src)) {
              idx = src.indexOf(token, from);
              continue;
            }
            unresolved.push(rel + ':' + line + ' expr=' + JSON.stringify(expr));
          } else {
            for (const v of values) {
              if (!written.has(v)) written.set(v, []);
              written.get(v).push(rel + ':' + line);
            }
          }
          idx = src.indexOf(token, from);
        }
      }
    }

    // 解析失败必须是硬失败：新写法不得悄悄逃出对账范围
    expect(unresolved).toEqual([]);

    const missing = [...written.keys()].filter((a) => !whitelist.has(a)).sort();
    expect(missing).toEqual([]);
    // 扫描有效性下限：若调用点识别逻辑失效（例如 token 改名），
    // written 会退化成空集而"对账通过"——用下限断言防这种静默失效
    expect(written.size).toBeGreaterThanOrEqual(30);
    expect(written.has('account_temp_locked')).toBe(true);
  });

  test('P1-11 回归：account_temp_locked 在库可查（validateEnum 白名单命中）', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    expect(AUDIT_LOG_ACTIONS).toContain('account_temp_locked');
  });
});
