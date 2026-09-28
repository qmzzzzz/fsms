/**
 * 审计 action 白名单「可达性技术文档」（P3-62）
 *
 * 审计报告 §3.4 / §11.1 指出：`constants/audit.js` 的 AUDIT_LOG_ACTIONS 共 144 条，
 * 其中一批**永不产生**——既没有路由能派生出它们（GET 路由不在 auditGetPaths 白名单内，
 * 全局审计中间件直接跳过），也没有任何源码写入调用点。这类条目让审计页的下拉筛选
 * 里出现「永远筛不出结果」的选项，也让「白名单 = 实际可写入集合」这一心智模型失真。
 *
 * 报告给出的两种处置（删条目 / 补 auditGetPaths）都涉及**行为变更**，且删条目会
 * 破坏历史数据可查性（库里已有的 action 一旦不在白名单，validateEnum 直接 400）。
 * 因此本文件采取第三种处置：**把「永不产生」的集合钉成可执行技术文档**，达到：
 *   1. 不删任何条目（历史数据仍可查）；
 *   2. 集合一旦变化（新增/减少）立刻红——新增意味着有人补了 auditGetPaths 或加了写入点，
 *      减少意味着有人删了条目（需同步更新技术文档并说明理由）；
 *   3. 技术文档本身即「待清理清单」，附带每条的实测证据（路由 / 方法 / 原因）。
 *
 * 度量方法（与生产代码同源，非手抄）：
 *   - 路由派生：读 src/routes/*.js 的 `router.<method>('<path>'`，按 app.js 的挂载前缀
 *     拼出完整路径，动态段按真实形态（ObjectId / UUID）替换后调用**真实的**
 *     `deriveAction`（utils/auditMeta）——不复制其清洗规则，避免二次实现漂移；
 *   - 源码写入：与正向对账闸共用 helpers/auditWriteSites 的扫描器（见 scanWrittenActions
 *     的注释）——两套判据各写一份时，"写入"在两处不是同一个事实（F-201）；
 *   - 「永不产生」= 在白名单内 ∧ 不在源码写入集合 ∧ （不在路由派生集合 ∨ 该路由为 GET
 *     且未被 security.js 的 auditGetPaths 覆盖）。
 */

const fs = require('fs');
const path = require('path');

// 与正向对账闸（auditActionReconciliation）同一份取数实现，见 scanWrittenActions 注释。
const { scanWriteSites } = require('../helpers/auditWriteSites');

const SRC_DIR = path.resolve(__dirname, '../..');
const ROUTES_DIR = path.join(SRC_DIR, 'routes');

/** 与生产同源：动态段按真实请求形态替换，再交给真实 deriveAction */
const OID = '6aab4cb4ee7f2bc07fcd7a8d';
const UUID = '550e8400-e29b-41d4-a716-446655440000';

/** app.js 的挂载前缀（从源码读，不手抄） */
function readMounts() {
  const appSrc = fs.readFileSync(path.join(SRC_DIR, 'app.js'), 'utf8');
  const mounts = {};
  for (const m of appSrc.matchAll(/app\.use\(\s*'([^']+)',\s*(\w+)/g)) mounts[m[2]] = m[1];
  return mounts;
}

/** security.js 的 auditGetPaths（从源码读，不手抄——手抄必然漂移） */
function readAuditGetPaths() {
  const secSrc = fs.readFileSync(path.join(SRC_DIR, 'middleware/security.js'), 'utf8');
  const start = secSrc.indexOf('auditGetPaths = [');
  if (start < 0) {
    throw new Error('security.js 里找不到 auditGetPaths 的起点：生产结构已变，守卫必须显式失败');
  }
  // 数组成员全是字符串字面量、不含嵌套方括号 → 起点后的第一个 ']' 就是收尾。
  // 原先这里写的是 indexOf('] = options;')，而生产源码里**根本没有这个串**
  // （实际是 `],\n  } = options;`）→ end = -1 → slice(start, -1) 一路截到
  // 倒数第二个字符（实测 12,289 字符 ≈ 整个文件后半段），全靠后面
  // `.startsWith('/api/')` 侥幸把噪音滤掉。解析失败必须响，不能静默降级。
  const end = secSrc.indexOf(']', start);
  if (end < 0) throw new Error('auditGetPaths 数组没有收尾的 ]');
  const block = secSrc.slice(start, end);
  const paths = [...block.matchAll(/'([^']+)'/g)]
    .map((m) => m[1])
    .filter((p) => p.startsWith('/api/'));
  if (paths.length === 0) {
    throw new Error('解析到 0 条 auditGetPaths：解析器与生产代码已失配，不得当作「无需审计」放行');
  }
  return paths;
}

const concretize = (routePath) =>
  routePath.replace(/\/:([^/]+)/g, (_m, name) => {
    const n = name.toLowerCase();
    if (n === 'sid' || n.includes('uuid') || n === 'token') return `/${UUID}`;
    if (n.includes('username') || n === 'code' || n.includes('name')) return '/abc';
    return `/${OID}`;
  });

/** 扫描全部路由，产出 { method, route, action, audited } */
function scanRoutes() {
  const { deriveAction, deriveCategory } = require('../../utils/auditMeta');
  const mounts = readMounts();
  const auditGetPaths = readAuditGetPaths();
  const isAudited = (full) => auditGetPaths.some((p) => full === p || full.startsWith(`${p}/`));

  const rows = [];
  for (const f of fs.readdirSync(ROUTES_DIR)) {
    if (!f.endsWith('.js')) continue;
    const prefix = mounts[f.replace('.js', '')];
    if (!prefix) continue;
    const src = fs.readFileSync(path.join(ROUTES_DIR, f), 'utf8');
    for (const m of src.matchAll(/router\.(get|post|put|patch|delete)\(\s*'([^']*)'/g)) {
      const method = m[1].toUpperCase();
      const route = (prefix + (m[2] === '/' ? '' : m[2])).replace(/\/+/g, '/');
      const concrete = concretize(route);
      const category = deriveCategory(concrete);
      rows.push({
        method,
        route,
        action: deriveAction(method, concrete, category),
        // 非 GET 走 auditLog 中间件的 operations 默认集（POST/PUT/DELETE/PATCH）
        audited: method === 'GET' ? isAudited(route) : true,
      });
    }
  }
  return rows;
}

/**
 * 源码写入集合 —— 与正向对账闸**共用同一个扫描器**（helpers/auditWriteSites）。
 *
 * 原先本文件自带一套裸正则全文扫 `action: '...'`，于是**只读**上下文也被算成写入点：
 * `AuditLog.countDocuments({ action: 'login_failed' })`（securityController.js:306、
 * securityAlert.js:399 同类）。后果不是"多算了几条"这么轻——本闸的判据是
 * 「白名单 ⊆ 可达集合」，多算的写入点会把"其实没人写"的条目洗成"可达"，于是
 * 实测把 recordLogin 源码里的 'login_failed' 改成未登记的名字，本闸 5 例照旧全绿
 * （正向对账同轮转红，见 F-201）。两个闸共用取数之后，"写入"在两处是同一个事实，
 * 对账结论不再只是"两份实现都同意的那部分"。
 *
 * 也不在这里硬编码任何"方法自身决定的 action"（原先写着
 * `written.add('login_success')` / `add('login_failed')` 两行）：硬编码等于给
 * "扫不到也算可达"开一个无主例外。若哪天写入形态变更导致扫不出来，本闸必须以
 * "白名单里的某条无人写入"红出来并要求显式判定，而不是静默降级。
 */
function scanWrittenActions() {
  return new Set(scanWriteSites().written.keys());
}

/**
 * 「永不产生」的实测集合（2026-09-17 度量，共 39 条）
 *
 * 判定口径（与下方用例完全一致，不是手抄清单）：
 *   在白名单内 ∧ 没有任何「会被审计的」路由能派生出它 ∧ 没有任何源码写入点。
 *   「会被审计的路由」= 非 GET 路由（走 auditLog 中间件的 operations 默认集），
 *     或 GET 但命中 security.js 的 auditGetPaths 白名单。
 *
 * 分两类，处置口径不同：
 *
 * ── A 类（25 条）：路由可派生，但该 GET 路由未被 auditGetPaths 覆盖
 *    全局审计中间件对 GET 只在命中 auditGetPaths 时才记录（见 security.js 的 isGetAudit），
 *    因此这批 action 虽能由 deriveAction 推导出来，实际永远不会落库。
 *    它们正是报告 §3.4「看了哪台设备/哪个报警无留痕」的清单本身。
 *    是否纳入属合规口径决策（报告 §13 V-9 明确标注「无法从代码判断」），
 *    本技术文档不代为决定——只保证一旦决定并落地（补 auditGetPaths），这里立刻红并提示更新。
 *
 * ── B 类（14 条）：既无路由派生、也无源码写入点
 *    三种成因（处置建议不同，勿一刀切删除）：
 *      b1 语义已被替代/改名——实际写入用的是另一个 action：
 *         security_report-suspicious → 实际写 suspicious_report（POST /api/security/report）
 *         （同类但不入本技术文档：security_view-sensitive 可派生且会进审计中间件，
 *           只是控制器置了 skipGlobalAudit 并改写 view_sensitive_data，故不在下表中）
 *         security_view / security_users_view → 无对应无子路径的 GET 路由
 *      b2 从未接线——常量定义了但没有任何调用点：
 *         suspicious_ip_activity（ALERT_TYPES.SUSPICIOUS_IP 从未被 record 调用）
 *         audit_log_query（查审计日志是读操作，自身不产生写入）
 *         logout（models/TokenBlacklist.js 的 reason 默认值，非审计 action）
 *      b3 历史兼容（**保留，勿删**）——早期 req.path 被 Express 剥离时产生的记录：
 *         system_update / system_delete / batch_delete_users / role_assign_permissions /
 *         permission_batch_create / device_status_update / device_maintenance_add /
 *         alarm_false_alarm
 *        删除会破坏存量数据的可查性（validateEnum 对不在白名单的 action 直接 400）。
 *
 * ⚠️ 本技术文档不是「免责名单」：下面第二个用例会反向校验——任何登记的条目一旦变得可达
 *    （有人补了 auditGetPaths 或加了写入点），测试立即失败，强制同步更新技术文档。
 */
const NEVER_PRODUCED = [
  // ── A 类：GET 路由存在但未被 auditGetPaths 覆盖 ──
  'auth_captcha',
  'auth_captcha-status',
  'auth_login-public-key',
  'auth_session',
  'auth_me',
  'auth_mfa_status',
  'security_my-info',
  'security_bindings',
  'security_stats',
  'security_overview',
  'security_alerts',
  'security_ip-list_query',
  'device_stats',
  'device_expiring',
  'device_reminders',
  'device_view',
  'alarm_stats',
  'alarm_view',
  'inspection_stats',
  'inspection_view',
  'report_dashboard',
  'report_devices',
  'report_alarms',
  'report_inspections',
  'security_my-logs',

  // ── B 类 b1：语义已被替代/改名 ──
  'security_report-suspicious',
  'security_view',
  'security_users_view',

  // ── B 类 b2：从未接线 ──
  'suspicious_ip_activity',
  'audit_log_query',
  'logout',

  // ── B 类 b3：历史兼容（保留，勿删——删了存量数据查不出来） ──
  'system_update',
  'system_delete',
  'batch_delete_users',
  'role_assign_permissions',
  'permission_batch_create',
  'device_status_update',
  'device_maintenance_add',
  'alarm_false_alarm',
];

describe('审计 action 白名单可达性技术文档（P3-62）', () => {
  test('白名单 ⊆（路由派生可达 ∪ 源码写入可达 ∪ 技术文档登记）', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    const routes = scanRoutes();
    const written = scanWrittenActions();

    const derived = new Set(routes.map((r) => r.action));
    const auditedDerived = new Set(routes.filter((r) => r.audited).map((r) => r.action));
    const ledger = new Set(NEVER_PRODUCED);

    const unexplained = AUDIT_LOG_ACTIONS.filter(
      (a) => !auditedDerived.has(a) && !written.has(a) && !ledger.has(a)
    );
    // 失败信息必须能直接定位：列出条目 + 它是否路由可达（区分「补技术文档」与「补写入」）
    const detail = unexplained.map(
      (a) => `${a}（路由派生可达=${derived.has(a)}，已审计=${auditedDerived.has(a)}）`
    );
    expect(detail).toEqual([]);
  });

  test('技术文档无冗余：登记的每一条都确实不可达（防止技术文档变成「免责名单」）', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    const routes = scanRoutes();
    const written = scanWrittenActions();
    const auditedDerived = new Set(routes.filter((r) => r.audited).map((r) => r.action));
    const whitelist = new Set(AUDIT_LOG_ACTIONS);

    const stale = NEVER_PRODUCED.filter(
      (a) => whitelist.has(a) && (auditedDerived.has(a) || written.has(a))
    );
    // 命中说明该条目已变得可达（有人补了 auditGetPaths 或加了写入点）：
    // 请从本技术文档移除，并确认审计页筛选行为符合预期
    expect(stale).toEqual([]);
  });

  test('技术文档内条目必须都在白名单内（删白名单条目会破坏历史数据可查性）', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    const whitelist = new Set(AUDIT_LOG_ACTIONS);
    const orphan = NEVER_PRODUCED.filter((a) => !whitelist.has(a));
    // 白名单里没有它 → 技术文档失效（可能已被删除）。删除前必须确认存量数据已无该 action。
    expect(orphan).toEqual([]);
  });

  // 解析器自检：这条用例不为生产代码服务，守的是本文件自己的取数逻辑。
  // 曾经的实现把「数组收尾」锚在一个源码里并不存在的串上，end=-1 于是截到
  // 整个文件后半段（实测 12,289 字符）——只要样例还在，这类失配必须当场响。
  test('auditGetPaths 解析器边界自证（不得越出数组尾部）', () => {
    const paths = readAuditGetPaths();
    expect(paths.length).toBeGreaterThanOrEqual(5);
    expect(paths.every((p) => p.startsWith('/api/'))).toBe(true);
    // 数组本身只占源码很小一段；若哪天解析结果里混进了数组之外的字面量，
    // 数量与内容都会先在这里露出来
    const secSrc = fs.readFileSync(path.join(SRC_DIR, 'middleware/security.js'), 'utf8');
    const start = secSrc.indexOf('auditGetPaths = [');
    const end = secSrc.indexOf(']', start);
    expect(end - start).toBeLessThan(1000);
    expect(paths).toContain('/api/security/audit-logs');
  });

  test('技术文档无重复项', () => {
    const dup = NEVER_PRODUCED.filter((a, i) => NEVER_PRODUCED.indexOf(a) !== i);
    expect(dup).toEqual([]);
  });
});
