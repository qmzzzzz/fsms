/**
 * 「唯一留痕」写不进去时，必须既不静默也不改变业务语义（批次 88）
 *
 * 背景（P0-5 之后才成立的性质）：控制器写 `res.locals.skipGlobalAudit = true` 后，
 * 全局审计中间件在**响应时刻**读到该标志就不再补记 ⇒ 紧随其后的手写
 * `AuditLog.create(...)` 是这次操作在审计集合里的**唯一留痕**。
 * `utils/auditWriteFailure.js` 为此把纪律写死：落库失败要「不阻断主流程，但绝不静默」
 * （logger.error + `audit_write_failed` 指标）。本仓 10 处该形态写入点里，
 * 8 处按纪律带了 `.catch(onAuditWriteFailure(...))`，2 处裸奔：
 *   - `viewSensitiveData`（PII 查看）
 *   - `reportSuspiciousActivity`（安全举报）
 * 裸奔的实测后果：DB 抖动时异常穿过 asyncHandler ⇒ 客户端 500，而服务端
 * **一行日志没有、指标不涨**，同时 `skipGlobalAudit` 已生效 ⇒ 这次查看/举报
 * 在审计面与可观测面双双蒸发。合规上这比「留下一条失败标记」更糟。
 *
 * 为什么这两处不能照抄另外 8 处的吞错形态：吞掉错误后 `res.json` 照样把 PII
 * 发出去（查看）或回一句「举报已提交」（举报），而那条留痕根本不存在——
 * 「没记成」被包装成「记好了」。实测（本文件 rethrow 两条用例）：
 * 修复前 create 被拒时 `incSecurityAlert` 调用次数为 0。
 * 因此这两处的正确形态是**记账后重抛**：业务照旧失败（不对外宣称成功、不发 PII），
 * 但失败从此可观测。`AuditLog.record` 不在此列——它自带 catch 并计入 medium 档，
 * 见 models/auditLogWriteStatics.js 的 `record`，由「record 自带兜底」那条前提用例自证。
 */

const path = require('path');
const fs = require('fs');

// ===== 依赖桩（必须在 require 控制器之前声明） =====

jest.mock('../../middleware/rbac', () => ({
  ...jest.requireActual('../../middleware/rbac'),
  assertRecordInScope: jest.fn(async () => ({ allowed: true, dataScope: { type: 'all' } })),
}));

const mockUserFindById = jest.fn();
jest.mock('../../models/User', () => ({
  findById: (...args) => mockUserFindById(...args),
}));

const mockAuditLogCreate = jest.fn();
jest.mock('../../models/AuditLog', () => ({
  create: (...args) => mockAuditLogCreate(...args),
}));

jest.mock('../../utils/encryption', () => ({
  DataMasking: {
    maskPhone: (v) => (v ? '***' + String(v).slice(-4) : ''),
    maskEmail: (v) => (v ? '***@example.com' : ''),
  },
}));

jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// asyncHandler 原样返回：不桩就会把内部抛错吞进 next()，读不到「重抛是否发生」
jest.mock('../../middleware/errorHandler', () => ({
  asyncHandler: (fn) => fn,
}));

jest.mock('express-validator', () => ({
  validationResult: () => ({ isEmpty: () => true, array: () => [] }),
}));

const {
  viewSensitiveData,
  reportSuspiciousActivity,
} = require('../../controllers/securityController');

const logger = require('../../utils/logger');
const metrics = require('../../utils/metrics');

// ===== 夹具 =====

const makeRes = () => {
  const res = {
    statusCode: null,
    payload: null,
    locals: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.payload = data;
      return this;
    },
  };
  return res;
};

const makeReq = (body) => ({
  body,
  ip: '203.0.113.9',
  user: { userId: 'op-1', username: 'admin' },
  get: (h) => (h.toLowerCase() === 'user-agent' ? 'jest-ua' : ''),
});

const viewReq = () => makeReq({ dataType: 'phone' }); // 不带 targetUserId ⇒ isSelf 分支
const reportReq = () => makeReq({ targetType: 'user', targetId: 't-1', reason: '异常登录' });

// ===== 静态闸的取数（与用例同一份判据，不在生产码里留钩子） =====

const SRC_DIR = path.resolve(__dirname, '../..');
const GUARD_SWALLOW = 'onAuditWriteFailure';
const GUARD_RETHROW = 'onAuditWriteFailureRethrow';

/** 生产代码文件（跳过 tests 与 node_modules），与 helpers/auditWriteSites 同口径 */
function listProdFiles(dir = SRC_DIR, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listProdFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/** 从 openIdx（指向 '('）起配平括号，返回实参文本与闭括号下标 */
function readArgs(src, openIdx) {
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
      if (depth === 0) return { args: src.slice(openIdx + 1, i), close: i };
    }
  }
  return null;
}

/** 该写入点的兜底符号：闭括号后紧跟的 .catch(...) 实参里出现哪个守卫名 */
function guardOf(src, closeIdx) {
  const tail = src.slice(closeIdx + 1);
  const m = /^\s*\.catch\(\s*([A-Za-z_$][\w$]*)/.exec(tail);
  if (!m) return 'none';
  return m[1] === GUARD_SWALLOW || m[1] === GUARD_RETHROW ? m[1] : `other:${m[1]}`;
}

/** 写入点所属的处理器名（最近的顶层 `const <Name> =`），比行号稳、比 action 字面量全覆盖 */
function enclosingHandler(src, idx) {
  let name = '(module-level)';
  const re = /^const\s+([A-Za-z_$][\w$]*)\s*=/gm;
  let m;
  while ((m = re.exec(src)) !== null) {
    if (m.index > idx) break;
    name = m[1];
  }
  return name;
}

/**
 * 扫描「设过 skipGlobalAudit 的文件」里的每一处手写 `AuditLog.create(`。
 * 只认 create：`AuditLog.record` 由模型静态方法自带兜底（前提用例自证），
 * 把它纳进来会让闸的判据变成「两种写入形态一个口径」的假命题。
 */
function scanSkipGlobalAuditSites() {
  const sites = [];
  for (const file of listProdFiles()) {
    const src = fs.readFileSync(file, 'utf8');
    if (!/res\.locals\.skipGlobalAudit\s*=/.test(src)) continue;
    const rel = path.relative(SRC_DIR, file).replace(/\\/g, '/');
    const re = /AuditLog\.create\(/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      const parsed = readArgs(src, m.index + m[0].length - 1);
      if (!parsed) continue;
      // 注释里的同形写法不算写入点（本仓扫描器的既有口径）
      const lineStart = src.lastIndexOf('\n', m.index - 1) + 1;
      if (/^\s*(?:\/\/|\*|\/\*)/.test(src.slice(lineStart, m.index))) continue;
      sites.push({
        site: `${rel}#${enclosingHandler(src, m.index)}`,
        guard: guardOf(src, parsed.close),
      });
    }
  }
  return sites;
}

function tally(sites) {
  const acc = {};
  for (const { site, guard } of sites) {
    acc[site] = acc[site] || {};
    acc[site][guard] = (acc[site][guard] || 0) + 1;
  }
  return acc;
}

/**
 * 第二条闸要扫的形态：`AuditLog.recordSensitiveAction(`
 *
 * 上一条闸只普查「设过 skipGlobalAudit 的文件里的 AuditLog.create」，而 recordSensitiveAction
 * 的四个调用点（authController 的改密 ×2、单设备吊销、批量吊销）**都不设该标志** ⇒ 全在闸外。
 * 它也不属于"模型自带兜底"那一类：`auditLogWriteStatics.js` 里 `record` 是
 * `this.create(entry).catch(...)`（resolve null），而 `recordSensitiveAction` 直接
 * `return this.create({...})` **没有 catch** ⇒ rejection 一律落到调用方手里，
 * 调用方接到哪一档这件事本身没有任何东西看守。
 *
 * 实测缺陷形状（本轮修复前，四处同形）：
 *   `.catch((e) => logger.warn(\`改密审计落库失败：${e.message}\`))`
 *   ① 降到 warn ⇒ 生产 log level 下等于不留痕；② 不计 `audit_write_failed` 指标 ⇒
 *   「敏感操作没写上留痕」在监控面完全不可见（而这条指标正是 P0-5 之后建起来的）；
 *   ③ `e.message` 假设被 catch 的一定是 Error——本仓 `utils/auditWriteFailure.js` 的
 *   `errText` 就是为此存在（裸 reject 字符串/driver 裸对象都见过），旧写法会在这步 TypeError。
 *
 * 这里不复用上面的 guardOf：它把"内联箭头函数"与"完全没有 .catch"都读成 'none'，
 * 而那两种形态的修法相反（前者要换守卫，后者要补守卫）。
 */
function scanSensitiveActionSites() {
  const sites = [];
  for (const file of listProdFiles()) {
    const src = fs.readFileSync(file, 'utf8');
    const re = /AuditLog\.recordSensitiveAction\(/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      const lineStart = src.lastIndexOf('\n', m.index - 1) + 1;
      if (/^\s*(?:\/\/|\*|\/\*)/.test(src.slice(lineStart, m.index))) continue;
      const parsed = readArgs(src, m.index + m[0].length - 1);
      if (!parsed) continue;
      const tail = src
        .slice(parsed.close + 1, parsed.close + 60)
        .replace(/\s+/g, ' ')
        .trim();
      const named = /^\.catch\(\s*([A-Za-z_$][\w$]*)/.exec(tail);
      const guard = named ? named[1] : tail.startsWith('.catch(') ? 'inline-lambda' : 'NO-CATCH';
      sites.push({
        site: `${path.relative(SRC_DIR, file).replace(/\\/g, '/')}#${enclosingHandler(src, m.index)}`,
        guard,
      });
    }
  }
  return sites;
}

// 登记表：键名与计数为**实测原样**（4 处全在 authController，改密 handler 占 2 处）。
const EXPECTED_SENSITIVE_REGISTRY = {
  'controllers/authController.js#changePassword': { [GUARD_SWALLOW]: 2 },
  'controllers/authController.js#revokeSession': { [GUARD_SWALLOW]: 1 },
  'controllers/authController.js#revokeOtherSessions': { [GUARD_SWALLOW]: 1 },
};

// ===== 用例 =====

// 登记表：key = `相对 src/ 路径#所在 handler 名`，value = 该写入点用到的兜底档位计数。
// 为什么按 handler 而不是 action 字面量做键：5 处的 action 是三元
// （`ip_blacklist_added`/`ip_whitelist_added`、`registration_enabled`/`registration_disabled`），
// 从写入点上取不到唯一字面量，按 action 归组会把三个独立 handler 的三处写入压成一条
// `security_config_change: 3`——那时"删掉其中一个的 .catch"只让计数变 2，
// 读起来像"配置类少了一处"，而不是"setLoginCaptchaConfig 失去了兜底"。
// 键名一律为本轮实测原样（见 zztmpctl/b88red2.txt 的 Received 块），不是推演值。
const EXPECTED_REGISTRY = {
  'controllers/auditController.js#verifyAuditChainIntegrity': { [GUARD_SWALLOW]: 1 },
  'controllers/ipListController.js#addIPEntry': { [GUARD_SWALLOW]: 1 },
  'controllers/ipListController.js#removeIPEntry': { [GUARD_SWALLOW]: 1 },
  'controllers/securityController.js#changePasswordSecure': { [GUARD_SWALLOW]: 1 },
  'controllers/securityController.js#resetUserMfa': { [GUARD_SWALLOW]: 1 },
  'controllers/securityController.js#setLoginCaptchaConfig': { [GUARD_SWALLOW]: 1 },
  'controllers/securityController.js#setRegisterCaptchaConfig': { [GUARD_SWALLOW]: 1 },
  'controllers/securityController.js#setRegistrationConfig': { [GUARD_SWALLOW]: 1 },
  'controllers/securityController.js#viewSensitiveData': { [GUARD_RETHROW]: 1 },
  'controllers/securityController.js#reportSuspiciousActivity': { [GUARD_RETHROW]: 1 },
};

beforeEach(() => {
  jest.clearAllMocks();
  // 守卫内部是 `require('./metrics').incSecurityAlert(...)`（调用时才取），
  // 所以桩必须打在模块对象上而不是 import 绑定上，否则记不到调用
  jest.spyOn(metrics, 'incSecurityAlert').mockImplementation(() => {});
  mockUserFindById.mockResolvedValue({ username: 'admin', phone: '13800138000', email: 'a@b.c' });
  mockAuditLogCreate.mockResolvedValue({ _id: 'audit-id' });
});

describe('skipGlobalAudit 手写审计的失败通路', () => {
  test('闸：每一处该形态写入点的兜底档位必须等于登记表', () => {
    // 为什么钉到「档位」而不只是「有没有兜底」：吞错与重抛是两种相反的业务语义
    // （前者=结果已达成、留痕可有可无；后者=留痕写不成就不能宣称达成）。
    // 把一处静默改成吞错，响应会从 500 变成「成功但没留痕」，而"有无兜底"的闸对此全绿。
    const sites = scanSkipGlobalAuditSites();
    expect(tally(sites)).toEqual(EXPECTED_REGISTRY);
    expect(sites).toHaveLength(10);
  });

  test('闸：每一处 recordSensitiveAction 的失败通路必须等于登记表（不設 skipGlobalAudit，故不在上条闸范围内）', () => {
    // 只钉"用的哪个守卫"这一件事，不外推：守卫本身记 error 日志 + high 指标由本文件的
    // 行为用例（PII 查看 / 安全举报两处）钉住，两处共用同一个 helper ⇒ 判据归一处。
    const sites = scanSensitiveActionSites();
    expect(tally(sites)).toEqual(EXPECTED_SENSITIVE_REGISTRY);
    expect(sites).toHaveLength(4);
  });

  test('前提自证：recordSensitiveAction 真的不自带兜底（排除它才是放水）', () => {
    const src = fs.readFileSync(path.resolve(SRC_DIR, 'models/auditLogWriteStatics.js'), 'utf8');
    const body =
      /schema\.statics\.recordSensitiveAction\s*=\s*async function[\s\S]*?\n {2}\};/.exec(src);
    expect(body).toBeTruthy();
    // 与 record 相反：这条静态方法里没有 .catch，也没有 audit_write_failed 记账
    expect(body[0]).not.toContain('.catch(');
    expect(body[0]).not.toContain('incSecurityAlert');
    expect(body[0]).toContain('return this.create(');
  });

  test('前提自证：record 类写入点确实自带兜底，排除它不是放水', () => {
    // 上条用例只扫 AuditLog.create。若 record 其实不兜底，这个排除就是漏的一格。
    const src = fs.readFileSync(path.resolve(SRC_DIR, 'models/auditLogWriteStatics.js'), 'utf8');
    const body = /schema\.statics\.record\s*=\s*function[\s\S]*?\n {2}\};/.exec(src);
    expect(body).toBeTruthy();
    expect(body[0]).toContain('.catch(');
    expect(body[0]).toContain("incSecurityAlert('audit_write_failed', 'medium')");
    expect(body[0]).toContain('return null');
  });

  test('PII 查看写不成时：记账后重抛，且绝不把数据发出去', async () => {
    mockAuditLogCreate.mockRejectedValue(new Error('db down'));
    const res = makeRes();
    await expect(viewSensitiveData(viewReq(), res, jest.fn())).rejects.toThrow('db down');
    // 可观测性（修复前这一条实测为红：incSecurityAlert 调用次数 0）
    expect(metrics.incSecurityAlert).toHaveBeenCalledWith('audit_write_failed', 'high');
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('审计写入失败'),
      expect.objectContaining({ auditAction: 'view_sensitive_data' })
    );
    // 语义不变：审计是唯一留痕，写不成就不该有"查看成功"的响应体（PII 未外发）
    expect(res.payload).toBeNull();
  });

  test('安全举报写不成时：记账后重抛，不得回「举报已提交」', async () => {
    mockAuditLogCreate.mockRejectedValue(new Error('db down'));
    const res = makeRes();
    await expect(reportSuspiciousActivity(reportReq(), res, jest.fn())).rejects.toThrow('db down');
    expect(metrics.incSecurityAlert).toHaveBeenCalledWith('audit_write_failed', 'high');
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('审计写入失败'),
      expect.objectContaining({ auditAction: 'suspicious_report' })
    );
    expect(res.payload).toBeNull();
  });

  test('对照：写入成功时两处都正常达成且不产生失败记账', async () => {
    const res1 = makeRes();
    await viewSensitiveData(viewReq(), res1, jest.fn());
    expect(res1.payload.data).toEqual({
      type: 'phone',
      masked: '***8000',
      full: '13800138000',
    });

    const res2 = makeRes();
    await reportSuspiciousActivity(reportReq(), res2, jest.fn());
    expect(res2.payload.data).toEqual({ reportId: 'audit-id' });

    expect(metrics.incSecurityAlert).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });

  test('反向对照：吞错档位不得被误升到重抛（另外 8 处的语义是"结果已达成"）', () => {
    // password_changed 一类：业务动作在写审计**之前**已经完成（密码已改），
    // 重抛会把已生效的变更报成失败，客户端重试再改一次 ⇒ 语义更坏。
    // 这条把"两处用重抛"的边界钉住，防止后来人一刀切改齐 10 处。
    const swallowOnly = Object.entries(EXPECTED_REGISTRY).filter(
      ([, guards]) => guards[GUARD_SWALLOW]
    );
    const rethrowOnly = Object.entries(EXPECTED_REGISTRY).filter(
      ([, guards]) => guards[GUARD_RETHROW]
    );
    expect(rethrowOnly.map(([k]) => k).sort()).toEqual([
      'controllers/securityController.js#reportSuspiciousActivity',
      'controllers/securityController.js#viewSensitiveData',
    ]);
    expect(swallowOnly).toHaveLength(8);
  });
});
