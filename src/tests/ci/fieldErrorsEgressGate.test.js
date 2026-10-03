'use strict';

/**
 * 校验错误出站面：`value` 一律不出站（把文档里的消费契约接成机器判据）
 *
 * 起因：`src/utils/validationRules.js:100-116` 的 `safeFieldErrors` 文件头写着两条硬口径——
 *   "express-validator 的 errors.array() 默认 formatter 返回含 value（用户原始输入）的完整错误对象"，
 *   "所有 fieldErrors: errors.array() 调用点必须经本函数出站——新增校验消费点时同样走这里"。
 * 之所以要紧：本仓校验链大量覆盖口令字段（登录/注册/改密/MFA），强度或长度校验失败时
 * `value` 就是**明文口令本身**，一旦进响应体就会被前端 errorReporter 采集上报、
 * 进代理访问日志、留在浏览器 DevTools 里。
 *
 * 而这条契约在本仓**一个用例都没有**（实测：`grep -rl safeFieldErrors src/tests` 结果为空）。
 * 按本仓既有判据「只登记不接线 = 缺陷」，写在注释里的口径等于没写：
 * 任何人在新路由里补一句 `fieldErrors: errors.array()` 都不会被任何东西拦下，
 * 而且这一条是**静默**的——响应 200/400 都对、功能都对，只有口令多出站一次。
 * 所以这里把它做成三条独立判据：
 *   1. 行为（真跑）：同一条 express-validator 链，raw `result.array()` 里确有明文口令，
 *      而 `safeFieldErrors(result)` 里没有——这条同时是" sanitizer 确实在做事"的前提自证，
 *      如果哪天 express-validator 换了默认 formatter 不再带 value，本用例会红并提醒口径变了；
 *   2. 端到端（真跑）：POST /api/auth/login 提交超长口令 ⇒ 400 且 fieldErrors 里点名
 *      path='password'（前提自证，避免"根本没进校验分支所以断言恒真"的假绿），
 *      而响应全文不含那个口令串；
 *   3. 全仓扫描（静态）：生产码里 `.array()` 只允许出现在 safeFieldErrors 自己的函数体内；
 *      所有非包装的 `fieldErrors:` 出站点必须等于冻结的例外集（今天只有 1 处，理由见 EXCEPTIONS）。
 *
 * 反向对照也做成用例（见 R9-F3/F4 的变异台账）：
 *   - 把某个控制器的 `safeFieldErrors(errors)` 改成 `errors.array()` ⇒ 本套件必须红；
 *   - 往路由文件加一行**注释里的** `// fieldErrors: errors.array()` ⇒ 本套件必须保持绿
 *     （否则第 3 条只是我对扫描器的乐观假设，扫注释会产出假阳性并把所有人逼成改测试）。
 */
const fs = require('fs');
const path = require('path');
const { body } = require('express-validator');

const SRC_DIR = path.resolve(__dirname, '../..');

/** 生产码文件（跳过 tests 与 node_modules），与仓内其余静态闸同口径 */
function listProdFiles(dir = SRC_DIR, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listProdFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/** 行注释与块注释都剥掉——注释里提"errors.array()"是在讲口径，不是在出站 */
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((line) => !/^\s*(\/\/|\*)/.test(line))
    .join('\n');

const relOf = (file) => path.relative(SRC_DIR, file).replace(/\\/g, '/');

/**
 * 生产码里所有 `X.array()` 形态的调用（校验结果出站的原语）。
 * 注释剥离在**函数内部**做：两个扫描器都必须对同一份口径负责，
 * 否则调用方忘记 strip 就会把文档里的 `errors.array()` 算成出站点（本仓文档确有 3 处提及）。
 */
function scanArrayCalls(src) {
  return [...stripComments(src).matchAll(/([A-Za-z_$][\w$]*)\s*\.\s*array\s*\(\s*\)/g)].map(
    (m) => m[1]
  );
}

/**
 * 生产码里所有 `fieldErrors: <表达式>` 出站点。
 * 必须**连行一起返回**：早先版本只返回表达式，判"手写明细不得夹带 value"时
 * 用 `/fieldErrors:/` 在文件里 find 第一行——命中的是同文件更早的那条包装出站，
 * 于是无论字面量里加不加 value 都恒真（R9-F4 变异实测：SURVIVED）。
 *
 * 表达式的取值范围必须**跨行括号配平**：按行取 `[^,}]+` 时，
 * `fieldErrors: [` 后换行写明细的那种形态只把 `[` 当成表达式，`value:` 落在下一行
 * 就绕过了"手写明细不得夹带 value"（2026-10-01 R10-D 变异 M2 实测 SURVIVED，
 * 台账 mut-round11-ledger-green.json）。现在 span = 该值配平后的完整文本，
 * 逐条 `value:` 检查用 span；line 仍是站点所在物理行，用于定位与形态自证。
 */
function scanEgress(src) {
  const out = [];
  // 剥注释在函数内部再做一次（调用方也剥）：双剥幂等，但少了它，
  // 直接把带 `// fieldErrors: errors.array()` 的文本传进来就会被当成出站点——
  // 那正是反向对照用例要保证"扫注释会产出假阳性"的形态
  const text = stripComments(src);
  const keyRe = /fieldErrors\s*:/g;
  for (let m = keyRe.exec(text); m !== null; m = keyRe.exec(text)) {
    let i = m.index + m[0].length;
    while (i < text.length && /\s/.test(text[i])) i += 1;
    const start = i;
    let depth = 0;
    while (i < text.length) {
      const ch = text[i];
      if (ch === '(' || ch === '[' || ch === '{') depth += 1;
      else if (ch === ')' || ch === ']' || ch === '}') {
        if (depth === 0) break; // 闭合的是外层对象：这个值到此为止
        depth -= 1;
      } else if (ch === ',' && depth === 0) break;
      i += 1;
    }
    const nlBefore = text.lastIndexOf('\n', m.index - 1) + 1;
    const nlAfter = text.indexOf('\n', m.index);
    const line = text.slice(nlBefore, nlAfter === -1 ? text.length : nlAfter);
    const span = text.slice(start, i).replace(/\s+/g, ' ').trim();
    out.push({ expr: span, line, span });
  }
  return out;
}

/** 是否经 safeFieldErrors 出站 */
const isWrapped = (expr) => /^safeFieldErrors\s*\(/.test(expr);
/** 手写明细（不可能带 express-validator 的 value，因为值是本机字面量） */
const isHandBuilt = (expr) => expr.startsWith('[');
/** ApiResponse 的透传形（值由调用方决定，本身不产 value） */
const isPassThrough = (expr) => /^options\.fieldErrors$/.test(expr);

const PROD_FILES = listProdFiles();
const read = (rel) => fs.readFileSync(path.join(SRC_DIR, rel), 'utf8');

// 例外登记：不经过 safeFieldErrors 的 fieldErrors 出站点。
// 之所以可以放行，是因为它们的值来源里根本没有"用户原始输入"这一项——
// 见下面逐条 reason 与 middleware/errorHandler.js 的形状自证用例。
const EXCEPTIONS = {
  // Mongoose ValidationError 走的是 errorHandler：{field, message} 两键，
  // 键名不是 express-validator 的 {path,msg,value,type,location}，且整体被 isDev 闸住。
  'middleware/errorHandler.js': {
    expr: 'safeErrors',
    reason: 'Mongoose 形状 {field,message}，且 isDev 为假时置 undefined（生产不出站）',
  },
};

describe('校验错误出站面：value 一律不出站', () => {
  describe('行为判据（真跑 express-validator，不是扫描出来的）', () => {
    const SECRET = 'Sup3r-Long-Login-Password-Value-Must-NOT-Egress-0123456789';

    async function runPasswordChain() {
      const req = {
        body: { password: SECRET.repeat(3) },
        get: () => '',
        headers: {},
        query: {},
        params: {},
      };
      // 与 routes/authRoutes.js:116-122 登录链的口令约束同值（max 128）
      const result = await body('password')
        .notEmpty()
        .isLength({ max: 128 })
        .withMessage('密码长度异常')
        .run(req);
      return result;
    }

    it('前提自证：raw array() 确实带明文口令（所以"必须包装"不是空话）', async () => {
      const result = await runPasswordChain();
      const raw = result.array();
      expect(raw.length).toBeGreaterThan(0);
      expect(raw.some((e) => e.path === 'password')).toBe(true);
      // 这就是泄露面本身：默认 formatter 把用户原样输入挂在 value 上
      expect(raw.some((e) => e.value === SECRET.repeat(3))).toBe(true);
      expect(JSON.stringify(raw)).toContain(SECRET);
    });

    it('safeFieldErrors 出站后 value 消失，且只剩定位四键', async () => {
      const result = await runPasswordChain();
      const safe = require('../../utils/validationRules').safeFieldErrors(result);
      expect(safe.length).toBeGreaterThan(0);
      expect(JSON.stringify(safe)).not.toContain(SECRET);
      for (const e of safe) {
        expect(Object.keys(e).sort()).toEqual(['location', 'msg', 'path', 'type']);
      }
    });
  });

  describe('端到端判据（真打登录接口）', () => {
    const request = require('supertest');
    let app;
    const EGRESS_PROBE = 'EgressProbe-Pa55w0rd-Should-Never-Appear-In-Response-Body-9137';

    beforeAll(async () => {
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
      require('../../models/AuditLog');
      require('../../models/TokenBlacklist');
      const { createApp } = require('../../app');
      app = createApp();
    });

    it('登录口令超长 ⇒ 400 且点名 password（前提）+ 响应全文不含该口令', async () => {
      // repeat(3) = 180 字符 > 登录链的 max 128（实测：128 → 401，129 → 400 密码长度异常）
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'zz_egress_probe', password: EGRESS_PROBE.repeat(3) });

      expect(res.status).toBe(400);
      // 前提自证：真的走到了"口令字段被点名"的分支，否则下一条断言恒真
      // （本仓 ApiResponse 把明细挂在 errors 下：{errors:{errorCode, fieldErrors}}）
      const emitted = JSON.stringify(res.body);
      expect(emitted).toContain('password');
      const fieldErrors = res.body.errors.fieldErrors;
      expect(Array.isArray(fieldErrors)).toBe(true);
      expect(fieldErrors.some((e) => e.path === 'password')).toBe(true);
      // 判据：明文口令不出站（含 value 键、含任何回显形态）
      expect(res.text).not.toContain(EGRESS_PROBE);
      expect(emitted).not.toContain('"value"');
    });
  });

  describe('全仓扫描判据', () => {
    const arraySites = [];
    const egressSites = [];
    for (const file of PROD_FILES) {
      const rel = relOf(file);
      const src = stripComments(fs.readFileSync(file, 'utf8'));
      for (const receiver of scanArrayCalls(src)) arraySites.push({ rel, receiver });
      for (const site of scanEgress(src)) egressSites.push({ rel, ...site });
    }

    it('前提自证：扫描器扫到了真实站点（格式漂移时它会静默返回空）', () => {
      // 包装出站是本仓主流写法，数量级掉了就说明 fieldErrors 的书写形态变了，扫描器需同步
      expect(egressSites.filter((s) => isWrapped(s.expr))).toHaveLength(47);
      expect(arraySites.length + egressSites.length).toBeGreaterThan(50);
    });

    it('生产码里 `.array()` 只存在于 safeFieldErrors 自己体内', () => {
      const offenders = arraySites.filter((s) => s.rel !== 'utils/validationRules.js');
      expect(offenders).toEqual([]);
      // 且确实在函数体内，而不是同文件别处
      const body = read('utils/validationRules.js');
      const fn = body.match(/function safeFieldErrors[\s\S]*?\n}/);
      expect(fn).not.toBeNull();
      expect(fn[0]).toMatch(/result\.array\(\)/);
    });

    it('非包装的 fieldErrors 出站点必须逐一登记在案（新增裸出站必须响）', () => {
      const unregistered = egressSites.filter(
        (s) => !isWrapped(s.expr) && !isHandBuilt(s.expr) && !isPassThrough(s.expr)
      );
      expect(unregistered.map((s) => `${s.rel} => ${s.expr}`)).toEqual(
        Object.entries(EXCEPTIONS).map(([rel, e]) => `${rel} => ${e.expr}`)
      );
      // 每条例外的理由必须是当前事实，不是历史备忘
      for (const [rel, e] of Object.entries(EXCEPTIONS)) {
        expect(stripComments(read(rel))).toContain(`fieldErrors: ${e.expr}`);
      }
    });

    it('手写明细类不得夹带 value（那是把泄露重新接回来）', () => {
      const literals = egressSites.filter((s) => isHandBuilt(s.expr));
      expect(literals.length).toBeGreaterThan(0);
      // 逐条看**它自己的值文本**（跨行配平后的 span），不是同文件第一条 fieldErrors（R9-F4），
      // 也不是它所在的那一行（M2：`fieldErrors: [` 换行后 value: 在下一行，按行判恒真）
      for (const s of literals) {
        expect(`${s.rel} ${s.line}`).toMatch(/fieldErrors\s*:/);
        expect(`${s.rel} ${s.span}`).not.toMatch(/\bvalue\s*:/);
      }
    });

    it('例外之所以是例外：errorHandler 的 fieldErrors 仍被 isDev 闸住且是 Mongoose 形状', () => {
      const src = read('middleware/errorHandler.js');
      expect(src).toMatch(/const isDev =[^;]*development/);
      expect(src).toMatch(/const safeErrors = isDev \? errors : undefined;/);
      // 值来源里只有 field/message 两键，没有用户原始输入
      expect(src).toMatch(/field: e\.path/);
      expect(src.match(/fieldErrors: safeErrors/)).not.toBeNull();
      expect(src).not.toMatch(/value: e\.(value|stringValue)/);
    });

    it('反向对照（口径本身可证伪）：注释里的 errors.array() 不算出站', () => {
      const synthetic = [
        '/** 口径说明：不要直接 errors.array() 出站 */',
        '  // fieldErrors: errors.array()',
        '  const ok = safeFieldErrors(errors);',
      ].join('\n');
      expect(scanEgress(synthetic)).toEqual([]);
      expect(scanArrayCalls(synthetic)).toEqual([]);
      // 真代码形态必须被扫到（否则上面两条断言是恒真的）
      expect(scanEgress('  fieldErrors: errors.array(),')).toEqual([
        { expr: 'errors.array()', line: '  fieldErrors: errors.array(),', span: 'errors.array()' },
      ]);
      expect(scanArrayCalls('const x = errors.array();')).toEqual(['errors']);

      // M2 的常驻对偶：值换行时 span 必须覆盖到下一行的 `value:`。
      // 按行取表达式的旧口径在这里 span 只剩 `[`，`value:` 因此隐身（变异实测 SURVIVED）
      const multiline = [
        'res.status(400).json(ApiResponse.fail({',
        '  fieldErrors: [',
        "    { path: 'password', value: req.body.password },",
        '  ],',
        '}));',
      ].join('\n');
      const sites = scanEgress(multiline);
      expect(sites).toHaveLength(1);
      expect(isHandBuilt(sites[0].expr)).toBe(true);
      expect(sites[0].span).toMatch(/\bvalue\s*:/);
      // 同一形态去掉 value 必须是干净的（否则上一条断言可能只是在挑任何文本）
      const clean = multiline.replace(
        "    { path: 'password', value: req.body.password },",
        "    { path: 'password', msg: 'x' },"
      );
      expect(scanEgress(clean)[0].span).not.toMatch(/\bvalue\s*:/);
    });
  });
});
