/**
 * 响应头策略加固守护（2026-10-15）
 *
 * 覆盖三件事，都是「改错了不会有别的红灯」的类型：
 *
 * ① Trusted Types report-only 灰度（P1）
 *    只写 `Content-Security-Policy-Report-Only`，与强制 CSP 头名不同、互不覆盖；
 *    上报出口随 CSP_REPORT_ENABLED 开关（关闭时不下发 report-uri/report-to）。
 *    ⚠ 构造期陷阱：helmet 7.2.0 的 normalizeDirectives() 要求「必须有 default-src，
 *    除非显式 dangerouslyDisableDefaultSrc」（node_modules/helmet/index.cjs:90-92），
 *    reportOnly 也一视同仁。只写 require-trusted-types-for 会在 require 期直接抛错，
 *    app 起不来——所以本中间件的构造成功本身就是一条断言。
 *
 * ② CORP 由 same-site 收紧到 same-origin（P2）
 * ③ Referrer-Policy 由 strict-origin-when-cross-origin 收紧到 same-origin（P2）
 *    ③ 的关键不是单点取值，而是**五份副本取值一致**：nginx.conf.example 三份
 *    （server 级 + `location /` + `location /assets/`，add_header 在嵌套块是整体替换）、
 *    web-admin/vite.config.js 的 buildSecurityHeaders、后端 helmet 各一份。此前全仓
 *    没有任何断言看着这五份，漏改一份就是一条静默退化的路径（nginxProxyContract
 *    只钉了静态 CSP 的两份副本）。
 *
 * 可证伪性：②③ 的跨副本比对走纯函数（referrerPolicyValuesFrom / corpValuesFrom），
 * 下面用合成反证钉住「值不一致时必须报出来」，避免出现「提取器恒返回空数组 ⇒ 全绿」。
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const request = require('supertest');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const { applyResponseHardening, trustedTypesReportOnly } = require('../../middleware/security');

const buildApp = () => {
  const app = express();
  applyResponseHardening(app);
  app.use((req, res) => res.json({ ok: true }));
  return app;
};

// ---------------------------------------------------------------------------
// 跨副本提取器（纯函数，正反两向共用同一份判据）
// ---------------------------------------------------------------------------

/** nginx 里所有 `add_header Referrer-Policy "X" always;` 的取值（按出现顺序） */
const referrerPolicyValuesFrom = (text) =>
  [...text.matchAll(/^[ \t]*add_header[ \t]+Referrer-Policy[ \t]+"([^"]+)"[ \t]+always;/gm)].map(
    (m) => m[1]
  );

/** nginx 里所有 `add_header Cross-Origin-Resource-Policy "X" always;` 的取值 */
const corpValuesFrom = (text) =>
  [
    ...text.matchAll(
      /^[ \t]*add_header[ \t]+Cross-Origin-Resource-Policy[ \t]+"([^"]+)"[ \t]+always;/gm
    ),
  ].map((m) => m[1]);

/** vite.config.js buildSecurityHeaders 里 `'Referrer-Policy': 'X',` 的取值 */
const viteHeaderValueFrom = (text, header) => {
  const m = new RegExp(`'${header}':\\s*'([^']+)'`).exec(text);
  return m ? m[1] : null;
};

/** 后端 helmet 配置里 `referrerPolicy: { policy: 'X' }` 的取值 */
const helmetPolicyFrom = (text, key) => {
  const m = new RegExp(`${key}:\\s*\\{\\s*policy:\\s*'([^']+)'`).exec(text);
  return m ? m[1] : null;
};

// ---------------------------------------------------------------------------

describe('Trusted Types report-only 灰度（P1）', () => {
  test('下发独立的 Report-Only 头，且只有 require-trusted-types-for 一条指令', async () => {
    const res = await request(buildApp()).get('/api/anything').expect(200);
    const ro = res.headers['content-security-policy-report-only'];
    expect(ro).toBeDefined();
    // 只此一条：default-src 必须被摘掉，否则 helmet 的整套默认指令会被拖进来制造噪音
    expect(ro).toBe("require-trusted-types-for 'script'");
    expect(ro).not.toContain('default-src');
  });

  test('不污染强制 CSP：强制头仍在，且不含 require-trusted-types-for', async () => {
    const res = await request(buildApp()).get('/api/anything').expect(200);
    const enforced = res.headers['content-security-policy'];
    expect(enforced).toBeDefined();
    expect(enforced).toContain("default-src 'self'");
    expect(enforced).not.toContain('require-trusted-types-for');
    // 两个头必须同时存在（头名不同 ⇒ 互不覆盖，不是「后写覆盖前写」）
    expect(res.headers['content-security-policy-report-only']).toBeDefined();
  });

  test('灰度是只上报不阻断：中间件本身不返回错误、不拦截请求', async () => {
    const res = await request(buildApp()).get('/api/anything');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  test('CSP_REPORT_ENABLED=false 时不附带任何上报指令（默认态）', async () => {
    const ro = await request(buildApp())
      .get('/x')
      .then((r) => r.headers['content-security-policy-report-only']);
    expect(ro).not.toContain('report-uri');
    expect(ro).not.toContain('report-to');
  });

  test('CSP_REPORT_ENABLED=true 时 report-uri/report-to 与主 CSP 同口径', async () => {
    // cspReportEnabled 在模块加载期取值 ⇒ 必须在隔离的模块注册表里重新 require
    const prev = process.env.CSP_REPORT_ENABLED;
    process.env.CSP_REPORT_ENABLED = 'true';
    let mod;
    try {
      jest.resetModules();
      jest.isolateModules(() => {
        mod = require('../../middleware/security');
      });
    } finally {
      if (prev === undefined) delete process.env.CSP_REPORT_ENABLED;
      else process.env.CSP_REPORT_ENABLED = prev;
      jest.resetModules();
    }

    const app = express();
    mod.applyResponseHardening(app);
    app.use((req, res) => res.json({ ok: true }));
    const res = await request(app).get('/x').expect(200);

    const ro = res.headers['content-security-policy-report-only'];
    expect(ro).toContain('report-uri /csp-report');
    expect(ro).toContain('report-to csp-endpoint');
    expect(ro).toContain("require-trusted-types-for 'script'");
    // 上报出口由 Reporting-Endpoints 提供，report-to 才有解析依据
    expect(res.headers['reporting-endpoints']).toContain('csp-endpoint="/csp-report"');
    // 主 CSP 侧同口径（同一开关驱动两条策略，不应出现一条有一没有）
    expect(res.headers['content-security-policy']).toContain('report-uri /csp-report');
  });

  test('导出的中间件可直接挂载（消费侧不必自己重建配置）', () => {
    expect(typeof trustedTypesReportOnly).toBe('function');
  });
});

describe('A7：Trusted Types 升强制开关（TRUSTED_TYPES_ENFORCE）', () => {
  /** 在隔离的模块注册表里按给定环境重新加载 middleware/security */
  const loadWith = (env) => {
    const saved = {};
    for (const [k, v] of Object.entries(env)) {
      saved[k] = process.env[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    let mod;
    try {
      jest.resetModules();
      jest.isolateModules(() => {
        mod = require('../../middleware/security');
      });
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      jest.resetModules();
    }
    return mod;
  };

  const headersWith = async (env) => {
    const mod = loadWith(env);
    const app = express();
    mod.applyResponseHardening(app);
    app.use((req, res) => res.json({ ok: true }));
    const res = await request(app).get('/x').expect(200);
    return res.headers;
  };

  test('默认（未设置）：仍是灰度——主 CSP 不含该指令，report-only 头单独下发', async () => {
    const headers = await headersWith({ TRUSTED_TYPES_ENFORCE: undefined });
    expect(headers['content-security-policy']).not.toContain('require-trusted-types-for');
    expect(headers['content-security-policy-report-only']).toBe(
      "require-trusted-types-for 'script'"
    );
  });

  test('置 true：指令挪进主 CSP，且不再下发 report-only 头（同一策略不下发两遍）', async () => {
    const headers = await headersWith({ TRUSTED_TYPES_ENFORCE: 'true' });
    expect(headers['content-security-policy']).toContain("require-trusted-types-for 'script'");
    // 主 CSP 的其余指令必须还在（证明是"追加"而不是"替换整条策略"）
    expect(headers['content-security-policy']).toContain("default-src 'self'");
    // report-only 头必须消失：否则浏览器按两条独立策略各报一次，违规计数翻倍，
    // 而"报告数"正是本开关的决策依据
    expect(headers['content-security-policy-report-only']).toBeUndefined();
  });

  test('非 "true" 的字面量一律不升强制（fail-closed：只有精确 true 才生效）', async () => {
    for (const value of ['1', 'TRUE', 'yes', '']) {
      const headers = await headersWith({ TRUSTED_TYPES_ENFORCE: value });
      expect({ value, csp: headers['content-security-policy'] }).toEqual({
        value,
        csp: expect.not.stringContaining('require-trusted-types-for'),
      });
    }
  });

  test('强制态下上报出口仍随 CSP_REPORT_ENABLED 走（两个开关互不吞掉）', async () => {
    const headers = await headersWith({
      TRUSTED_TYPES_ENFORCE: 'true',
      CSP_REPORT_ENABLED: 'true',
    });
    expect(headers['content-security-policy']).toContain('report-uri /csp-report');
    expect(headers['reporting-endpoints']).toContain('csp-endpoint="/csp-report"');
  });
});

describe('CORP / Referrer-Policy 取值与五份副本一致性（P2）', () => {
  const nginx = read('deployment/nginx.conf.example');
  const vite = read('web-admin/vite.config.js');
  const security = read('src/middleware/security.js');

  test('后端实际下发的 CORP 与 Referrer-Policy 均为 same-origin', async () => {
    const res = await request(buildApp()).get('/api/anything').expect(200);
    expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(res.headers['referrer-policy']).toBe('same-origin');
  });

  test('Referrer-Policy 五份副本取值一致（3 nginx + vite + helmet）', () => {
    const nginxValues = referrerPolicyValuesFrom(nginx);
    // 前提自证：三份副本必须都被提取到，否则下面的 every() 是空集恒真
    expect(nginxValues).toHaveLength(3);
    const all = [
      ...nginxValues,
      viteHeaderValueFrom(vite, 'Referrer-Policy'),
      helmetPolicyFrom(security, 'referrerPolicy'),
    ];
    expect(all).toHaveLength(5);
    expect(new Set(all).size).toBe(1);
    expect(all[0]).toBe('same-origin');
  });

  test('CORP 五份副本取值一致（3 nginx + vite + helmet）', () => {
    const nginxValues = corpValuesFrom(nginx);
    expect(nginxValues).toHaveLength(3);
    const all = [
      ...nginxValues,
      viteHeaderValueFrom(vite, 'Cross-Origin-Resource-Policy'),
      helmetPolicyFrom(security, 'crossOriginResourcePolicy'),
    ];
    expect(new Set(all).size).toBe(1);
    expect(all[0]).toBe('same-origin');
  });

  test('可证伪：把 nginx 的一份副本改回旧值时，一致性判据必须报出来', () => {
    // 三份副本里只改一份 —— 这正是「add_header 在嵌套块整体替换」最容易漏改的形态
    const mutated = nginx.replace(
      /^( {8}add_header[ \t]+Referrer-Policy[ \t]+")same-origin(")/m,
      '$1strict-origin-when-cross-origin$2'
    );
    expect(mutated).not.toBe(nginx); // 替身没替换成功 = 空跑
    const values = referrerPolicyValuesFrom(mutated);
    expect(values).toHaveLength(3);
    expect(new Set(values).size).toBe(2); // 不一致必须可见
    expect(values).toContain('strict-origin-when-cross-origin');
  });

  test('可证伪：提取器不是恒空数组（合成输入必须被读到）', () => {
    const synthetic =
      '  add_header Referrer-Policy "same-origin" always;\n' +
      '        add_header Cross-Origin-Resource-Policy "same-origin" always;\n';
    expect(referrerPolicyValuesFrom(synthetic)).toEqual(['same-origin']);
    expect(corpValuesFrom(synthetic)).toEqual(['same-origin']);
    expect(referrerPolicyValuesFrom('')).toEqual([]);
    expect(viteHeaderValueFrom("    'Referrer-Policy': 'same-origin',", 'Referrer-Policy')).toBe(
      'same-origin'
    );
    expect(helmetPolicyFrom("  referrerPolicy: { policy: 'same-origin' },", 'referrerPolicy')).toBe(
      'same-origin'
    );
  });
});
