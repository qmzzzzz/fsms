/**
 * OpenAPI 文档同步守卫（防漂移）
 *
 * 从 Express Router 的真实路由栈（router.stack）提取全部已注册端点，
 * 与 src/docs/openapi.json 双向对账：
 *   - 已注册但文档缺失 → 新端点漏文档（本次修复的历史欠账）
 *   - 文档存在但无路由 → 幽灵文档误导调用方
 * 任何一边漂移都会让本测试红灯，强制新端点同步文档。
 *
 * 文档豁免清单：health 系列（存活/就绪探针）与内部指标端点——
 * 它们面向容器编排与运维抓取，不属于业务 API 文档面。
 */

const fs = require('fs');
const path = require('path');
const spec = require('../../docs/openapi.json');
// 文档豁免的路径（精确匹配）
const DOC_EXEMPT = new Set(['/health', '/readyz', '/api/metrics']);

// 挂载表：与 app.js 的 app.use 前缀一致（单一事实来源的镜像，
// 修改 app.js 挂载点时必须同步此处——openapiSync 测试会兜底对账）
const MOUNTS = [
  { name: 'authRoutes', prefix: '/api/auth' },
  { name: 'userRoutes', prefix: '/api/users' },
  { name: 'roleRoutes', prefix: '/api/roles' },
  { name: 'permissionRoutes', prefix: '/api/permissions' },
  { name: 'deviceRoutes', prefix: '/api/devices' },
  { name: 'alarmRoutes', prefix: '/api/alarms' },
  { name: 'inspectionRoutes', prefix: '/api/inspections' },
  { name: 'reportRoutes', prefix: '/api/reports' },
  { name: 'securityRoutes', prefix: '/api/security' },
];

describe('OpenAPI 文档同步守卫', () => {
  /** 从 Express Router 栈提取 (METHOD /fullPath) 集合 */
  const collectRegistered = () => {
    const routers = require('../../routes');
    const registered = new Set();
    // app.js 直挂路由（不经 MOUNTS 子路由，文档中已有定义）
    registered.add('GET /api');
    registered.add('GET /health');
    for (const { name, prefix } of MOUNTS) {
      const router = routers[name];
      expect(router).toBeTruthy();
      expect(router.name).toBe('router');
      for (const layer of router.stack) {
        if (!layer.route) continue; // 子挂载/中间件层跳过
        const methods = Object.keys(layer.route.methods).map((m) => m.toUpperCase());
        // :param → {param} 与 OpenAPI 参数风格对齐；尾斜杠归一（router '/' 挂载产生 'xxx/'）
        let fullPath = (prefix + layer.route.path).replace(/:([a-zA-Z]+)/g, '{$1}');
        if (fullPath.length > 1) fullPath = fullPath.replace(/\/+$/, '');
        for (const method of methods) {
          registered.add(method + ' ' + fullPath);
        }
      }
    }
    return registered;
  };

  /** 从 spec.paths 提取文档端点集合 */
  const collectDocumented = () => {
    const documented = new Set();
    for (const [p, ops] of Object.entries(spec.paths)) {
      for (const method of Object.keys(ops)) {
        if (method === 'parameters') continue;
        documented.add(method.toUpperCase() + ' ' + p);
      }
    }
    return documented;
  };

  test('openapi.json 基本结构有效', () => {
    expect(spec.openapi).toMatch(/^3\./);
    expect(spec.info).toBeTruthy();
    expect(spec.paths).toBeTruthy();
  });

  test('已注册端点全部入文档（无漏文档）', () => {
    const registered = collectRegistered();
    const documented = collectDocumented();
    const missing = [...registered].filter(
      (r) => !documented.has(r) && !DOC_EXEMPT.has(r.split(' ')[1])
    );
    expect(missing).toEqual([]);
  });

  test('文档中不存在幽灵端点（无对应路由）', () => {
    const registered = collectRegistered();
    const documented = collectDocumented();
    const ghosts = [...documented].filter((d) => {
      const path = d.split(' ')[1];
      return !registered.has(d) && !DOC_EXEMPT.has(path);
    });
    expect(ghosts).toEqual([]);
  });

  // L-24：生成器与产物的一致性守卫。
  //
  // 上面两条对账的是「产物 ↔ 真实路由」，但生成器（src/docs/generate.js）
  // 此前无人对账——它只写不读，require 即重写产物。结果：产物被人工补全到 83 个
  // 端点，生成器还停在 69 个，任何人跑一次 `node src/docs/generate.js` 都会
  // 静默抹掉 14 个端点（session 4 / mfa 6 / verify / export / 公钥 / 注册开关）。
  // 本测试把这条路径堵死：生成器的输出必须与已提交产物等价。
  describe('生成器与产物一致性（L-24）', () => {
    const generator = require('../../docs/generate.js');

    test('生成器可被 require 且不产生写盘副作用（不再 require 即重写产物）', () => {
      expect(generator).toBeTruthy();
      expect(generator.openapi).toMatch(/^3\./);
      expect(generator.paths).toBeTruthy();
    });

    test('path 集合与产物完全一致（双向）', () => {
      const genPaths = new Set(Object.keys(generator.paths));
      const docPaths = new Set(Object.keys(spec.paths));
      expect([...genPaths].filter((p) => !docPaths.has(p))).toEqual([]);
      expect([...docPaths].filter((p) => !genPaths.has(p))).toEqual([]);
    });

    test('每个端点的 method 集合与产物一致', () => {
      const ops = (s) => {
        const out = [];
        for (const [p, o] of Object.entries(s.paths)) {
          for (const m of Object.keys(o)) out.push(`${m.toUpperCase()} ${p}`);
        }
        return out.sort();
      };
      expect(ops(generator)).toEqual(ops(spec));
    });

    test('端点定义内容逐条一致（防止生成器写出过时描述）', () => {
      // 逐端点深比对。若此处红灯，说明改了一边忘了另一边——
      // 正确处置是重跑 `node src/docs/generate.js` 并提交产物，
      // 而不是放宽断言。
      const diffs = [];
      for (const p of Object.keys(spec.paths)) {
        if (JSON.stringify(generator.paths[p]) !== JSON.stringify(spec.paths[p])) diffs.push(p);
      }
      expect(diffs).toEqual([]);
    });
  });

  // ================= P2-45 对账盲区补齐 =================
  //
  // 原 MOUNTS 只列 9 个业务子路由，导致三类真实路由完全不参与对账：
  //   1. wellKnownRoutes（挂在根路径，不在任何 /api 前缀下）
  //   2. app.js 直挂的 /api-docs.json（文档自身，随 ENABLE_API_DOCS 开关）
  //   3. app.js 直挂的 /metrics（随 METRICS_ENABLED 开关）
  // 盲区期间，这些端点无论怎么漂移测试都不会红——「任何一边漂移都会
  // 让本测试红灯」的宣称对它们是假的。
  //
  // 补法：把上述路由纳入**显式豁免清单**并单独断言其存在性。
  // 之所以是豁免而非纳入 spec.paths：
  //   - security.txt 由 RFC 9116 规定路径，不是业务 API；
  //   - /csp-report 与 /client-errors 是浏览器自动发起的单向上报端点，
  //     调用方是浏览器而非 API 消费者；
  //   - /api-docs.json 与 /metrics 面向运维/文档工具，且随开关可缺席。
  // 若把它们塞进 openapi.json，反而会让「文档面 = 业务 API 面」这条
  // 边界失效。故改为「必须存在 + 明确豁免」的双向锁定：
  // 端点消失或豁免清单被误删，本组用例都会红。
  describe('对账盲区补齐（P2-45）', () => {
    /** 根路径路由（不挂 /api 前缀） */
    const ROOT_MOUNTS = [{ name: 'wellKnownRoutes', prefix: '' }];

    const collectRootRegistered = () => {
      const routers = require('../../routes');
      const registered = new Set();
      for (const { name, prefix } of ROOT_MOUNTS) {
        const router = routers[name];
        expect(router).toBeTruthy();
        for (const layer of router.stack) {
          if (!layer.route) continue;
          const methods = Object.keys(layer.route.methods).map((m) => m.toUpperCase());
          let fullPath = (prefix + layer.route.path).replace(/:([a-zA-Z]+)/g, '{$1}');
          if (fullPath.length > 1) fullPath = fullPath.replace(/\/+$/, '');
          for (const method of methods) registered.add(method + ' ' + fullPath);
        }
      }
      return registered;
    };

    test('wellKnownRoutes 的真实路由被完整采集（防挂载表与实现漂移）', () => {
      const registered = collectRootRegistered();
      // 逐条锁定：少一条即说明路由被删或挂载方式变了，必须显式更新本清单
      expect([...registered].sort()).toEqual([
        'GET /.well-known/security.txt',
        'GET /security.txt',
        'POST /client-errors',
        'POST /csp-report',
      ]);
    });

    test('wellKnownRoutes 端点属于豁免面（不进 openapi.json，且豁免有据）', () => {
      const documented = collectDocumented();
      for (const ep of [
        'GET /.well-known/security.txt',
        'GET /security.txt',
        'POST /client-errors',
        'POST /csp-report',
      ]) {
        expect({ ep, documented: documented.has(ep) }).toEqual({ ep, documented: false });
      }
    });

    test('app.js 直挂端点：/api-docs.json 与 /metrics 在源码中真实存在', () => {
      // 这两个端点随 ENABLE_API_DOCS / METRICS_ENABLED 开关条件注册，
      // 无法通过 router.stack 采集，故对 app.js 源码做**存在性**断言。
      // 这不是「源码文本断言代替行为」——行为验证需要同时满足
      // 「开关打开时端点可访问」「开关关闭时端点 404」，属 e2e 范畴；
      // 此处只防「有人删掉注册语句」这类静默消失。
      const appSource = fs.readFileSync(path.join(__dirname, '../../app.js'), 'utf8');
      expect(appSource).toMatch(/app\.get\(\s*'\/api-docs\.json'/);
      expect(appSource).toMatch(/app\.get\(\s*'\/metrics'/);
    });

    test('app.js 直挂端点不进入 openapi.json（同为豁免面）', () => {
      const documented = collectDocumented();
      for (const ep of ['GET /api-docs.json', 'GET /metrics', 'GET /readyz']) {
        expect({ ep, documented: documented.has(ep) }).toEqual({ ep, documented: false });
      }
    });
  });

  test('新增安全端点已在文档中（本轮同步回归锚点）', () => {
    const documented = collectDocumented();
    for (const endpoint of [
      'GET /api/auth/login-public-key',
      'GET /api/auth/sessions',
      'DELETE /api/auth/sessions/others',
      'DELETE /api/auth/sessions/{sid}',
      'GET /api/auth/mfa/status',
      'POST /api/auth/mfa/enroll',
      'POST /api/auth/mfa/enable',
      'POST /api/auth/mfa/disable',
      'POST /api/auth/mfa/recovery-codes',
      'GET /api/auth/session',
    ]) {
      expect(documented.has(endpoint)).toBe(true);
    }
  });
});
