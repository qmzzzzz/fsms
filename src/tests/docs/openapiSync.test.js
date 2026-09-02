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
