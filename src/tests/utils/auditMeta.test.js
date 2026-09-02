/**
 * auditMeta 单元测试：审计元数据（category / action）派生
 *
 * 覆盖修复要点：Express 多级挂载会剥离 req.path，派生必须基于 originalUrl，
 * 否则全部记录退化为 category=system；且派生出的 category 必须落在模型 enum 内。
 */

const {
  ROUTE_CATEGORY_MAP,
  isDynamicSegment,
  auditPath,
  deriveCategory,
  deriveAction,
  deriveAuditMeta,
} = require('../../utils/auditMeta');

// 与 models/AuditLog.js 的 category enum 保持同步
const CATEGORY_ENUM = [
  'auth',
  'user',
  'role',
  'permission',
  'device',
  'alarm',
  'inspection',
  'security',
  'report',
  'system',
];

const OID = '6a587774afeb797dd4de03e3';

describe('auditMeta（审计元数据派生）', () => {
  describe('auditPath', () => {
    test('优先取 originalUrl 并去掉查询串', () => {
      expect(auditPath({ originalUrl: '/api/users?page=2&limit=10', path: '/2' })).toBe(
        '/api/users'
      );
      expect(auditPath({ originalUrl: '/api/users/abc' })).toBe('/api/users/abc');
    });

    test('originalUrl 缺失时依次回退 url / path', () => {
      expect(auditPath({ url: '/api/roles' })).toBe('/api/roles');
      expect(auditPath({ path: '/api/roles' })).toBe('/api/roles');
      expect(auditPath({})).toBe('');
    });
  });

  describe('deriveCategory', () => {
    test('各业务前缀映射到正确 category', () => {
      expect(deriveCategory('/api/users')).toBe('user');
      expect(deriveCategory(`/api/users/${OID}`)).toBe('user');
      expect(deriveCategory('/api/devices/x')).toBe('device');
      expect(deriveCategory('/api/alarms/x')).toBe('alarm');
      expect(deriveCategory('/api/inspections/x')).toBe('inspection');
      expect(deriveCategory('/api/roles/x')).toBe('role');
      expect(deriveCategory('/api/permissions/x')).toBe('permission');
      expect(deriveCategory('/api/security/x')).toBe('security');
      expect(deriveCategory('/api/auth/login')).toBe('auth');
      expect(deriveCategory('/api/reports/export')).toBe('report');
    });

    test('未匹配任何前缀时回退 system', () => {
      expect(deriveCategory('/api/unknown')).toBe('system');
      expect(deriveCategory('/health')).toBe('system');
      expect(deriveCategory('')).toBe('system');
    });

    test('前缀匹配需按路径分段，避免相似前缀误判', () => {
      // /api/userscustom 不应被判为 user
      expect(deriveCategory('/api/userscustom')).toBe('system');
    });

    test('被剥离前缀的路径（修复前的错误输入）确实无法正确派生', () => {
      // 这正是 Bug 1 的根因：中间件里读 req.path 得到的是剥离后的路径
      expect(deriveCategory('/login')).toBe('system');
      expect(deriveCategory(`/${OID}/roles`)).toBe('system');
    });

    test('ROUTE_CATEGORY_MAP 的取值全集必须在模型 enum 内', () => {
      const values = [...new Set(Object.values(ROUTE_CATEGORY_MAP))];
      expect(values.filter((v) => !CATEGORY_ENUM.includes(v))).toEqual([]);
    });
  });

  describe('deriveAction', () => {
    test('无子路径时按方法映射 create / update / delete', () => {
      expect(deriveAction('POST', '/api/users', 'user')).toBe('user_create');
      expect(deriveAction('PUT', `/api/users/${OID}`, 'user')).toBe('user_update');
      expect(deriveAction('PATCH', `/api/users/${OID}`, 'user')).toBe('user_update');
      expect(deriveAction('DELETE', `/api/users/${OID}`, 'user')).toBe('user_delete');
    });

    test('有子路径时以子路径为动作后缀（不受方法影响）', () => {
      expect(deriveAction('PUT', `/api/users/${OID}/roles`, 'user')).toBe('user_roles');
      expect(deriveAction('PUT', `/api/alarms/${OID}/dispatch`, 'alarm')).toBe('alarm_dispatch');
      expect(deriveAction('POST', '/api/alarms/report', 'alarm')).toBe('alarm_report');
      expect(deriveAction('PUT', `/api/devices/${OID}/status`, 'device')).toBe('device_status');
      expect(deriveAction('POST', `/api/devices/${OID}/maintenance`, 'device')).toBe(
        'device_maintenance'
      );
    });

    test('ObjectId 与纯数字段被剔除，不混入 action', () => {
      expect(deriveAction('PUT', `/api/users/${OID}/roles`, 'user')).not.toContain(OID);
      expect(deriveAction('PUT', '/api/devices/123/status', 'device')).toBe('device_status');
    });

    // 会话管理路由的路径参数是 sid（randomUUID）。若 UUID 不被剔除，
    // DELETE /api/auth/sessions/<uuid> 会派生出 auth_sessions_550e8400-…：
    // action 取值随请求无限膨胀，既撑爆 {action:1} 索引的基数，
    // 也让审计页的 action 枚举筛选永远命中不到。
    test('UUID 段（会话 sid）被剔除，action 基数不随请求膨胀', () => {
      const sidA = '550e8400-e29b-41d4-a716-446655440000';
      const sidB = 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6';
      expect(deriveAction('DELETE', `/api/auth/sessions/${sidA}`, 'auth')).toBe('auth_sessions');
      // 不同 sid 必须派生出同一个 action —— 这正是「基数不膨胀」的含义
      expect(deriveAction('DELETE', `/api/auth/sessions/${sidB}`, 'auth')).toBe('auth_sessions');
      expect(deriveAction('DELETE', `/api/auth/sessions/${sidA}`, 'auth')).not.toContain(sidA);
    });

    test('大写形式的 UUID 同样被剔除（Mongo 存储与客户端大小写不保证一致）', () => {
      const upper = '550E8400-E29B-41D4-A716-446655440000';
      expect(deriveAction('DELETE', `/api/auth/sessions/${upper}`, 'auth')).toBe('auth_sessions');
    });

    test('固定字面量段不被误剔除：/sessions/others 保留 others', () => {
      // others 与 :sid 是两条不同路由，action 必须可区分，
      // 否则「退出其他设备」与「踢除单台设备」在审计里无法分辨
      expect(deriveAction('DELETE', '/api/auth/sessions/others', 'auth')).toBe(
        'auth_sessions_others'
      );
    });

    test('isDynamicSegment 只认三种动态形状，不误伤业务段', () => {
      expect(isDynamicSegment(OID)).toBe(true);
      expect(isDynamicSegment('123')).toBe(true);
      expect(isDynamicSegment('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
      // 业务字面量与配置键必须保留，否则 action 丢失语义
      expect(isDynamicSegment('others')).toBe(false);
      expect(isDynamicSegment('sessions')).toBe(false);
      expect(isDynamicSegment('loginCaptchaEnabled')).toBe(false);
      // 形状相近但不是 UUID（少一段）不应被剔除
      expect(isDynamicSegment('550e8400-e29b-41d4-a716')).toBe(false);
    });

    test('多级子路径用下划线连接', () => {
      expect(deriveAction('PUT', '/api/security/config/loginCaptchaEnabled', 'security')).toBe(
        'security_config_loginCaptchaEnabled'
      );
      expect(deriveAction('PUT', `/api/security/users/${OID}/lock`, 'security')).toBe(
        'security_users_lock'
      );
    });

    test('保留原始连字符（与白名单/i18n 键一致）', () => {
      expect(deriveAction('PUT', `/api/alarms/${OID}/false-alarm`, 'alarm')).toBe(
        'alarm_false-alarm'
      );
      expect(deriveAction('POST', '/api/security/ip-list', 'security')).toBe('security_ip-list');
    });
  });

  describe('deriveAuditMeta 端到端', () => {
    const cases = [
      ['POST', '/api/auth/login', 'auth', 'auth_login'],
      ['POST', '/api/auth/register', 'auth', 'auth_register'],
      ['PUT', '/api/auth/password', 'auth', 'auth_password'],
      ['POST', '/api/users', 'user', 'user_create'],
      ['DELETE', '/api/users/batch', 'user', 'user_batch'],
      ['PUT', `/api/users/${OID}/roles`, 'user', 'user_roles'],
      ['PUT', `/api/roles/${OID}/permissions`, 'role', 'role_permissions'],
      ['POST', '/api/permissions/batch', 'permission', 'permission_batch'],
      ['PUT', `/api/devices/${OID}/scrap`, 'device', 'device_scrap'],
      ['PUT', `/api/alarms/${OID}/resolve`, 'alarm', 'alarm_resolve'],
      ['PUT', `/api/inspections/${OID}/review`, 'inspection', 'inspection_review'],
      ['DELETE', `/api/security/ip-list/${OID}`, 'security', 'security_ip-list'],
    ];

    test.each(cases)('%s %s → %s / %s', (method, originalUrl, category, action) => {
      // 模拟 Express 剥离后的 req.path，验证派生不受其影响
      const req = { method, originalUrl, path: '/stripped' };
      expect(deriveAuditMeta(req)).toEqual({ path: originalUrl, category, action });
    });

    test('所有派生结果的 category 均在模型 enum 内', () => {
      for (const [method, originalUrl] of cases) {
        const { category } = deriveAuditMeta({ method, originalUrl });
        expect(CATEGORY_ENUM).toContain(category);
      }
    });

    test('带查询串时 path 已去参、action 不受影响', () => {
      const req = { method: 'DELETE', originalUrl: `/api/users/${OID}?force=true` };
      expect(deriveAuditMeta(req)).toEqual({
        path: `/api/users/${OID}`,
        category: 'user',
        action: 'user_delete',
      });
    });
  });

  // P3-11 回归：AUDIT_LOG_ACTIONS 白名单曾滞后于路由——记录在库里、
  // 审计页却筛不出来（validateEnum 打 400）。此用例把「路由可派生出的一切
  // action」与「审计筛选白名单」做交叉核对，新增路由而忘补白名单时立即失败。
  describe('AUDIT_LOG_ACTIONS 与路由派生 action 对齐（P3-11）', () => {
    // 从各路由文件静态提取路径模式，模拟 deriveAction 的清洗规则生成候选 action。
    // 静态提取而非逐个手写：保证未来新增路由自动纳入比对范围。
    const fs = require('fs');
    const path = require('path');

    const ROUTE_FILES = [
      'authRoutes.js',
      'userRoutes.js',
      'roleRoutes.js',
      'permissionRoutes.js',
      'deviceRoutes.js',
      'alarmRoutes.js',
      'inspectionRoutes.js',
      'reportRoutes.js',
      'securityRoutes.js',
    ];

    const collectActions = () => {
      const actions = new Set();
      const methods = ['get', 'post', 'put', 'delete', 'patch'];
      for (const file of ROUTE_FILES) {
        const src = fs.readFileSync(path.join(__dirname, '../../routes', file), 'utf8');
        // 匹配 router.get(\n  '/xxx' 与 router.get('/xxx' 两种写法
        const routeRe = /router\.(get|post|put|delete|patch)\(\s*\n?\s*'([^']+)'/g;
        let m;
        while ((m = routeRe.exec(src)) !== null) {
          const [, method, routePath] = m;
          if (!methods.includes(method)) continue;
          // 挂载前缀（与 app.js 一致）
          const prefix = `api/${file.replace('Routes.js', '').replace('security', 'security')}`;
          const full = `/${prefix}${routePath === '/' ? '' : routePath}`;
          // 复刻 deriveAction 清洗：剔除运行期取值为动态标识的段
          // （:id / :userId 为 ObjectId，:sid 为会话 UUID）。
          // :key 之类「参数名即语义」的段不剔除——它们的取值是有限枚举，
          // 会正常进入 action（如 security_config_loginCaptchaEnabled）
          const segments = full.split('/').filter(Boolean);
          const cleaned = segments.filter((s) => !/^\d+$/.test(s) && !/^:(id|userId|sid)$/.test(s));
          const subAction = cleaned.slice(2).join('_');
          const category = cleaned[1] || 'system';
          if (subAction) {
            actions.add(`${category}_${subAction}`);
          } else if (method === 'get') actions.add(`${category}_view`);
          else if (method === 'post') actions.add(`${category}_create`);
          else if (method === 'delete') actions.add(`${category}_delete`);
          else actions.add(`${category}_update`);
        }
      }
      return actions;
    };

    test('全部路由派生型 action 均在 AUDIT_LOG_ACTIONS 白名单内', () => {
      const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
      const whitelist = new Set(AUDIT_LOG_ACTIONS);
      const missing = [...collectActions()].filter((a) => !whitelist.has(a));
      expect(missing).toEqual([]);
    });

    test('排除路径（登录/刷新）不要求进白名单', () => {
      const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
      // auth_login/auth_refresh 由 authController 写专用事件型审计，
      // 全局中间件 excludePaths 排除，白名单中不需要
      expect(AUDIT_LOG_ACTIONS).toContain('login_success');
    });
  });
});
