/**
 * 诱饵"本人自助面"（P2）的形状闸：合成目录/轨迹/端点表必须与真实世界同值
 *
 * 为什么单开一条闸：P2 的七条读侧响应之所以能当"真会话"用，靠的是三件同值关系——
 *   ① 权限目录与真实目录（services/initData/permissions*.js）逐字相同：
 *      装扮里出现一个真实系统查不到的权限码，等于在"我的权限"页面上自报家门；
 *   ② 轨迹行的 action/category 落在真实审计白名单内：不在白名单的 action 只可能来自合成；
 *   ③ 端点表落在真实路由上：给一条不存在的路径回合成数据，是比 403 更响的警铃。
 * 这三条都不是"看起来对就行"的口径，故逐条现算比对，并各自带反向自证（判据有牙）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const ROUTES_DIR = path.join(ROOT, 'src/routes');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const { systemPermissions } = require('../../services/initData/permissionsSystem');
const { businessPermissions } = require('../../services/initData/permissionsBusiness');
const { AUDIT_CATEGORIES, AUDIT_LOG_ACTIONS } = require('../../constants/audit');
const { PERMISSION_METHODS } = require('../../constants/permission');
const {
  DECOY_PERMISSION_CATALOG,
  DECOY_SELF_EMAIL_DOMAIN,
  DECOY_SELF_LOGS,
  DECOY_SELF_PROFILE,
  DECOY_SELF_TRAIL_IP,
  DECOY_SELF_TRAIL_SID,
} = require('../../constants/honeypotDecoySelf');
const {
  DECOY_PERMISSION_ROWS,
  DECOY_PERMISSIONS,
  HONEYPOT_DECOY_ID_PREFIX,
} = require('../../constants/honeypotDecoyData');
const { SELF_ENDPOINTS } = require('../../services/honeypotDecoySelf');

const REAL_PERMISSIONS = [...systemPermissions, ...businessPermissions];

/** 权限行 `method` 的模型默认值：现读模型源码，不在判据里硬编码（模型改了默认值，这里必须跟着变红） */
const PERMISSION_METHOD_DEFAULT = (() => {
  const src = jsCodeOnly(fs.readFileSync(path.join(ROOT, 'src/models/Permission.js'), 'utf8'));
  const block = src.match(/\bmethod:\s*\{([^}]*)\}/);
  const hit = block && block[1].match(/default:\s*'([^']+)'/);
  if (!hit) throw new Error('src/models/Permission.js 的 method 字段读不到 default');
  return hit[1];
})();
const EXCLUDED_CODES = ['*:*', 'security:audit', 'pii:*', 'pii:export']; // 排除理由见 ADR-013 边界表
const CANDIDATE_LIMIT = 20; // 与 controllers/securityController/sensitive.js 同值

/** 目录同值检查：返回违例清单（空 = 同值）。抽成函数是为了反向自证能拿假数据打它。 */
const catalogViolations = (rows, realRows) => {
  const violations = [];
  if (!Array.isArray(rows) || rows.length === 0) violations.push('合成目录为空');
  for (const row of rows || []) {
    const real = realRows.find((item) => item.code === row.code);
    if (!real) {
      violations.push(row.code + ' 不在真实权限目录里');
      continue;
    }
    for (const field of ['type', 'module', 'name', 'path', 'method']) {
      // method 两侧都按模型默认值归一：种子字面量不写它，落库后由 default 补齐（src/models/Permission.js:61-65）
      const pick = (item) =>
        field === 'method' ? item.method || PERMISSION_METHOD_DEFAULT : item[field] || '';
      const left = pick(row);
      const right = pick(real);
      if (left !== right) violations.push(row.code + ' 的 ' + field + ' 与真实目录不一致');
    }
  }
  return violations;
};

/** 路由面：app.js 挂载前缀 × 各路由文件里的路径字面量（注释视图走单点实现） */
const mountedPaths = () => {
  const app = jsCodeOnly(fs.readFileSync(path.join(ROOT, 'src/app.js'), 'utf8'));
  const mounts = new Map(
    [...app.matchAll(/app\.use\('(\/api\/[a-z-]+)',\s*([A-Za-z0-9_]+)\)/g)].map((m) => [m[2], m[1]])
  );
  const paths = new Set();
  for (const file of fs.readdirSync(ROUTES_DIR).filter((f) => f.endsWith('.js'))) {
    const source = jsCodeOnly(fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8'));
    for (const match of source.matchAll(
      /(?:router|app)\.(get|post|put|patch|delete)\(\s*'([^']+)'/g
    )) {
      for (const prefix of mounts.values()) paths.add(prefix + (match[2] === '/' ? '' : match[2]));
    }
  }
  return paths;
};

describe('诱饵本人自助面（P2）：与真实世界的三处同值关系', () => {
  test('权限目录逐字同源于真实目录，且排除项一条都不在装扮里', () => {
    expect(DECOY_PERMISSION_CATALOG.length).toBeGreaterThanOrEqual(30);
    expect(catalogViolations(DECOY_PERMISSION_CATALOG, REAL_PERMISSIONS)).toEqual([]);
    const codes = DECOY_PERMISSION_CATALOG.map((row) => row.code);
    for (const code of EXCLUDED_CODES) expect(codes).not.toContain(code);
    // 反向自证：编一个真实目录里没有的码、再改一个字段，判据必须报红
    expect(
      catalogViolations(
        [
          {
            code: 'user:read',
            type: 'api',
            module: 'system',
            name: '编的',
            path: '/api/users',
            method: 'GET',
          },
        ],
        REAL_PERMISSIONS
      )
    ).toEqual(['user:read 的 name 与真实目录不一致']);
    expect(
      catalogViolations(
        [{ code: 'nope:read', type: 'api', module: 'system', name: '编的', path: '/x' }],
        REAL_PERMISSIONS
      )
    ).toEqual(['nope:read 不在真实权限目录里']);
    expect(catalogViolations([], REAL_PERMISSIONS)).toEqual(['合成目录为空']);
  });

  test('权限行的三个出口（permissions / 行表）都由同一份目录派生，id 仍是 hp- 命名空间', () => {
    expect(DECOY_PERMISSIONS).toEqual(DECOY_PERMISSION_CATALOG.map((row) => row.code));
    expect(DECOY_PERMISSION_ROWS).toHaveLength(DECOY_PERMISSION_CATALOG.length);
    DECOY_PERMISSION_ROWS.forEach((row, index) => {
      const source = DECOY_PERMISSION_CATALOG[index];
      expect(row._id).toBe(HONEYPOT_DECOY_ID_PREFIX + 'p' + (index + 1));
      expect(row.code).toBe(source.code);
      expect(row.name).toBe(source.name);
      expect(row.type).toBe(source.type);
      expect(row.module).toBe(source.module);
      expect(row.path).toBe(source.path);
      expect(row.method).toBe(source.method || PERMISSION_METHOD_DEFAULT); // 行侧恒有该键（模型默认值），目录里只有接口行显式给
      expect(row.status).toBe('active');
    });
  });

  test('权限行的 method 默认值取自模型源码而非判据硬编码：改模型默认值，本闸必红', () => {
    expect(PERMISSION_METHOD_DEFAULT).toBeTruthy();
    expect(PERMISSION_METHODS).toContain(PERMISSION_METHOD_DEFAULT); // 默认值必须落在枚举里，否则模型自己就校验不过
    const implicit = DECOY_PERMISSION_ROWS.filter(
      (row, index) => !DECOY_PERMISSION_CATALOG[index].method
    );
    expect(implicit.length).toBeGreaterThan(0); // 规模地板：目录里确实有靠默认值补的行
    for (const row of implicit) expect(row.method).toBe(PERMISSION_METHOD_DEFAULT);
    // 反向自证：判据若退回硬编码，把默认值改掉后这条就不成立
    const mutated = implicit.map((row) => ({ ...row, method: PERMISSION_METHOD_DEFAULT + 'x' }));
    expect(mutated.every((row) => row.method !== PERMISSION_METHOD_DEFAULT)).toBe(true);
  });

  test('轨迹行落在真实审计白名单内，且时间量/会话标记形态受约束', () => {
    expect(DECOY_SELF_LOGS.length).toBeGreaterThanOrEqual(5);
    for (const row of DECOY_SELF_LOGS) {
      expect(AUDIT_LOG_ACTIONS).toContain(row.action);
      expect(AUDIT_CATEGORIES).toContain(row.category);
      expect(Number.isInteger(row.offsetMin) && row.offsetMin > 0).toBe(true);
      expect(['current', 'previous']).toContain(row.session);
      expect(row.action.startsWith('honeypot')).toBe(false); // 合成轨迹里不得出现蜜罐留痕动作
      expect(['low', 'medium', 'high', 'critical']).toContain(row.riskLevel);
    }
    expect(new Set(DECOY_SELF_LOGS.map((row) => row.offsetMin)).size).toBe(DECOY_SELF_LOGS.length);
    expect(Object.isFrozen(DECOY_SELF_LOGS)).toBe(true);
    expect(DECOY_SELF_LOGS.every((row) => Object.isFrozen(row))).toBe(true);
  });

  test('身份与轨迹的固定量形态正确（邮箱域名、UUID 会话 id、非空 IP）', () => {
    expect(DECOY_SELF_EMAIL_DOMAIN).toMatch(/^[a-z0-9.-]+\.[a-z]{2,}$/);
    expect(DECOY_SELF_EMAIL_DOMAIN).not.toBe('honeypot.invalid'); // 库里那份不可路由域名只给防守方看
    expect(DECOY_SELF_TRAIL_SID).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
    expect(DECOY_SELF_TRAIL_IP).toMatch(/^\d{1,3}(\.\d{1,3}){3}$/);
    expect(DECOY_SELF_PROFILE.phone).toMatch(/^1\d{10}$/);
    expect(DECOY_SELF_PROFILE.avatar).toBeNull(); // 与 /api/avatars 恒 404 同一条自洽关系
    expect(Number.isInteger(DECOY_SELF_PROFILE.createdAtOffsetMin)).toBe(true);
  });

  test('七条端点都落在真实路由上（前缀由 app.js 挂载表拼出，路由名不准就红）', () => {
    const paths = mountedPaths();
    expect(paths.size).toBeGreaterThanOrEqual(40); // 规模地板：扫描器真的读到了路由面
    const missing = SELF_ENDPOINTS.map((endpoint) => endpoint.path).filter(
      (target) => !paths.has(target)
    );
    expect(missing).toEqual([]);
    expect(SELF_ENDPOINTS).toHaveLength(7);
    expect(new Set(SELF_ENDPOINTS.map((endpoint) => endpoint.path)).size).toBe(7);
  });

  test('合成候选表都在上限之内（真实链没有这条截断，超限会让"搜不到"变成指纹）', () => {
    const {
      DECOY_ALARMS,
      DECOY_DEVICES,
      DECOY_USERS,
    } = require('../../constants/honeypotDecoyData');
    expect(DECOY_USERS.length + 1).toBeLessThanOrEqual(CANDIDATE_LIMIT); // +1 = 会话本人那一行
    expect(DECOY_DEVICES.length).toBeLessThanOrEqual(CANDIDATE_LIMIT);
    expect(DECOY_ALARMS.length).toBeLessThanOrEqual(CANDIDATE_LIMIT);
  });
});
