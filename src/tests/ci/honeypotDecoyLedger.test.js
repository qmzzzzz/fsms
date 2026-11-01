/**
 * 蜜罐影子数据面的接线台账（P1）
 *
 * 为什么值得一个门禁：P1 的安全性来自**一个接线点**——`authenticate` 里那句 `steer(...)` 把所有
 * 诱饵会话的请求从真实控制器前改道。这条性质不靠「每个路由自觉」，靠的是**判定表覆盖面**：
 * 只要 `src/app.js` 挂了一个新的 `/api/xxx` 前缀，而判定表既没给它合成数据面、又没登记
 * 「这不是数据面」，那这个前缀就可能让攻击者从陷阱会话里读到真实内容。
 *
 * 台账形状：
 *  - 合成数据面集合（constants/honeypotDecoy.js 的 DECOY_COLLECTIONS）↔ app.js 实际挂载前缀，双向对齐：
 *    少一个 = 有前缀没数据面（本闸红）；多一个 = 有数据面没挂载（僵尸表，也红）；
 *  - 不承接数据面的前缀必须逐条登记并写明理由；
 *  - 写方法在任何前缀上都不许落进数据面，只允许落进逐条钉死的放行白名单。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const ROOT = path.resolve(__dirname, '../../..');
const APP_SRC = fs.readFileSync(path.join(ROOT, 'src/app.js'), 'utf8');
const {
  DECOY_COLLECTIONS,
  DECOY_TABLES,
  DECOY_USERS,
  HONEYPOT_DECOY_ID_PREFIX,
  HONEYPOT_VERDICT,
  PASSTHROUGH_ROUTES,
  WRITE_METHODS,
  resolveDecoyVerdict,
} = require('../../constants/honeypotDecoy');
const { FILE_ENDPOINTS } = require('../../constants/honeypotDecoyFiles');
const { matchRoute } = require('../../constants/honeypotRouteTable');
const { resolveFileResponse } = require('../../services/honeypotDecoyFiles');

const MOUNT_RE = /app\.use\('(\/api\/[a-z-]+)'/g;
const MOUNTED_PREFIXES = [...APP_SRC.matchAll(MOUNT_RE)]
  .map((m) => m[1])
  .filter((p) => p !== '/api/');

/** 承接业务数据、因此必须有合成数据面的例外清单：登记式，新增必须表态 */
const NON_DATA_MOUNTS = [
  { prefix: '/api/auth', why: '会话自身的登录/续期/登出/改密：不读业务集合；并进白名单逐条放行' },
  {
    prefix: '/api/avatars',
    why: '头像二进制：GET/HEAD 一律 404「尚未设置头像」（诱饵不产出任何真实字节，见 services/honeypotDecoyFiles.js），写方法恒拒',
  },
  { prefix: '/api/version', why: '构建版本号，公开信息，放行' },
];
const NON_DATA_SET = new Set(NON_DATA_MOUNTS.map((x) => x.prefix));
const DECOY_PREFIX_SET = new Set(DECOY_COLLECTIONS.map((c) => c.prefix));
const SANCTIONED_PASSTHROUGH = [
  'GET /api/version',
  'POST /api/auth/logout',
  'POST /api/auth/refresh',
];
/**
 * 写方法的判决只有两支，两支都与真实链同码：**声明过的写路由** ⇒ 403（真实链零角色 ⇒ RBAC 拒绝，
 * 用的是同一个 codeError 构造器）；**表里没有这个路径** ⇒ 404（真实链落 app.js 兜底 404）。
 * 两支都不进数据面——「写方法绝不落进诱饵数据」这条不变式由「不许 DECOY / PASSTHROUGH」守住。
 */
const ALLOWED_WRITE_VERDICTS = [HONEYPOT_VERDICT.DENY, HONEYPOT_VERDICT.NOT_FOUND];

describe('蜜罐影子数据面台账：app.js 挂载面必须逐条表态', () => {
  test('前提自证：挂载前缀与数据面集合都非空，且台账例外逐条写了理由', () => {
    expect(MOUNTED_PREFIXES.length).toBeGreaterThanOrEqual(8);
    expect(DECOY_COLLECTIONS.length).toBeGreaterThanOrEqual(5);
    expect(NON_DATA_MOUNTS.every((x) => x.why && x.why.length > 8)).toBe(true);
    // 反证：正则确实在筛（不匹配任何东西时必须为空）
    expect([...APP_SRC.matchAll(/app\.use\('(\/definitely-not-there)'/g)]).toHaveLength(0);
  });

  test('覆盖性：每个挂载前缀要么有合成数据面、要么在例外清单里（新增挂载必须表态）', () => {
    const uncovered = MOUNTED_PREFIXES.filter(
      (prefix) => !DECOY_PREFIX_SET.has(prefix) && !NON_DATA_SET.has(prefix)
    );
    expect(uncovered).toEqual([]);
  });

  test('双向：合成数据面的每个前缀都必须在 app.js 真的挂着（禁止僵尸表）', () => {
    const zombies = DECOY_COLLECTIONS.map((c) => c.prefix).filter(
      (prefix) => !MOUNTED_PREFIXES.includes(prefix)
    );
    expect(zombies).toEqual([]);
  });

  test('写方法在任何挂载前缀上都不落进数据面：要么 403、要么路由不存在 404、要么放行白名单', () => {
    const violations = [];
    for (const prefix of MOUNTED_PREFIXES) {
      for (const method of WRITE_METHODS) {
        const verdict = resolveDecoyVerdict({ method, path: prefix });
        const sanctioned = SANCTIONED_PASSTHROUGH.includes(method + ' ' + prefix);
        const ok = sanctioned
          ? verdict === HONEYPOT_VERDICT.PASSTHROUGH
          : ALLOWED_WRITE_VERDICTS.includes(verdict);
        if (!ok) violations.push(method + ' ' + prefix + ' => ' + verdict);
      }
    }
    expect(violations).toEqual([]);
    // 有牙的定点：POST /api/users 在表里 ⇒ 403；PUT /api/users 不在表里 ⇒ 404（不再是 403）
    expect(resolveDecoyVerdict({ method: 'POST', path: '/api/users' })).toBe(HONEYPOT_VERDICT.DENY);
    expect(resolveDecoyVerdict({ method: 'PUT', path: '/api/users' })).toBe(
      HONEYPOT_VERDICT.NOT_FOUND
    );
    // 业务前缀上的写方法：声明过的写路由一律 403，未声明的一律 404（放行白名单只允许挂在 /api/auth 上）
    for (const collection of DECOY_COLLECTIONS) {
      for (const method of WRITE_METHODS) {
        const declared = matchRoute({ method, path: collection.prefix });
        expect(resolveDecoyVerdict({ method, path: collection.prefix })).toBe(
          declared ? HONEYPOT_VERDICT.DENY : HONEYPOT_VERDICT.NOT_FOUND
        );
      }
    }
  });

  test('放行白名单逐条钉死：多一条少一条都红（放行即等于把真实处理器接到陷阱会话上）', () => {
    expect(PASSTHROUGH_ROUTES.map((r) => r.method + ' ' + r.path).sort()).toEqual(
      [...SANCTIONED_PASSTHROUGH].sort()
    );
    for (const route of PASSTHROUGH_ROUTES) {
      const covered = NON_DATA_MOUNTS.some(
        (x) => x.prefix === route.path || route.path.startsWith(x.prefix + '/')
      );
      expect(covered).toBe(true);
    }
  });

  test('合成数据的 id 命名空间与真实集不相交：撞号即等于读到真记录', () => {
    const rows = Object.values(DECOY_TABLES).flat();
    expect(rows.length).toBeGreaterThanOrEqual(15);
    for (const row of rows) {
      expect(row._id.startsWith(HONEYPOT_DECOY_ID_PREFIX)).toBe(true);
      expect(mongoose.isValidObjectId(row._id)).toBe(false);
      expect(Object.isFrozen(row)).toBe(true);
    }
    expect(DECOY_USERS.some((u) => u.username === 'admin')).toBe(false);
  });
});

describe('文件/导出类端点台账（P1c）：注册表、形态与"写方法永不出文件"', () => {
  const SANCTIONED_FILE_ENDPOINTS = [
    'audit-logs-export',
    'avatars',
    'reports-export',
    'reports-export-pii',
  ];
  const SAMPLE_PATH = {
    'reports-export': '/api/reports/export',
    'reports-export-pii': '/api/reports/export/pii',
    'audit-logs-export': '/api/security/audit-logs/export',
    avatars: '/api/avatars/hp-u1',
  };

  test('注册表逐条钉死：新增/删改文件类端点必须同时改这里与 services/honeypotDecoyFiles.js', () => {
    expect(FILE_ENDPOINTS.map((e) => e.id).sort()).toEqual(SANCTIONED_FILE_ENDPOINTS);
    for (const endpoint of FILE_ENDPOINTS) {
      expect(endpoint.methods.length).toBeGreaterThan(0);
      expect(SAMPLE_PATH[endpoint.id]).toBeTruthy();
    }
  });

  test('注册表路径必须落在已挂载前缀内（拼错前缀的症状是"诱饵永不可达"，静默无感）', () => {
    const uncovered = FILE_ENDPOINTS.filter(
      (e) => !MOUNTED_PREFIXES.some((p) => e.path === p || e.path.startsWith(p + '/'))
    ).map((e) => e.id);
    expect(uncovered).toEqual([]);
  });

  test('只读形态：报表导出给合成文件，审计导出/头像逐字拒绝，且没有一个落进放行白名单', () => {
    expect(
      resolveFileResponse({ method: 'GET', path: '/api/reports/export', query: {} })
    ).toMatchObject({
      kind: 'workbook',
      type: 'alarms',
      verdict: HONEYPOT_VERDICT.DECOY,
      write: false,
    });
    expect(
      resolveFileResponse({ method: 'HEAD', path: '/api/reports/export', query: {} })
    ).toMatchObject({ kind: 'workbook', head: true });
    expect(
      resolveFileResponse({ method: 'GET', path: '/api/security/audit-logs/export', query: {} })
    ).toMatchObject({ kind: 'codeError', code: 'PERMISSION_DENIED', write: false });
    expect(
      resolveFileResponse({ method: 'GET', path: '/api/avatars/hp-u1', query: {} })
    ).toMatchObject({
      kind: 'codeError',
      code: 'AVATAR_NOT_FOUND',
      options: { statusCode: 404 },
    });
    for (const endpoint of FILE_ENDPOINTS) {
      for (const method of endpoint.methods) {
        expect(resolveDecoyVerdict({ method, path: SAMPLE_PATH[endpoint.id] })).not.toBe(
          HONEYPOT_VERDICT.PASSTHROUGH
        );
      }
    }
  });

  test('参数/权限拒绝复用真实判据：格式/时区/日期/审计权限/类型各一条', () => {
    const at = (query) =>
      resolveFileResponse({ method: 'GET', path: '/api/reports/export', query });
    expect(at({ format: 'csv' })).toMatchObject({ kind: 'formatUnsupported', format: 'csv' }); // 文案由发送端内联（占位符码）
    expect(at({ tz: 'Not/AZone' })).toMatchObject({
      kind: 'plainError',
      message: '时区参数无效',
      statusCode: 400,
    });
    expect(at({ startDate: 'abc' })).toMatchObject({ code: 'DATE_PARAM_INVALID' });
    expect(at({ startDate: '-1' })).toMatchObject({ code: 'DATE_PARAM_INVALID' }); // 数字形态串：与真实链同一个 isValidDateParam
    expect(at({ startDate: '2026-10-02', endDate: '2026-10-01' })).toMatchObject({
      code: 'DATE_RANGE_INVALID',
    });
    expect(at({ type: 'audit' })).toMatchObject({ code: 'AUDIT_EXPORT_REQUIRES_AUDIT_PERM' });
    expect(at({ type: 'none' })).toMatchObject({ code: 'REPORT_TYPE_UNSUPPORTED' });
    expect(at({ type: '' })).toMatchObject({ code: 'REPORT_TYPE_UNSUPPORTED' });
  });

  test('写方法在文件类端点上永远拿不到文件：要么逐字拒绝（带 write 标记），要么落回通用 DENY', () => {
    const violations = [];
    for (const endpoint of FILE_ENDPOINTS) {
      for (const method of WRITE_METHODS) {
        const response = resolveFileResponse({ method, path: SAMPLE_PATH[endpoint.id], query: {} });
        if (response) {
          if (response.kind !== 'codeError' || response.write !== true) {
            violations.push(method + ' ' + SAMPLE_PATH[endpoint.id] + ' => ' + response.kind);
          }
        } else {
          // 文件面不认这次写：判决必须落在「403（已声明写路由）」或「404（路径不存在）」，
          // 两者都与真实链同码，且都出不了文件
          const verdict = resolveDecoyVerdict({ method, path: SAMPLE_PATH[endpoint.id] });
          if (!ALLOWED_WRITE_VERDICTS.includes(verdict)) {
            violations.push(method + ' ' + SAMPLE_PATH[endpoint.id] + ' => ' + verdict);
          }
        }
      }
    }
    expect(violations).toEqual([]);
    // 未脱敏导出（真实链的"未脱敏"腿）尤其不许出文件：两种类型都只能拿到拒绝
    for (const type of ['alarms', 'devices']) {
      expect(
        resolveFileResponse({ method: 'POST', path: '/api/reports/export/pii', query: { type } })
          .kind
      ).toBe('codeError');
    }
  });
});
