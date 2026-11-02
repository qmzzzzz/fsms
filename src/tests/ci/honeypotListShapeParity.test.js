'use strict';

/**
 * 六个列表端点：合成面与真实链的**契约对账**（批次 D）
 *
 * 为什么要有这份：E2 的拒绝路径是「照真实路由的校验链现取一份」，抄本不会被自动同步——
 * 两份规则一旦分叉，攻击者一次请求就能分辨（真实链 400「页码无效」vs 合成面 200）。
 * 所以这里不比对「我写在表里的值」，而是：
 *  1) 从路由源码里**括配对现取** listQueryValidation 那条链，在真的 express-validator
 *     query() 上跑，用 safeFieldErrors 的出站形态与合成面的拒绝体逐条对账；
 *  2) 规则表（字段序/文案/校验器/optional 形态/枚举来源/min-max）另做静态对账；
 *  3) 信封（message / 默认 limit / 上限 / nextCursor 位 / 排序键）与投影键集**全部从源码现推**，
 *     判据里不写手抄的 10、100、'获取设备列表成功'、字段清单这类字面量。
 * 反向对照见最后一组：改坏一条文案、多下发一个键、少下发一个键都必须被同一套判据抓红。
 */

jest.setTimeout(120000);

const fs = require('fs');
const path = require('path');
const { createRequire } = require('module');
const { query, validationResult } = require('express-validator');

const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const { safeFieldErrors } = require('../../utils/validationRules');
const ApiResponse = require('../../utils/apiResponse');
const honeypotWatch = require('../../services/honeypotWatch');
const honeypotDecoy = require('../../services/honeypotDecoy');
const decoy = require('../../constants/honeypotDecoy');
const shape = require('../../constants/honeypotDecoyListShape');
const listQuery = require('../../constants/honeypotDecoyListQuery');
const { ALARM_STATUSES } = require('../../constants/alarm');

const BT = String.fromCharCode(96);
const ROOT = path.join(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const codeOf = (rel) => jsCodeOnly(read(rel));
const requireFrom = (rel, spec) => createRequire(path.join(ROOT, rel))(spec);

const ENDPOINTS = [
  {
    key: 'users',
    path: '/api/users',
    route: 'src/routes/userRoutes.js',
    controller: 'src/controllers/userController/read.js',
    service: 'src/services/userService.js',
    model: 'src/models/User.js',
    modelRel: '../../models/User',
  },
  {
    key: 'roles',
    path: '/api/roles',
    route: 'src/routes/roleRoutes.js',
    controller: 'src/controllers/roleController.js',
    service: 'src/services/roleService.js',
    model: 'src/models/Role.js',
    modelRel: '../../models/Role',
  },
  {
    key: 'permissions',
    path: '/api/permissions',
    route: 'src/routes/permissionRoutes.js',
    controller: 'src/controllers/permissionController.js',
    service: 'src/services/permissionService.js',
    model: 'src/models/Permission.js',
    modelRel: '../../models/Permission',
  },
  {
    key: 'devices',
    path: '/api/devices',
    route: 'src/routes/deviceRoutes.js',
    controller: 'src/controllers/deviceController.js',
    service: 'src/services/DeviceService.js',
    model: 'src/models/FireDevice.js',
    modelRel: '../../models/FireDevice',
  },
  {
    key: 'alarms',
    path: '/api/alarms',
    route: 'src/routes/alarmRoutes.js',
    controller: 'src/controllers/alarmController.js',
    service: 'src/services/AlarmService.js',
    model: 'src/models/FireAlarm.js',
    modelRel: '../../models/FireAlarm',
  },
  {
    key: 'inspections',
    path: '/api/inspections',
    route: 'src/routes/inspectionRoutes.js',
    controller: 'src/controllers/inspectionController.js',
    service: 'src/services/InspectionService.js',
    model: 'src/models/Inspection.js',
    modelRel: '../../models/Inspection',
  },
];
const ENDPOINT_BY_KEY = Object.fromEntries(ENDPOINTS.map((e) => [e.key, e]));
const tableOf = (key) => shape.LIST_ENDPOINTS_BY_KEY[key];

/** 源码视图上的括配对：方括号（校验链数组）与圆括号（分页调用实参表）都走同一段机器。 */
const matchedBlock = (code, startIdx, open, close) => {
  let depth = 0;
  let quote = null;
  for (let i = startIdx; i < code.length; i += 1) {
    const ch = code[i];
    if (quote) {
      if (ch === '\\') i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === BT) quote = ch;
    else if (ch === open) depth += 1;
    else if (ch === close) {
      depth -= 1;
      if (depth === 0) return code.slice(startIdx, i + 1);
    }
  }
  throw new Error('括配对失败：' + open + ' ' + close);
};

const listQueryBlockOf = (rel) => {
  const code = codeOf(rel);
  const at = code.indexOf('listQueryValidation = [');
  if (at < 0) throw new Error('未找到 listQueryValidation：' + rel);
  return matchedBlock(code, code.indexOf('[', at), '[', ']');
};

/** 路由自己的 require 作用域：枚举对象的来源必须是该路由真的 import 的那一份。 */
const requireScopeOf = (rel) => {
  const scope = {};
  for (const m of codeOf(rel).matchAll(/const\s*\{([^}]+)\}\s*=\s*require\('([^']+)'\)/g)) {
    for (const raw of m[1].split(',')) {
      const name = raw.trim().split(':').pop().trim();
      if (name) scope[name] = requireFrom(rel, m[2])[name];
    }
  }
  return scope;
};
/** 动态求值只用于「在路由自己的作用域里求它自己写的那个表达式」，不是评测任意代码。 */
const evalInScope = (rel, expr) => {
  const scope = requireScopeOf(rel);
  const names = Object.keys(scope).filter((n) => n !== 'query');
  // eslint-disable-next-line no-new-func
  return new Function(...names, 'return (' + expr + ');')(...names.map((n) => scope[n]));
};
const chainsOf = (rel) => {
  const scope = requireScopeOf(rel);
  const names = Object.keys(scope).filter((n) => n !== 'query');
  const block = listQueryBlockOf(rel);
  // eslint-disable-next-line no-new-func
  return new Function('query', ...names, 'return ' + block + ';')(
    query,
    ...names.map((n) => scope[n])
  );
};
const realErrorsOf = async (rel, q) => {
  const req = { query: { ...q }, body: {}, params: {}, headers: {} };
  for (const chain of chainsOf(rel)) await chain.run(req);
  return safeFieldErrors(validationResult(req));
};

const KINDS = [
  ['isIn', 'in'],
  ['isInt', 'int'],
  ['isLength', 'length'],
  ['isMongoId', 'mongoId'],
  ['isISO8601', 'iso8601'],
];
const descriptorsOf = (block) =>
  block
    .split(/\bquery\(/)
    .slice(1)
    .map((chunk) => {
      const intOpts = /\.isInt\(\{([^}]*)\}\)/.exec(chunk);
      const lengthOpts = /\.isLength\(\{([^}]*)\}\)/.exec(chunk);
      const isIn = /\.isIn\((.+)\)\s*\.withMessage/.exec(chunk);
      return {
        field: /^'([^']+)'/.exec(chunk)[1],
        kind: KINDS.find((pair) => chunk.includes('.' + pair[0] + '('))[1],
        msg: /withMessage\('([^']*)'\)/.exec(chunk)[1],
        optional: /optional\(\{\s*values:\s*'falsy'\s*\}\)/.test(chunk) ? 'falsy' : 'undefined',
        isInExpr: isIn ? isIn[1] : null,
        min: intOpts ? Number(/min:\s*(\d+)/.exec(intOpts[1])[1]) : undefined,
        max:
          intOpts && /max:\s*(\d+)/.test(intOpts[1])
            ? Number(/max:\s*(\d+)/.exec(intOpts[1])[1])
            : lengthOpts
              ? Number(/max:\s*(\d+)/.exec(lengthOpts[1])[1])
              : undefined,
      };
    });

const PROBES = {
  status: ['', 'active', 'inactive', 'processing', 'pending', 'resolved', 'nope', '0'],
  page: ['', '0', '1', '2', '-1', '1.0', '01', '1e3', ' 2', 'abc'],
  limit: ['', '0', '1', '10', '100', '101', '-5', '007', 'abc'],
  department: ['', '维保部', 'x'.repeat(100), 'x'.repeat(101), '  ', ' 中控室 '],
  role: ['', 'DUTY', 'y'.repeat(50), 'y'.repeat(51), ' '],
  type: ['', 'menu', 'button', 'api', 'data', 'nope'],
  module: ['', 'device', 'z'.repeat(50), 'z'.repeat(51)],
  deviceType: ['', 'smoke_detector', 'heat_detector', 'nope'],
  building: ['', 'A1', 'w'.repeat(100), 'w'.repeat(101)],
  floor: ['', '1', 'v'.repeat(101)],
  level: ['', 'info', 'warning', 'critical', 'emergency', 'nope'],
  alarmType: ['', 'smoke', 'other', 'nope'],
  inspectionType: ['', 'daily', 'special', 'nope'],
  assignedTo: ['', '507f1f77bcf86cd799439011', 'hp-u1', '507f1f77bcf86cd79943901', 'zz'],
  startDate: [
    '',
    '2026-03-10',
    '2026-03-10T10:00:00Z',
    '2026-04-31',
    '20260310',
    '2026',
    '2026-03',
    'abc',
    '2026-13-45',
    '2026-3-10',
    '26-03-10',
    ' 2026-03-10 ',
  ],
  endDate: ['', '2026-03-10', 'abc', '2026-13-45', '20260801'],
};
const casesOf = (fields) => {
  const cases = [{}];
  for (const field of fields) for (const value of PROBES[field]) cases.push({ [field]: value });
  return cases.concat([{ status: 'nope', page: 'x', limit: '999' }]);
};

const decoyFieldErrors = (key, q) => {
  const got = listQuery.listQueryRejection(key, q);
  return got && got.code === 'VALIDATION_FAILED' ? got.fieldErrors : [];
};
const payloadOf = (key, q) =>
  decoy.resolveDecoyPayload({ path: tableOf(key).path, query: q || {} });

const splitTopLevel = (src) => {
  const parts = [];
  let depth = 0;
  let quote = null;
  let cur = '';
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (quote) {
      cur += ch;
      if (ch === '\\') {
        cur += src[i + 1];
        i += 1;
      } else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === BT) {
      quote = ch;
      cur += ch;
      continue;
    }
    if ('([{'.includes(ch)) depth += 1;
    if (')]}'.includes(ch)) depth -= 1;
    if (ch === ',' && depth === 0) {
      parts.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
};

/** 控制器里每个 ApiResponse.paginated 调用的第三/第四实参：分页字面量的键、与它逐字给出的 message。 */
const paginatedCallsOf = (rel) => {
  const code = codeOf(rel);
  const out = [];
  let idx = code.indexOf('ApiResponse.paginated(');
  while (idx >= 0) {
    const paren = idx + 'ApiResponse.paginated'.length;
    const inner = matchedBlock(code, paren, '(', ')').slice(1, -1);
    const args = splitTopLevel(inner);
    const pagination = args[2] || '';
    const messageArg = (args[3] || '').trim();
    out.push({
      line: code.slice(0, idx).split('\n').length,
      keys: [
        ...new Set(
          [...pagination.matchAll(/\b(page|limit|total|totalPages|nextCursor|hasMore)\b/g)].map(
            (m) => m[1]
          )
        ),
      ],
      message: /^'([^']*)'$/.test(messageArg) ? messageArg.slice(1, -1) : null,
    });
    idx = code.indexOf('ApiResponse.paginated(', paren);
  }
  return out;
};
/** 列表分支的分页键序：挑那条带 totalPages 且不带 hasMore 的调用（游标分支才带 hasMore）。 */
const listPaginationShapeOf = (rel) => {
  const calls = paginatedCallsOf(rel).filter(
    (c) => c.keys.includes('totalPages') && !c.keys.includes('hasMore')
  );
  if (!calls.length) throw new Error('未找到列表分页调用：' + rel);
  return {
    keys: calls[0].keys,
    messages: [...new Set(calls.map((c) => c.message).filter(Boolean))],
  };
};
const destructuredLimitsOf = (rel) =>
  [...codeOf(rel).matchAll(/\{[^{}]*?limit = (\d+)[^{}]*?\}\s*=\s*req\.query/g)].map((m) =>
    Number(m[1])
  );
const normalizePaginationCapsOf = (rel) => {
  const helperDefault = Number(/maxLimit = (\d+)/.exec(codeOf('src/utils/helpers.js'))[1]);
  return [...codeOf(rel).matchAll(/normalizePagination\(page, limit(?:,\s*(\d+))?\)/g)].map((m) =>
    m[1] ? Number(m[1]) : helperDefault
  );
};
const sortPairsOf = (rel) => {
  const out = [];
  for (const m of codeOf(rel).matchAll(/\.sort\(\{([^{}]*)\}\)/g)) {
    const pairs = [...m[1].matchAll(/([A-Za-z0-9_.]+)\s*:\s*(-?1)\b/g)].map((x) => [
      x[1],
      Number(x[2]),
    ]);
    if (pairs.length) out.push(pairs);
  }
  return out;
};

beforeAll(() => {
  process.env.HONEYPOT_ENABLED = 'true';
});

const makeRes = () => {
  const res = { statusCode: null, body: null };
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body) => {
    res.body = body;
    return res;
  };
  return res;
};
const makeReq = (url, q) => ({
  method: 'GET',
  originalUrl: url,
  query: q || {},
  ip: '10.44.0.9',
  headers: { 'user-agent': 'jest' },
  user: { userId: 'hp-u1', username: 'hptrapuser', isHoneypot: true },
});

describe('A/B 校验规则：静态对账 + 行为矩阵对账', () => {
  test('A. 规则描述符与路由源码逐条对齐（字段序/文案/校验器/optional 形态/枚举来源/参数）', () => {
    for (const spec of ENDPOINTS) {
      const parsed = descriptorsOf(listQueryBlockOf(spec.route));
      const rules = tableOf(spec.key).rules;
      expect(parsed.map((d) => d.field)).toEqual(rules.map((r) => r.field));
      expect(parsed.map((d) => d.msg)).toEqual(rules.map((r) => r.msg));
      expect(parsed.map((d) => d.kind)).toEqual(rules.map((r) => r.kind));
      expect(parsed.map((d) => d.optional)).toEqual(rules.map((r) => r.optional));
      expect(parsed.map((d) => d.min)).toEqual(rules.map((r) => r.min));
      expect(parsed.map((d) => d.max)).toEqual(rules.map((r) => r.max));
      parsed.forEach((d, i) => {
        if (d.kind !== 'in') return;
        expect(d.isInExpr).toBeTruthy();
        // 枚举必须来自该路由自己 import 的对象：不是抄来的字面量数组
        expect([...evalInScope(spec.route, d.isInExpr)]).toEqual([...rules[i].values]);
      });
    }
  });

  test('B. 行为对账：矩阵上每条查询的 fieldErrors 与真实链逐条、逐序、逐字相同', async () => {
    for (const spec of ENDPOINTS) {
      const fields = tableOf(spec.key).rules.map((r) => r.field);
      for (const field of fields) expect(PROBES[field]).toBeDefined();
      for (const q of casesOf(fields)) {
        const real = await realErrorsOf(spec.route, q);
        expect({ key: spec.key, q, mine: decoyFieldErrors(spec.key, q) }).toEqual({
          key: spec.key,
          q,
          mine: real,
        });
      }
    }
  });

  test('C. 日期闸：码与优先级同真实控制器（坏形态先被路由链拦下，再判形态/区间）', () => {
    for (const key of ['alarms', 'inspections']) {
      const code = codeOf(ENDPOINT_BY_KEY[key].controller);
      const gate = code.indexOf('isValidDateParam(');
      expect(gate).toBeGreaterThan(-1);
      expect(gate).toBeLessThan(code.indexOf('isDateRangeReversed('));
      expect(decoyFieldErrors(key, { startDate: 'abc' })).toHaveLength(1);
      expect(listQuery.listQueryRejection(key, { startDate: '20260801' })).toEqual({
        code: 'DATE_PARAM_INVALID',
      });
      expect(
        listQuery.listQueryRejection(key, { startDate: '2026-03-10', endDate: '2026-03-01' })
      ).toEqual({ code: 'DATE_RANGE_INVALID' });
      expect(
        listQuery.listQueryRejection(key, { startDate: '2026-03-01', endDate: '2026-03-10' })
      ).toBeNull();
    }
    for (const key of ['users', 'roles', 'permissions', 'devices']) {
      expect(listQuery.listQueryRejection(key, { startDate: 'abc' })).toBeNull();
    }
  });
});

describe('D/E 信封与 HTTP 面', () => {
  test('D. 信封全部从源码现推：message/默认 limit/上限/分页键序/排序键都与控制器与服务对齐', () => {
    for (const spec of ENDPOINTS) {
      const endpoint = tableOf(spec.key);
      const listShape = listPaginationShapeOf(spec.controller);
      expect(listShape.messages).toContain(endpoint.message);
      expect(listShape.keys.slice().sort()).toEqual(
        ['page', 'limit', 'total', 'totalPages', ...(endpoint.nextCursor ? ['nextCursor'] : [])]
          .slice()
          .sort()
      );
      expect(destructuredLimitsOf(spec.controller)).toContain(endpoint.defaultLimit);
      for (const cap of normalizePaginationCapsOf(spec.controller))
        expect(cap).toBe(endpoint.maxLimit);
      const paginationKeys = Object.keys(payloadOf(spec.key).pagination);
      expect(paginationKeys[0]).toBe('page');
      expect(paginationKeys[1]).toBe('limit');
      expect(paginationKeys.slice().sort()).toEqual(listShape.keys.slice().sort());
      if (spec.key === 'users') {
        const defaultSort = /defaultSort:\s*'(-?)([A-Za-z0-9_]+)'/.exec(codeOf(spec.controller));
        expect(endpoint.sort.map((s) => [s.field, s.dir])).toEqual([
          [defaultSort[2], defaultSort[1] === '-' ? -1 : 1],
        ]);
        const allowed = /allowedFields:\s*\[([\s\S]*?)\]/.exec(codeOf(spec.controller));
        for (const pair of endpoint.sort) expect(allowed[1]).toContain(pair.field);
      } else {
        const pairs = sortPairsOf(spec.service);
        const wanted = JSON.stringify(endpoint.sort.map((s) => [s.field, s.dir]));
        expect(pairs.map((p) => JSON.stringify(p))).toContain(wanted);
      }
    }
  });

  test('E. HTTP 面：非法查询回真实链同一个 400 体；六个列表的合法首屏回控制器信封', async () => {
    const spy = jest.spyOn(honeypotWatch, 'recordHoneypotProbe').mockResolvedValue(undefined);
    try {
      const illegal = { status: 'nope', page: 'x' };
      const res = makeRes();
      expect(await honeypotDecoy.steer(makeReq('/api/users', illegal), res)).toBe(true);
      const mirror = makeRes();
      ApiResponse.codeError(mirror, 'VALIDATION_FAILED', {
        fieldErrors: await realErrorsOf(ENDPOINT_BY_KEY.users.route, illegal),
      });
      expect(res.body).toEqual(mirror.body);
      for (const spec of ENDPOINTS) {
        const endpoint = tableOf(spec.key);
        const ok = makeRes();
        expect(await honeypotDecoy.steer(makeReq(endpoint.path, {}), ok)).toBe(true);
        expect(ok.body.message).toBe(endpoint.message);
        expect(ok.body.data.length).toBeGreaterThan(0);
        expect(Object.keys(ok.body.pagination).slice().sort()).toEqual(
          listPaginationShapeOf(spec.controller).keys.slice().sort()
        );
      }
    } finally {
      spy.mockRestore();
    }
  });

  test('F. 分页语义：total 是过滤后条数、空结果 totalPages:0、越界页回空数组且不回第一页', () => {
    const all = payloadOf('alarms');
    const filtered = payloadOf('alarms', { status: 'resolved' });
    expect(filtered.pagination.total).toBe(filtered.data.length);
    expect(filtered.pagination.total).toBeLessThan(all.pagination.total);
    const emptyPage = payloadOf('users', { role: 'NO_SUCH_ROLE' });
    expect(emptyPage.data).toEqual([]);
    expect(emptyPage.pagination).toEqual({
      page: 1,
      limit: tableOf('users').defaultLimit,
      total: 0,
      totalPages: 0,
    });
    const firstPage = payloadOf('users', { limit: '2' });
    const over = payloadOf('users', { limit: '2', page: '99' });
    expect(over.data).toEqual([]);
    expect(over.pagination.totalPages).toBe(firstPage.pagination.totalPages);
    expect(firstPage.data.length).toBeGreaterThan(0);
  });

  test('G. fieldErrors 契约：恰好四键、无 value、文案取自常量表而非回显请求值', () => {
    const hostile = [
      '<img src=x onerror=alert(1)>',
      'a'.repeat(4000),
      '__proto__',
      'constructor',
      '"双引号"',
      '中文引号「」与括号（x）',
    ];
    let checked = 0;
    for (const spec of ENDPOINTS) {
      for (const rule of tableOf(spec.key).rules) {
        for (const value of hostile) {
          const q = { [rule.field]: value };
          const got = listQuery.listQueryRejection(spec.key, q);
          if (!got || got.code !== 'VALIDATION_FAILED') continue;
          for (const entry of got.fieldErrors) {
            checked += 1;
            expect(Object.keys(entry).slice().sort()).toEqual(['location', 'msg', 'path', 'type']);
            expect(entry.type).toBe('field');
            expect(entry.location).toBe('query');
            expect(entry.path).toBe(rule.field);
            expect(entry.msg).toBe(rule.msg);
            expect(entry).not.toHaveProperty('value');
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(0);
  });
});

describe('H/I/J 投影键集、值域桥与反向对照', () => {
  const SERVICE_DERIVED = {
    users: {
      phoneMasked: { file: 'src/services/userService.js', anchor: 'obj.phoneMasked' },
      emailMasked: { file: 'src/services/userService.js', anchor: 'obj.emailMasked' },
    },
    roles: {
      userCount: { file: 'src/services/roleService.js', anchor: 'userCount: countMap.get(' },
    },
  };
  /** 真实读侧显式排除的字段：从模型源码现取排除清单，再套上它的 filter 表达式（PII 变体保留 phone/email）。 */
  const userExcludedForList = () => {
    const code = codeOf('src/models/User.js');
    const list = /USER_RESPONSE_EXCLUDE_FIELDS = \[([\s\S]*?)\]/.exec(code)[1];
    const names = [...list.matchAll(/-([A-Za-z0-9_]+)'/g)].map((m) => m[1]);
    const filter =
      /USER_RESPONSE_EXCLUDE_PII_VISIBLE = USER_RESPONSE_EXCLUDE_FIELDS\.filter\(([\s\S]*?)\)\s*\.join/.exec(
        code
      )[1];
    const kept = new Set([...filter.matchAll(/!==\s*'-([A-Za-z0-9_]+)'/g)].map((m) => m[1]));
    return new Set(names.filter((n) => !kept.has(n)));
  };
  /** 脱敏函数的增删键：phoneMasked/emailMasked 是加进来的，phone/email 是被删掉的（源码现取）。 */
  const maskTouchedKeys = () => {
    const code = codeOf('src/services/userService.js');
    const body = code.slice(
      code.indexOf('function toMaskedAdminUser'),
      code.indexOf('return obj;')
    );
    return {
      added: [...body.matchAll(/obj\.([A-Za-z0-9_]+)\s*=/g)].map((m) => m[1]),
      removed: [...body.matchAll(/delete obj\.([A-Za-z0-9_]+)/g)].map((m) => m[1]),
    };
  };
  const expectedKeysOf = (key) => {
    const model = require(ENDPOINT_BY_KEY[key].modelRel);
    const out = new Set();
    for (const dotted of Object.keys(model.schema.paths)) {
      const top = dotted.split('.')[0];
      const leaf = model.schema.paths[top];
      if (leaf && leaf.options && leaf.options.select === false) continue;
      out.add(top);
    }
    if (key === 'users') {
      for (const name of userExcludedForList()) out.delete(name);
      const touched = maskTouchedKeys();
      for (const name of touched.removed) out.delete(name);
      for (const name of touched.added) out.add(name);
    }
    for (const name of Object.keys(SERVICE_DERIVED[key] || {})) out.add(name);
    return out;
  };
  /** 第三刀把下列键改名：本表就是「改名待办」，改名落地后条目必须删，否则 stale 判红。 */
  const PENDING_RENAME = {
    users: {},
    roles: {},
    permissions: {},
    devices: {},
    alarms: {},
    inspections: {},
  };
  /**
   * 改名已落地的集合：待办表必须为空，且**不许再往回填**（回填即判红）。
   * 表一旦删空，H 里那句 `extra === 待办键` 就自动翻转成"旧名必须消失"——这半句才是棘轮。
   */
  const RENAME_LANDED = ['alarms', 'devices', 'inspections', 'users'];
  const MUST_EMIT = ['_id', 'status'];
  /** 条件物化：数据面没有该偏移量时整键不出现（第三刀可评估是否统一补齐）。 */
  const VARYING_KEYS = {
    // u1（引导管理员）不带 createdBy：真实链里引导账户的该字段就是 undefined——键缺席是忠实形状
    users: ['createdBy'],
    roles: [],
    permissions: [],
    devices: ['expiryDate', 'nextCheckDate', 'remark', 'scrapDate', 'scrapReason'],
    alarms: ['arrivedAt', 'cause', 'dispatchedAt', 'handleResult', 'handler', 'resolvedAt'],
    inspections: [
      'actualEndTime',
      'actualStartTime',
      'result',
      'reviewComment',
      'reviewResult',
      'reviewedAt',
      'reviewedBy',
    ],
  };

  /** 凭证/内部字段：模型 schema 的 select:false 全路径 + 用户模型源码声明的排除清单。 */
  const credentialSetOf = (key) => {
    const model = require(ENDPOINT_BY_KEY[key].modelRel);
    const out = new Set();
    for (const dotted of Object.keys(model.schema.paths)) {
      const leaf = model.schema.paths[dotted];
      if (leaf && leaf.options && leaf.options.select === false) out.add(dotted.split('.')[0]);
    }
    if (key === 'users') for (const name of userExcludedForList()) out.add(name);
    return out;
  };

  const projectionVerdict = (key, emitted, pending = PENDING_RENAME[key] || {}) => {
    const expected = expectedKeysOf(key);
    const extra = emitted
      .filter((k) => !expected.has(k))
      .slice()
      .sort();
    return {
      extra,
      undeclared: extra.filter((k) => !Object.prototype.hasOwnProperty.call(pending, k)),
      stale: Object.keys(pending).filter((k) => !emitted.includes(k)),
      unbacked: Object.keys(pending).filter((k) => !expected.has(pending[k])),
      missing: MUST_EMIT.filter((k) => !emitted.includes(k)),
      forbidden: [...expected].filter((k) => credentialSetOf(key).has(k)),
    };
  };

  test('H. 投影键集双向：emitted ⊆ 期望 ∪ 待改名；期望 ⊆ 模型源码 + 具名服务派生；键集跨行跨页一致', () => {
    for (const spec of ENDPOINTS) {
      const rows = payloadOf(spec.key).data.concat(
        payloadOf(spec.key, { page: '2', limit: '2' }).data
      );
      const union = [...new Set(rows.flatMap((row) => Object.keys(row)))].slice().sort();
      // 行间必须同形，只有登记在案的条件物化键可以缺席（数据面不给偏移量时该键不出现）
      const varying = union
        .filter((k) => rows.some((row) => !(k in row)))
        .slice()
        .sort();
      expect({ key: spec.key, varying }).toEqual({
        key: spec.key,
        varying: VARYING_KEYS[spec.key].slice().sort(),
      });
      const common = union.filter((k) => !varying.includes(k));
      for (const row of rows) {
        expect(
          Object.keys(row)
            .filter((k) => !varying.includes(k))
            .slice()
            .sort()
        ).toEqual(common);
      }
      const emitted = union;
      const verdict = projectionVerdict(spec.key, emitted);
      expect({
        key: spec.key,
        undeclared: verdict.undeclared,
        stale: verdict.stale,
        unbacked: verdict.unbacked,
        missing: verdict.missing,
        forbidden: verdict.forbidden,
      }).toEqual({
        key: spec.key,
        undeclared: [],
        stale: [],
        unbacked: [],
        missing: [],
        forbidden: [],
      });
      expect(verdict.extra).toEqual(Object.keys(PENDING_RENAME[spec.key]).slice().sort());
      if (RENAME_LANDED.includes(spec.key)) {
        // 改名已落地 ⇒ 待办表只能是空的（回填旧名即判红），且行里不许再见到旧名
        expect({ key: spec.key, pending: Object.keys(PENDING_RENAME[spec.key]) }).toEqual({
          key: spec.key,
          pending: [],
        });
      }
      for (const [name, derived] of Object.entries(SERVICE_DERIVED[spec.key] || {})) {
        expect({ name, found: codeOf(derived.file).includes(derived.anchor) }).toEqual({
          name,
          found: true,
        });
      }
      // 期望方向：每个键都要有出处——模型源码现读、具名服务派生、或 mongoose 内置（时间戳需模型声明）。
      const modelText = codeOf(spec.model);
      const implicit = new Set(['_id', '__v']);
      for (const name of expectedKeysOf(spec.key)) {
        const derived = (SERVICE_DERIVED[spec.key] || {})[name];
        let found;
        if (derived) found = codeOf(derived.file).includes(derived.anchor);
        else if (implicit.has(name))
          found = Boolean(require(ENDPOINT_BY_KEY[spec.key].modelRel).schema.paths[name]);
        else if (name === 'createdAt' || name === 'updatedAt')
          found = modelText.includes('timestamps');
        else found = modelText.includes(name);
        expect({ key: spec.key, name, found }).toEqual({ key: spec.key, name, found: true });
      }
    }
  });

  test('I. 未终结集合与 AlarmService 源码的 $in 集合双向一致；openAlarms 按成员计数（旧减法口径会算错）', () => {
    const code = codeOf('src/services/AlarmService.js');
    const openSet = [...code.matchAll(/status:\s*\{\s*\$in:\s*\[([^\]]*)\]/g)]
      .map((m) =>
        m[1]
          .split(',')
          .map((s) => s.trim().replace(/^'|'$/g, ''))
          .filter(Boolean)
      )
      .find((list) => list.includes('pending'));
    expect(openSet.slice().sort()).toEqual(shape.ALARM_OPEN_STATUSES.slice().sort());
    const rows = payloadOf('alarms').data;
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.filter((row) => !ALARM_STATUSES.includes(row.status))).toEqual([]);
    // 「旧减法口径」= 总数减已处理档：拿真实枚举现推的终结档集合，不写字面量
    const terminal = ALARM_STATUSES.filter((s) => !shape.ALARM_OPEN_STATUSES.includes(s));
    const otherTerminal = terminal.find((s) => s !== terminal[0]);
    const oldFormulaOf = (list) =>
      list.length - list.filter((r) => r.status === terminal[0]).length;
    const widened = rows.concat([{ status: otherTerminal }]);
    const mine = widened.filter((r) => shape.ALARM_OPEN_STATUSES.includes(r.status)).length;
    expect(oldFormulaOf(widened)).toBeGreaterThan(mine);
    const raw = decoy.DECOY_ALARMS;
    expect(decoy.DECOY_SUMMARY.openAlarms).toBe(
      raw.filter((r) => shape.ALARM_OPEN_STATUSES.includes(r.status)).length
    );
    const stale = raw.filter(
      (r) => !shape.ALARM_OPEN_STATUSES.includes(r.status) && r.status !== terminal[0]
    );
    if (stale.length) expect(decoy.DECOY_SUMMARY.openAlarms).toBeLessThan(oldFormulaOf(raw));
  });

  test('K. 值域桥已删净：形状文件里不得再出现中文档报警字面量与桥表标识符（删桥前必红）', () => {
    const src = read('src/constants/honeypotDecoyListShape.js');
    const chineseLabels = ['待处理', '处理中', '已处理', '误报', '已取消', '预警', '故障', '火警'];
    expect(chineseLabels.filter((label) => src.includes(label))).toEqual([]);
    expect(
      src.match(
        /ALARM_STATUS_FACETS|ALARM_STATUS_LABELS|ALARM_LEVEL_LABELS|ALARM_OPEN_LABELS|labelOfStatus/g
      )
    ).toBeNull();
  });
  test('J. 反向对照：改坏一条文案 / 多下发一个键 / 少下发一个键，都必须被同一套判据抓红', () => {
    const spec = ENDPOINT_BY_KEY.alarms;
    const rules = tableOf('alarms').rules;
    const parsed = descriptorsOf(listQueryBlockOf(spec.route));
    const brokeMessage = parsed.map((d, i) => (i === 0 ? { ...d, msg: d.msg + '（改坏）' } : d));
    expect(brokeMessage.map((d) => d.msg)).not.toEqual(rules.map((r) => r.msg));
    // 本组只断言键集（以及自造数组），不读任何行的值：改数据面的值不会让本组红——别把它当脆弱耦合；反过来，往这里加值断言前先想清楚本组的定位
    const emitted = Object.keys(payloadOf('alarms').data[0]).slice().sort();
    const extraVerdict = projectionVerdict('alarms', emitted.concat(['secretFlag']).slice().sort());
    expect(extraVerdict.undeclared).toEqual(['secretFlag']);
    // 改名已落地的一半：旧名回魂必须落到"未声明键"，而不是"待改名"（跟着字段走）
    const relapsed = projectionVerdict('alarms', emitted.concat(['code', 'time']).slice().sort());
    expect(relapsed.undeclared).toEqual(['code', 'time']);
    expect(relapsed.stale).toEqual([]);
    // 少下发一个键：待改名键缺席即 stale（跟着字段走）。四张改名待办现已全部清空，没有现成靶子，
    // 这里显式给一份合成待办走**同一条**判定路径——stale 通道常年在测，不随棘轮收口而空转。
    const inspectionsEmitted = Object.keys(payloadOf('inspections').data[0]).slice().sort();
    const missingVerdict = projectionVerdict(
      'inspections',
      inspectionsEmitted.filter((k) => k !== 'title'),
      { title: 'code' }
    );
    expect(missingVerdict.stale).toEqual(['title']);
    expect(missingVerdict.undeclared).toEqual([]); // 'title' 本身是合法键：少下发 ≠ 多下发
    const droppedCore = projectionVerdict(
      'alarms',
      emitted.filter((k) => k !== 'status')
    );
    expect(droppedCore.missing).toEqual(['status']);
    const coreDrift = descriptorsOf(listQueryBlockOf(ENDPOINT_BY_KEY.users.route)).map((d, i) =>
      i === 0 ? { ...d, field: 'statusX' } : d
    );
    expect(coreDrift.map((d) => d.field)).not.toEqual(tableOf('users').rules.map((r) => r.field));
  });

  /** 引用路径从模型 schema 现扫（数组元素、子文档数组内部的 ref 都算），不是手抄清单。 */
  const referencePathsOf = (schema, prefix = '') => {
    const out = [];
    for (const [name, sp] of Object.entries(schema.paths)) {
      const dotted = prefix ? prefix + '.' + name : name;
      if (sp.options && sp.options.ref) out.push({ field: dotted, model: sp.options.ref });
      else if (sp.$embeddedSchemaType) {
        const ref = sp.$embeddedSchemaType.options && sp.$embeddedSchemaType.options.ref;
        if (ref) out.push({ field: dotted, model: ref });
        else if (sp.schema) out.push(...referencePathsOf(sp.schema, dotted));
      } else if (sp.schema) out.push(...referencePathsOf(sp.schema, dotted));
    }
    return out;
  };

  const valuesAt = (node, segs) => {
    if (!segs.length) return [node].flatMap((v) => (Array.isArray(v) ? v : [v]));
    if (Array.isArray(node)) return node.flatMap((item) => valuesAt(item, segs));
    if (node && typeof node === 'object' && Object.prototype.hasOwnProperty.call(node, segs[0])) {
      return valuesAt(node[segs[0]], segs.slice(1));
    }
    return [];
  };

  /**
   * L 的静态模型表：字符串字面量 require（不走 spec.modelRel 动态拼路径）。
   * 缺键会在 L 开头直接 TypeError——fail-loud，不会静默漏扫。
   */
  const L_MODELS = {
    users: require('../../models/User'),
    roles: require('../../models/Role'),
    permissions: require('../../models/Permission'),
    devices: require('../../models/FireDevice'),
    alarms: require('../../models/FireAlarm'),
    inspections: require('../../models/Inspection'),
  };

  /**
   * 「扫到≠比过」登记豁免：下列引用路径在装饰行上**没有值可比**（vacuum），按条给理由。
   * 双向棘轮：路径一旦有值可比、或从 schema 消失，就必须同时出登记表——否则 stale 判红，
   * 登记表不能变成永久豁免口。
   */
  const L_REF_VACUUM_LEDGER = {
    // FireDevice.js:139-141：inspectionRecord 的写入方法全仓零调用 ⇒ 真实设备也不会有记录，空数组是忠实形状
    'devices.inspectionRecord.inspector':
      '写入方法全仓零调用（FireDevice.js:139-141）：空数组是忠实形状',
  };

  test('L. 引用完整性：行里每个引用型 id 都能在对应合成表的 _id 里找到（引用路径从模型 schema 现扫）', () => {
    const keyByModel = {};
    for (const spec of ENDPOINTS) keyByModel[L_MODELS[spec.key].modelName] = spec.key;
    const dangling = [];
    const checkedBy = {};
    const discovered = new Set();
    let checked = 0;
    for (const spec of ENDPOINTS) {
      const rows = payloadOf(spec.key).data.concat(
        payloadOf(spec.key, { page: '2', limit: '2' }).data
      );
      for (const { field, model: refModel } of referencePathsOf(L_MODELS[spec.key].schema)) {
        const path = spec.key + '.' + field;
        discovered.add(path);
        const target = keyByModel[refModel];
        if (!target) {
          dangling.push({ key: spec.key, field, id: '无对应合成表:' + refModel });
          continue;
        }
        const known = new Set(decoy.DECOY_TABLES[target].map((row) => String(row._id)));
        for (const row of rows) {
          for (const value of valuesAt(row, field.split('.'))) {
            const id = value && typeof value === 'object' ? value._id : value;
            if (id === undefined || id === null) continue;
            checked += 1;
            checkedBy[path] = (checkedBy[path] || 0) + 1;
            if (!known.has(String(id))) dangling.push({ key: spec.key, field, id: String(id) });
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(0);
    expect(dangling).toEqual([]);
    // 每条引用路径要么至少比过一次，要么在登记表里；反向（登记了却比过/路径消失）同样红
    const unverified = [...discovered].filter(
      (path) => !checkedBy[path] && !Object.prototype.hasOwnProperty.call(L_REF_VACUUM_LEDGER, path)
    );
    const staleLedger = Object.keys(L_REF_VACUUM_LEDGER).filter(
      (path) => checkedBy[path] || !discovered.has(path)
    );
    expect({ unverified, staleLedger }).toEqual({ unverified: [], staleLedger: [] });
  });
});
