'use strict';

/**
 * 未知 outcome 必须按失败处理（authController 5 条 outcome 状态机的 fail-closed 闸）
 *
 * 缺陷类别：`switch (result.outcome)` 不列 `case 'OK'` 而以 `default: break;` 收尾时，
 * 业务层新增一个 outcome 而控制器忘了映射 ⇒ **静默按成功处理**。
 * 这一类在本仓发生过一次并有源码自陈（`authController.js` 里 CONFIRM_MISMATCH 曾缺失，
 * 用户实际没改密却收到"密码修改成功"）。2026-09-20 五处 switch 已收口为
 * `case 'OK'` + `default: return rejectUnknownOutcome(...)`，但**收口本身无人断言**：
 * 只要有人把某个 default 改回 `break;`，全套用例仍绿。本文件补两层判据：
 *
 *  A. 行为级：五个处理器各注入一个"声明集合之外"的 outcome ⇒ 必须 500 + INTERNAL_ERROR，
 *     且**不得留下成功痕迹**（不Set-Cookie、不写成功审计）。
 *     每条都配"已知 outcome 仍走各自分支"的反例，防止"什么都返回 500"把用例顶绿。
 *  B. 结构级（全仓闸）：任何 `switch (*.outcome)` 必须显式列 `case 'OK'`，
 *     且其 `default` 条款必须在 switch 体内 `return`/`throw`（不许裸 `break;` 落空）。
 *     并附**闸的自检**：把判据喂一个退化样例（`default: break;`），必须判为违规——
 *     否则这条闸就是恒真的（本仓踩过一次 `gateSelfTest` 正则恒真的坑）。
 */

jest.mock('express-validator', () => ({
  validationResult: (req) => ({
    isEmpty: () => !req._invalid,
    array: () => req._errors || [{ msg: 'mock validation error' }],
  }),
}));
jest.mock('../../services/authService');
jest.mock('../../services/captchaService');
jest.mock('../../services/sessionService');
jest.mock('../../services/tokenService', () => ({
  isAccessTokenValid: jest.fn(),
  isRefreshTokenValid: jest.fn(),
}));
jest.mock('../../utils/permissionHelper', () => ({
  getUserPermissions: jest.fn(),
  getMenuTree: jest.fn(),
}));
jest.mock('../../models/AuditLog', () => ({
  recordSensitiveAction: jest.fn(() => Promise.resolve()),
  record: jest.fn(() => Promise.resolve()),
}));
jest.mock('../../utils/loginCipher', () => ({
  getPublicKeyInfo: jest.fn(() => ({ keyId: 'k1', publicKey: 'PUB' })),
}));
jest.mock('../../utils/fingerprint', () => ({ computeFingerprint: jest.fn(() => 'fp') }));
jest.mock('../../models', () => ({
  SystemConfig: {
    isLoginCaptchaEnabled: jest.fn(),
    isRegisterCaptchaEnabled: jest.fn(),
  },
}));
jest.mock('../../middleware/rbac', () => ({
  getDataScope: jest.fn(async () => ({ type: 'all' })),
  checkPermission: jest.fn(() => (req, res, next) => next()),
  checkRole: jest.fn(() => (req, res, next) => next()),
}));

const fs = require('fs');
const path = require('path');
const authService = require('../../services/authService');
const AuditLog = require('../../models/AuditLog');
const controller = require('../../controllers/authController');

const makeRes = () => {
  const res = {};
  res.statusCode = 200;
  res.status = jest.fn((c) => {
    res.statusCode = c;
    return res;
  });
  res.json = jest.fn((body) => {
    res.body = body;
    return res;
  });
  res.cookie = jest.fn();
  res.clearCookie = jest.fn();
  res.headersSent = false;
  return res;
};

const makeReq = (over = {}) => ({
  body: {},
  params: {},
  query: {},
  ip: '127.0.0.1',
  method: 'POST',
  path: '/api/auth/unit',
  originalUrl: '/api/auth/unit',
  headers: {},
  get: jest.fn(() => 'jest-agent'),
  user: { userId: 'u-1', username: 'alice', sid: 'sid-cur' },
  ...over,
});

const invoke = async (fn, req, res) => {
  const next = jest.fn((e) => {
    if (e) throw e;
  });
  await fn(req, res, next);
  await new Promise((resolve) => setImmediate(resolve));
  return res;
};

// 取自各处理器"声明集合之外"的值：任何一个真实 outcome 都不该撞名
const BOGUS = 'OUTCOME_ADDED_IN_SERVICE_BUT_NOT_MAPPED';

describe('未知 outcome 必须 fail-closed（行为级）', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const cases = [
    ['register', 'registerUser', controller.register],
    ['login', 'loginUser', controller.login],
    ['refreshToken', 'refreshSession', controller.refreshToken],
    ['changePassword', 'changeUserPassword', controller.changePassword],
    ['updateProfile', 'updateUserProfile', controller.updateProfile],
  ];

  test.each(cases)(
    '%s：注入未知 outcome ⇒ 500/INTERNAL_ERROR 且无成功痕迹',
    async (_name, method, handler) => {
      authService[method].mockResolvedValue({ outcome: BOGUS });
      const res = await invoke(handler, makeReq(), makeRes());
      expect(res.statusCode).toBe(500);
      expect(res.body?.success).toBe(false);
      expect(res.body?.errors?.errorCode).toBe('INTERNAL_ERROR');
      // 成功痕迹：认证 cookie 与"成功类"审计都不得出现
      expect(res.cookie).not.toHaveBeenCalled();
      const written = AuditLog.record.mock.calls.map((c) => c[0] && c[0].action).filter(Boolean);
      expect(written).toEqual([]);
    }
  );

  test('反对照：已知 outcome 仍各自走映射分支（防止"一律 500"把上面五条顶绿）', async () => {
    authService.registerUser.mockResolvedValue({ outcome: 'WEAK', message: '密码强度不足' });
    const res = await invoke(controller.register, makeReq(), makeRes());
    expect(res.statusCode).not.toBe(500);
    expect(res.body?.errors?.errorCode).not.toBe('INTERNAL_ERROR');

    authService.loginUser.mockResolvedValue({ outcome: 'INVALID_CREDENTIALS' });
    const res2 = await invoke(controller.login, makeReq(), makeRes());
    expect(res2.statusCode).not.toBe(500);
    expect(res2.body?.errors?.errorCode).not.toBe('INTERNAL_ERROR');
  });
});

describe('全仓闸：任何 switch (*.outcome) 不得让 default 落空', () => {
  const srcRoot = path.join(__dirname, '..', '..');

  const stripLineComments = (text) =>
    text
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*)/.test(l))
      .join('\n');

  /** 从 idx 之后第一个 '{' 起做配对（跳过字符串字面量），返回 switch 体 */
  const blockBody = (text, idx) => {
    const open = text.indexOf('{', idx);
    if (open === -1) return null;
    let depth = 0;
    for (let i = open; i < text.length; i += 1) {
      const c = text[i];
      if (c === "'" || c === '"' || c === '`') {
        const q = c;
        let j = i + 1;
        while (j < text.length) {
          if (text[j] === '\\') j += 2;
          else if (text[j] === q) break;
          else j += 1;
        }
        i = j;
        continue;
      }
      if (c === '{') depth += 1;
      else if (c === '}') {
        depth -= 1;
        if (depth === 0) return text.slice(open + 1, i);
      }
    }
    return null;
  };

  /** 判据：返回违规清单（空=合规）。default 里必须在 switch 体内 return/throw */
  const findViolations = (text) => {
    const clean = stripLineComments(text);
    const out = [];
    const re = /switch\s*\(\s*[^)]*outcome[^)]*\)\s*\{/gi;
    let m;
    while ((m = re.exec(clean))) {
      const body = blockBody(clean, m.index);
      if (!body) {
        out.push(`无法解析 switch 体：${m[0]}`);
        continue;
      }
      if (!/case\s+'OK'/.test(body)) out.push(`缺显式 case 'OK'：${m[1] || m[0]}`);
      const di = body.search(/default\s*:/);
      if (di === -1) {
        out.push('无 default（新增 outcome 会静默落到最后一个 case 之后）');
        continue;
      }
      const def = body.slice(di + 8);
      const firstStatement = def.replace(/^\s*/, '').split('\n')[0];
      const returnsOrThrows = /\b(return|throw)\b/.test(def.split(/case\s+'/)[0]);
      if (/^break\s*;/.test(firstStatement) || !returnsOrThrows) {
        out.push(`default 落空（未 return/throw）：${firstStatement.slice(0, 40)}`);
      }
    }
    return out;
  };

  const walk = (dir, acc = []) => {
    for (const name of fs.readdirSync(dir)) {
      if (name === 'node_modules') continue;
      const full = path.join(dir, name);
      const st = fs.statSync(full);
      if (st.isDirectory()) {
        if (full === path.join(srcRoot, 'tests')) continue;
        walk(full, acc);
      } else if (name.endsWith('.js')) acc.push(full);
    }
    return acc;
  };

  test('闸本身有效：退化样例必须被判为违规（防恒真门禁）', () => {
    const bad = `
      const h = async (req, res) => {
        const result = await svc.doIt();
        switch (result.outcome) {
          case 'WEAK': return res.status(400).json({});
          default:
            break;
        }
        return res.json({ success: true });
      };`;
    expect(findViolations(bad).length).toBeGreaterThan(0);
    const good = `
      const h = async (req, res) => {
        const result = await svc.doIt();
        switch (result.outcome) {
          case 'WEAK': return res.status(400).json({});
          case 'OK': return res.json({ success: true });
          default:
            return rejectUnknownOutcome(res, 'h', result.outcome);
        }
      };`;
    expect(findViolations(good)).toEqual([]);
  });

  test('全仓现存 outcome switch 全部合规，且数量与普查一致', () => {
    const offenders = [];
    let total = 0;
    for (const f of walk(srcRoot)) {
      const text = fs.readFileSync(f, 'utf8');
      if (!/switch\s*\(\s*[^)]*outcome/i.test(text)) continue;
      total += (text.match(/switch\s*\(\s*[^)]*outcome[^)]*\)\s*\{/gi) || []).length;
      const v = findViolations(text);
      if (v.length)
        offenders.push(`${path.relative(srcRoot, f).split('\\').join('/')}: ${v.join(' | ')}`);
    }
    expect(offenders).toEqual([]);
    // 5 处 authController + 2 处 securityController；少一处说明判据没扫到东西（闸失效）
    expect(total).toBeGreaterThanOrEqual(7);
  });
});
