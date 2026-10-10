'use strict';

/**
 * 「拿 access 密钥验签的入口」清单闸（2026-10-03）
 *
 * 起因是 `src/utils/tokenPurpose.js` 的头注释那句「任何新增的验签入口都必须引用同一份」。
 * 这句话此前**没有**任何判据：`src/tests/utils/tokenPurposeAndConsumers.test.js` 的
 * `三个入口都引用 utils/tokenPurpose` 用的是**手写死的三个文件名**——它证的是"这三份今天还引用着"，
 * 而不是"没有第四份"。新增一处 `jwt.verify(x, config.jwt.secret)` 而忘了用途闸时，
 * 那两个闸都会照常绿。同文件里其实已经有全仓扫描的机器（`全仓不得再内联写一份 type 比较`），
 * 只是没扫这一维。本闸补的正是那一维：**枚举**入口，而不是点名已知入口。
 *
 * 枚举结果（实测 5 处，逐条归队）：3 处引用 utils/tokenPurpose，2 处没有——
 *   · `src/middleware/logoutAuth.js:92`
 *   · `src/services/authService.js`（revokeTokensOnLogout）
 * 两处都**不是**缺陷，但"不是缺陷"必须由行为证明，不能由白名单的名字证明：
 *   · 登出侧那次验签只决定"走哪条身份通路"，权威判定仍然过 `authenticate()`（用途闸在它里面），
 *     用例②实测：两把密钥配成同值时拿 refresh 当 Bearer access 打登出入口 ⇒ 401 AUTH_TOKEN_INVALID；
 *   · 吊销侧那次验签的唯一产物是"把这条串写进黑名单"，少一道用途闸的失效方向是
 *     **多吊销一条**而不是多放行一个，用例③实测：refresh 串填进 accessToken 槽 ⇒ findOneAndUpdate 被调用。
 * 这两条就是这两处豁免的**根据**。哪天改动让根据不再成立（比如有人在吊销路径上开始
 * 用 payload 构造 req.user），本闸的清单不变、但那条行为用例会先红——这是刻意的顺序。
 *
 * 判据口径：只看 `jwt.verify(<第一参>, config.jwt.secret …)` 且第二参**不是** refreshSecret 的调用。
 * refresh 侧验签不需要这条闸（它的用途判据是 `decoded.type !== 'refresh'`，已各自存在）。
 * 注释先剥掉再扫，所以注释里引用 `jwt.verify` 不会被算成入口。
 */

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const config = require('../../config');
const TokenBlacklist = require('../../models/TokenBlacklist');
const authService = require('../../services/authService');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(ROOT, 'src');

const listJs = (dir) => {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...listJs(abs));
    else if (e.name.endsWith('.js')) out.push(abs);
  }
  return out;
};

const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

/** 一次 `jwt.verify(...)` 调用是否用 access 密钥验签（refresh 密钥签名的不算） */
const isAccessVerifyCall = (call) =>
  /config\.jwt\.secret|process\.env\.JWT_SECRET/.test(call) && !/refreshSecret/.test(call);

/** 判据本体：从源码里取出所有"用 access 密钥验签"的调用 */
const findAccessVerifyCalls = (code) => {
  const stripped = stripComments(code);
  return (stripped.match(/jwt\.verify\([^)]*\)/g) || [])
    .filter(isAccessVerifyCall)
    .map((c) => c.replace(/\s+/g, ' '));
};

const referencesPurposeGuard = (code) => /utils\/tokenPurpose/.test(stripComments(code));

/** 枚举 src/（测试目录除外）的全部入口，返回相对路径 + 调用原文 + 是否引用判据 */
const inventory = () => {
  const rows = [];
  for (const abs of listJs(SRC)) {
    if (abs.includes(`${path.sep}tests${path.sep}`)) continue;
    const code = fs.readFileSync(abs, 'utf8');
    const calls = findAccessVerifyCalls(code);
    if (calls.length === 0) continue;
    rows.push({
      rel: path.relative(ROOT, abs).split(path.sep).join('/'),
      calls,
      guarded: referencesPurposeGuard(code),
    });
  }
  return rows.sort((a, b) => a.rel.localeCompare(b.rel));
};

/** 豁免清单：文件 → 这条豁免的**行为根据**（下面各有一条用例证它） */
const EXEMPTIONS = {
  'src/middleware/logoutAuth.js': '只决定走哪条身份通路，权威判定仍在 authenticate()（用例②）',
  'src/services/authService.js': '唯一产物是写黑名单，失效方向=多吊销（用例③）',
};

const rows = inventory();

describe('入口清单：用 access 密钥验签的地方必须引用用途判据或留下行为根据', () => {
  test('枚举本身不是空集（扫描塌缩不许静默绿）', () => {
    expect(rows.length).toBeGreaterThanOrEqual(4);
    expect(rows.every((r) => r.calls.length > 0)).toBe(true);
  });

  test('清单逐条归队：每一处要么引用 utils/tokenPurpose，要么在豁免表里有根据', () => {
    const offenders = rows
      .filter((r) => !r.guarded && !EXEMPTIONS[r.rel])
      .map((r) => `${r.rel} ⇒ ${r.calls.join(' / ')}`);
    expect(offenders).toEqual([]);
  });

  test('清单规模钉住：新增入口会红，删掉入口也会红（两条方向都不许静默）', () => {
    expect(rows.map((r) => r.rel)).toEqual([
      'src/middleware/auth.js',
      'src/middleware/logoutAuth.js',
      'src/services/authService.js',
      'src/services/tokenService.js',
      'src/services/websocketService.js',
    ]);
    // 引用判据的三份也不许缩水成两份：这里把"谁引用"当场数出来而不是只测总数
    expect(rows.filter((r) => r.guarded).map((r) => r.rel)).toEqual([
      'src/middleware/auth.js',
      'src/services/tokenService.js',
      'src/services/websocketService.js',
    ]);
  });

  test('反向自证：一处没引用判据的新入口确实会被本闸抓出（防空集假绿）', () => {
    const dirty = [
      "const jwt = require('jsonwebtoken');",
      'const config = require("../config");',
      'const handle = (token) => jwt.verify(token, config.jwt.secret, { algorithms: ["HS256"] });',
    ].join('\n');
    const clean = [
      "const jwt = require('jsonwebtoken');",
      'const config = require("../config");',
      'const { violatesAccessTokenPurpose } = require("../utils/tokenPurpose");',
      'const handle = (token) => jwt.verify(token, config.jwt.secret, { algorithms: ["HS256"] });',
    ].join('\n');
    // 判据本体（classify 三件套）对同一段代码的两个版本必须给出相反答案，
    // 且"注释里提到 jwt.verify"不能被当成入口——第三个样本就是测这一条的。
    const commentedOut = '/* jwt.verify(t, config.jwt.secret) 只是注释 */\nconst x = 1;\n';
    expect(findAccessVerifyCalls(dirty)).toHaveLength(1);
    expect(referencesPurposeGuard(dirty)).toBe(false);
    expect(findAccessVerifyCalls(clean)).toHaveLength(1);
    expect(referencesPurposeGuard(clean)).toBe(true);
    expect(findAccessVerifyCalls(commentedOut)).toEqual([]);
  });

  test('豁免表里不许躺着用不到的条目（豁免本身也不许静止）', () => {
    const unused = Object.keys(EXEMPTIONS).filter(
      (rel) => !rows.some((r) => r.rel === rel && !r.guarded)
    );
    expect(unused).toEqual([]);
  });
});

describe('豁免的行为根据（根据失效即红，不看文件名）', () => {
  afterEach(() => jest.restoreAllMocks());

  const drive = async (middleware, token) => {
    const req = {
      headers: token ? { authorization: `Bearer ${token}` } : {},
      body: {},
      ip: '203.0.113.7',
      method: 'POST',
      originalUrl: '/api/auth/logout',
      app: { get: () => undefined },
    };
    const res = {
      statusCode: null,
      payload: null,
      status(c) {
        this.statusCode = c;
        return this;
      },
      json(b) {
        this.payload = b;
        return this;
      },
    };
    const next = jest.fn();
    await middleware(req, res, next);
    return { passed: next.mock.calls.length === 1, status: res.statusCode, req, res };
  };

  /**
   * 「两把密钥被配成同值」时攻击者手里的那个东西：type:'refresh' 的载荷、用 access 密钥签名。
   * 不去改 `config.jwt.secret`（改了就得在全局对象上留一个时间窗，同文件里另一条用例会被它带偏），
   * 而是直接构造同形态的串——这与换密钥等价，因为同值拓扑下二者本来就是同一把。
   * 口径与 src/tests/utils/tokenPurposeAndConsumers.test.js 的 sign() 一致。
   */
  const refreshShapedOnAccessSecret = (jti) =>
    jwt.sign(
      { userId: 'inv-user', type: 'refresh', tokenVersion: 0, jti, sid: 'inv-sid' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

  test('用例②：登出入口那次未套判据的验签不授权——refresh 当 Bearer access 打登出 ⇒ 401', async () => {
    const token = refreshShapedOnAccessSecret('inv-logout');
    // 前提自证：这条串确实过得了 logoutAuth.js:92 那次（没套判据的）验签，
    // 否则本用例测的是"签名根本不对"，与用途判据无关。
    expect(jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] }).type).toBe('refresh');

    const { authenticateForLogout } = require('../../middleware/logoutAuth');
    const r = await drive(authenticateForLogout, token);
    expect(r.passed).toBe(false);
    expect(r.status).toBe(401);
    // 必须是"用途不符"这一条错误码：换成 401 的另一条原因（缺失/过期）本用例就不指错了
    expect(r.res.payload?.errors?.errorCode).toBe('AUTH_TOKEN_INVALID');
    // 而 req.user 根本没被构造：登出处理体读到的是 undefined，无从按身份吊销
    expect(r.req.user).toBeUndefined();
  });

  test('用例③：吊销路径少一道用途闸的失效方向是"多吊销"，不是"多放行"', async () => {
    const token = refreshShapedOnAccessSecret('inv-revoke');
    const spy = jest.spyOn(TokenBlacklist, 'findOneAndUpdate').mockResolvedValue(null);
    const ret = await authService.revokeTokensOnLogout({ accessToken: token });
    // 这条路径唯一的副作用就是把它写进黑名单（=让它更不可用），返回值里没有任何身份
    expect(spy).toHaveBeenCalledTimes(1);
    expect(Object.keys(ret)).toEqual(['revokeFailed']);
    expect(ret.revokeFailed).toBe(false);
  });
});
