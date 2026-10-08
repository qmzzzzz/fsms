'use strict';

/**
 * 【这台闸守什么】
 * 手册里的"验证步骤"必须**真的能失败**。`deployment/secret-rotation.md` 的 L-01 ① 有两处同根缺陷：
 *  ① 命令发的 cookie 名与服务端读的名字不匹配：手册写 `accessToken`，服务端只读
 *     `src/utils/cookie.js` 的 `ACCESS_COOKIE_NAME`（经 `src/middleware/auth.js` 的
 *     extractAccessToken 取用）。名字错时请求被当成"根本没带令牌"，而"没带令牌"与
 *     "令牌已失效"**同为 401**——判据于是永不失败。
 *  ② 判据只写"预期 401"，没有轮换前的正向对照：匿名请求同样 401，所以即便名字写对，
 *     这一条也证明不了任何事。
 * 两者的共同形状是"检查没跑"与"检查通过"输出完全一样。人读看不出来，只有把文档重放进代码才看得见。
 *
 * 【判据】
 *  A. Cookie 名契约——**行为比对，不抄字符串清单**：文档里每条 `Cookie: <name>=…` 与
 *     `curl -b <name>=…` 的 name，拼成真实请求头喂给服务端的读取点
 *     （access 走 `src/middleware/auth.js` 的 extractAccessToken，即 /api/auth/me 上
 *     authenticate 的第一步；refresh 走四处共用的 `getCookies(req)[REFRESH_COOKIE_NAME]`），
 *     断言至少有一条读取点取回原值。
 *     合法名集合由 `src/utils/cookie.js` 的 `*_COOKIE_NAME` 导出派生，且每个导出名必须有登记
 *     的读取点：改名时闸跟着文档一起动，加名时闸先要求登记，否则静默留出盲区。
 *  B. 负面判据必须自带对照：代码块里出现 401/403 这类"负面结论"时，同块必须给出
 *     200 级的正向对照，或给出同一状态码下可区分的 errorCode/AUTH_* 码。围栏外的散文不算。
 *
 * 【覆盖面与排除】
 *  扫描集 = deployment/*.md、docs/incident-response.md、README.md、SECURITY.md、
 *  migrations/README.md（与 runbookSecretSource 同一套"说明书"口径）。
 *  刻意排除 CHANGELOG.md、deliverables/、docs/adr/：记录里写"曾经错成 accessToken"是**证据**，
 *  不是可复制执行的指令；为了过闸改写它等于伪造现场。
 *
 * 【已知边界（有意不收的，写清楚免得下个读者以为收了）】
 *  - `Authorization: Bearer` 形态不受 A 约束：extractAccessToken 优先读它，与 cookie 名无关。
 *  - A 判的是**名字存不存在于服务端契约**，不判"这个名字配这个端点对不对"：
 *    把 refresh_token 发给 /api/auth/me 会过 A（名字合法）而实际 401。端点归属由
 *    cookie 的 path 属性（/api 与 /api/auth）与浏览器决定，脚本命令里的端点错配是另一类
 *    缺陷，不在本闸的收口范围——收进来需要"每条命令的目标端点"这层解析，收益不抵误判。
 *  - B 是文本判据，分不出"这样判"与"不要这样判"（同 runbookSecretSource 的取舍），所以按**块**
 *    收口：块内解释性的 401 也算触发面。代价由"同块自带对照或码级判据"吸收，
 *    不给"这条不算"的豁免口——豁免一旦能靠措辞触发，判据就等于没有。
 *
 * 【前提自证 / 反面自证】
 *  两条"真文档"腿各有地面，不是只等违例为空：Cookie 名 ≥1 且必须来自被修的那个文件；
 *  负面判据块 ≥1 且同样钉在该文件上，外加每篇扫描文档的**围栏行数必须为偶**——
 *  块边界靠奇偶追踪，实测证明一个裸 ``` 就能把缺陷块读成散文（401 原地不动而本腿绿），
 *  所以采集器自己的前提也得由文档证明。
 *  Cookie 通道按**写法**穷举：`-H`、`--header`、大写 `COOKIE:`、`-b/--cookie` 四条合成违例各点亮一次；
 *  合成合法文档判绿、合成缺陷文档判红且红在同一处；排除规则反向验证（围栏外的 401 散文、
 *  Authorization 头、Set-Cookie 字样都不被判为违例）；另把 ① 的**成立前提**钉住——
 *  AUTH_TOKEN_MISSING 与 AUTH_TOKEN_INVALID 的 status 同为 401，正因为如此才必须看 errorCode。
 */

const fs = require('fs');
const path = require('path');

const { extractAccessToken } = require('../../middleware/auth');
const { getCookies } = require('../../utils/cookie');
const cookie = require('../../utils/cookie');
const { ERROR_CODES } = require('../../utils/errorCodes');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const DOCS = [
  'README.md',
  'SECURITY.md',
  'migrations/README.md',
  'docs/incident-response.md',
  ...fs
    .readdirSync(path.join(ROOT, 'deployment'))
    .filter((f) => f.endsWith('.md'))
    .map((f) => `deployment/${f}`),
];

/** 合法 cookie 名：由被测模块自己导出，闸不另立清单 */
const COOKIE_NAME_EXPORTS = Object.keys(cookie).filter((k) => /_COOKIE_NAME$/.test(k));
const LEGAL_COOKIE_NAMES = COOKIE_NAME_EXPORTS.map((k) => cookie[k]);

/**
 * `-H "Cookie: a=1; b=2"` / `--header "Cookie: …"`：引号内的整串按 `;` 拆，每段取 `=` 前的名字。
 * `--header` 是 curl 的官方长写法，头部名按 HTTP 大小写不敏感（`COOKIE:` 同样有效）——
 * 这两种写法实测收不到时，手册只要换个写法就能绕开 A，而绕开的正是本闸要抓的那个错
 * （名字写成 accessToken）。所以按写法穷举，不收"应该没人这么写"。
 */
const H_COOKIE_RE = /(?:-H|--header)\s+(["'])\s*[Cc][Oo][Oo][Kk][Ii][Ee]:\s*([^"']+)\1/g;
/** `curl -b name=…` / `--cookie name=…` / `--cookie=name=…`（裸文件名不带 `=`，不匹配） */
const CURL_COOKIE_RE = /(?:^|[\s;&|`(])(?:-b|--cookie)\s*=?\s*["']?([A-Za-z_][A-Za-z0-9_.-]*)\s*=/g;

const cookieRefs = (doc, text) => {
  const seen = new Set();
  const out = [];
  const push = (line, name, form) => {
    const key = `${line}|${name}|${form}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ doc, line, name, form });
  };
  text.split(/\r?\n/).forEach((raw, i) => {
    for (const m of raw.matchAll(H_COOKIE_RE)) {
      for (const pair of m[2].split(';')) {
        const idx = pair.indexOf('=');
        if (idx <= 0) continue;
        const name = pair.slice(0, idx).trim();
        if (name) push(i + 1, name, '-H/--header "Cookie: …"');
      }
    }
    for (const m of raw.matchAll(CURL_COOKIE_RE)) push(i + 1, m[1], '-b/--cookie …=…');
  });
  return out;
};

const PROBE = 'runbook-probe-value';
const reqWithCookie = (name) => ({ headers: { cookie: `${name}=${PROBE}` } });

/**
 * 服务端读 cookie 的入口，一个名字一条：
 *  - access：`src/middleware/auth.js` 的 extractAccessToken（/api/auth/me 上 authenticate 的第一步）
 *  - refresh：refresh/logout/会话三处（authController）与 logoutAuth 的 authorizeByRefreshToken
 *    共用的表达式 `getCookies(req)[REFRESH_COOKIE_NAME]`——复用同一原语与同一常量，
 *    闸不另立第二份名字清单。
 */
const READERS = [
  { key: 'ACCESS_COOKIE_NAME', read: extractAccessToken },
  {
    key: 'REFRESH_COOKIE_NAME',
    read: (req) => getCookies(req)[cookie.REFRESH_COOKIE_NAME] || null,
  },
];

/** 这条文档命令发出的名字，服务端有没有任何一处读得到 */
const servedToken = (name) => {
  const req = reqWithCookie(name);
  return READERS.some((r) => r.read(req) === PROBE) ? PROBE : null;
};

const cookieViolations = (refs) => refs.filter((r) => servedToken(r.name) !== PROBE);
const formatViolation = (v) =>
  `${v.doc}:${v.line} 发的是 ${v.name}｜服务端读的是 ${LEGAL_COOKIE_NAMES.join(' / ')}`;

const FENCE_RE = /^\s*(?:```|~~~)/;
const NEGATIVE_VERDICT = /\b40[13]\b/;
const POSITIVE_CONTROL = /\b200\b/;
const CODE_LEVEL_VERDICT = /errorCode|AUTH_[A-Z_]+/;

/**
 * 把文档切成围栏代码块。**只有成对 ``` 之间的内容算块**——
 * 围栏奇偶一旦不追踪，散文里的一句"接口返回 401"就会被当成命令块（实测：README.md 的
 * 405–452 段会被拼成一个"块"），判据从"检查命令"退化成"检查文档里有没有出现 401"。
 * 未闭合的尾段仍收：那是笔误，宁可多判。
 */
const fencedBlocks = (text) => {
  const blocks = [];
  let inFence = false;
  let cur = null;
  text.split(/\r?\n/).forEach((raw, i) => {
    if (FENCE_RE.test(raw)) {
      if (inFence) {
        blocks.push(cur);
        cur = null;
        inFence = false;
      } else {
        cur = { start: i + 1, lines: [] };
        inFence = true;
      }
      return;
    }
    if (inFence) cur.lines.push(raw);
  });
  if (inFence && cur) blocks.push(cur);
  return blocks;
};

const uncontrolledBlocks = (doc, text) =>
  fencedBlocks(text)
    .filter(
      (b) =>
        b.lines.some((l) => NEGATIVE_VERDICT.test(l)) &&
        !b.lines.some((l) => POSITIVE_CONTROL.test(l) || CODE_LEVEL_VERDICT.test(l))
    )
    .map((b) => ({ doc, line: b.start }));

const allCookieRefs = () => DOCS.flatMap((d) => cookieRefs(d, read(d)));
const allUncontrolled = () => DOCS.flatMap((d) => uncontrolledBlocks(d, read(d)));

const ROTATION_DOC = 'deployment/secret-rotation.md';

test('前提自证｜cookie.js 每导出一个名字，闸就有一条对应的读取点', () => {
  expect(COOKIE_NAME_EXPORTS.length).toBeGreaterThanOrEqual(2);
  expect(new Set(LEGAL_COOKIE_NAMES).size).toBe(COOKIE_NAME_EXPORTS.length);
  // 有人往 cookie.js 加第三个名字而没在这里登记读取点 ⇒ 这里红，闸不会静默留出盲区
  expect(READERS.map((r) => r.key).sort()).toEqual([...COOKIE_NAME_EXPORTS].sort());
  for (const { key, read } of READERS) {
    const name = cookie[key];
    expect(typeof name).toBe('string');
    expect(read(reqWithCookie(name))).toBe(PROBE);
    // 每条读取点只认自己那一个名字（refresh 当 access 发取不到，是边界不是漏判）
    for (const other of LEGAL_COOKIE_NAMES.filter((n) => n !== name))
      expect(read(reqWithCookie(other))).toBeNull();
  }
});

test('真文档｜手册里发出的每个 Cookie 名，认证中间件都取得到令牌（照抄即可用）', () => {
  const refs = allCookieRefs();
  expect(refs.length).toBeGreaterThanOrEqual(1);
  // 被修的这条必须仍在扫描面内：文档被删/改名也应让闸显式红，而不是静默绿
  expect(refs.some((r) => r.doc === ROTATION_DOC)).toBe(true);
  expect(cookieViolations(refs).map(formatViolation)).toEqual([]);
});

test('真文档｜每个"负面判据"代码块都自带正向对照或码级判据', () => {
  // 采集器自己的前提先钉住：块的边界靠围栏奇偶，奇偶一错，缺陷块就被读成"散文"。
  // 实测（祸害恒定）：删掉对照行 ⇒ 本腿红；401 文本原样不动、只在该块开围栏前插一行裸 ``` ⇒ 本腿绿。
  // 一个字符能抹掉判据，所以"我检查过"必须由文档自己证明，不能靠违例列表为空。
  expect(
    DOCS.map((d) => ({
      doc: d,
      n: read(d)
        .split(/\r?\n/)
        .filter((l) => FENCE_RE.test(l)).length,
    }))
      .filter((x) => x.n % 2 !== 0)
      .map((x) => `${x.doc} 围栏行=${x.n}(奇数)：块边界不可追踪，本腿在它上面无效`)
  ).toEqual([]);
  // 覆盖面地面，与"真文档 Cookie 名"那条同形：闸必须知道自己确实检查过东西。
  const negBlocks = DOCS.flatMap((d) =>
    fencedBlocks(read(d))
      .filter((b) => b.lines.some((l) => NEGATIVE_VERDICT.test(l)))
      .map((b) => ({ doc: d, line: b.start }))
  );
  expect(negBlocks.length).toBeGreaterThanOrEqual(1);
  expect(negBlocks.some((b) => b.doc === ROTATION_DOC)).toBe(true);
  expect(
    allUncontrolled().map(
      (b) => `${b.doc}:${b.line} 起的代码块断言 401/403 却无 200/errorCode 对照`
    )
  ).toEqual([]);
});

test('缺陷前提｜401 不可区分：令牌缺失与验签失败同码，所以判据只能取 errorCode', () => {
  // ① 之所以能"永远通过"，前提是两种失败同状态码。若哪天状态码被分开，本用例先红，
  //    提示 B 判据的强度可以降级——前提变了，建在前提上的闸不能继续装作没事。
  expect(ERROR_CODES.AUTH_TOKEN_MISSING.status).toBe(401);
  expect(ERROR_CODES.AUTH_TOKEN_INVALID.status).toBe(401);
  expect(formatViolation({ doc: 'd.md', line: 1, name: 'accessToken' })).toContain(
    cookie.ACCESS_COOKIE_NAME
  );
});

test('反面自证｜缺陷形状（accessToken）判红、修好后的形状判绿，两条通道都覆盖', () => {
  const wrong = [
    '```bash',
    'curl -s -o /dev/null -w "%{http_code}" -H "Cookie: accessToken=T" "$D"',
    'curl -s -b accessToken=T "$D"',
    // 同一错误的另外两种合法写法：漏任何一种，手册改个写法就能绕过 A
    'curl -s --header "Cookie: accessToken=T" "$D"',
    'curl -s -H "COOKIE: accessToken=T" "$D"',
    '```',
  ].join('\n');
  const wrongRefs = cookieRefs('syn.md', wrong);
  expect(wrongRefs).toHaveLength(4);
  expect(wrongRefs.map((r) => r.form)).toEqual([
    '-H/--header "Cookie: …"',
    '-b/--cookie …=…',
    '-H/--header "Cookie: …"',
    '-H/--header "Cookie: …"',
  ]);
  expect(cookieViolations(wrongRefs).map((v) => v.name)).toEqual([
    'accessToken',
    'accessToken',
    'accessToken',
    'accessToken',
  ]);

  const right = wrong.replace(/accessToken/g, cookie.ACCESS_COOKIE_NAME);
  const rightRefs = cookieRefs('syn.md', right);
  expect(rightRefs).toHaveLength(4);
  expect(cookieViolations(rightRefs)).toEqual([]);
});

test('反面自证｜只断言 401 的块判红，补上正向对照或码级判据即判绿', () => {
  const bare = ['```bash', 'curl -s -o /dev/null -w "%{http_code}" "$D"   # 预期 401', '```'].join(
    '\n'
  );
  expect(uncontrolledBlocks('syn.md', bare)).toHaveLength(1);

  const withControl = [
    '```bash',
    'curl -s -o /dev/null -w "%{http_code}" "$D"   # 预期 401',
    '# 轮换前 200',
    '```',
  ].join('\n');
  expect(uncontrolledBlocks('syn.md', withControl)).toEqual([]);

  const withCode = [
    '```bash',
    'curl -s "$D"   # 预期 401 + errorCode AUTH_TOKEN_INVALID',
    '```',
  ].join('\n');
  expect(uncontrolledBlocks('syn.md', withCode)).toEqual([]);
});

test('排除规则反向验证｜散文里的 401、Authorization 头、Set-Cookie 字样都不是违例', () => {
  const prose = [
    '- **接口返回 401**：令牌过期时刷新',
    '```bash',
    'curl -H "Authorization: Bearer x" "$D"',
    'curl -s "$D"   # 200',
    '```',
    '响应头 `Set-Cookie（httpOnly）` 由服务端下发',
  ].join('\n');
  expect(uncontrolledBlocks('syn.md', prose)).toEqual([]);
  expect(cookieRefs('syn.md', prose).map((r) => r.name)).toEqual([]);
});
