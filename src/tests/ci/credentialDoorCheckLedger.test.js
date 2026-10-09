'use strict';

/**
 * 凭证门与账户可校验：谁在铸造/校验凭证，它有没有复查账户状态（机器差集 + 双向登记）
 *
 * 起因（第 23 轮主动审计线）：全仓有 14 个"铸造或校验凭证"的调用点，分布在 7 个文件里。
 * 其中 `services/authService.js` 的 `refreshSession` 校验了 `status !== 'active'`，
 * 却**没有**校验 `lockUntil`；而另外三扇门（`loginUser`、`middleware/auth.js` 的
 * `assertAccountUsable`、websocket 票据）都校验了。这个不对称本身不是可利用漏洞
 * （refresh 换出来的 access 令牌仍会被 `assertAccountUsable` 拒掉），真正的问题是：
 * **没有任何东西把"门的集合"与"每扇门该做哪些复查"钉在一起**，所以它到底是决策还是疏漏，
 * 只有同时读过四个函数的人才能回答——而下一扇新门（新的铸造点）出现时，没人会想起来问。
 *
 * 本闸做三件事：
 *  1. 采集器扫全仓生产码，把每个 `generateToken(` / `generateRefreshToken(` / `jwt.verify(`
 *     归到**包它的函数**上（不是按文件名，也不是按行号——见第 5 族：一个闸的覆盖面
 *     等于它采集器的覆盖面）。注释行必须先剥掉，否则 `// 原先 refresh 一路 jwt.verify(…)`
 *     这类历史注释会凭空造出一扇门。
 *  2. 把"门集合"与"每扇门的复查形状"**双向**钉死：多一扇没登记的门要红，
 *     少一扇（把门改名/搬走而不动台账）也要红；台账里声明的
 *     `{mint, checksStatus, checksLock}` 必须等于代码里实测到的，否则红。
 *     ⇒ 谁给 `refreshSession` 补上 `lockUntil` 检查，本闸立刻红着要求他把豁免条目删掉，
 *     而不是让一条过期豁免永久留在表里（登记即接线）。
 *  3. 钉住 `assertAccountUsable` 的**判定顺序**：`middleware/auth.js` 的注释写着
 *     "顺序不能颠倒：locked 必须在兜底分支之前，否则锁定账户拿到『已禁用』文案"。
 *     这句是纯文字承诺，今天没有任何用例能因它被违反而变红。本闸把它做成可杀判据。
 *
 * 自证（防第 1 族：判据在自证里被重抄一遍）：`collectDoors` / `bodyOf` 从本文件导出，
 * 真实树与合成反例**走同一条函数**；负控用的是"喂给采集器一张假文件表"，
 * 而不是另写一份尺子。
 *
 * 一条本仓特有的实现约束（实测，不是通用建议）：仓库行尾混用——`services/authService.js`
 * 与 `middleware/auth.js` 是 CRLF，`middleware/logoutAuth.js` 是 LF。
 * 所以本闸所有分行一律 `split(/\r?\n/)`，跨行匹配前先按目标文件自己的行尾归一；
 * 用 `split('\n')` 的静态闸在 CRLF 文件上会把 `\r` 留在行尾，`$` 锚与"整行相等"判据静默失效。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../..');
const MINT_OR_VERIFY = /(?:\bgenerateToken\(|\bgenerateRefreshToken\(|\bjwt\.verify\()/;

/** 剥掉行注释与块注释，保持行号不变（第 6 族要求：本闸要报 `文件:行`） */
function stripCommentsPreserveLines(src) {
  const out = [];
  let inBlock = false;
  for (const line of src.split(/\r?\n/)) {
    if (inBlock) {
      out.push('');
      if (line.includes('*/')) inBlock = false;
      continue;
    }
    const t = line.trimStart();
    if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) {
      if (t.startsWith('/*') && !t.includes('*/')) inBlock = true;
      out.push('');
      continue;
    }
    out.push(line);
  }
  return out.join('\n');
}

/** 生产码 js 文件（与仓内其余静态闸同口径：跳过 tests 与 node_modules） */
function listProdFiles(dir = ROOT, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'tests') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) listProdFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

const FN_FORMS = [
  /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)/,
  /^\s*(?:export\s+)?const\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z0-9_$]+)\s*=>/,
  /^\s*(?:export\s+)?const\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?function\b/,
  /^\s{2}([A-Za-z0-9_$]+)\s*:\s*(?:async\s*)?function\b/,
  /^\s{2}(?:async\s+)?([A-Za-z0-9_$]+)\s*\([^)]*\)\s*\{/,
];

/** `^\s{2}name(...)` 这类形状会把 `if (…) {` 当成函数名——控制流关键字必须排除 */
const NOT_A_FUNCTION = new Set([
  'if',
  'for',
  'while',
  'switch',
  'catch',
  'return',
  'else',
  'try',
  'do',
  'function',
  'const',
  'let',
  'var',
]);

/** 向上找包住房第一行的函数名与其起始行 */
function enclosingFunction(lines, idx) {
  for (let i = idx; i >= 0; i -= 1) {
    for (const re of FN_FORMS) {
      const m = lines[i].match(re);
      if (m && !NOT_A_FUNCTION.has(m[1]) && !MINT_OR_VERIFY.test(lines[i]))
        return { name: m[1], start: i };
    }
  }
  return { name: '<module>', start: 0 };
}

/** 从函数起始行做花括号配对，取出函数体（含签名行） */
function bodyOf(lines, start) {
  let depth = 0;
  let seen = false;
  const parts = [];
  for (let i = start; i < lines.length; i += 1) {
    parts.push(lines[i]);
    for (const ch of lines[i]) {
      if (ch === '{') {
        depth += 1;
        seen = true;
      } else if (ch === '}') depth -= 1;
    }
    if (seen && depth <= 0) break;
  }
  return parts.join('\n');
}

/** 采集：文件 → 门（同一函数里的多个铸造点合并为一扇门） */
function collectDoors(files) {
  const doors = new Map();
  for (const { name, text } of files) {
    const clean = stripCommentsPreserveLines(text);
    const lines = clean.split(/\r?\n/);
    lines.forEach((line, i) => {
      if (!MINT_OR_VERIFY.test(line)) return;
      const { name: fn, start } = enclosingFunction(lines, i);
      const key = `${name}#${fn}`;
      if (!doors.has(key)) {
        const body = bodyOf(lines, start);
        doors.set(key, {
          file: name,
          fn,
          lines: [],
          mint: /\bgenerate(?:Refresh)?Token\(/.test(body),
          verify: /\bjwt\.verify\(/.test(body),
          checksLock: /\blockUntil\b/.test(body),
          checksStatus: /\bstatus\s*[!=]==?\s*|USER_STATUS\./.test(body),
        });
      }
      doors.get(key).lines.push(i + 1);
    });
  }
  return doors;
}

/**
 * 台账（双向钉死）。列的语义**只有"自身函数体里有没有"**——采集器不做跨函数数据流，
 * 所以 `checksLock: false` 不等于"这扇门放行锁定账户"，它等于"这道关不在它自己身上，
 * 而在 `lockWhere` 点名的地方"。`why` 必须写成能被拿去问人的具体句子，不接受"历史原因/待定"。
 *
 * role：entry = 直接受理**客户端送来**的凭证（HTTP 中间件 / WS 票据 / 服务入口），
 *       primitive = 只被仓内代码调用的签发或验签原语。
 * 这个区分是判据的一部分（第 5、7 条用例只统计 entry 门），所以把 primitive 改成 entry
 * 或反之，都会改变判据的结论 ⇒ 而不是改变一条注释。
 *
 * verdict（只有"裸 entry 门"必须填，取值见 VERDICTS）：
 *   deliberate-waiver = 仓里已有成文的理由说明这道关**必须**不在这扇门做；
 *   needs-decision    = 现状与同族门不一致，缺的是哪道关已实测写清，等 owner 拍板。
 * 这个字段是判据：第 5 条用例按它分区，把 waiver 改成 needs-decision（或反之）会立刻红，
 * 所以它不能用来给"我懒得查"背书。
 */
const VERDICTS = ['deliberate-waiver', 'needs-decision'];
const LEDGER = {
  'middleware/auth.js#authenticate': {
    role: 'entry',
    mint: false,
    verify: true,
    checksStatus: false,
    checksLock: false,
    lockWhere: 'middleware/auth.js#assertAccountUsable',
    why:
      '每请求主门：账户复查委托给同文件的 assertAccountUsable（tokenVersion/status/lockUntil 三连），' +
      '本条第 6 个用例专门钉它内部的**判定顺序**',
  },
  'middleware/logoutAuth.js#authorizeByRefreshToken': {
    role: 'primitive',
    mint: false,
    verify: true,
    checksStatus: false,
    checksLock: false,
    lockWhere: null,
    why:
      '登出前置：只看"这把 refresh 令牌是不是真的、属于谁"，不判账户档——' +
      '登出是 refresh 令牌与设备会话的唯一吊销入口，access 先于 refresh 过期是常态，' +
      '在此加账户复查会让锁定/禁用账户再也清不掉自己手里的令牌（比留着更危险）',
  },
  'middleware/logoutAuth.js#authenticateForLogout': {
    role: 'entry',
    mint: false,
    verify: true,
    checksStatus: false,
    checksLock: false,
    lockWhere: null,
    verdict: 'deliberate-waiver',
    why: '同上：登出入口必须对已过期/已锁定账户同样开放，否则吊销通道被账户状态挡住',
  },
  'services/authService.js#issueRevocableTokenPair': {
    role: 'primitive',
    mint: true,
    verify: false,
    checksStatus: false,
    checksLock: false,
    lockWhere: 'services/authService.js#assertAccountUsable',
    why:
      '签发原语，实测只有两个调用点：services/authService.js:181（registerUser） 与 services/authService.js:864（issueLoginSession）。' +
      '登录链的账户复查在 services/authService.js:250（loginUser） 委托的 services/authService.js:330（assertAccountUsable，lockUntil 判定在 services/authService.js:356）' +
      '——注意 loginUser **自己函数体内没有** lockUntil/status（实测），所以委托对象必须写这道关真正落笔的函数；' +
      '注册链的账户是本次 services/authService.js:166（User.create） 新建的文档，lockUntil 不存在。' +
      '注意本闸不做跨函数数据流：若将来把注册改成"允许认领既有账号"，没有用例会自动变红，' +
      '这条豁免要**人工**重登（这是登记式台账的固有盲区，写明以免被当成"闸会提醒我"）',
  },
  'services/authService.js#refreshSession': {
    role: 'entry',
    mint: true,
    verify: true,
    checksStatus: true,
    checksLock: false,
    lockWhere: null,
    verdict: 'needs-decision',
    why:
      '【本闸要人看的不对称，实测非推测】刷新门在自己函数体里查了 status（:924 ' +
      "`user.status !== 'active'`）、allowedIPs、passwordChangedAt、tokenVersion 与设备会话，" +
      '唯独不查 lockUntil ⇒ 临时锁定期间仍可轮换出新一对凭证。' +
      '今天不构成提权：换出来的 access 令牌一进 authenticate 就被 assertAccountUsable 的 lockUntil 分支拒掉。' +
      '这里钉的是**现状**而不是"这样才对"。补检查属行为变更（锁定用户的前端会在 10 分钟里连 cookie 都换不动），' +
      '需 owner 拍板；拍板补上之后请把本条改成 checksLock: true —— 本闸会红着提醒你别忘改台账',
  },
  'services/authService.js#revokeOneRefreshToken': {
    role: 'primitive',
    mint: false,
    verify: true,
    checksStatus: false,
    checksLock: false,
    lockWhere: null,
    why: '吊销路径的原子消费原语：越"不检查账户状态"越好，禁用/锁定账户也必须能完成吊销',
  },
  'services/authService.js#revokeTokensOnLogout': {
    role: 'primitive',
    mint: false,
    verify: true,
    checksStatus: false,
    checksLock: false,
    lockWhere: null,
    why: '同上：登出批量吊销，不该被账户档挡住',
  },
  'services/tokenService.js#isAccessTokenValid': {
    role: 'entry',
    mint: false,
    verify: true,
    checksStatus: true,
    checksLock: false,
    lockWhere: null,
    verdict: 'needs-decision',
    why:
      '第二个同形不对称（本轮实测才发现，原先我只知道 refresh 这一处）：它查了 ' +
      "`user.status !== 'active'`（services/tokenService.js:85-86）却不查 lockUntil。" +
      '调用点本轮已复核（上一条登记里写的"未复核"是当时的状态，现已补齐）：全仓只有 ' +
      'controllers/authController.js:560 一处，属于 GET /api/auth/session 的会话预筛，' +
      '它把返回值直接当作 `authenticated` 布尔量，不签发/不轮换/不吊销（该端点注释自陈' +
      '"安全结论以 getMe 为准"）。⇒ 影响面钉死为"锁定账户在该端点被报成已登录，' +
      '随后 getMe 才 401"，不是凭证可达性放开。要不要在这两个布尔预检里补 lockUntil，' +
      '与 refreshSession 是同一个口径决定，所以三条一起登记为 needs-decision',
  },
  'services/tokenService.js#isRefreshTokenValid': {
    role: 'entry',
    mint: false,
    verify: true,
    checksStatus: true,
    checksLock: false,
    lockWhere: null,
    verdict: 'needs-decision',
    why:
      '同上（:102-103 同一形状）：查 status 不查 lockUntil。调用点实测只有 ' +
      'controllers/authController.js:562 一处（同一端点的 access 失效分支），' +
      '返回布尔量给"是否已登录"提示',
  },
  'services/websocketService.js#authenticateSocket': {
    role: 'entry',
    mint: false,
    verify: true,
    checksStatus: true,
    checksLock: true,
    lockWhere: 'self',
    why: 'WS 票据门：与 HTTP 同口径，唯一一道把 status 与 lockUntil 都写在自己函数体里的门（第 5 轮同源修复）',
  },
};

const realFiles = () =>
  listProdFiles().map((f) => ({
    name: path.relative(ROOT, f).replace(/\\/g, '/'),
    text: fs.readFileSync(f, 'utf8'),
  }));

/** 按 `文件#函数名` 取回函数体：用于把 `lockWhere` 点名的委托对象**真的**验一遍 */
function bodyFor(cleanFiles, key) {
  const [file, fn] = key.split('#');
  const f = cleanFiles.find((x) => x.name === file);
  if (!f) return null;
  const lines = f.clean.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    for (const re of FN_FORMS) {
      const m = lines[i].match(re);
      if (m && m[1] === fn && !NOT_A_FUNCTION.has(m[1])) return bodyOf(lines, i);
    }
  }
  return null;
}

const realClean = () =>
  realFiles().map((f) => ({ name: f.name, clean: stripCommentsPreserveLines(f.text) }));

const doors = collectDoors(realFiles());
const measuredKeys = [...doors.keys()].sort();
const registeredKeys = Object.keys(LEDGER).sort();

describe('凭证门集合与账户复查形状（双向登记 + 判定顺序）', () => {
  test('前提自证：采集器在真实树上确实扫到足量门，且注释里的同名字面串不被收成门（防空集假绿）', () => {
    expect(measuredKeys.length).toBeGreaterThanOrEqual(8);
    // 反向对照（合成表走同一条 collectDoors，不是另写一把尺子）：
    // 一条注释里的 jwt.verify( 必须被剥掉，而一条真代码必须被收进来
    const synthetic = collectDoors([
      {
        name: 'x/history.js',
        text: [
          '// 历史注释提到 jwt.verify( 的老写法',
          'function withComment() {',
          '  // const t = generateToken(u);',
          '  return true;',
          '}',
          'function realDoor() {',
          '  return jwt.verify(sig, secret);',
          '}',
        ].join('\n'),
      },
    ]);
    expect([...synthetic.keys()].sort()).toEqual(['x/history.js#realDoor']);
    expect(synthetic.has('x/history.js#withComment')).toBe(false);
  });

  test('门集合双向相等：新增一扇没登记的门要红，把门改名/搬走而不动台账也要红', () => {
    const unregistered = measuredKeys.filter((k) => !registeredKeys.includes(k));
    const stale = registeredKeys.filter((k) => !measuredKeys.includes(k));
    expect({ unregistered, stale }).toEqual({ unregistered: [], stale: [] });
  });

  test('每扇门的复查形状实测等于台账声明（改名/搬动/加检查都必须同步台账）', () => {
    for (const key of registeredKeys) {
      const declared = LEDGER[key];
      const m = doors.get(key);
      expect({
        key,
        mint: m && m.mint,
        verify: m && m.verify,
        checksStatus: m && m.checksStatus,
        checksLock: m && m.checksLock,
      }).toEqual({
        key,
        mint: declared.mint,
        verify: declared.verify,
        checksStatus: declared.checksStatus,
        checksLock: declared.checksLock,
      });
    }
  });

  test('lockWhere 点名的委托对象必须真的存在、真的做这道关（防止豁免指向一个已被改名/删掉的函数）', () => {
    const clean = realClean();
    for (const key of registeredKeys) {
      const where = LEDGER[key].lockWhere;
      if (!where || where === 'self') continue;
      const body = bodyFor(clean, where);
      expect({ key, where, exists: body !== null }).toEqual({ key, where, exists: true });
      expect(body).toMatch(/lockUntil|status\s*!==|USER_STATUS\./);
    }
    // WS 门声明 lockWhere:'self' ⇒ 复查必须真的在自己函数体里（否则声明与实测相反）
    const ws = doors.get('services/websocketService.js#authenticateSocket');
    expect(ws.checksLock).toBe(true);

    // 同名委托实测有**两份实现**（本仓的命名冲突，实测不是推测）：
    // services/authService.js:330 的 assertAccountUsable 是 async、带口令/风控入参并会写审计；
    // middleware/auth.js:283 的同名函数是同步的 res 错误码助手，只看账户档。
    // ⇒ 本闸的 lockWhere 一律要求"文件限定"，`assertAccountUsable` 这种裸名指向不了任何一处。
    const svcBody = bodyFor(clean, 'services/authService.js#assertAccountUsable');
    const mwBody = bodyFor(clean, 'middleware/auth.js#assertAccountUsable');
    expect(typeof svcBody).toBe('string');
    expect(typeof mwBody).toBe('string');
    expect(svcBody).not.toBe(mwBody);
    expect(svcBody).toMatch(/password/);
    expect(mwBody).not.toMatch(/\bpassword\b/);
  });

  test('裸门名单：实测「自己体内无 lockUntil、也没有委托对象」的 entry 门精确 4 条，且每条必须带 verdict', () => {
    // 用**实测形状**筛，不用台账声明筛（声明由第 3 条用例与实测对齐；这里再走一遍采集器口径）
    const naked = measuredKeys
      .filter((k) => {
        const d = LEDGER[k];
        const m = doors.get(k);
        return d.role === 'entry' && m && !m.checksLock && !d.lockWhere;
      })
      .sort();
    expect(naked).toEqual([
      'middleware/logoutAuth.js#authenticateForLogout',
      'services/authService.js#refreshSession',
      'services/tokenService.js#isAccessTokenValid',
      'services/tokenService.js#isRefreshTokenValid',
    ]);
    for (const k of naked) expect(VERDICTS).toContain(LEDGER[k].verdict);

    // needs-decision 三条是一个可实测的同形家族：**查了 status 却不查 lockUntil**。
    // 这条判据的用处：给这三扇门的任意一扇补上 lockUntil 检查，本用例立刻红，
    // 要求把它从名单里删掉（而不是留一条已经失效的"待决"记录骗过后人）。
    const needsDecision = naked.filter((k) => LEDGER[k].verdict === 'needs-decision').sort();
    expect(needsDecision).toEqual([
      'services/authService.js#refreshSession',
      'services/tokenService.js#isAccessTokenValid',
      'services/tokenService.js#isRefreshTokenValid',
    ]);
    for (const k of needsDecision) {
      expect(doors.get(k).checksStatus).toBe(true);
      // verdict 不是换个名字的注释：理由里必须点明缺的是哪道关
      expect(LEDGER[k].why).toMatch(/lockUntil/);
    }

    // deliberate-waiver 反过来必须"两样都不查"（实测），否则"必须对不可用账户开放"这条理由不成立；
    // 今天只有登出前置门满足，名单外多一条就要红
    const waivers = naked.filter((k) => LEDGER[k].verdict === 'deliberate-waiver');
    expect(waivers).toEqual(['middleware/logoutAuth.js#authenticateForLogout']);
    expect(doors.get(waivers[0]).checksStatus).toBe(false);
    expect(LEDGER[waivers[0]].why).toMatch(/登出|吊销/);
  });

  test('钉住 middleware/auth.js#assertAccountUsable 的判定顺序：locked 在 active 兜底之前、lockUntil 在其后（此前只是注释里的承诺）', () => {
    // 取"定义"必须走与采集器同一套 FN_FORMS。上一版这里用 findIndex(/assertAccountUsable\s*[=(]/)，
    // 实测命中的是 :230 的**调用行**（findIndex=229 而非 -1），从调用行做花括号配对圈到的是无关块
    // ⇒ 顺序判据会在"看起来在测 assertAccountUsable"的前提下测别的代码（第 8 族：按名字探测）。
    const body = bodyFor(realClean(), 'middleware/auth.js#assertAccountUsable');
    expect(typeof body).toBe('string');
    const iLocked = body.search(/USER_STATUS\.LOCKED/);
    const iActive = body.search(/USER_STATUS\.ACTIVE/);
    const iTemp = body.search(/lockUntil\b/);
    expect(iLocked).toBeGreaterThanOrEqual(0);
    expect(iActive).toBeGreaterThanOrEqual(0);
    expect(iTemp).toBeGreaterThanOrEqual(0);
    // 颠倒顺序 = 锁定账户收到"已禁用"文案（注释 :293 自己声明的失败形态）
    expect(iLocked).toBeLessThan(iActive);
    // 临时锁必须真的参与判定，而不是只出现在注释里（注释已被剥掉，这里只剩代码）
    expect(body.slice(iTemp, iTemp + 120)).toMatch(/ACCOUNT_TEMP_LOCKED/);
  });

  test('refreshSession 是唯一"受理客户端凭证 + 铸造新凭证 + 不看 lockUntil"的 entry 门——多于一条即红', () => {
    const minting = registeredKeys.filter(
      (k) => LEDGER[k].role === 'entry' && LEDGER[k].mint && !LEDGER[k].checksLock
    );
    expect(minting).toEqual(['services/authService.js#refreshSession']);
    // 结论必须由实测支撑而不是只读台账：实测的 mint/lock 形状要与声明一致
    const m = doors.get('services/authService.js#refreshSession');
    expect({ mint: m.mint, lock: m.checksLock, status: m.checksStatus }).toEqual({
      mint: true,
      lock: false,
      status: true,
    });
  });
});

module.exports = { collectDoors, bodyOf, stripCommentsPreserveLines, LEDGER, doors, measuredKeys };
