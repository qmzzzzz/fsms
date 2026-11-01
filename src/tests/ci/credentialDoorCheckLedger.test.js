'use strict';

/**
 * 凭证门与账户可校验：谁在铸造/校验凭证，它有没有复查账户状态（机器差集 + 双向登记）
 *
 * 起因（第 23 轮主动审计线）：全仓有 14 个"铸造或校验凭证"的调用点，分布在 7 个文件里。
 * 其中 `services/authService/token.js` 的 `refreshSession` 当时校验了 `status !== 'active'`，
 * 却**没有**校验 `lockUntil`；而另外三扇门（`loginUser`、`middleware/auth.js` 的
 * `assertAccountUsable`、websocket 票据）都校验了。该不对称已补齐（refreshSession 与两个
 * tokenService 探测门现在都查 lockUntil），真正的问题是：
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
 *     ⇒ 谁给某扇门补上/删掉复查，本闸立刻红着要求台账同步（refreshSession 的
 *     豁免就是这样删掉的），而不是让一条过期豁免永久留在表里（登记即接线）。
 *  3. 钉住 `assertAccountUsable` 的**判定顺序**：`middleware/auth.js` 的注释写着
 *     "顺序不能颠倒：locked 必须在兜底分支之前，否则锁定账户拿到『已禁用』文案"。
 *     这句是纯文字承诺，今天没有任何用例能因它被违反而变红。本闸把它做成可杀判据。
 *
 * 自证（防第 1 族：判据在自证里被重抄一遍）：`collectDoors` / `bodyOf` 从本文件导出，
 * 真实树与合成反例**走同一条函数**；负控用的是"喂给采集器一张假文件表"，
 * 而不是另写一份尺子。
 *
 * 一条本仓特有的实现约束（实测，不是通用建议）：仓库行尾混用——`services/authService/*.js`
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

/**
 * `start` 起的花括号块是否真的包住了 `target` 行。
 *
 * 为什么需要：`enclosingFunction` 只向上找"最近的函数形态行"，而函数体内可以先定义
 * 一个内联箭头助手（如 `refreshSession` 里的 `const deny = async (...) => {...}`）。
 * 助手的签名行同样是 `const X = async (...) =>`，会被当成"包住铸造点的函数"，
 * 于是 generateToken 那一行被归到 `#deny` 名下、凭空多出一扇没有凭据操作的门
 * （2026-10-25 实测：`services/authService/token.js#deny` + 台账 TypeError）。
 * 判据必须是"该函数的块真的延伸到这个行"，而不是"它出现在上面"。
 */
function spansLine(lines, start, target) {
  let depth = 0;
  let seen = false;
  for (let i = start; i < lines.length; i += 1) {
    for (const ch of lines[i]) {
      if (ch === '{') {
        depth += 1;
        seen = true;
      } else if (ch === '}') depth -= 1;
    }
    if (seen && depth <= 0) return target <= i;
  }
  return false;
}

/** 向上找包住房第一行的函数名与其起始行 */
function enclosingFunction(lines, idx) {
  for (let i = idx; i >= 0; i -= 1) {
    for (const re of FN_FORMS) {
      const m = lines[i].match(re);
      if (
        m &&
        !NOT_A_FUNCTION.has(m[1]) &&
        !MINT_OR_VERIFY.test(lines[i]) &&
        spansLine(lines, i, idx)
      )
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
  'services/authService/session.js#issueRevocableTokenPair': {
    role: 'primitive',
    mint: true,
    verify: false,
    checksStatus: false,
    checksLock: false,
    lockWhere: 'services/authService/login.js#assertAccountUsable',
    why:
      '签发原语，实测只有两个调用点：eervices/authService/session.js:127（registerUser） 与 services/authService/session.js:209（issueLoginSession）。' +
      '登录链的账户复查在 services/authService/login.js:116（loginUser） 委托的 services/authService/login.js:218（assertAccountUsable，lockUntil 判定在 services/authService/login.js:244）' +
      '——注意 loginUser **自己函数体内没有** lockUntil/status（实测），所以委托对象必须写这道关真正落笔的函数；' +
      '注册链的账户是本次 services/authService/session.js:109（User.create） 新建的文档，lockUntil 不存在。' +
      '注意本闸不做跨函数数据流：若将来把注册改成"允许认领既有账号"，没有用例会自动变红，' +
      '这条豁免要**人工**重登（这是登记式台账的固有盲区，写明以免被当成"闸会提醒我"）',
  },
  'services/authService/token.js#refreshSession': {
    role: 'entry',
    mint: true,
    verify: true,
    checksStatus: true,
    checksLock: true,
    lockWhere: 'self',
    why:
      '刷新门在自己的函数体里查 status、lockUntil、allowedIPs、passwordChangedAt、tokenVersion 与设备会话。' +
      'lockUntil 检查在本轮补齐：临时锁定期间 refresh 此前仍能轮换出新一对凭证，' +
      '换出来的 access 虽会被 authenticate 拒掉，但客户端会陷入"刷新成功却始终 403"的空转；' +
      '现在直接以 ACCOUNT_LOCKED 拒绝，与 loginUser / authenticate 同口径',
  },
  'services/authService/token.js#revokeOneRefreshToken': {
    role: 'primitive',
    mint: false,
    verify: true,
    checksStatus: false,
    checksLock: false,
    lockWhere: null,
    why: '吊销路径的原子消费原语：越"不检查账户状态"越好，禁用/锁定账户也必须能完成吊销',
  },
  'services/authService/token.js#isForeignRefreshToken': {
    role: 'primitive',
    mint: false,
    verify: true,
    checksStatus: false,
    checksLock: false,
    lockWhere: null,
    why:
      '登出属主预检（F-100 另一半）：只回答"这枚 refresh 串是不是当前操作者的"，不判账户档。' +
      '与 revokeOneRefreshToken / logoutAuth 同旨：吊销通道必须对已禁用/已锁定账户开放，' +
      '否则被锁定的用户永远清不掉自己手里的令牌（比留着更危险）。' +
      '它只做判别不做消费——返回 true 时上层整次拒绝登出，一枚令牌都不会进黑名单。',
  },
  'services/authService/token.js#revokeTokensOnLogout': {
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
    checksLock: true,
    lockWhere: 'self',
    why:
      '会话状态预筛：本轮补齐 lockUntil 与设备会话状态（有 sid 时必须指向可用会话），' +
      '与 authenticate 同口径。此前锁定账户在该端点被报成已登录、已踢设备也仍显示在线，' +
      '要等 getMe 才纠正',
  },
  'services/tokenService.js#isRefreshTokenValid': {
    role: 'entry',
    mint: false,
    verify: true,
    checksStatus: true,
    checksLock: true,
    lockWhere: 'self',
    why: '同上：补齐 lockUntil、设备会话状态，并拒绝无 sid 的 refresh（该类令牌无法被设备级吊销终止）',
  },
  'services/websocketService/handshake.js#authenticateSocket': {
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

    // 嵌套助手回归：内联箭头助手的签名行不得把真正的铸造点抢走
    const nested = collectDoors([
      {
        name: 'x/nested.js',
        text: [
          'async function outer() {',
          '  const deny = async (outcome) => {',
          '    return { outcome };',
          '  };',
          '  const token = generateToken(user);',
          '  return deny("OK"), token;',
          '}',
        ].join('\n'),
      },
    ]);
    expect([...nested.keys()]).toEqual(['x/nested.js#outer']);
    expect(nested.get('x/nested.js#outer').mint).toBe(true);
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
    const ws = doors.get('services/websocketService/handshake.js#authenticateSocket');
    expect(ws.checksLock).toBe(true);

    // 同名委托实测有**两份实现**（本仓的命名冲突，实测不是推测）：
    // services/authService/login.js:215 的 assertAccountUsable 是 async、带口令/风控入参并会写审计；
    // middleware/auth.js:286 的同名函数是同步的 res 错误码助手，只看账户档。
    // ⇒ 本闸的 lockWhere 一律要求"文件限定"，`assertAccountUsable` 这种裸名指向不了任何一处。
    const svcBody = bodyFor(clean, 'services/authService/login.js#assertAccountUsable');
    const mwBody = bodyFor(clean, 'middleware/auth.js#assertAccountUsable');
    expect(typeof svcBody).toBe('string');
    expect(typeof mwBody).toBe('string');
    expect(svcBody).not.toBe(mwBody);
    expect(svcBody).toMatch(/password/);
    expect(mwBody).not.toMatch(/\bpassword\b/);
  });

  test('裸门名单：实测「自己体内无 lockUntil、也没有委托对象」的 entry 门精确 1 条（登出豁免）', () => {
    // 用**实测形状**筛，不用台账声明筛（声明由第 3 条用例与实测对齐；这里再走一遍采集器口径）
    const naked = measuredKeys
      .filter((k) => {
        const d = LEDGER[k];
        const m = doors.get(k);
        return d.role === 'entry' && m && !m.checksLock && !d.lockWhere;
      })
      .sort();
    expect(naked).toEqual(['middleware/logoutAuth.js#authenticateForLogout']);
    for (const k of naked) expect(VERDICTS).toContain(LEDGER[k].verdict);

    // needs-decision 家族已清零：refreshSession 与两个 tokenService 探测门本轮都补上了
    // lockUntil 检查（台账同步改为 checksLock:true / lockWhere:'self'）。
    // 若将来有人删掉其中任一检查，第 3 条实测形状断言会先红；这里保留空名单，
    // 让"又出现一扇缺 lockUntil 的裸门"必须显式登记 verdict 而不是悄悄混入。
    const needsDecision = naked.filter((k) => LEDGER[k].verdict === 'needs-decision').sort();
    expect(needsDecision).toEqual([]);

    // 反向对照：三扇已补检查的门必须是由实测判为 checksLock:true（不是只改了台账）
    for (const key of [
      'services/authService/token.js#refreshSession',
      'services/tokenService.js#isAccessTokenValid',
      'services/tokenService.js#isRefreshTokenValid',
    ]) {
      expect(doors.get(key).checksLock).toBe(true);
      expect(doors.get(key).checksStatus).toBe(true);
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

  test('"受理客户端凭证 + 铸造新凭证"的 entry 门不得绕过 lockUntil——出现一条即红', () => {
    const minting = registeredKeys.filter(
      (k) => LEDGER[k].role === 'entry' && LEDGER[k].mint && !LEDGER[k].checksLock
    );
    expect(minting).toEqual([]);
    // 结论必须由实测支撑而不是只读台账：实测的 mint/lock 形状要与声明一致
    const m = doors.get('services/authService/token.js#refreshSession');
    expect({ mint: m.mint, lock: m.checksLock, status: m.checksStatus }).toEqual({
      mint: true,
      lock: true,
      status: true,
    });
  });
});

module.exports = { collectDoors, bodyOf, stripCommentsPreserveLines, LEDGER, doors, measuredKeys };
