/**
 * 检测查询里的「幽灵令牌」闸。
 *
 * 【背景】
 * `services/securityAlert.js` 的检测查询用 `action: { $in: [...] }` / `riskFactors: { $in: [...] }`
 * 圈定候选动作，其中几个令牌**全仓没有任何写入方**——它们不为零而存在，是为了继续命中
 * 改名之前落库的历史审计行。删掉它们等于洗掉历史，所以不能"清理"。
 * 问题是这批令牌正好卡在两道既有闸的缝里：
 *   · `constants/auditActionReconciliation.test.js` 的文件头第 3 条把"查询/过滤上下文"
 *     明确划在扫描范围外（那不是写入调用）；
 *   · `constants/auditActionReachability.test.js` 只对**白名单内**的条目要求可达。
 * ⇒ 今天新增一个打不中任何行的查询令牌，两闸都不会响；而它一旦被补上写入方，
 *   也没有任何东西提醒登记该更新。本闸把这一格补成双向的账。
 *
 * 【判据】
 *   1. 扫描集按目录派生（不是逐文件白名单）：漏登记的新幽灵 ⇒ 红；
 *   2. 已登记的幽灵若被补上写入方 ⇒ 同样红（逼着更新本清单，而不是烂成僵尸条目）；
 *   3. 每条登记项必须带出处与家族，且**确实不在** `AUDIT_LOG_ACTIONS` 白名单里——
 *      若哪天进了白名单，归属就回到可达闸，本清单必须缩小；
 *   4. 反向对照：同一个 `$in` 数组里确有写入方的那些令牌不得出现在清单里，
 *      否则本闸就是在测一个空集合。
 *
 * 【为什么按文本引用而不是行号】
 * 对端这段时间一直在改 `securityAlert.js`：同一处查询的行号在同一天里从 197/202/345/402
 * 漂到 127/132/223/266 又漂回来。邻闸（`NOT_AUDIT_ACTION_LITERALS`）要求出处写行号，
 * 那是它的口径；这里若照抄就会变成"别人正常改代码 ⇒ 我的闸恒红"，所以出处写的是
 * **可在源码里逐字找到的代码文本**，第 3 条用例负责核对这些文本确实还在。
 */

const fs = require('fs');
const path = require('path');
const { scanWriteSites } = require('../helpers/auditWriteSites');
const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');

const SRC_DIR = path.resolve(__dirname, '../..');

/** 逐行/块注释都剥掉：`// 兼容 permission_denied` 这种说明文字不是引用 */
const stripComments = (code) => code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

function walkJs(dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkJs(full, acc);
    else if (entry.name.endsWith('.js')) acc.push(full);
  }
  return acc;
}

/** 抓 `字段: { $in: ['a', 'b'] }` 里的字面量，返回 [{token, file, line}] */
function grabInArray(re, text, rel) {
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const line = text.slice(0, m.index).split('\n').length;
    for (const t of m[1].matchAll(/'([^']*)'/g)) out.push({ token: t[1], file: rel, line });
    if (re.lastIndex === m.index) re.lastIndex += 1; // 零宽匹配保护
  }
  return out;
}

/** 扫描全部查询侧令牌：action 与 riskFactors 两条链都要 */
function scanQueryTokens() {
  const actionRefs = [];
  const riskRefs = [];
  const riskWritten = [];
  for (const file of walkJs(SRC_DIR)) {
    const rel = path.relative(SRC_DIR, file).replace(/\\/g, '/');
    const code = stripComments(fs.readFileSync(file, 'utf8'));
    const withField = (field, rows) => rows.map((r) => ({ ...r, field }));
    actionRefs.push(
      ...withField('action', grabInArray(/action:\s*\{\s*\$in:\s*\[([^\]]*)\]/g, code, rel))
    );
    riskRefs.push(
      ...withField(
        'riskFactors',
        grabInArray(/riskFactors:\s*\{\s*\$in:\s*\[([^\]]*)\]/g, code, rel)
      )
    );
    // riskFactors 的"写入方"是审计文档里那个数组字面量：字段: ['x', 'y']（不带 $in）
    riskWritten.push(
      ...withField('riskFactors', grabInArray(/riskFactors:\s*\[([^\]]*)\]/g, code, rel))
    );
  }
  return { actionRefs, riskRefs, riskWritten };
}

/**
 * 幽灵登记表（例外显式登记）。
 * code   —— 令牌本身
 * field  —— 它在查询里挂哪个字段（决定"写入方"的判据来源）
 * anchor —— 必须在源码里能逐字找到的代码文本（引用位置，不用行号）
 * why    —— 为什么留着：删掉会失去对历史行的命中
 */
const GHOST_TOKENS = [
  {
    code: 'auth_failed',
    field: 'action',
    anchor: "action: { $in: ['login_failed', 'auth_failed'] }",
    why: '登录失败计数的历史命名；现网写入方是 login_failed',
  },
  {
    code: 'permission_denied',
    field: 'action',
    anchor: "{ action: { $in: ['permission_denied', 'forbidden'] } }",
    why: 'B-L6 兼容显式写入的 403 动作；活体信号是 statusCode: 403',
  },
  {
    code: 'forbidden',
    field: 'action',
    anchor: "{ action: { $in: ['permission_denied', 'forbidden'] } }",
    why: '同上，同一批 $in 候选里的第二个别名',
  },
  {
    code: 'unusual_time',
    field: 'riskFactors',
    anchor: "riskFactors: { $in: ['unusual_time', 'unusual_time_access'] }",
    why: '非常规时间访问的历史标记名；现网写入方是 unusual_time_access',
  },
];

describe('检测查询里的幽灵令牌：例外显式登记 + 双向回球闸', () => {
  const { actionRefs, riskRefs, riskWritten } = scanQueryTokens();
  const writtenActions = new Set(scanWriteSites().written.keys());
  const writtenRisks = new Set(riskWritten.map((r) => r.token));

  /**
   * 前提自证：扫描器不是空转。这条先于一切判据——否则下面的"集合相等"
   * 可能是在两个空集合之间成立。
   */
  test('前提：扫描集非空，且确有写入方的令牌被正确归类为"有写入方"', () => {
    expect(actionRefs.length).toBeGreaterThan(0);
    expect(riskRefs.length).toBeGreaterThan(0);
    const produced = actionRefs.filter((r) => writtenActions.has(r.token));
    expect(produced.length).toBeGreaterThan(0);
    // 具体一条：登录失败检测既在查询里、也有写入方（今天实测 login_failed 有写入方）
    expect(
      actionRefs.some((r) => r.token === 'login_failed' && writtenActions.has('login_failed'))
    ).toBe(true);
    expect(
      riskRefs.some(
        (r) => r.token === 'unusual_time_access' && writtenRisks.has('unusual_time_access')
      )
    ).toBe(true);
  });

  test('方向一：查询侧每个令牌要么有写入方，要么逐条登记在幽灵清单（漏登记 ⇒ 红）', () => {
    const ghosts = [
      ...actionRefs.filter((r) => !writtenActions.has(r.token)),
      ...riskRefs.filter((r) => !writtenRisks.has(r.token)),
    ];
    const found = [...new Set(ghosts.map((r) => `${r.field} :: ${r.token}`))].sort();
    expect(found).toEqual(GHOST_TOKENS.map((g) => `${g.field} :: ${g.code}`).sort());
  });

  test('方向二：已登记的幽灵若被补上写入方也红（登记不会烂成僵尸账）', () => {
    for (const g of GHOST_TOKENS) {
      const produced = g.field === 'action' ? writtenActions.has(g.code) : writtenRisks.has(g.code);
      expect({ token: g.code, hasWriterNow: produced }).toEqual({
        token: g.code,
        hasWriterNow: false,
      });
    }
  });

  test('登记项的出处可核对：anchor 文本必须仍在源码里，且理由齐备', () => {
    const allCode = walkJs(SRC_DIR)
      .map((f) => stripComments(fs.readFileSync(f, 'utf8')))
      .join('\n');
    for (const g of GHOST_TOKENS) {
      expect(typeof g.why === 'string' && g.why.length > 8).toBe(true);
      // 带 code 的对象比对：anchor 烂掉时要能一眼看出是**哪一条**（裸 toBe(true) 只报
      // "Expected: true / Received: false"，四条登记项里烂掉谁都长一样）
      expect({ code: g.code, anchorInSource: allCode.includes(g.anchor) }).toEqual({
        code: g.code,
        anchorInSource: true,
      });
    }
  });

  test('归属边界：幽灵令牌不得同时挂在审计动作白名单里（进了白名单就该由可达闸负责）', () => {
    for (const g of GHOST_TOKENS.filter((x) => x.field === 'action')) {
      expect(AUDIT_LOG_ACTIONS.includes(g.code)).toBe(false);
    }
  });

  test('反向对照：确有写入方的那些令牌不在清单里（否则本闸在测空集合）', () => {
    const registered = new Set(GHOST_TOKENS.map((g) => g.code));
    const producedTokens = [
      ...actionRefs.filter((r) => writtenActions.has(r.token)).map((r) => r.token),
      ...riskRefs.filter((r) => writtenRisks.has(r.token)).map((r) => r.token),
    ];
    expect(producedTokens.length).toBeGreaterThan(0);
    for (const t of new Set(producedTokens)) expect(registered.has(t)).toBe(false);
  });
});
