/**
 * 第 5 族门禁：回指式裸行锚（`（:353）`、`上方 210/233 行`）
 *
 * 为什么需要这个文件：`commentAnchorFreshness` 的采集正则要求锚点**自带文件名**。于是仓库里所有
 * "只写行号、靠同注释块上一行点过的文件来指代"的锚点一条都不进它的扫描集——不是它判得松，是它
 * 根本看不见。一个闸的覆盖面等于它采集器的覆盖面，判据层数再多也补不上采集口的洞。
 *
 * 本轮实测（2026-10-03）：这类站点 20 处——8 处当场可证失实（DEBT）、6 处正确但未署名（LIVE）、
 * 4 处尚未复核（UNVERIFIED）、2 处指向依赖内部行号（EXTERNAL）。
 * CENSUS total=20 DEBT=8 LIVE=6 UNVERIFIED=4 EXTERNAL=2
 * 上面这行不是排版：最后一条用例把它读回来和台账逐项对撞。写散文的计数会被改台账的人漏掉
 * （第 15 轮就出现过"闸对、文档写着 4 处、闸里断言 5 处"），机器可读的一行才能被闸管住。
 *
 * 为什么指代必须由作者登记、不能自动解析：试过"同注释块内向上找最近的文件名 token"，它把
 * websocketService 里明写「同文件」的 `（:353）` 解析到 src/index.js，把 auditWalChain 的
 * `（:521）` 也解析到 src/index.js 的越界区（该文件只有 476 行）——自动解析同时造假红与假绿。
 * 所以本闸只做两件事：①站点钉死（新增裸锚必须显式署名，否则红）；②已登记的指代当场可核
 * （那几行真的有那个符号）。「自动回指解析被否决」那条用例把这条设计决定本身钉成断言
 * （按用例名引用不按序号：序号会随新增用例漂移，上一版写「第 7 条」时它已经是第 8 条了）。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
/** 比 commentAnchorFreshness 多扫 migrations/e2e/web-admin：那些目录里的锚点它同样看不见 */
const SCAN_ROOTS = ['src', 'scripts', 'deployment', 'docs', 'migrations', 'e2e', 'web-admin'];
const SELF = 'src/tests/ci/bareAnchorAttribution.test.js';
const EXT = /\.(js|jsx|ts|tsx|vue|md|cjs|mjs|sh|json|ya?ml)$/i;
const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.git',
  '.next',
  'test-results',
  'playwright-report',
]);

const slash = (p) => path.relative(ROOT, p).split(path.sep).join('/');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const linesOf = (rel) => read(rel).split(/\r?\n/);

function listFiles(dir, acc) {
  if (!fs.existsSync(dir)) return acc;
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) {
      if (!SKIP_DIRS.has(name)) listFiles(full, acc);
    } else if (EXT.test(name)) acc.push(full);
  }
  return acc;
}
const SCANNED = SCAN_ROOTS.flatMap((d) => listFiles(path.join(ROOT, d), []))
  .map(slash)
  .filter((rel) => rel !== SELF)
  .sort();

/** 本闸采集器：括注里的裸行号锚 + 连冒号都没有的 `上方 N/M 行` */
const BARE_PAREN_RE = /[（(]\s*[:：](\d{1,4})(?:\s*[-–~]\s*(\d{1,4}))?\s*[)）]/g;
const BARE_NUMERIC_RE = /上方\s*(\d{1,4})\s*\/\s*(\d{1,4})\s*行/g;

const keyOf = (c) => `${c.site}::L${c.siteLine}::${c.raw}`;

/** 采集只认字面形态，不做任何语义或指代猜测 */
function collectBare(rel) {
  const lines = linesOf(rel);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    for (const RE of [BARE_PAREN_RE, BARE_NUMERIC_RE]) {
      RE.lastIndex = 0;
      let m;
      while ((m = RE.exec(lines[i])) !== null) {
        const rec = {
          site: rel,
          siteLine: i + 1,
          from: Number(m[1]),
          to: m[2] ? Number(m[2]) : Number(m[1]),
          raw: m[0],
        };
        out.push(rec);
      }
    }
  }
  return out;
}
const ALL_SITES = SCANNED.flatMap((rel) => collectBare(rel).map((c) => ({ ...c, key: keyOf(c) })));

/** 无内容锚点的三种形态（与 commentAnchorFreshness 的 2a/2b/2c 同语义） */
const MARKUP_ONLY = /^\s*(?:\/{2}|\*|\/\*)*\s*$/;
const PUNCT_ONLY = /^[\s)}\];,]*$/;
function contentFreeKind(rel, from, to, lines = linesOf(rel)) {
  if (from < 1 || from > lines.length) return '超出文件行数（死区间）';
  const seg = lines.slice(from - 1, Math.min(to, lines.length)).map((l) => l.trim());
  if (seg.every((s) => s === '')) return '空行';
  if (seg.every((s) => MARKUP_ONLY.test(s))) return '只剩注释排版';
  if (seg.every((s) => PUNCT_ONLY.test(s))) return '只剩闭合标点';
  return null;
}
const hasSymbol = (rel, from, to, needle) =>
  linesOf(rel)
    .slice(from - 1, to)
    .join('\n')
    .includes(needle);

/**
 * 「欠账仍然欠着」的唯一判据：站点行现在写着的这对坐标，读出来命中不了真符号。
 * 单独一份是为了让下面那条对调反例能量到它——判据只有一行断言时，把 `=== false` 改成
 * 恒真即可静默撤掉整档的保护，别处不会有任何反应（本轮变异 M11 当场验过）。
 */
const anchorStillWrong = (e) => hasSymbol(e.site, e.wrongFrom, e.wrongTo, e.mustRead) === false;

/**
 * 台账。四档 status：
 *  - LIVE       指代已登记且当场可核（文件存在 + 区间有内容 + 命中 mustRead）
 *  - DEBT       已知失实，绑"站点行仍写着那个错行号"；改对了本闸红，要求晋升
 *  - UNVERIFIED 站点钉死、指代本轮未复核（有上限，不许当豁免堆）
 *  - EXTERNAL   指代指向依赖内部行号，本闸不核（有上限）
 * mustRead 用**子串**不用正则：判据要能被"加一个后缀"证伪，正则加后缀会误伤自身语法。
 */
const LEDGER = [
  {
    site: 'src/middleware/rateLimitStore.js',
    siteLine: 143,
    raw: '（:715-726）',
    status: 'EXTERNAL',
    note: '指 express-rate-limit/index.cjs 里 store.increment 的抛点；依赖内部行号随版本必漂，本闸不核，只钉站点',
  },

  {
    site: 'src/services/authService.js',
    siteLine: 432,
    raw: '上方 210/233 行',
    status: 'DEBT',
    wrongFrom: 210,
    wrongTo: 233,
    referent: 'src/services/authService.js',
    from: 247,
    to: 318,
    mustRead: 'checkBruteForce(',
    note: '同口径真实站点是 :247 与 :318；:210 是 @returns JSDoc 行、:233 是"查找用户"注释（他人 M，不代改）',
  },
  {
    site: 'src/services/authService.js',
    siteLine: 1278,
    raw: '（:350）',
    status: 'DEBT',
    wrongFrom: 350,
    wrongTo: 350,
    referent: 'src/services/authService.js',
    from: 223,
    to: 223,
    mustRead: 'async function loginUser',
    note: 'loginUser 实在 :223；:350 落在 assertAccountUsable 里。同一个错号还被 src/tests/security/userLockBooleanBoundary.test.js 抄过一次（本轮已改对那一处），这里是"错锚自我复制"的第二个现场（他人 M）',
  },
  {
    site: 'src/services/permissionService.js',
    siteLine: 169,
    raw: '（:3248）',
    status: 'EXTERNAL',
    note: '指 mongoose 的 model.js（上一行点名 model.js:3218-3220）；本文件只有 189 行，按所在文件反解必判死锚——依赖内部行号，本闸不核，只钉站点',
  },
  {
    site: 'src/services/securityAlert.js',
    siteLine: 55,
    raw: '（:266）',
    status: 'DEBT',
    wrongFrom: 266,
    wrongTo: 266,
    referent: 'src/models/IPBlacklist.js',
    from: 269,
    to: 269,
    mustRead: '$setOnInsert',
    note: '$setOnInsert: { createdAt } 实在 :269（他人 M）',
  },
  {
    site: 'src/services/securityAlert.js',
    siteLine: 55,
    raw: '（:89）',
    status: 'DEBT',
    wrongFrom: 89,
    wrongTo: 89,
    referent: 'src/models/IPBlacklist.js',
    from: 92,
    to: 92,
    mustRead: 'expireAfterSeconds',
    note: 'TTL 索引实在 :92（他人 M）',
  },
  {
    site: 'src/services/securityAlert.js',
    siteLine: 253,
    raw: '（:266）',
    status: 'DEBT',
    wrongFrom: 266,
    wrongTo: 266,
    referent: 'src/models/IPBlacklist.js',
    from: 269,
    to: 269,
    mustRead: '$setOnInsert',
    note: ':55 那条错锚的第二处复制（他人 M）',
  },
  {
    site: 'src/services/securityAlert.js',
    siteLine: 253,
    raw: '（:89）',
    status: 'DEBT',
    wrongFrom: 89,
    wrongTo: 89,
    referent: 'src/models/IPBlacklist.js',
    from: 92,
    to: 92,
    mustRead: 'expireAfterSeconds',
    note: ':55 那条错锚的第二处复制（他人 M）',
  },
  {
    site: 'src/services/websocketService.js',
    siteLine: 204,
    raw: '（:353）',
    status: 'DEBT',
    wrongFrom: 353,
    wrongTo: 353,
    referent: 'src/services/websocketService.js',
    from: 390,
    to: 391,
    mustRead: 'this.authenticateSocket(',
    note: '原文写「同文件」，:353 实为连接数上限分支的 return;（他人 M）',
  },
  {
    site: 'src/tests/services/websocketHandlerRejectionGuard.test.js',
    siteLine: 12,
    raw: '（:353）',
    status: 'DEBT',
    wrongFrom: 353,
    wrongTo: 353,
    referent: 'src/services/websocketService.js',
    from: 390,
    to: 391,
    mustRead: 'this.authenticateSocket(',
    note: '把上一条的错锚当设计前提抄了一遍；本文件仅 283 行，:353 在本文件里越界（他人 A）',
  },

  {
    site: 'src/services/initData.js',
    siteLine: 1132,
    raw: '（:89）',
    status: 'LIVE',
    referent: 'migrations/20260831000000-reconcile-audit-index-options.js',
    from: 89,
    to: 89,
    mustRead: 'createIndex({ timestamp: -1 }',
    note: '指迁移脚本 down() 重建的无 TTL 索引——该文件在 migrations/，不在 commentAnchorFreshness 的 SCAN_ROOTS 内',
  },
  {
    site: 'src/services/reportDashboardService.js',
    siteLine: 19,
    raw: '（:112-114）',
    status: 'LIVE',
    referent: 'src/services/statsCache.js',
    from: 112,
    to: 114,
    mustRead: 'publishInvalidate(',
    note: 'invalidateByUserId 体内确实在 :114 调 publishInvalidate',
  },
  {
    site: 'src/tests/ci/commentAnchorFreshness.test.js',
    siteLine: 25,
    raw: '（:423）',
    status: 'LIVE',
    referent: 'src/services/DeviceService.js',
    from: 423,
    to: 423,
    mustRead: 'countDocuments(',
    note: '原文点名 DeviceService.js，:416 是该符号距被引行最近的一次出现',
  },
  {
    site: 'src/tests/config/startupGuards.test.js',
    siteLine: 467,
    raw: '（:39-43）',
    status: 'LIVE',
    referent: 'src/config/database.js',
    from: 39,
    to: 43,
    mustRead: 'envInt(',
    note: '那五个开关确实由 envInt 读出',
  },
  {
    site: 'src/tests/inspectionInputBoundary.test.js',
    siteLine: 13,
    raw: '（:371-384）',
    status: 'LIVE',
    referent: 'src/services/InspectionService.js',
    from: 371,
    to: 384,
    mustRead: 'findOneAndUpdate(',
    note: 'cancelValidation 走 findOneAndUpdate 的那段注释',
  },
  {
    site: 'src/tests/services/auditWalChainOrphanRejection.test.js',
    siteLine: 16,
    raw: '（:521）',
    status: 'LIVE',
    referent: 'src/services/auditBufferWal.js',
    from: 521,
    to: 521,
    mustRead: 'onError ||',
    note: 'serialize() 的默认兜底臂；文件已从 utils/auditBuffer.js 迁到 services/auditBufferWal.js（第 4 族），行号仍对',
  },

  {
    site: 'web-admin/src/tests/components/mfaSettingsCard.test.js',
    siteLine: 14,
    raw: '（:259-289）',
    status: 'UNVERIFIED',
    note: '指代大概是 MfaSettingsCard.vue，本轮未逐行核',
  },
  {
    site: 'web-admin/src/tests/components/mfaSettingsCard.test.js',
    siteLine: 1038,
    raw: '（:26）',
    status: 'UNVERIFIED',
    note: '同一行两处裸锚之一，未核',
  },
  {
    site: 'web-admin/src/tests/components/mfaSettingsCard.test.js',
    siteLine: 1038,
    raw: '（:50）',
    status: 'UNVERIFIED',
    note: '同上；若按"本文件"反解则落在 :50 的 `}))` 上，属无内容形态——正是自动解析会判错的地方',
  },
  {
    site: 'web-admin/src/tests/utils/websocket.test.js',
    siteLine: 20,
    raw: '（:194）',
    status: 'UNVERIFIED',
    note: '未核',
  },
];
const LEDGER_KEYS = LEDGER.map(keyOf).sort();
const byStatus = (st) => LEDGER.filter((e) => e.status === st);

/**
 * 边界判据只有一份：本闸管"裸锚"，对方闸管"署名锚"。这里不复制对方那份尺子的**逻辑**，
 * 而是把它字面量原文钉成字符串，再由这个字符串编译出 used-by-both 的采集器；对方一改，
 * 第 6 条用例立刻红，两边不可能悄悄漂移成两套口径。
 */
const PEER_CITE_RE_SRC =
  '((?:[\\w.@-]+\\/)*[\\w.@-]+\\.(?:js|jsx|ts|tsx|vue|md|sh|json|ya?ml)):(\\d+)(?:\\s*[-–~]\\s*(\\d+))?(?!\\d)';
const ATTRIBUTED_RE = new RegExp(PEER_CITE_RE_SRC, 'g');
const PEER_GATE = 'src/tests/ci/commentAnchorFreshness.test.js';

describe('第 5 族 · 回指式裸行锚', () => {
  test('站点集合与台账逐字相等：新增裸锚必须有人登记，删了裸锚不许留空条目', () => {
    expect(ALL_SITES.map((c) => c.key).sort()).toEqual(LEDGER_KEYS);
  });

  test('四档状态互斥且合计等于台账条数；暂住档被压在小范围内', () => {
    const st = ['LIVE', 'DEBT', 'UNVERIFIED', 'EXTERNAL'];
    expect(st.flatMap((s) => byStatus(s)).length).toBe(LEDGER.length);
    for (const s of st) expect(byStatus(s).length).toBeGreaterThan(0);
    expect(byStatus('UNVERIFIED').length).toBeLessThanOrEqual(4);
    expect(byStatus('EXTERNAL').length).toBeLessThanOrEqual(2);
  });

  test('LIVE 台账：指代文件真实存在、区间有内容、且当场命中 mustRead', () => {
    const live = byStatus('LIVE');
    expect(live.length).toBeGreaterThanOrEqual(6);
    for (const e of live) {
      expect(fs.existsSync(path.join(ROOT, e.referent))).toBe(true);
      expect(contentFreeKind(e.referent, e.from, e.to)).toBeNull();
      expect(hasSymbol(e.referent, e.from, e.to, e.mustRead)).toBe(true);
    }
  });

  test('LIVE 的 mustRead 不是恒真：加一个后缀就必须不命中', () => {
    for (const e of byStatus('LIVE')) {
      expect(hasSymbol(e.referent, e.from, e.to, `${e.mustRead}__NOT_IN_SOURCE__`)).toBe(false);
    }
  });

  test('DEBT 台账仍错着，且晋升目标预登记有牙：正确行成立、当前错行不成立', () => {
    for (const e of byStatus('DEBT')) {
      expect(linesOf(e.site)[e.siteLine - 1]).toContain(e.raw);
      expect(fs.existsSync(path.join(ROOT, e.referent))).toBe(true);
      expect(contentFreeKind(e.referent, e.from, e.to)).toBeNull();
      expect(hasSymbol(e.referent, e.from, e.to, e.mustRead)).toBe(true);
      expect(anchorStillWrong(e)).toBe(true);
    }
  });

  test('DEBT 判据不是恒真：把真指代和错坐标对调，同一条判据必须改口', () => {
    // 合成反例，不是自证。对调后"站点当前写的"就是真指代本身 ⇒ 锚不再是谎 ⇒ 判据必须为 false。
    // 判据被改成恒真（M11 那种 `!== undefined`）时，上面那条仍然全绿，只有这条红。
    const debt = byStatus('DEBT');
    expect(debt.length).toBeGreaterThan(0);
    for (const e of debt) {
      expect(anchorStillWrong({ ...e, site: e.referent, wrongFrom: e.from, wrongTo: e.to })).toBe(
        false
      );
    }
    // 反向：真判据必须能同时给出 true 和 false，否则它退化成常量
    const answers = new Set([
      ...debt.map((e) => anchorStillWrong(e)),
      ...debt.map((e) =>
        anchorStillWrong({ ...e, site: e.referent, wrongFrom: e.from, wrongTo: e.to })
      ),
    ]);
    expect([...answers].sort()).toEqual([false, true]);
  });

  test('档位不是自由字段：status 由字段形状双向唯一决定', () => {
    // LIVE 的检查集是 DEBT 的真子集（DEBT 多一条"站点当前仍写着那个错号"）。只要允许随手改档，
    // 撤掉欠账钉法就退化成"把 status 改一个字母"——检查静默消失、全绿。
    // 所以档位必须由字段形状唯一决定：改档要改字段，改字段要改档。
    const carriesTruth = (e) =>
      ['referent', 'from', 'to', 'mustRead'].every((k) => e[k] !== undefined);
    const carriesWrong = (e) => e.wrongFrom !== undefined || e.wrongTo !== undefined;
    const shapeByStatus = {
      LIVE: 'true/false',
      DEBT: 'true/true',
      UNVERIFIED: 'false/false',
      EXTERNAL: 'false/false',
    };
    expect(Object.keys(shapeByStatus).length).toBe(4);
    // 第五档要先在这里登记（并补 CENSUS 与上限），否则本条红——防止"新增一档却什么都不核"
    const unknown = LEDGER.filter((e) => shapeByStatus[e.status] === undefined).map(
      (e) => `${e.site}:${e.siteLine}`
    );
    expect(unknown).toEqual([]);
    for (const e of LEDGER) {
      expect(`${carriesTruth(e)}/${carriesWrong(e)}`).toBe(shapeByStatus[e.status]);
    }
  });

  test('台账里那对数字必须就是锚上写的那对数：不许用装饰性坐标冒充钉住', () => {
    const byKey = new Map(ALL_SITES.map((c) => [c.key, c]));
    for (const e of byStatus('LIVE').concat(byStatus('DEBT'))) {
      const rec = byKey.get(keyOf(e));
      expect(typeof rec).toBe('object');
      // mustRead 得有鉴别力：空串时 `hasSymbol(...,'')` 恒真（`includes('')` 永远成立），
      // 而"加后缀就不命中"那条自检对空串同样放行（后缀串本身不在源码里）。台账里最短的
      // 真符号是 `envInt(`（7 字符），地板定在 7 而不是 1。
      expect(typeof e.mustRead).toBe('string');
      expect(e.mustRead.length).toBeGreaterThanOrEqual(7);
      // LIVE：锚的裸数字 == 登记的真指代（缺的只是文件名）。
      // DEBT：锚的裸数字 == 登记的错坐标，且必须 ≠ 真指代——否则它不是欠账，是 LIVE。
      const anchor = [rec.from, rec.to];
      expect(anchor).toEqual([
        e.wrongFrom === undefined ? e.from : e.wrongFrom,
        e.wrongTo === undefined ? e.to : e.wrongTo,
      ]);
      if (e.status === 'DEBT') expect(anchor).not.toEqual([e.from, e.to]);
      if (e.status === 'LIVE') expect(anchor).toEqual([e.from, e.to]);
    }
  });

  test('与对方闸的分工由字面对拍保证：它的 CITE_RE 原文没被悄悄改过', () => {
    const src = read(PEER_GATE);
    const m = src.match(/const CITE_RE =\s*\r?\n?\s*\/([\s\S]*?)\/g;/);
    if (!m)
      throw new Error(`${PEER_GATE} 里解析不出 CITE_RE——它搬了目录或改了写法，需要重新对齐边界`);
    expect(m[1]).toBe(PEER_CITE_RE_SRC);
  });

  test('边界互斥且互补：同一行上"署名锚"与"裸锚"不重复计数，也没有哪边被放宽', () => {
    const attributed = [];
    for (const rel of SCANNED) {
      const lines = linesOf(rel);
      for (let i = 0; i < lines.length; i++) {
        ATTRIBUTED_RE.lastIndex = 0;
        let m;
        while ((m = ATTRIBUTED_RE.exec(lines[i])) !== null) {
          attributed.push({ site: rel, siteLine: i + 1, raw: m[0] });
        }
      }
    }
    const bareKeys = new Set(ALL_SITES.map((c) => c.key));
    const overlap = attributed.filter((a) => bareKeys.has(keyOf(a)));
    expect(overlap.map(keyOf)).toEqual([]);
    // 两边合起来才是全集：任何一边被改成恒假，这里的地板就会红
    expect(bareKeys.size).toBeGreaterThanOrEqual(18);
    expect(attributed.length).toBeGreaterThanOrEqual(200);
  });

  test('自动回指解析被否决：把两处实测误判钉成断言', () => {
    const wal = ALL_SITES.find((c) => c.site.endsWith('auditWalChainOrphanRejection.test.js'));
    // 自动解析给出的指代（同块最近 token = src/index.js）里没有那个符号 ⇒ 会判成死锚
    expect(hasSymbol('src/index.js', wal.from, wal.to, 'onError ||')).toBe(false);
    // 真实指代在另一个文件里、行号完全正确 ⇒ 只有作者登记才给得出来
    expect(contentFreeKind('src/services/auditBufferWal.js', 521, 521)).toBeNull();
    expect(hasSymbol('src/services/auditBufferWal.js', 521, 521, 'onError ||')).toBe(true);
    for (const e of byStatus('LIVE').concat(byStatus('DEBT'))) {
      expect(typeof e.referent).toBe('string');
      expect(e.from).toBeGreaterThan(0);
    }
  });

  test('采集器有牙：合成未署名裸锚必被抓，合成署名锚不被本闸抓', () => {
    const forged = '  // 见上一行的 registerUser（:120）与解密（:128-130）\n';
    expect(forged.match(BARE_PAREN_RE)).toEqual(['（:120）', '（:128-130）']);
    const attributed = '  // 见 src/services/authService.js:120 与 authService.js:128\n';
    expect(attributed.match(BARE_PAREN_RE)).toBeNull();
    // 数值形态连冒号都没有，CITE_RE 永远看不见它
    expect('与上方 210/233 行同口径'.match(BARE_NUMERIC_RE)).toEqual(['上方 210/233 行']);
  });

  test('无内容三形态各自能判，且正常行不误判', () => {
    // 这里**必须调用被本闸使用的 contentFreeKind 本身**，只在最后一个参数上喂合成行。
    // 早先这份是在用例里另写一遍同样的三行 every()，于是"死区间"这条真实存在的分支
    // 在测试里根本不存在（合成版没有 from>length 的守卫，[].every() 恒真判成"空行"）——
    // 判据用例证明了它自己那份副本，没证明闸。
    const fixture = ['const a = 1;', '', '//', '   * 索引声明', '   }', '});'];
    const kind = (from, to) => contentFreeKind('fixture', from, to, fixture);
    expect(kind(1, 1)).toBeNull();
    expect(kind(2, 2)).toBe('空行');
    // `//` 与 `* 索引声明` 都不是"代码"：前者只剩排版符号，后者整行是 docblock 续行
    expect(kind(3, 3)).toBe('只剩注释排版');
    expect(kind(4, 5)).toBeNull();
    expect(kind(5, 6)).toBe('只剩闭合标点');
    // 死区间（本仓实测：把 src/index.js 的 476 行当成有 521 行）——必须是独立第四种，
    // 不能和"空行"混成一种：前者是锚指向不存在的位置，后者是锚指向了真实但无内容的行。
    expect(kind(7, 9)).toBe('超出文件行数（死区间）');
    expect(kind(0, 3)).toBe('超出文件行数（死区间）');
  });

  test('自排除是双向事实：本文件确实在扫描目录里，但不在扫描集里', () => {
    const relHere = path.relative(ROOT, __filename).split(path.sep).join('/');
    expect(SCANNED.length).toBeGreaterThan(500);
    expect(SCANNED).not.toContain(relHere);
    expect(listFiles(path.join(ROOT, 'src'), []).map(slash)).toContain(relHere);
  });

  test('头部计数不是散文：CENSUS 行逐项等于台账，缺一档或多一档都红', () => {
    const text = fs.readFileSync(__filename, 'utf8').split(/\r?\n/).join('\n');
    const line = text.split('\n').find((l) => l.includes('* CENSUS '));
    expect(typeof line).toBe('string');
    const fields = {};
    for (const m of line.matchAll(/(\w+)=(\d+)/g)) fields[m[1].toUpperCase()] = Number(m[2]);
    expect(Object.keys(fields).sort()).toEqual(['DEBT', 'EXTERNAL', 'LIVE', 'TOTAL', 'UNVERIFIED']);
    expect(fields.TOTAL).toBe(LEDGER.length);
    for (const st of ['LIVE', 'DEBT', 'UNVERIFIED', 'EXTERNAL']) {
      expect(fields[st]).toBe(byStatus(st).length);
    }
    // 四档相加必须等于总数：漏一档（例如新增第五档却忘了写进 CENSUS）会在这里露出来
    expect(fields.LIVE + fields.DEBT + fields.UNVERIFIED + fields.EXTERNAL).toBe(fields.TOTAL);
  });
});
