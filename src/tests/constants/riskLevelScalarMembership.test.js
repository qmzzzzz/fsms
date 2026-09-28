/**
 * `riskLevel` 标量字面量的成员闸（查询侧 / 比较侧）。
 *
 * 【为什么要这一闸】
 * `AUDIT_RISK_LEVELS`（`src/constants/audit.js`）是风险档位的唯一事实来源，写路径确实有兜底：
 * `src/models/AuditLog.js` 的 `riskLevel: { enum: AUDIT_RISK_LEVELS }` 会把非法档位顶成校验失败，
 * 而 `src/tests/models/AuditLog.test.js` 已把 `schema.path('riskLevel').enumValues` 钉成与常量相等。
 * **但这条兜底只覆盖"落库"**：
 *   · `AuditLog.countDocuments({ riskLevel: 'critcal' })` 不报错，只返回 0；
 *   · `item.riskLevel === 'medeum' ? '警告' : '信息'` 不报错，只把每一行都标成"信息"。
 * 也就是说档位打错一个字母的失效模式不是红，是**静默少算/静默错标**——与批次 82 的
 * 「幽灵令牌」、`constants/audit.js` 头注释里 F-149 记的那族切片漂移是同一个形状。
 * 数组形态（`{ $in: [...] }`）由 F-149 的派生判据与幽灵令牌闸管着；**标量形态此前没有任何判据**，
 * 本闸补的就是这一格。
 *
 * 【判据】
 *   1. 扫描集按目录派生（`src`、`scripts`、`migrations`），不是逐文件白名单：
 *      新加的站点自动被看见，漏登记 ⇒ 红。
 *   2. 只认两种"标量绑定"文本形态：`riskLevel: '<lit>'`（赋值/过滤条件）与
 *      `riskLevel (===|!==|==) '<lit>'`（比较）。捕获到的字面量必须逐条 ∈ `AUDIT_RISK_LEVELS`。
 *   3. 判据跑在 `helpers/jsCodeOnly` 的"只剩代码"视图上：注释里写 `'low'` 不算数，
 *      把真实调用删掉、只在注释里留一份也不算数。
 *   4. 前提自证：站点数、四种档位各自至少出现一次、两种形态各自非空、扫描文件数与
 *      几份关键后端文件在场——抽成空集会让第 2 条恒绿，所以那些都得钉住。
 *   5. 有牙证明：对**真实源码**做内存变异（把一个真档位改成非档位）⇒ 违规数必须等于被改站点数，
 *      且违规的字面量与文件都对得上。全程不改盘。
 *
 * 【已知限制一：不抓 `||` / 三元默认值】
 * 曾想把 `riskLevel: alert.riskLevel || 'low'`、`x.riskLevel || '-'` 这类兜底也纳入。实测（2026-09-26，
 * 探针 `zztmpctl/zZbProbeRiskScalars86.js`）：加上该规则后全仓唯一的不成员命中是
 * `src/services/reportExportService.js` 的导出占位符 `|| '-'`——那是"这一列显示什么"，不是档位。
 * 任何把占位符与错默认值区分开的文本判据都得再配一份白名单，而白名单正是这类闸最先腐烂的地方。
 * 因此本闸刻意不收这一类：落库侧有 enum 兜底，非落库的告警对象（`alert.riskLevel`、`meta.riskLevel`）
 * 本来也不受 `AUDIT_RISK_LEVELS` 约束。要真收，得先有"哪个字段属于哪个域"的归属表——已登记进台账残留。
 *
 * 【已知限制二：不排除的域是实测出来的，不是抄来的】
 *   · `src/tests`：纳入后会出现合法反例夹具（`auditQuerySharedBuilder.test.js` 用
 *     `riskLevel: 'extreme'` 断言接口抛 400）。非成员命中实测 1 处 ⇒ 必须排除。
 *   · `web-admin/src`：不是本闸的根。实测非成员 8 处，全是 i18n 文案（`riskLevel: '风险等级'`）、
 *     前端夹具与筛选默认值 `riskLevel: ''`。
 *   · `src/constants` **不**排除：实测那里没有本闸两种形态的站点，多排一份目录只会少一份覆盖。
 *
 * 【已知限制三：字段名即域】
 * 判据按字段名 `riskLevel` 认域。今天 34 处站点全部属于审计档位语义；若将来引入另一个
 * 也叫 `riskLevel`、档位表不同的字段，红是本闸的正确行为——那时要按"字段的归属对象"拆规则，
 * 不是给某一行加豁免。
 */

const fs = require('fs');
const path = require('path');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const { AUDIT_RISK_LEVELS } = require('../../constants/audit');

const ROOT = path.resolve(__dirname, '../../..');
const SCAN_ROOTS = ['src', 'scripts', 'migrations'];
const SKIP_DIR = /(^|[/\\])(?:tests?|__tests__|node_modules)([/\\]|$)/;

/** 标量绑定的两种形态：捕获组 2 = 字面量内容 */
const RULES = [
  { kind: 'assign', re: /\briskLevel\s*:\s*(['"])([^'"\n]*)\1/g },
  { kind: 'compare', re: /\briskLevel\s*(?:===|!==|==)\s*(['"])([^'"\n]*)\1/g },
];

const EOL = /\r?\n/;

function walkFiles(dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (SKIP_DIR.test(path.relative(ROOT, full))) continue;
    if (entry.isDirectory()) walkFiles(full, acc);
    else if (/\.(?:js|vue)$/.test(entry.name)) acc.push(full);
  }
  return acc;
}

const scanRootFiles = () => SCAN_ROOTS.flatMap((r) => walkFiles(path.join(ROOT, r))).sort();

/**
 * 扫一份源码文本，返回所有 riskLevel 标量字面量站点。
 * @param {string} rel 仓库内相对路径（只用于报告）
 * @param {string} raw 原始字节
 */
function scanSites(rel, raw) {
  const rawLines = raw.split(EOL);
  const sites = [];
  // 行号用"代码视图的行文本回查原文件"，不数索引：jsCodeOnly 会整行丢弃 `//` 注释，
  // 拿视图行号当原始行号会偏（实测：同一处在视图里是 329 行，在原文件里是 397 行）。
  jsCodeOnly(raw)
    .split('\n')
    .forEach((line, i) => {
      for (const { kind, re } of RULES) {
        re.lastIndex = 0;
        for (const m of line.matchAll(re)) {
          const literal = m[2];
          const trimmed = line.trim();
          const idx = rawLines.findIndex((l) => l.trim() === trimmed);
          sites.push({
            file: rel,
            kind,
            literal,
            line: idx >= 0 ? idx + 1 : null,
            snippet: trimmed,
            order: i,
          });
        }
      }
    });
  return sites;
}

const format = (s) => `${s.file}:${s.line ?? '?'} [${s.kind}] ${JSON.stringify(s.literal)}`;

const violationsOf = (sites) =>
  sites
    .filter((s) => !AUDIT_RISK_LEVELS.includes(s.literal))
    .map((s) => `${format(s)} ∉ AUDIT_RISK_LEVELS  ${s.snippet}`);

const allSites = () =>
  scanRootFiles().flatMap((f) =>
    scanSites(path.relative(ROOT, f).replace(/\\/g, '/'), fs.readFileSync(f, 'utf8'))
  );

/** 内存变异：把某 (文件, 档位) 的所有标量绑定改成非档位，绝不写盘 */
const TYPO = 'zz-not-a-risk-level';
function typoLiteralIn(raw, site) {
  const lit = site.literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const sep = site.kind === 'assign' ? String.raw`\s*:\s*` : String.raw`\s*(?:===|!==|==)\s*`;
  const re = new RegExp(String.raw`\briskLevel(${sep})(['"])${lit}\2`, 'g');
  const out = raw.replace(re, (_m, s, q) => `riskLevel${s}${q}${TYPO}${q}`);
  return { text: out, changed: out !== raw };
}

describe('riskLevel 标量字面量必须是 AUDIT_RISK_LEVELS 的成员', () => {
  const sites = allSites();

  test('真源码：每个 riskLevel 标量字面量都在权威档位内', () => {
    expect(violationsOf(sites)).toEqual([]);
  });

  test('前提自证：扫描集与规则都真的抽到了东西（空集会让他条用例假绿）', () => {
    const files = scanRootFiles();
    for (const r of SCAN_ROOTS) {
      expect(fs.existsSync(path.join(ROOT, r))).toBe(true);
    }
    // 目录改名/挪走会让扫描集静默缩水，这里钉住量级与几份关键文件
    expect(files.length).toBeGreaterThanOrEqual(150);
    const rel = files.map((f) => path.relative(ROOT, f).replace(/\\/g, '/'));
    for (const must of [
      'src/utils/auditQuery.js',
      'src/services/securityAlert.js',
      'src/services/reportExportService.js',
    ]) {
      expect(rel).toContain(must);
    }
    expect(rel.some((f) => SKIP_DIR.test(f))).toBe(false);

    // 站点数实测 34（2026-09-26）；阈值留余量，但必须非空且能覆盖整份档位表
    expect(sites.length).toBeGreaterThanOrEqual(30);
    expect(new Set(sites.map((s) => `${s.file}#${s.order}`)).size).toBe(sites.length);
    expect(new Set(sites.map((s) => s.literal))).toEqual(new Set(AUDIT_RISK_LEVELS));
    for (const kind of ['assign', 'compare']) {
      expect(sites.filter((s) => s.kind === kind).length).toBeGreaterThanOrEqual(1);
    }
    for (const s of sites) expect(s.snippet).toContain(s.literal);
    // 失败信息里的行号靠"代码视图的行文本回查原文件"得到；回查不到只能报 '?'，
    // 会把人指错地方。今天 34 处站点必须全部回查命中（行尾带注释的站点会让视图文本与原行不一致）。
    expect(sites.filter((s) => s.line === null).map((s) => `${s.file}  ${s.snippet}`)).toEqual([]);
  });

  test('判据自证（合成源码）：脏字面量两种形态都要被抓到，干净的不许报', () => {
    const dirty = `
      const q = { riskLevel: 'critcal' };
      if (row.riskLevel !== 'medeum') mark(row);
    `;
    expect(violationsOf(scanSites('synthetic.js', dirty)).sort()).toEqual(
      [
        'synthetic.js:2 [assign] "critcal" ∉ AUDIT_RISK_LEVELS  const q = { riskLevel: \'critcal\' };',
        'synthetic.js:3 [compare] "medeum" ∉ AUDIT_RISK_LEVELS  if (row.riskLevel !== \'medeum\') mark(row);',
      ].sort()
    );

    const clean = `
      const q = { riskLevel: 'high', action: 'login_failed' };
      return row.riskLevel === 'low' ? 1 : 2;
    `;
    expect(scanSites('clean.js', clean).map((s) => s.literal)).toEqual(['high', 'low']);
    expect(violationsOf(scanSites('clean.js', clean))).toEqual([]);
  });

  test('判据自证：注释里的档位不算数（否则删掉真调用也能骗绿）', () => {
    const commented = `
      // 历史遗留：riskLevel: 'critcal' 曾经出现在这里
      /*  likewise riskLevel === 'nope'  */
      // const x = { riskLevel: 'wrong' };
    `;
    expect(scanSites('commented.js', commented)).toEqual([]);
    // 反向：把注释里的东西真写进代码就必须响
    expect(
      violationsOf(scanSites('commented.js', `${commented}\nconst y = { riskLevel: 'critcal' };`))
    ).toHaveLength(1);
  });

  test.each(['assign', 'compare'])(
    '有牙证明（内存变异真源码，%s 形态）：改档位必红，且只红这一处',
    (kind) => {
      const target = allSites().find((s) => s.kind === kind);
      expect(target).toBeTruthy();
      const abs = path.join(ROOT, target.file);
      const raw = fs.readFileSync(abs, 'utf8');
      const same = allSites().filter((s) => s.file === target.file && s.literal === target.literal);
      expect(same.length).toBeGreaterThanOrEqual(1);

      const { text, changed } = typoLiteralIn(raw, target);
      // 变异必须真的动了字节，否则这一臂什么都没测
      expect(changed).toBe(true);
      expect(raw.includes(TYPO)).toBe(false);

      const mutated = scanSites(target.file, text);
      expect(mutated.filter((s) => s.literal === TYPO)).toHaveLength(same.length);
      expect(violationsOf(mutated).map((v) => v.split(' ')[0].split(':')[0])).toEqual(
        same.map(() => target.file)
      );
      // 变异只改档位值、不改站点数：同一份文件的站点总数必须与基线一致
      expect(mutated.length).toBe(allSites().filter((s) => s.file === target.file).length);
      expect(mutated.filter((s) => s.literal !== TYPO).length).toBe(
        allSites().filter((s) => s.file === target.file && s.literal !== target.literal).length
      );
    }
  );
});
