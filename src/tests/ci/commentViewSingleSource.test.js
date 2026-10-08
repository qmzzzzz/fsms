'use strict';

/**
 * 文本判据的「什么算注释」口径单点（第 30 轮）
 *
 * 【这条闸在防什么】
 * 本仓所有文本型闸门都靠"只剩代码"视图判据：视图的语义**就是**判据的语义。共享实现在
 * `src/tests/helpers/jsCodeOnly.js`（第 25 轮收敛），但收敛那天起，测试树里的**私有复制品一个都没少**——
 * 本轮实测 49 处 / 46 个文件（两种形状：块剥离正则 41 处 / 整行前缀过滤与两字符扫描 8 处）。
 * 复制品的害处不是重复代码，而是"任一处改坏，另一处仍然绿"（第 1 族），
 * 而且这里改坏的后果是双向的：
 *   A) 只会剥整行注释（或只剥块注释）的复制品 ⇒ **行尾注释文本对判据可见** ⇒ 在注释里补一个
 *      被要求的调用串就能骗绿，把真调用删掉也没人看见；
 *   B) 全局按"两个斜杠"屏蔽的复制品 ⇒ 字符串/模板里的 URL（`https:` 后面那两个字符）会被当成
 *      注释起点，**本行后续的真代码整段抹掉** ⇒ 判据少采，报"零命中=干净"。
 * B 不是理论：本轮实测旧共享视图（同一形状）在生产代码里抹掉过 33 行，其中
 * `src/middleware/rateLimit.js:121`（`skipResourceLimiter` 定义）被**整行**吞掉——起因是它上方
 * `:108` 的行注释里写了 `/api/**`，块起始两字符在那里，而下一个块结束两字符在 `:130`。
 * helper 已修，但 46 份复制品仍在原地各自坏着。
 *
 * 【为什么不顺手把它们迁到 helper】
 * 那是几十个并行 agent 的在途文件，且每份迁移都会改变那把闸的判据面积（颜色整套作废）。
 * 本闸因此只做两件本分的事：**把复制品封成封闭清单**（新增一律红，迁移必须来删条目），
 * 以及**把"复制品确实有洞"钉成判据**（第 6 组，用夹具双向证明，不靠注释里的口头声明）。
 *
 * 【登记口径】
 * 站点键 = `相对路径|站点数`，不用行号（本仓闸被别人的行号漂移打过多次，槽文本/计数才是本体）。
 * 站点 = 视图里含"块注释剥离正则签名"（家族 A）或"整行前缀过滤/两字符扫描字面量"（家族 B）的行。
 * 签名用三段拼接而成，本文件自身不含该连续序列（#8 自查）。
 * 签名同时会命中 `new RegExp(签名字符串)` 这种形态——**这是有意的**：用字符串拼出的剥离实现同样是
 * 第二份口径，不该因为写法不同就逃脱登记。
 *
 * 【面积对"视图 vs 原文"是单向敏感的（实测，别把它当成口径守护腿）】
 * 全测试树 562 个 .js：家族 A 站点原文 41 = 视图 41（没有任何文件在注释里写这个正则），
 * 取用点差 0；家族 B 不同——它的前缀过滤字面量是**适合写进说明文字**的，所以原文会比视图多采
 * （本文件的头注自己就是这种文字，实测被 #8 的自查抓过一次）。
 * 推论：把采集口径换成原文只会**多采**（假红），不会少采（假绿），所以本闸不给这条加腿，
 * 只在这里记下来——反过来（视图比原文采得多）不可能发生，因为视图只做删除。
 *
 * 【判据面积完全来自采集器 ⇒ 采集器必须有牙】
 * #1 用四类合成输入（真代码 / 行注释里提到 / 块注释里提到 / 只 require helper）证明采集器
 * 既不漏也不误伤；#4/#5 的清单今天一个是空集、一个是 4 条，所以它们的牙齿写在合成输入侧，
 * 否则"空清单"永远绿（第 10 族）。
 */
const fs = require('fs');
const path = require('path');
const { jsCodeOnly, jsCodeOnlyKeepingLines } = require('../helpers/jsCodeOnly');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const SCAN_REL_DIRS = ['src/tests'];
const SELF_EXCLUDE = 'src/tests/helpers/jsCodeOnly.js';

/**
 * 块注释剥离正则的签名：三段拼接，本文件不出现连续形态（见头注）。**家族 A**。
 *
 * **家族 B（第 31 轮补，形状换了所以签名换了）**：`t.startsWith('/*') || t.startsWith('//') ||
 * t.startsWith('*')` 这种"整行前缀过滤"实现，以及 `two === '/*'` 的两字符扫描。它们不含任何
 * 剥离正则，所以家族 A 一条都采不到——实测全测试树 562 个 .js：家族 A 41 处，家族 B 8 处，
 * 且 B 有 6 个文件是 A 完全没覆盖的。**B 正是头注说的缺陷 A 形状**（只按行首判定 ⇒ 行尾注释
 * 文本原样留给判据 ⇒ 在注释里补一个被要求的串就能骗绿），所以它比 A 更危险，不是补充说明。
 * 刻意**不**收的候选：`slice(0, 2)`（实测 4 个文件命中，全是权限码/游标排序键之类，与注释无关）
 * ——按形状放宽面积会把无关代码登记成复制品，面积就不可信了（第 5 族的反方向）。
 */
const SIG_A = '\\/\\*';
const SIG_B = '[\\s\\S]*?';
const SIG_C = '\\*\\/';
const SIG = SIG_A + SIG_B + SIG_C;

/** 家族 B 的字面量同样要拼接：本闸的采集器判的是行内连续文本，源码写全就等于自增面积 */
const CALL_OPEN = 'start' + 'sWith' + '(';
const Q_BLOCK = "'" + '/*' + "'";
const Q_LINE = "'" + '//' + "'";
const Q_STAR = "'" + '*' + "'";
const SIGS = [
  SIG,
  CALL_OPEN + Q_BLOCK + ')',
  CALL_OPEN + Q_LINE + ')',
  CALL_OPEN + Q_STAR + ')',
  '=== ' + Q_BLOCK,
];

const HELPER_USE_RE = /require\([^)]*helpers\/jsCodeOnly[^)]*\)/;
const LOCAL_DEF_RE = /(?:function|const)\s+jsCodeOnly(?:KeepingLines)?\s*(?:\(|=)/g;

/**
 * 夹具用的两段"被探测形态"必须拼接：本闸的采集器判的是**文本**，源码里只要出现连续形态，
 * 本文件就会成为自己的靶（实测第一版正是这样被 #5/#8 打红的——那不是误伤的坏味道，
 * 而是"连续形态确实算一处"的正确行为，所以出路是拼接，而不是给采集器开后门）。
 * 拼接后运行时仍是连续形态，#8 用正对照钉住这一点，免得"零命中"来自探测器坏了。
 */
const FN_DEF_TOKEN = 'function jsCodeOnly' + '(';
const HELPER_PATH_LITERAL = 'helpers/jsCodeOnly';
const REQ_FIXTURE = () => "const { jsCodeOnly } = require('" + HELPER_PATH_LITERAL + "');";

/** 家族 B 的正对照（运行时才是连续形态）：整行前缀过滤，正是"尾注释留给判据"的那把尺 */
const PREFIX_FILTER_SAMPLE = 'if (t.' + CALL_OPEN + Q_BLOCK + ')) continue;';
/** 刻意不收的形状：`slice(0, 2)` 在全仓有 4 个与注释无关的命中，收进来就是把无关代码登记成复制品 */
const NON_COMMENT_SLICE_SAMPLE = 'const seg = s.slice(0, 2); // 排序键，与注释无关';

/** 纯函数：视图文本 -> 站点行号（合成腿与真树走同一条接线，第 2 族） */
const sitesInView = (viewText) => {
  const out = [];
  viewText.split('\n').forEach((l, i) => {
    if (SIGS.some((s) => l.includes(s))) out.push(i + 1);
  });
  return out;
};
/** 按家族拆开计数：#2 用它钉"家族 B 确实采到了东西"，否则面积扩大只体现为一个总数 */
const famACount = (viewText) => countLinesWith(viewText, [SIG]);
const famBCount = (viewText) => countLinesWith(viewText, SIGS.slice(1));
function countLinesWith(viewText, sigs) {
  let n = 0;
  viewText.split('\n').forEach((l) => {
    if (sigs.some((s) => l.includes(s))) n += 1;
  });
  return n;
}
const helperUsedIn = (viewText) => HELPER_USE_RE.test(viewText);
/**
 * 取用点**计数**：布尔判据 `helperUsedIn` 数不出"几处"，而"本闸只有一处取用点"这条自查
 * 要的正是数量。计数必须由无 g 的 `HELPER_USE_RE.source` 现场重建 /g，且和下面的合成对照
 * 走同一个函数——否则"恰好一处"会因为 match 只返回第一个命中而退化成恒真（第 4 族）。
 */
const reqCountIn = (viewText) =>
  [...viewText.matchAll(new RegExp(HELPER_USE_RE.source, 'g'))].length;
const localDefsIn = (viewText) => {
  LOCAL_DEF_RE.lastIndex = 0;
  return viewText.match(LOCAL_DEF_RE) || [];
};

/** 一个文件的全部事实只从这一处构造：合成输入与真树共用，判据腿因此不会与采集脱钩 */
const rowFromView = (rel, viewText) => ({
  rel,
  sites: sitesInView(viewText),
  famA: famACount(viewText),
  famB: famBCount(viewText),
  helper: helperUsedIn(viewText),
  defs: localDefsIn(viewText),
});

/** 判据谓词同样只有一处：#4 的空清单与它的合成对照必须经过同一个谓词，否则"采集器坏掉 ⇒ 空清单更绿" */
const hasSites = (r) => r.sites.length > 0;
const isMixed = (r) => hasSites(r) && r.helper;
const hasLocalDefs = (r) => r.defs.length > 0;

const listTestFiles = (relDir) => {
  const abs = path.join(ROOT, relDir);
  if (!fs.existsSync(abs)) return [];
  const out = [];
  for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const child = `${relDir}/${e.name}`;
    if (e.isDirectory()) out.push(...listTestFiles(child));
    else if (e.name.endsWith('.js') && child !== SELF_EXCLUDE) out.push(child);
  }
  return out;
};

const collect = () =>
  SCAN_REL_DIRS.flatMap(listTestFiles).map((rel) =>
    rowFromView(rel, jsCodeOnlyKeepingLines(fs.readFileSync(path.join(ROOT, rel), 'utf8')))
  );

const offenders = () => collect().filter(hasSites);

/**
 * 封闭清单：`相对路径|站点数`。新增复制品 ⇒ 出现未登记条目 ⇒ 红；把某把闸的复制品迁到共享
 * helper ⇒ 条目必须同时从这里删掉，否则"登记了但源码里已经没有了"同样红（双向）。
 */
const DECLARED_OFFENDERS = [
  'src/tests/app/queryDefenseSingleSource.test.js|1',
  'src/tests/app/staticSurfaceRateLimitGate.test.js|1',
  'src/tests/architecture/requireCycles.test.js|1',
  'src/tests/auditCategoryLiteralWhitelist.test.js|1',
  'src/tests/auditFieldSetsImmutable.test.js|1',
  'src/tests/ci/credentialDoorCheckLedger.test.js|2',
  'src/tests/ci/fieldErrorsEgressGate.test.js|1',
  'src/tests/ci/permissionCatalogRouteParity.test.js|1',
  'src/tests/ci/userCredentialProjectionLedger.test.js|1',
  'src/tests/config/gateLayerExistence.test.js|1',
  'src/tests/config/migrateConfigHostQualifiedAllowlist.test.js|1',
  'src/tests/config/scriptSecretHydration.test.js|1',
  'src/tests/config/startupGuards.test.js|2',
  'src/tests/constants/businessHourSingleSource.test.js|1',
  'src/tests/constants/deadExportGuard.test.js|1',
  'src/tests/constants/detectionTokenGhosts.test.js|1',
  'src/tests/constants/tzBusinessEnvNormalization.test.js|1',
  'src/tests/deploy/imageRequireClosure.test.js|1',
  'src/tests/deploy/nginxSourcemapDenyParity.test.js|1',
  'src/tests/k6JourneyContract.test.js|1',
  'src/tests/middleware/abortedAuditReasonCleaning.test.js|1',
  'src/tests/middleware/rateLimitKeyNormalization.test.js|1',
  'src/tests/middleware/sentryOutboundScrub.test.js|1',
  'src/tests/middleware/writeMethodSingleSource.test.js|1',
  'src/tests/migrateConfigFailClosed.test.js|1',
  'src/tests/models/builtInRoleCodeSource.test.js|1',
  'src/tests/observability/logShipperShutdownWiring.test.js|1',
  'src/tests/riskLevelSingleSource.test.js|1',
  'src/tests/routes/readPermissionContract.test.js|1',
  'src/tests/security/tokenPurposeEntryInventory.test.js|1',
  'src/tests/services/auditSchemaCastRewriters.test.js|1',
  'src/tests/services/deviceAlertOutletParity.test.js|1',
  'src/tests/services/observabilityWritesNeverReject.test.js|1',
  'src/tests/services/rateLimitEscalation.test.js|2',
  'src/tests/services/securityAlertContainmentDecoupling.test.js|1',
  'src/tests/services/userSessionIpGate.test.js|1',
  'src/tests/services/websocketAuthGhostConnection.test.js|1',
  'src/tests/services/websocketHandlerRejectionGuard.test.js|1',
  'src/tests/utils/dateParamGateSingleSource.test.js|1',
  'src/tests/utils/mongoFailureAttribution.test.js|1',
  'src/tests/utils/roleLevelSingleSource.test.js|1',
  'src/tests/utils/shutdownBudgetContract.test.js|1',
  'src/tests/utils/shutdownStepOrder.test.js|1',
  'src/tests/utils/tokenPurposeAndConsumers.test.js|1',
  'src/tests/utils/wildcardPermissionSingleSource.test.js|1',
];

/**
 * 混合口径（既 require 共享 helper、又自带剥离实现）：今天实测 0 处。
 * 空清单本身没有牙（第 10 族），所以牙齿在 #4 的合成输入里：造一段"两者都有"的源码，
 * 采集器必须把它报出来——否则这条腿会在"采集器坏掉"时继续绿。
 */
const DECLARED_MIXED = [];

/** 本地同名定义（`function jsCodeOnly` / `const jsCodeOnly =`）：读代码的人会以为那是共享实现 */
const DECLARED_LOCAL_DEFS = [
  'src/tests/observability/logShipperShutdownWiring.test.js|1',
  'src/tests/services/websocketAuthGhostConnection.test.js|1',
  'src/tests/utils/shutdownBudgetContract.test.js|1',
  'src/tests/utils/shutdownStepOrder.test.js|1',
];

const siteKey = (r) => `${r.rel}|${r.sites.length}`;
const defKey = (r) => `${r.rel}|${r.defs.length}`;

/* ── 第 6 组用的两份"复制品形状"夹具：它们不是本闸的判据口径，只用来证明形状确实有洞 ── */
const NAIVE_LINE_STRIP = new RegExp('\\/\\/[^\\n]*', 'g');
const WHOLE_LINE_STRIP = new RegExp('^\\s*\\/\\/.*$', 'gm');
const naiveCopy = (src) =>
  src
    .replace(new RegExp(SIG, 'g'), ' ')
    .split('\n')
    .map((l) => l.replace(NAIVE_LINE_STRIP, ' '))
    .join('\n');
const wholeLineCopy = (src) => src.replace(new RegExp(SIG, 'g'), '').replace(WHOLE_LINE_STRIP, '');

describe('注释口径单点：私有复制品的封闭清单与牙齿', () => {
  /* ---------- 第 0 组：采集器自身 ---------- */
  test('#1 采集器有牙：真代码命中，注释里提到不命中，只 require helper 不命中', () => {
    const SYNTH = [
      'const codeOnly = (s) => s.replace(/' + SIG + "/g, ' ');", // 1：真复制品
      '// 说明：不要用 ' + SIG + ' 这种写法（行注释里提到）', // 2：不该命中
      '/* 块注释里提到 ' + SIG + ' 也不算 */', // 3：不该命中
      'const x = 1; // 尾注释里什么都没有', // 4
      "const y = '字符串里 ' + '" + SIG + "';", // 5：有意命中（new RegExp 同形）
    ].join('\n');
    const view = jsCodeOnlyKeepingLines(SYNTH);
    expect(sitesInView(view)).toEqual([1, 5]);
    // 只 require 共享实现的文本：零站点
    const onlyHelper = REQ_FIXTURE() + '\njsCodeOnly(src);';
    expect(sitesInView(jsCodeOnlyKeepingLines(onlyHelper))).toEqual([]);
    expect(helperUsedIn(jsCodeOnlyKeepingLines(onlyHelper))).toBe(true);
    expect(helperUsedIn(jsCodeOnlyKeepingLines(SYNTH))).toBe(false);
    // 计数口径的合成对照：两处取用点必须数成 2（数不出 2 的计数器守不住 #8 的"恰好一处"）
    expect(reqCountIn([REQ_FIXTURE(), REQ_FIXTURE(), 'jsCodeOnly(src);'].join('\n'))).toBe(2);
    expect(reqCountIn('jsCodeOnly(src);')).toBe(0);
    // 家族 B（整行前缀过滤）：漏了它，"只按行首判定"的复制品就完全不在面积里
    expect(sitesInView(jsCodeOnlyKeepingLines(PREFIX_FILTER_SAMPLE + '\nconst z = 1;'))).toEqual([
      1,
    ]);
    // 家族 B 的正对照同时必须是**家族 B**（不是靠家族 A 蒙中的）
    expect(famBCount(PREFIX_FILTER_SAMPLE)).toBe(1);
    expect(famACount(PREFIX_FILTER_SAMPLE)).toBe(0);
    expect(famACount('const k = /' + SIG + '/g;')).toBe(1);
    // 刻意不收的形状：`slice(0, 2)` 与注释无关（全仓 4 个命中都是别的东西），必须零命中
    expect(sitesInView(NON_COMMENT_SLICE_SAMPLE)).toEqual([]);
  });

  test('#2 面积不空转：站点数/文件数下界 + 点名已知复制品 + 家族 B 确实采到了', () => {
    const rows = offenders();
    const sites = rows.reduce((a, r) => a + r.sites.length, 0);
    // 下界取自实测 49 站点/46 文件，留余量：允许别人顺手删自己的复制品，不允许面积塌成空集
    expect(sites).toBeGreaterThanOrEqual(45);
    expect(rows.length).toBeGreaterThanOrEqual(40);
    for (const named of [
      'src/tests/architecture/requireCycles.test.js',
      'src/tests/utils/shutdownBudgetContract.test.js',
      'src/tests/services/websocketAuthGhostConnection.test.js',
      'src/tests/constants/deadExportGuard.test.js',
      'src/tests/constants/detectionTokenGhosts.test.js',
      'src/tests/ci/credentialDoorCheckLedger.test.js',
    ]) {
      expect(rows.map((r) => r.rel)).toContain(named);
    }
    // 一个文件里两处复制品必须是 2，不能被去重成 1
    const two = rows.find((r) => r.rel === 'src/tests/services/rateLimitEscalation.test.js');
    expect(two.sites).toHaveLength(2);
    // 家族 B 独有的文件必须存在且有下界：只报总数就分不清"补了签名"与"补了个空数组"
    const pureB = rows.filter((r) => r.famA === 0 && r.famB > 0);
    expect(pureB.length).toBeGreaterThanOrEqual(5);
    // 下界随实测下调 8→7：`src/tests/ci/mongooseTeardownLedger.test.js` 的行前缀过滤已迁到
    // 共享 helper（家族 B 少一份复制品，属"口径单点"的改善而不是面积塌陷），它的条目也已从
    // DECLARED_OFFENDERS 删掉。再往下掉意味着又有家族 B 被整族清空，那时要回来改这条。
    expect(rows.reduce((a, r) => a + r.famB, 0)).toBeGreaterThanOrEqual(7);
  });

  /* ---------- 第 1 组：封闭清单 ---------- */
  test('#3 复制品是封闭清单：实测与登记双向相等（新增红、迁移不删条目也红）', () => {
    const measured = offenders().map(siteKey).sort();
    expect(new Set(measured).size).toBe(measured.length);
    expect(new Set(DECLARED_OFFENDERS).size).toBe(DECLARED_OFFENDERS.length);
    const unexpected = measured.filter((k) => !DECLARED_OFFENDERS.includes(k));
    const stale = DECLARED_OFFENDERS.filter((k) => !measured.includes(k));
    expect({ unexpected, stale }).toEqual({ unexpected: [], stale: [] });
  });

  test('#4 混合口径（helper + 自带复制品）是封闭清单，且这条判据有牙', () => {
    const rows = collect().filter(isMixed);
    expect(rows.map((r) => r.rel).sort()).toEqual(DECLARED_MIXED);
    // 牙齿：合成一段"两者都有"的源码，走**同一个谓词**。空清单若只靠真树，采集器一坏就更绿。
    const both = rowFromView(
      'syn-mixed.js',
      jsCodeOnlyKeepingLines(
        [REQ_FIXTURE(), 'const mine = (s) => s.replace(/' + SIG + "/g, ' ');"].join('\n')
      )
    );
    expect(isMixed(both)).toBe(true);
    // 负对照 1：只 require helper ⇒ 不算混合
    expect(isMixed(rowFromView('syn-helper.js', jsCodeOnlyKeepingLines(REQ_FIXTURE())))).toBe(
      false
    );
    // 负对照 2：只在注释里提到签名 ⇒ 不算混合（视图口径生效）
    expect(
      hasSites(
        rowFromView('syn-note.js', jsCodeOnlyKeepingLines(`// 不要用 ${SIG_A}${SIG_B}${SIG_C}`))
      )
    ).toBe(false);
  });

  test('#5 本地同名 jsCodeOnly 定义是封闭清单（读代码的人会把私有副本当成共享实现）', () => {
    const rows = collect().filter(hasLocalDefs);
    const measured = rows.map(defKey).sort();
    expect(new Set(measured).size).toBe(measured.length);
    expect(measured).toEqual([...DECLARED_LOCAL_DEFS].sort());
    // 前提：这些定义点确实同时也是复制品站点（同名 + 同形状，不是两件事）
    for (const r of rows) expect(hasSites(r)).toBe(true);
    // 牙齿：合成一段本地同名定义（拼接后再比较，见文件头对"本文件是自己的靶"的说明）
    const SYNTH = FN_DEF_TOKEN + 'src) {\n  return src;\n}\n';
    const row = rowFromView('syn-def.js', SYNTH);
    expect(row.defs).toEqual([FN_DEF_TOKEN]);
    expect(hasLocalDefs(row)).toBe(true);
    expect(hasLocalDefs(rowFromView('syn-call.js', 'jsCodeOnly(src);'))).toBe(false);
  });

  /* ---------- 第 2 组：复制品的洞是真的 ---------- */
  test('#6 形状缺陷实证：naive 复制品会吞掉 URL 之后的真代码，整行口径的复制品会把尾注释留给判据', () => {
    const URL_LINE = "const u = 'https://x.example/P'; MUST_SURVIVE();";
    // 缺陷形状（旧共享视图与本轮 2 处 naiveTrailing 复制品同形）：两个斜杠之后的真代码消失
    expect(naiveCopy(URL_LINE)).not.toContain('MUST_SURVIVE');
    // 共享视图：整行保留（本轮 764 文件对拍已证"只会少抹"，这里钉住这一类）
    expect(jsCodeOnlyKeepingLines(URL_LINE)).toContain('MUST_SURVIVE();');

    const TRAILING = 'const a = 1; // REQUIRED_TOKEN_IN_COMMENT';
    // 只剥整行的复制品：行尾注释文本对判据可见 ⇒ 骗绿通道
    expect(wholeLineCopy(TRAILING)).toContain('REQUIRED_TOKEN_IN_COMMENT');
    expect(jsCodeOnlyKeepingLines(TRAILING)).not.toContain('REQUIRED_TOKEN_IN_COMMENT');
    expect(jsCodeOnly(TRAILING)).not.toContain('REQUIRED_TOKEN_IN_COMMENT');

    // 反向对照：块注释里提到的东西，两种实现都必须抹掉（否则上面两条"缺陷"就成了唯一差异）
    const BLOCK = 'const a = 1; /* REQUIRED_TOKEN_IN_BLOCK */ const b = 2;';
    expect(jsCodeOnlyKeepingLines(BLOCK)).not.toContain('REQUIRED_TOKEN_IN_BLOCK');
    expect(wholeLineCopy(BLOCK)).not.toContain('REQUIRED_TOKEN_IN_BLOCK');
  });

  /* ---------- 第 3 组：前提锚 ---------- */
  test('#7 共享 helper 仍是那把尺：两个视图都在剥注释，且行号契约没被掏空', () => {
    expect(typeof jsCodeOnly).toBe('function');
    expect(typeof jsCodeOnlyKeepingLines).toBe('function');
    const SRC = ['const A = 1;', '// 整行注释 GONE', 'const B = 2; /* 块 GONE2 */', ''].join('\n');
    const keep = jsCodeOnlyKeepingLines(SRC).split('\n');
    expect(keep).toHaveLength(4); // 行号一一对应：报 file:line 的判据依赖它
    expect(keep[1].trim()).toBe('');
    expect(keep[2]).toContain('const B = 2;');
    expect(keep.join('')).not.toContain('GONE2');
    expect(jsCodeOnly(SRC).split('\n').length).toBeLessThan(4);
    // helper 只有一处定义（本闸的采集口径全靠它）
    const helperPath = path.join(ROOT, 'src', 'tests', 'helpers', 'jsCodeOnly.js');
    const helperView = jsCodeOnlyKeepingLines(fs.readFileSync(helperPath, 'utf8'));
    expect(localDefsIn(helperView)).toHaveLength(2);
  });

  test('#8 自查：本闸自身零站点，helper 取用点恰好一处', () => {
    const selfView = jsCodeOnlyKeepingLines(fs.readFileSync(__filename, 'utf8'));
    expect(sitesInView(selfView)).toEqual([]);
    expect(localDefsIn(selfView)).toEqual([]);
    // 计数走 #1 里同一个 `reqCountIn`（含它的 2 处/0 处对照），这条腿才不是恒真
    expect(reqCountIn(selfView)).toBe(1);
    // 正对照：三个探测各自对"连续形态"确实有反应——否则上面的零命中只是探测器坏了（第 4 族）
    expect(sitesInView(SIG_A + SIG_B)).toEqual([]);
    expect(sitesInView('x = /' + SIG + '/g;')).toEqual([1]);
    expect(sitesInView(PREFIX_FILTER_SAMPLE)).toEqual([1]);
    expect(localDefsIn(FN_DEF_TOKEN + 'src) {}')).toEqual([FN_DEF_TOKEN]);
    expect(helperUsedIn("require('" + HELPER_PATH_LITERAL + "')")).toBe(true);
  });
});

/* ============================== 变异台账（2026-10-04 第 31 轮全量重测）==============================
 * 跑法：node <工作区>/tools/ledger.js src/tests/ci/commentViewSingleSource.test.js \
 *        src/tests/ci/commentViewSingleSource.test.js <模式=预测>
 * 被测文件 = 门禁文件本身：这条闸的仪器（采集器/谓词/登记）全在同一个文件里，所以台账只动自己的
 * 源码，一行都没碰并行 agent 的 helpers/jsCodeOnly.js（它是 dirty M）。"helper 被掏空"这一族用
 * 本文件的 require 行换成恒等实现来模拟（cvs-identity-view），效果等价且可逐字节恢复。
 * 腿编号按文件里的声明顺序（8 腿）：
 *   #1 采集器有牙（含 reqCountIn / famA / famB 与"刻意不收"的负对照）｜#2 面积下界与家族构成
 *   #3 复制品封闭清单双向｜#4 混合口径清单 + 合成对照｜#5 本地同名定义清单 + 前提
 *   #6 两种缺陷形状实证｜#7 共享 helper 前提锚｜#8 自查（零站点 + 取用点计数）
 * 基线：8 采集 / 8 绿 / 0 红（四次开跑各带一次基线，四次同值）；15 条模式跑完，每条恢复校验均
 * "与被测开始时逐字节相同"（sha 79819e3a9631a478），0 条 MUT-ABORT。
 *
 * 【为什么整套重测而不是只补新腿】仪器在本轮动了四处：面积从"只认块剥离正则签名"扩成
 * 家族 A ∪ 家族 B（整行前缀过滤与两字符扫描）、行号采集改走 SIGS.some、row 新增 famA/famB 计数、
 * #8 的取用点计数抽成 reqCountIn 并配 2 处/0 处对照。任何一处都会改变"哪些腿吃这条退化"，
 * 旧颜色整批作废（本轮上午先在旧仪器上跑过 4 条，那 4 条的颜色已作废、下面不再引用）。
 * 实测结果：15/15 全部被杀（零存活），其中 2 条的实测红腿集合比预测**多**，都是"腿变严了"的方向。
 *
 *   cvs-collector-blind        预测 红:#1,#2,#3,#4,#5,#8  实测 同 ✓（#6/#7 全程绿=它们不吃站点采集）
 *   cvs-site-offbyone          预测 红:#1,#8              实测 同 ✓（只有逐行断言抓得到行号）
 *   cvs-require-count-g        预测 红:#1,#8              实测 同 ✓（matchAll 直接抛，不是静默少数）
 *   cvs-area-collapse          预测 红:#2,#3              实测 同 ✓（#4 的判据走 collect 不走 offenders）
 *   cvs-def-detector-blind     预测 红:#5,#7,#8           实测 同 ✓
 *   cvs-mixed-predicate-blind  预测 红:#4                 实测 同 ✓（本轮重构的 payoff：真树 0 处
 *                                                            混合，只有合成对照经过同一个谓词才杀得掉）
 *   cvs-identity-view          预测 红:#1,#3,#4,#6,#7,#8  实测 红:#1,#3,#4,#5,#6,#7,#8 ← 偏差①
 *   cvs-collect-raw-view       预测 红:#3,#4,#5           实测 同 ✓
 *   cvs-naive-strip-shape      预测 红:#6                 实测 同 ✓
 *   cvs-wholeline-strip-shape  预测 红:#6                 实测 同 ✓
 *   cvs-declared-drop          预测 红:#3                 实测 同 ✓
 *   cvs-declared-key-drift     预测 红:#3                 实测 同 ✓
 *   cvs-famb-blind             预测 红:#1,#2,#3,#8        实测 同 ✓（新增 6 文件从面积里消失时，
 *                                                            #2 的"家族构成"下界与 #8 的正对照都响）
 *   cvs-fam-count-blind        预测 红:#1,#2              实测 同 ✓
 *   cvs-slice-overcollect      预测 红:#1,#2,#3           实测 红:#1,#3,#4,#8 ← 偏差②
 *
 * 偏差①（视图掏空会让"本文件自己的说明文字"进入面积）：#5 也红了。恒等视图下本文件头注里那句
 * "本地同名定义（函数形态 / const 形态）"不再是注释而是代码 ⇒ 本文件成为一个本地同名定义点 ⇒
 * #5 的封闭清单冒出未登记条目。与旧仪器上那次"cvs-collect-raw-view 只红 #5"是同一个根源，
 * 只是这次连 #3/#4 一起红（家族 B 的字面量同样写在头注里）。读法：这条腿的红讯里出现
 * `src/tests/ci/commentViewSingleSource.test.js` 时，先怀疑视图而不是别人新写了复制品。
 * 偏差②（把"刻意不收"的形状收进签名会连累三条腿，比预测多 #4/#8、少 #2）：
 *  - #8 红：本文件的夹具 NON_COMMENT_SLICE_SAMPLE 与两处说明文字都含那个字面量，放宽签名后
 *    本文件立刻变成自己的靶（这是**正确行为**，见头注"连续形态确实算一处"）；
 *  - #4 红：src/tests/ci/testHookConsumerGate.test.js 同时 require 共享 helper 且含该字面量，
 *    放宽会把一个本来干净的文件登记成"混合口径"；
 *  - #2 反而绿：下界是"实测 49 站点/46 文件留余量"（45/40），加 4 处仍在带内，点名样本与家族
 *    构成下界也都不受影响。⇒ 面积下界这类腿天然抓不到"多采"，只有负对照腿抓得到，这条负对照
 *    是本轮唯一让 cvs-slice-overcollect 显形的判据腿。
 *
 * 观察①（第 8 族在本闸自己的面积上成立过一次）：头注原先只写"实测 41 处/40 个文件"，那是
 * 按块剥离正则签名采的。补采候选时实测：家族 B（`t.startsWith('/*') || t.startsWith('//') ||
 * t.startsWith('*')` 与 `two === '/*'`）有 8 处、其中 6 个文件签名完全采不到，而全测试树 562 个
 * .js 里没有任何文件用 unicode 转义或 `.split('/*')` 实现剥离（实测各 0 处）——所以签名不是
 * 被"改写逃脱"，是被"换了整个实现形状"逃脱。面积按一种实现形状采，就必须把其它形状逐个量一遍。
 * 观察②（放宽与收紧的代价不对称，用实测数字说话）：`slice(0, 2)` 这个候选命中 4 个文件，
 * 全都不是注释剥离（权限码目录、游标排序键、钩子消费点、测试钩子闸）。收进来 ⇒ 登记清单
 * 从 46 涨到 50 且 #4 多一个假混合；不收 ⇒ 只损失"两字符切片式扫描"这一面（实测那种写法在本仓
 * 是 `two === '/*'` 形态，已经被家族 B 采到）。所以本闸的判据是**按实测命中的字面量**列的，
 * 不是按"看起来像扫描"拍的。
 * 观察③（为什么 #2 要单独钉家族构成）：若只报总面积，"加了家族 B 但恒采不到"（签名文本拼错一个
 * 字符）与"加了家族 B 并真的采到 8 处"是同一个颜色。cvs-famb-blind/#2 红、cvs-fam-count-blind/#2
 * 红说明两个方向都有牙；#1 的 famA/famB 交叉对照钉住"这条 B 的正对照确实是靠 B 命中的"。
 *
 * 近似（本闸管不到的面，逐条写清"这里没有腿，别当已覆盖"）：
 *   1) 只登记"存在第二份口径"，不判定每份口径**坏成什么样**。本轮实测两类形状（A 吞 URL 之后的
 *      真代码、B 把行尾注释留给判据）只由 #6 用夹具证明形状有洞，没有逐文件核实那 46 份各自
 *      落在哪一类——归属要看代码，文本闸判不了。
 *   2) 面积按字面签名采 ⇒ 未来任何**新形状**（例如按行号区间删除、或先 tokenize 再判类型）
 *      仍然静默逃脱（第 8 族）。要闭死只能靠人：改动注释剥离实现时来看这条闸。
 *   3) 站点计数按"行"去重：一行里同时有 A 与 B 两个签名只算 1 处。若有人把两份实现写进同一行，
 *      面积会少算 1——形状上可能，实践里没遇到（实测 49 站点里 famA+famB=49，无同行重叠）。
 *   4) `message:` 型判据不在本闸射程：本闸只管"什么算注释"，不管某个具体调用串。
 *   5) 未迁移动机见头注（40+ 个并行在途文件）。真正迁移时本闸的条目要同时删，"登记了但源码里
 *      已经没有了"同样红（#3 双向，cvs-declared-drop/cvs-declared-key-drift 各自验证过一侧）。
 *   6) 与 src/tests/ci/codeViewPhantomLedger.test.js（并行 agent 的第 10 把元门禁）射程重叠但
 *      判据不同：它问"有没有真实代码行从视图里整行消失"（修复后实测 0），本闸问"测试树里还有
 *      几份私有口径"。两条闸互不引用——最大的隐患，谁改签名口径要来看对方一眼。
 * ========================================================================================== */
