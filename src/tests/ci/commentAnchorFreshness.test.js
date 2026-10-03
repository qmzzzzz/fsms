/**
 * 【这台闸守什么】
 * 本仓把"注释即事实"当判据用：多条门禁的注释里写着"为什么这样是安全的（见 foo.js:123）"。
 * 一旦代码上下移动而行号没跟着改，读者按锚点读到的会是**另一件事**，于是注释从证据变成
 * 误导——而且比没有注释更糟，因为它带着"我已经查过源码"的语气。第 16 轮普查 `index.js:4xx`
 * 时实测 7 条引用里 6 条指错；第 17 轮把普查扩到全仓（365+ 条锚点引用），又抓到
 * `auditQueryService.js:200` 被写成"这里调用了 applyAuditDataScope"（真实调用点在 :316，
 * 而 :200 是一句无关的注释）——**行号落在范围内、也不是空行，纯文本判据看不见它**。
 *
 * 【判据分层，强度递增、覆盖面递减】
 *  1) 死区间（零登记、当场可判）：被引行号 > 目标文件行数 ⇒ 必错。
 *  2) 无内容锚点（零登记、当场可判）：被引区间整段"没有信息" ⇒ 这条引用不指向任何东西。
 *     两种形态分开数，因为它们强度不同：
 *      2a 纯空行；2b **只剩注释标记**（` * `、`//` 这类排版字符，一个实词都没有）。
 *     本轮实测到的 2a **全部**是 off-by-N 漂移（auditController.js:38→43、
 *     permissionController.js:146→161、deviceController.js:101→102、app.js:156→189 …），
 *     所以"落在空行上"是漂移的高置信签名，不是排版瑕疵。2b 是 G 线实测补的：
 *     `src/config/database.js:59` 内容就是一个孤零零的 ` * `，而引用站点把它当成
 *     "这里有 process.exit"的证据 ⇒ 只判 trim()==='' 会整类漏掉。
 *  3) 登记符号谓词（要登记）：`{所在文件, 引用原文, 被引区间必须出现的符号}` 三元组。
 *     只有这一层抓得住"行号仍在范围内但指错了地方"。新增登记的正确姿势与
 *     stubReturnTypeParity 同一条：**先说出这一行凭什么算证据（符号名），再来登记**。
 *     3b 谓词必须**局部唯一**：登记的符号在被引区间外的最近出现必须 ≥ 6 行。
 *     否则"漂 3 行"照样绿——本轮实测到 `DeviceService.js:420` 的 `/countDocuments/`
 *     全文件命中 10 处、最近距离 3 行（:423），`/npm run validate/` 最近距离 1 行。
 *     （行号随 #11 查询预算折行漂移，锚与台账随迁。）
 *     这样的登记只是装饰，必须写成能区分邻行的形态。
 *
 * 【豁免必须绑死在会失效的前提上】（沿用 stubReturnTypeParity 的做法）
 * STALE 台账每条 = 一个已知欠账，绑定谓词 = "那个文件此刻仍有一行写着这个错误行号"。
 * 归属方一旦把行号改对 ⇒ 绑定不再成立 ⇒ 层 2 的"台账每条仍是真欠账"用例红，且红字里
 * 直接印出该条的 `shouldRead` 与晋升指令（这条承诺由该用例的 map 文案实现，不是空话）；
 * 反向也拦：STALE 条目没被任何站点用到同样红。晋升也不是删条目——`shouldRead` 预登记了
 * 改对之后必须出现的符号，改成一个仍不对的行号一样红。"缺陷修好而豁免留着"和
 * "豁免留着而缺陷没修"两种静止都不许。
 *
 * 【已知边界（有意不收的，写清楚免得下个读者以为收了）】
 *  - 扫描集 = src/ + scripts/ + deployment/ + docs/；web-admin 前端不在内。
 *  - 本文件自身不参与扫描：LIVE/STALE 里全是拼出来的引用串，混进扫描集就无法区分"闸的自证"
 *    和"一处真违规"。这条自排除由层 4 最后一条用例显式钉住。
 *  - **逗号/顿号续写只收第一段**：`index.js:243,304` 收 `:243`、`app.js:189-190、:429` 收
 *    `:189-190`，其后的 `,304` 与 `、:429` 不带文件名，正则压根看不见（本轮实测：全仓这类
 *    续写 3 处）。所以**写引用时把文件名重复一遍**，闸才看得见——本文件与
 *    edgeCases.test.js 已按这个姿势写。`#L123` 形态不收（实测 1 处）。
 *  - 判据作用在**原文**上：`describe('…（app.js:150）')` 这类测试标题里的引用同样被收、
 *    同样被要求指对。这是有意的——标题就是文档，读者会照着它去取证。
 *  - **层 3 只对它登记的那些锚点负责。** 一条注释写"见 foo.js:88 的 X"而 :88 既不是空行、
 *    不是注释标记、不是纯闭合标点（第 18 轮加的 `punct-only`：`middleware/errorHandler.js:195-196`
 *    漂到两个 `}` 上，旧判据放行）也没登记 ⇒ 本闸沉默。这不是漏判的借口，是把"覆盖面"写成可核对的清单：LIVE.length 有地板
 *    （只许涨不许跌），新增登记必须附带 `why`（这行为什么算证据）与 3b 要求的局部唯一谓词。
 *  - 裸文件名（`auditController.js:43`）是本仓主流写法（381 条里只有 187 条带目录），解析按
 *    "仓库根 → src/ → node_modules/ → 同目录 → 全仓唯一 basename"五步走，**basename 不唯一
 *    就跳过不判**。这条纪律是被一盆假阳逼出来的：上一版探针按 basename 兜底，把
 *    `winston/lib/winston/logger.js:350-361` 认成了 src/utils/logger.js（它只有 286 行），
 *    于是"报告 2 条越界锚点"——真去读才发现引的是 node_modules。宁可少判，不许猜。
 *    代价是 14 条锚点因 basename 撞名而判不到 ⇒ 层 4 用"解析率 ≥ 90%"把这笔账钉住，
 *    新增一个同名文件把一批裸引用打回不可判，就会红。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SCAN_ROOTS = ['src', 'scripts', 'deployment', 'docs'];
const SELF = 'src/tests/ci/commentAnchorFreshness.test.js';
const EXT = /\.(js|jsx|ts|tsx|vue|md|sh|json|ya?ml)$/i;

const read = (p) => fs.readFileSync(p, 'utf8');
const slash = (p) => path.relative(ROOT, p).replace(/\\/g, '/');

function listFiles(dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'coverage') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) listFiles(p, out);
    else if (EXT.test(e.name)) out.push(p);
  }
  return out;
}

const REPO_FILES = SCAN_ROOTS.flatMap((d) => listFiles(path.join(ROOT, d), []));
const SCANNED = REPO_FILES.filter((f) => slash(f) !== SELF);

const linesCache = new Map();
function linesOf(abs) {
  if (!linesCache.has(abs)) linesCache.set(abs, read(abs).split('\n'));
  return linesCache.get(abs);
}

/** 五步精确解析；basename 不唯一 ⇒ 返回 null（不判） */
function resolveTarget(citedRaw, siteAbs) {
  const cands = [
    path.join(ROOT, citedRaw),
    path.join(ROOT, 'src', citedRaw),
    path.join(ROOT, 'node_modules', citedRaw),
    path.join(path.dirname(siteAbs || ROOT), citedRaw),
  ];
  for (const c of cands) if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  const base = path.basename(citedRaw);
  const hits = REPO_FILES.filter((f) => path.basename(f) === base);
  return hits.length === 1 ? hits[0] : null;
}

const CITE_RE =
  /((?:[\w.@-]+\/)*[\w.@-]+\.(?:js|jsx|ts|tsx|vue|md|sh|json|ya?ml)):(\d+)(?:\s*[-–~]\s*(\d+))?(?!\d)/g;

/** 普查全部锚点引用（注释与字符串都算——这里要判的正是"写下来的引用"） */
function collectCitations(files) {
  const found = [];
  for (const f of files) {
    const lines = read(f).split('\n');
    for (let i = 0; i < lines.length; i++) {
      let m;
      CITE_RE.lastIndex = 0;
      while ((m = CITE_RE.exec(lines[i])) !== null) {
        found.push({
          site: slash(f),
          siteLine: i + 1,
          cited: m[1],
          from: Number(m[2]),
          to: m[3] ? Number(m[3]) : Number(m[2]),
          abs: resolveTarget(m[1], f),
        });
      }
    }
  }
  return found;
}

/**
 * 区间"没有信息"的两种形态：2a 纯空行；2b 只剩注释排版字符（` * `、`//`、`/*`、`*\/`）。
 * 2b 与 2a 分开数，因为红字要告诉读者是哪一种：本轮实测的 2b 全是"把 docblock 的
 * 一条空续行当成了代码站点"，修法是挪行号而不是删注释。
 */
const MARKUP_ONLY = /^\s*(?:\/{2}|\*|\/\*)*\s*$/;
/**
 * 只剩闭合标点（`}` `)` `];` 之类）——和第 17 轮实测到的 `middleware/errorHandler.js:195-196`
 * 同一种失实：注释引的是"属性式导出那两行"，而真实导出在 :199-200，区间落在函数收尾的两个 `}` 上。
 * 它不是空行也不是注释标记，所以旧判据放行；但它同样"无内容可核对"，漂移一格就换了语义。
 */
const PUNCT_ONLY = /^[\s)}\];,]*$/;
function contentFreeKind(abs, from, to) {
  const seg = linesOf(abs)
    .slice(from - 1, to)
    .map((l) => l.trim());
  if (seg.every((l) => l === '')) return 'blank';
  if (seg.every((l) => MARKUP_ONLY.test(l))) return 'markup-only';
  if (seg.every((l) => PUNCT_ONLY.test(l))) return 'punct-only';
  return null;
}

/** 当场可判的失效：死区间、无内容锚点（含 kind） */
function classify(found) {
  const deadRange = [];
  const blank = [];
  let resolved = 0;
  for (const c of found) {
    if (!c.abs) continue;
    resolved++;
    if (c.to > linesOf(c.abs).length) {
      deadRange.push(c);
      continue;
    }
    const kind = contentFreeKind(c.abs, c.from, c.to);
    if (kind) blank.push({ ...c, kind });
  }
  return { deadRange, blank, resolved };
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * 引用原文在所属文件里的出现行（登记即接线）。
 * 前后加边界：否则裸 token `secret-rotation.md:156` 会把限定形态
 * `deployment/secret-rotation.md:156` 的那次出现也数进来（两种写法在同一个文件里并存，
 * 本轮实测到），计数与判定都会串。
 */
function occurrences(fileRel, token) {
  const abs = path.join(ROOT, fileRel);
  if (!fs.existsSync(abs)) return [];
  const re = new RegExp(`(?:^|[^\\w./-])${esc(token)}(?!\\d)`);
  const hits = [];
  read(abs)
    .split('\n')
    .forEach((l, i) => {
      if (re.test(l)) hits.push(i + 1);
    });
  return hits;
}

/** 纯取区间实况文本——漂移反证直接用它，不必伪造一个"写错行号的站点" */
function rangeText(citedRaw, from, to, siteAbs) {
  const abs = resolveTarget(citedRaw, siteAbs || path.join(ROOT, 'src'));
  if (!abs) return null;
  const arr = linesOf(abs);
  if (to > arr.length) return null;
  return { target: slash(abs), from, to, text: arr.slice(from - 1, to).join('\n') };
}

const splitToken = (token) => {
  const m = token.match(/^(.+?):(\d+)(?:-(\d+))?$/);
  return { cited: m[1], from: Number(m[2]), to: m[3] ? Number(m[3]) : Number(m[2]) };
};

/** 由登记原文（`app.js:189` / `x.test.js:66-71`）解出被引区间 */
function citedRange(fileRel, token) {
  if (wiringHits(fileRel, token) === 0) return null;
  const { cited, from, to } = splitToken(token);
  const r = rangeText(cited, from, to, path.join(ROOT, fileRel));
  return r ? { ...r, sites: wiringHits(fileRel, token) } : null;
}

/**
 * 接线判据（只用于"这条登记还挂在真站点上吗"）。
 * 放宽一档：有人把裸文件名规范化成带目录的等价写法（`auditController.js:43` →
 * `src/controllers/auditController.js:43`）时，判据不该因此假红——它说的是同一条引用。
 * `occurrences()` 本身保持严格：STALE 台账的绑定必须能区分裸/限定两种写法（层 2 的
 * 边界自证钉的就是这个），放宽只发生在"接线"这一步。
 */
function wiringHits(fileRel, token) {
  const strict = occurrences(fileRel, token).length;
  if (strict > 0 || token.includes('/')) return strict;
  const { cited } = splitToken(token);
  const abs = resolveTarget(cited, path.join(ROOT, fileRel));
  if (!abs) return 0;
  return occurrences(fileRel, `${slash(abs)}${token.slice(cited.length)}`).length;
}

/**
 * 判据阈值只许在一处定义，真实数据与合成反证读同一个常量。
 * 第 26 轮变异台账实测：阈值在"判据"和"反证样本"里各写一遍时，放松判据的那一刀两边都不受影响
 * （M2 把 6 行改成 1 行、M7 把合成样本的 85 改成 95，具名用例照样绿）——写两遍等于没有阈值。
 * 共用常量后：放松阈值 ⇒ 合成反证变红；收紧阈值 ⇒ 真实数据变红，两个方向都有牙。
 */
const UNIQ_GAP = 6;
const RESOLVE_RATIO_FLOOR = 0.9;

/**
 * 3b：登记的符号在被引区间**外**的最近出现距离（Infinity = 全文件只此一处）。
 * 距离 < UNIQ_GAP 意味着"行号漂几行照样绿"——这种登记是装饰，不是判据。
 */
function mustNearestOutside(entry) {
  const { cited, from, to } = splitToken(entry.at);
  const abs = resolveTarget(cited, path.join(ROOT, entry.in));
  if (!abs) return null;
  let best = Infinity;
  linesOf(abs).forEach((l, i) => {
    const n = i + 1;
    if (n >= from && n <= to) return;
    if (entry.must.test(l)) best = Math.min(best, n < from ? from - n : n - to);
  });
  return best;
}

/** 3b 的采集器：把"没有牙的登记"收成一份名单，判据与反证都走它（阈值唯一来源） */
function toothlessRegistrations(entries) {
  const out = [];
  for (const e of entries) {
    const d = mustNearestOutside(e);
    if (d === null) {
      out.push(`${e.in} :: ${e.at} 解析不到目标，无法核对唯一性`);
    } else if (d < UNIQ_GAP) {
      out.push(
        `${e.in} :: ${e.at} 的谓词/${e.must.source}/在区间外 ${d} 行处又出现 ⇒ 漂 ${d} 行不会红，这条登记没有牙（把谓词收紧到区间内唯一）`
      );
    }
  }
  return out;
}

/** 被豁免的键里，台账推不出来的那些（豁免必须逐条兑现，不是装饰品） */
function unexplainedExemptions(exemptedKeys, ledgerKeys) {
  return exemptedKeys.filter((k) => !ledgerKeys.has(k));
}

/** LIVE：行号当场必须指得到那个符号 */
const LIVE = [
  {
    in: 'src/middleware/sentry.js',
    at: 'app.js:189',
    must: /sentryRequestHandler/,
    why: 'Sentry 请求处理器挂载点',
  },
  {
    in: 'src/middleware/sentry.js',
    at: 'app.js:429',
    must: /sentryErrorHandler/,
    why: 'Sentry 错误处理器挂载点',
  },
  {
    in: 'src/middleware/sentry.js',
    at: 'app.js:433',
    must: /app\.use\(errorHandler/,
    why: '通用 errorHandler 位置（口径是"在它之前"）',
  },
  {
    in: 'src/controllers/reportController.js',
    at: 'auditController.js:43',
    must: /applyAuditDataScope/,
    why: '审计列表的数据范围判据',
  },
  {
    in: 'src/controllers/reportController.js',
    at: 'auditQueryService.js:320',
    must: /applyAuditDataScope/,
    why: '同一条判据的第二处调用（17 轮实测原先写的 :200 是无关注释）',
  },
  {
    in: 'src/services/reportExportService.js',
    at: 'FireAlarm.js:160',
    must: /取值可重复/,
    why: '"必须有同向 _id 次级键"不变式出处一',
  },
  {
    in: 'src/services/reportExportService.js',
    at: 'Inspection.js:179',
    must: /排序键可重复/,
    why: '不变式出处二',
  },
  {
    in: 'src/services/reportExportService.js',
    at: 'AuditLog.js:309',
    must: /timestamp: -1, _id: -1/,
    why: '不变式出处三',
  },
  {
    in: 'src/services/reportExportService.js',
    at: 'AlarmService.js:118',
    must: /\.sort\(\{ occurredAt: -1, _id: -1 \}\)/,
    why: '列表侧实际用的全序（报警）',
  },
  {
    in: 'src/services/reportExportService.js',
    at: 'auditQueryService.js:154',
    must: /\.sort\(\{ timestamp: -1, _id: -1 \}\)/,
    why: '列表侧实际用的全序（审计）',
  },
  {
    in: 'src/config/validate.js',
    at: 'src/config/index.js:11',
    must: /hydrateSecretsFromFiles\(\)/,
    why: '库身份在 require 期回填，入口身份必须自己回填',
  },
  {
    in: 'src/config/validate.js',
    at: 'deployment/secret-rotation.md:207',
    must: /docker compose exec -T app npm run validate/,
    why: '手册把本步退出码当"轮换后配置自洽"的证据（裸 `npm run validate` 上下两行都有，必须连带容器命令才唯一）',
  },
  {
    in: 'src/tests/controllers/reportExportRowOrderAndCells.test.js',
    at: 'tests/explainSpotcheckContract.test.js:66-71',
    must: /occurredAt: -1, _id: -1/,
    why: '四份排序被逐字段钉住的那段',
  },
  {
    in: 'src/tests/auditExportDataScope.test.js',
    at: 'auditController.js:43',
    must: /applyAuditDataScope/,
    why: 'audit-logs 端点确实过数据范围',
  },
  {
    in: 'src/tests/auditExportDataScope.test.js',
    at: 'auditQueryService.js:320',
    must: /applyAuditDataScope/,
    why: '审计列表侧同一判据',
  },
  {
    in: 'src/tests/controllers/auditExportManifestBytes.test.js',
    at: 'auditController.js:43',
    must: /applyAuditDataScope/,
    why: '"删掉这行不会有任何测试变红"指的就是这一行',
  },
  {
    in: 'src/tests/controllers/deviceExpiringTruncation.test.js',
    at: 'deviceController.js:102',
    must: /ApiResponse\.paginated/,
    why: '兄弟接口如实带 total 的反证',
  },
  {
    in: 'src/tests/controllers/deviceExpiringTruncation.test.js',
    at: 'DeviceService.js:420',
    must: /countDocuments\(\{ \.\.\.scoped, \.\.\.alert\.needMaintenance \}, listCountOptions\(\)\)/,
    why: '同一档判据专门跑计数（:423/:424 是同符号的另两处，谓词必须区分得开；行号随 #11 查询预算折行漂移）',
  },
  {
    in: 'src/tests/controllers/deviceExpiringTruncation.test.js',
    at: 'auditExportService.js:69',
    must: /多取一条/,
    why: 'truncated 判定精确的探针写法',
  },
  {
    in: 'src/tests/controllers/deviceExpiringTruncation.test.js',
    at: 'reportWorkbookService.js:20',
    must: /恰好 EXPORT_LIMIT 行/,
    why: '恰好等于上限不得误报截断',
  },
  {
    in: 'src/tests/edge/edgeCases.test.js',
    at: 'auditController.js:25',
    must: /try \{/,
    why: '导出路径的外层 try',
  },
  {
    in: 'src/tests/edge/edgeCases.test.js',
    at: 'auditController.js:68',
    must: /catch \(error\)/,
    why: '接住拒绝并给 AUDIT_EXPORT_FAILED 的那条 catch',
  },
  {
    in: 'src/tests/reservedWildcardPermission.test.js',
    at: 'permissionController.js:161',
    must: /savePermission/,
    why: '"只有一个调用方"的那唯一调用点',
  },
  {
    in: 'src/tests/services/alertSeveritySurvivesRender.test.js',
    at: 'securityAlertDelivery.js:156',
    must: /logMethod/,
    why: 'low/medium 都映射到 info 的那一行',
  },
  // —— 以下 13 条是第 17 轮 G/H 两线实测出的错锚：站点已改对，登记钉住不再漂 ——
  {
    in: 'src/utils/loggerFlush.js',
    at: 'index.js:112',
    must: /logger\.warn\(`收到重复/,
    why: '二次信号 handler 的 logger.warn（原写 :70，落在 docblock 的空续行上）',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'app.js:150',
    must: /app\.set\('trust proxy'/,
    why: 'trust proxy 有效值分支的落点（原写 :96-97，那是 .filter(Boolean)）',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'app.js:377',
    must: /app\.get\('\/api'/,
    why: '/api 根路径处理器（原写 :297-298，那是 CSRF 注释）',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'app.js:334-355',
    must: /503[\s\S]*\.catch/,
    why: '/readyz 的 503 双路径：then 里按 mongo.ok 定码 + catch 里硬 503（原写 :258-278 是 body-parser）',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'app.js:343-352',
    must: /res\.status\(503\)\.json/,
    why: '头注里点名"两条失败路径"的具体行段',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'app.js:57',
    must: /checkMongoReady/,
    why: '加载期解构（原写 :48，那是别的 require）',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'app.js:189-190',
    must: /sentryRequestHandler/,
    why: 'Sentry 三件套前两件（原写 :134-136）',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'app.js:429',
    must: /sentryErrorHandler/,
    why: '三件套第三件（原写 :348-349，且那种"、:429"续写闸根本看不见）',
  },
  {
    in: 'src/tests/app/appTrustProxyAndReadyzGuards.test.js',
    at: 'src/config/validate.js:358',
    must: /requiresProductionSemantics/,
    why: 'validateConfig() 首行的非生产早退（原写 :264，那是 MAX_TRUST_PROXY_HOPS 常量）',
  },
  {
    in: 'src/tests/controllers/auditSummaryCache.test.js',
    at: 'auditQueryService.js:136',
    must: /\$group/,
    why: '与页码无关的那次全量聚合（原引的是已失效的对外报告行号）',
  },
  {
    in: 'src/tests/controllers/createUserScopeGate.test.js',
    at: 'userController.js:590',
    must: /assertRecordInScope/,
    why: 'updateUser 里的数据范围闸（原写 :326，那是另一个函数的 docblock）',
  },
  {
    in: 'src/tests/deploy/cliArgStrictness.test.js',
    at: 'deploy.js:283',
    must: /process\.exit\(2\)/,
    why: '参数非法时在任何副作用之前拒绝（原写 :255，那是 rollback 的注释）',
  },
  {
    in: 'src/tests/config/scriptSecretHydration.test.js',
    at: 'deployment/secret-rotation.md:207',
    must: /docker compose exec -T app npm run validate/,
    why: '"拿这一步退出码当证据"的那一步（本轮把 :156 两处一并改对，原 :156 是空行）',
  },
  {
    in: 'src/constants/runtime.js',
    at: 'services/reportDashboardService.js:18-22',
    must: /不做跨实例失效广播/,
    why: '清单条目改口"只靠 TTL"所依据的那段取舍注释（行号写错=运维读到另一套口径）',
  },
  {
    in: 'src/constants/runtime.js',
    at: 'statsCache.js:114',
    must: /sharedCache\.publishInvalidate\(/,
    why: '清单注释钉住的发布端行号（它是有行号的事实，就该被行号判据管着）',
  },
  {
    in: 'src/constants/runtime.js',
    at: 'statsCache.js:124',
    must: /sharedCache\.onInvalidate\(/,
    why: '清单注释钉住的消费端行号',
  },
  {
    in: 'src/tests/utils/auditFilterCombination.test.js',
    at: 'utils/auditQuery.js:30-35',
    must: /统一收口为抛错/,
    why: '"误导性空结果 ⇒ 抛错/400"这条裁定只有一份，新用例引用的就是它',
  },
  {
    in: 'src/tests/ci/runtimeInventoryClaims.test.js',
    at: 'src/services/reportDashboardService.js:18-22',
    must: /不做跨实例失效广播/,
    why: '同一处事实的第二个引用站点，同样必须指得到那段注释',
  },
];

/**
 * STALE：已知欠账台账，全部位于他人正在改的脏文件（M / A），我不代改。
 * `at` = 此刻写在文件里的**错误**行号（绑定谓词），`shouldRead` + `mustAfterFix` = 改对之后
 * 必须满足的判据（晋升目标）。
 */
const STALE = [
  {
    in: 'src/utils/transaction.js',
    at: 'src/index.js:446',
    owner: '他人脏文件（M）',
    shouldRead: 'src/index.js:456',
    mustAfterFix: /process\.on\('unhandledRejection'/,
  },
  {
    in: 'src/tests/utils/transactionTopology.test.js',
    at: 'src/index.js:446',
    owner: '他人脏文件（M）',
    shouldRead: 'src/index.js:456',
    mustAfterFix: /process\.on\('unhandledRejection'/,
  },
  {
    in: 'src/services/websocketService.js',
    at: 'src/index.js:446-463',
    owner: '他人脏文件（M）',
    shouldRead: 'src/index.js:456-474',
    mustAfterFix: /process\.on\('unhandledRejection'/,
  },
  {
    in: 'src/tests/services/websocketHandlerRejectionGuard.test.js',
    at: 'src/index.js:446-463',
    owner: '他人 staged（A）',
    shouldRead: 'src/index.js:456-474',
    mustAfterFix: /process\.on\('unhandledRejection'/,
  },
  {
    in: 'src/tests/observability/loggerFlush.test.js',
    at: 'database.js:59',
    owner: '他人脏文件（M）',
    shouldRead: 'src/config/database.js:117',
    mustAfterFix: /exitAfterFlush\(1\)/,
  },
];

const ALL = collectCitations(SCANNED);
const { deadRange, blank, resolved } = classify(ALL);

const key = (c) =>
  `${c.site}:${c.siteLine} => ${c.cited}:${c.from}${c.to !== c.from ? `-${c.to}` : ''}`;
const staleKey = (s) => {
  const { cited, from, to } = splitToken(s.at);
  return `${s.in}|${cited}|${from}|${to}`;
};
const citeKey = (c) => `${c.site}|${c.cited}|${c.from}|${c.to}`;
const STALE_KEYS = new Set(STALE.map(staleKey));

describe('层 1 · 死区间（零登记、无豁免）', () => {
  test('没有任何锚点落在目标文件之外', () => {
    expect(deadRange.map(key)).toEqual([]);
  });

  test('判据本身有牙：越界、空行、只剩注释标记、只剩闭合标点四种形态都必须被 classify 报出来', () => {
    const appAbs = path.join(ROOT, 'src/app.js');
    const ls = linesOf(appAbs);
    const blankAt = ls.findIndex((l) => l.trim() === '') + 1;
    const markupAt = ls.findIndex((l) => l.trim() !== '' && MARKUP_ONLY.test(l)) + 1;
    const punctAt =
      ls.findIndex((l) => l.trim() !== '' && !MARKUP_ONLY.test(l) && PUNCT_ONLY.test(l.trim())) + 1;
    const cleanAt = ls.findIndex((l) => /[A-Za-z_$]/.test(l) && !MARKUP_ONLY.test(l.trim())) + 1;
    expect(Math.min(blankAt, markupAt, punctAt, cleanAt)).toBeGreaterThan(0);
    expect(new Set([blankAt, markupAt, punctAt, cleanAt]).size).toBe(4);
    const mk = (siteLine, from, to) => ({
      site: 'synthetic',
      siteLine,
      cited: 'src/app.js',
      from,
      to,
      abs: appAbs,
    });
    const r = classify([
      mk(1, 999999, 999999),
      mk(2, blankAt, blankAt),
      mk(3, markupAt, markupAt),
      mk(4, cleanAt, cleanAt),
      mk(5, punctAt, punctAt),
    ]);
    expect(r.deadRange.map((c) => c.from)).toEqual([999999]);
    expect(r.blank.map((c) => `${c.from}:${c.kind}`)).toEqual([
      `${blankAt}:blank`,
      `${markupAt}:markup-only`,
      `${punctAt}:punct-only`,
    ]);
    expect(r.resolved).toBe(5);
    // 反证：有内容的行不许被 2b 顺手报掉（否则整仓引用都会红，判据就没人看了）
    expect(r.blank.some((c) => c.from === cleanAt)).toBe(false);
    // 混合段（`}` 之外还有代码）必须放行：判据只挑"整段都可有可无"的锚点
    expect(classify([mk(6, cleanAt, cleanAt + 1)]).blank).toEqual([]);
  });
});

describe('层 2 · 无内容锚点（空行 / 只剩注释标记；豁免 = STALE 台账，逐条绑死）', () => {
  test('未被 STALE 覆盖的无内容锚点必须为空', () => {
    expect(
      blank
        .filter((c) => !STALE_KEYS.has(citeKey(c)))
        .map((c) => `${key(c)} [${c.kind}]`)
        .sort()
    ).toEqual([]);
  });

  test('豁免确实豁免了真违规：站点行号由台账算出来，不硬编码（归属方挪一行就假红的那种）', () => {
    const exempted = blank
      .filter((c) => STALE_KEYS.has(citeKey(c)))
      .map(key)
      .sort();
    // 从台账反推：每条 STALE 的 token 在站点文件的哪几行 ⇒ 期望的被豁免键集合。
    // 站点行号变了（有人在注释上方插了一行）这里跟着变，不会假红；台账里删一条，这里少一条。
    const expected = [];
    for (const s of STALE) {
      const { cited, from, to } = splitToken(s.at);
      for (const line of occurrences(s.in, s.at))
        expected.push(`${s.in}:${line} => ${cited}:${from}${to !== from ? `-${to}` : ''}`);
    }
    // 台账条目分两种用途：一种此刻真的在制造"无内容锚点"违规（必须被豁免承接），
    // 另一种只是语义漂移（行号落在代码上但指错臂），它不进层 2 的违规集。
    // 这里判的是"没有一条豁免是白占着的"：被豁免的每个键都必须由台账反推出来。
    const derived = new Set(expected);
    expect(
      unexplainedExemptions(exempted, derived).map(
        (k) => `${k} 被豁免了，但台账里推不出这个站点行号`
      )
    ).toEqual([]);
    expect(exempted.length).toBeGreaterThanOrEqual(1);
    // 反证：台账清空 ⇒ 每一条真豁免都必须被判"无据"。
    // 把 unexplainedExemptions() 改成恒空数组（= 豁免不再要求台账兑现）这条立刻红；
    // 前一行的 length 地板保证这里不是拿空集比空集的恒真。
    expect(unexplainedExemptions(exempted, new Set())).toEqual(exempted);
    // 反证：台账推出来的键是"站点行号精确"的，不是前缀匹配——把真站点行号 +1 必须推不出
    const [firstExempt] = exempted;
    const [head, tail] = [firstExempt.split(' => ')[0], firstExempt.split(' => ')[1]];
    const shifted = `${head.split(':')[0]}:${Number(head.split(':')[1]) + 1} => ${tail}`;
    expect(derived.has(shifted)).toBe(false);
  });

  test('台账每条此刻仍是真欠账：站点仍写着那个错误行号', () => {
    const broken = STALE.map((s) => ({ s, n: occurrences(s.in, s.at).length })).filter(
      (x) => x.n === 0
    );
    expect(
      broken.map(
        (x) =>
          `${x.s.in} 不再写 ${x.s.at} ⇒ 该锚点已被改对：请把这条从 STALE 晋升进 LIVE 谓词登记，` +
          `晋升目标 shouldRead=${x.s.shouldRead}（改成一个仍不对的行号一样红）`
      )
    ).toEqual([]);
    // 前提自证：一个不存在的 token 必须判 0 次，否则上面那条 filter 是恒真
    expect(occurrences('src/index.js', 'src/app.js:424242').length).toBe(0);
    // 边界自证：裸 token 不许把限定形态的那次出现数进来。
    // 这两种写法今天在 scriptSecretHydration.test.js 里**并存**（:22 裸、:676 带目录），
    // 是同一条判据最好的现成样本；去掉 occurrences 的前导边界这条就会红。
    const bare = occurrences(
      'src/tests/config/scriptSecretHydration.test.js',
      'secret-rotation.md:207'
    );
    const qualified = occurrences(
      'src/tests/config/scriptSecretHydration.test.js',
      'deployment/secret-rotation.md:207'
    );
    expect(bare.length).toBe(1);
    expect(qualified.length).toBe(1);
    expect(occurrences('src/utils/loggerFlush.js', 'index.js:70').length).toBe(0);
    expect(occurrences('src/utils/loggerFlush.js', 'index.js:112').length).toBe(1);
  });
});

describe('层 3 · 登记符号谓词（行号在范围内但指错地方：纯文本判据看不见的那一类）', () => {
  test('每条登记的引用原文在所属文件里至少出现一次（不接线的登记要红）', () => {
    expect(
      LIVE.filter((e) => wiringHits(e.in, e.at) === 0).map((e) => `${e.in} :: ${e.at}`)
    ).toEqual([]);
    // 反证：一条没接线的登记必须被挑出来（等价于"登记是装饰品"那种静止态）
    expect(wiringHits('src/index.js', 'src/app.js:424242')).toBe(0);
  });

  test('每条登记的被引区间当场必须含声明的符号', () => {
    const bad = [];
    for (const e of LIVE) {
      const r = citedRange(e.in, e.at);
      if (!r) {
        bad.push(`${e.in}:${e.at} 解析不到目标或行号越界`);
        continue;
      }
      if (!e.must.test(r.text))
        bad.push(`${e.in} 引用 ${e.at} → ${r.target}:${r.from}-${r.to} 不含「${e.why}」`);
    }
    expect(bad).toEqual([]);
  });

  test('3b 每条登记的谓词必须局部唯一：同符号在区间外的最近出现 ≥ 6 行', () => {
    expect(toothlessRegistrations(LIVE)).toEqual([]);
    // 反证（放松方向）：区间外 3 行就重复出现的宽谓词必须被同一个采集器判无牙。
    // 阈值只在 UNIQ_GAP 一处定义——把 6 改成 1 时这条合成反证跟着变绿→用例红，
    // 这正是第 26 轮台账 M2 抓到的洞（阈值写两遍，放松判据抓不到）。
    const weakened = {
      in: 'src/tests/controllers/deviceExpiringTruncation.test.js',
      at: 'DeviceService.js:424',
      must: /countDocuments/,
    };
    expect(mustNearestOutside(weakened)).toBeLessThan(UNIQ_GAP);
    expect(toothlessRegistrations([weakened])).toHaveLength(1);
    // 正向自证：收紧后的同一条必须一条都不报（两向都过，才不是只验失败态）
    expect(toothlessRegistrations([LIVE.find((e) => e.at === 'DeviceService.js:420')])).toEqual([]);
  });

  test('谓词有牙（正向命中 + 反向不命中），不许跟着行号走', () => {
    const hit = citedRange('src/middleware/sentry.js', 'app.js:429');
    expect(/sentryErrorHandler/.test(hit.text)).toBe(true);
    expect(/绝不可能出现在这一行的符号ZZZ/.test(hit.text)).toBe(false);
    // 本轮之前的真实写法：auditController.js:38 是空行，同一条判据必须判它不含符号
    const drifted = rangeText(
      'auditController.js',
      38,
      38,
      path.join(ROOT, 'src/controllers/reportController.js')
    );
    expect(drifted).not.toBeNull();
    expect(/applyAuditDataScope/.test(drifted.text)).toBe(false);
    // 反向：修好的 :43 必须含符号（两向都过，才不是只验失败态）
    expect(/applyAuditDataScope/.test(rangeText('auditController.js', 43, 43).text)).toBe(true);
  });

  test('晋升目标预登记有牙：STALE 改对才绿，改成一个仍不对的行号一样红', () => {
    for (const s of STALE) {
      const { cited, from, to } = splitToken(s.shouldRead);
      const r = rangeText(cited, from, to, path.join(ROOT, s.in));
      expect(r).not.toBeNull();
      expect(s.mustAfterFix.test(r.text)).toBe(true);
      // 反证：漂移态锚点真正指进去的那一段（:436-454 = uncaughtException 臂）必须不含
      // 被声称的 unhandledRejection——这正是"行号在范围内但指错了臂"会让读者产生的误判。
      if (cited.endsWith('index.js')) {
        const drifted = rangeText(cited, 436, 454, path.join(ROOT, 'src')).text;
        expect(/process\.on\('unhandledRejection'/.test(drifted)).toBe(false);
        expect(/process\.on\('uncaughtException'/.test(drifted)).toBe(true);
      }
    }
  });
});

describe('层 4 · 规模与自排除不许静止', () => {
  test('STALE 里塞一条用不到的豁免必须被挑出来（反向静止也不许）', () => {
    const planted = [...STALE, { in: 'src/index.js', at: 'src/app.js:424242' }];
    expect(planted.filter((s) => occurrences(s.in, s.at).length === 0).map((s) => s.at)).toEqual([
      'src/app.js:424242',
    ]);
  });

  test('普查规模地板：扫描集非空、引用数与解析率都在地板之上（解析塌缩不许静默绿）', () => {
    expect(SCANNED.length).toBeGreaterThan(600);
    expect(ALL.length).toBeGreaterThanOrEqual(320);
    // 解析率是"绝对地板"抓不到的那一类塌缩的判据：新增一个与 logger.js/config.js 同名的
    // 文件，会把一批裸引用打回不可判（basename 不唯一 ⇒ 跳过），resolved 掉到 151 仍满足
    // 旧地板。所以这里同时判率与数。
    expect(resolved / ALL.length).toBeGreaterThanOrEqual(RESOLVE_RATIO_FLOOR);
    expect(resolved).toBeGreaterThanOrEqual(300);
    // 反证（塌缩方向）：15% 不可判的合成集必须掉到地板之下。
    // 正证（过严方向）：5% 不可判必须仍在地板之上——两向夹住，地板只能落在 (0.85, 0.95] 里。
    // 合成样本的 cited/abs 由同一个 unresolvable 参数算出：只改一半 = 没改（第 26 轮 M7 的教训，
    // 那一刀只动了 cited 没动 abs，解析率没变，于是"变异成功"是假的）。
    const mk = (unresolvable) =>
      Array.from({ length: 100 }, (_, i) => {
        const ok = i < 100 - unresolvable;
        return {
          site: 'synthetic',
          siteLine: i,
          cited: ok ? 'src/app.js' : 'no/such/dir/zzz.js',
          from: 1,
          to: 1,
          abs: ok ? path.join(ROOT, 'src/app.js') : null,
        };
      });
    expect(classify(mk(15)).resolved / 100).toBeLessThan(RESOLVE_RATIO_FLOOR);
    expect(classify(mk(5)).resolved / 100).toBeGreaterThanOrEqual(RESOLVE_RATIO_FLOOR);
    // 登记数只许涨不许跌（跌 = 有人删了判据）；晋升一条不该把闸弄红
    expect(LIVE.length).toBeGreaterThanOrEqual(42);
    expect(STALE.length).toBe(5);
  });

  test('本文件自身不在扫描集里（自证与真违规必须可区分）', () => {
    expect(SCANNED.some((f) => slash(f) === SELF)).toBe(false);
    expect(REPO_FILES.some((f) => slash(f) === SELF)).toBe(true);
    // 反证：把自己放进去，登记里的拼接串一定会多出引用
    expect(collectCitations(SCANNED.concat(path.join(ROOT, SELF))).length).toBeGreaterThan(
      ALL.length
    );
  });
});
