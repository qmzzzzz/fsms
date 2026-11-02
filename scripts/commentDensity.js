'use strict';

/**
 * 注释密度统计与棘轮基线（Q-1，见 ADR-011）
 *
 * 口径：逐行判定，只看**整行注释**与纯代码行：
 *   - 整行注释：trim 后以 `//`、`/*`、`*` 开头（含块注释续行 ` * `）；
 *   - 空行不计入分母；行尾注释依附代码行，不单独计数。
 * 与审计报告 §3.1 的 39.2% 同一口径：注释整行 / 非空行。
 *
 * 统计面只含生产代码（`src/**` 排除 `src/tests/**`）：测试里的夹具说明不承载
 * 运行期约束，混进来会让"删测试"看起来像"注释治理"。
 *
 * 用法：
 *   node scripts/commentDensity.js                 打印总量
 *   node scripts/commentDensity.js --print         逐文件 JSON（人工查看）
 *   node scripts/commentDensity.js --update-baseline  收紧基线（存在回退时拒绝）
 *
 * 退出码：0 = 无回退；1 = 有回退 / 基线缺失或损坏（fail-closed）；2 = 用法错误。
 * 未知参数必须拒绝，不能当成「没传」：手误 --chek 原先静默落到「打印总量」分支，
 * exit 0、零提示——接进 CI 就是一个永远绿、什么都没查的步骤。同仓 lint-ratchet.js
 * 已为 --update-basline 手误付过学费，此处照抄其口径（退出码 2，与「有债」的 1 分码）
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BASELINE_PATH = path.join(__dirname, 'commentDensity.baseline.json');

const LINE_COMMENT = /^\s*(\/\/|\/\*|\*)/;

/** 新文件允许的注释密度上限：低于全仓现状，新代码不得免费入场 */
const NEW_FILE_MAX = 0.3;

/**
 * 强制状态声明（第 23 轮）。本脚本**当前不强制**：没有任何 npm script 或 workflow 引用它，
 * 无参跑只打印总量并恒 exit 0 —— 那条 exit 0 不是"检查通过"，是"没在检查"。
 *
 * 这份声明由 src/tests/ci/commentDensityEnforcementStatus.test.js 与事实对账：
 * 未接线 ⇔ enforced:false；谁把 --check 接进 CI，就必须同批把这个开关翻掉（否则闸判红）。
 *
 * 不直接接线的原因：仓库现状 evaluate().regressions / newFilesOverCap 都非空，
 * 立刻强制会在 CI 里多一个**长期全红**的步骤，红会退化成噪音。
 */
const ENFORCEMENT = {
  enforced: false,
  rationale:
    '本脚本尚未接线（全仓零引用：无 npm script、无 workflow 引用）。接线需与 .github/workflows ' +
    '的守卫测试（ciTestStepWiring）同批评审，在此之前由本声明记录「未强制」这一事实。',
  enable:
    'node scripts/commentDensity.js --check（verdict.ok=false 时 exit 1）接进 .github/workflows，' +
    '同批把 ENFORCEMENT.enforced 置 true',
};

/** 本脚本认的全部参数 */
const KNOWN_FLAGS = ['--check', '--update-baseline', '--print'];

/**
 * 用户敲下的参数不得被静默丢弃，两类输入必须拒绝：
 *   ① 未知参数（手误）——原先静默落到「打印总量」分支：exit 0、零提示，接进 CI 就是
 *      一个永远绿、什么都没查的步骤。同仓 lint-ratchet.js 已为 --update-basline 手误
 *      付过学费；退出码 2 与「有债」的 1 分码，但同为非零。
 *   ② 模式叠加——--check / --update-baseline 互斥；--print 只在默认模式下有输出，
 *      与两者同时给出会被提前 return 静默吞掉，用户以为导出了却什么都没拿到。
 * 只在 main() 里调用：本模块被测试 require，顶层校验进程 argv 会误伤 jest。
 */
function assertKnownArgs(argv) {
  const args = argv.slice(2);
  const unknown = args.filter((a) => !KNOWN_FLAGS.includes(a));
  if (unknown.length > 0) {
    process.stderr.write(
      '注释密度：未知参数 ' +
        unknown.join(' ') +
        '\n' +
        '  可用参数：' +
        KNOWN_FLAGS.join(' ') +
        '（不带参数 = 打印总量）\n'
    );
    process.exit(2);
  }
  const modes = ['--check', '--update-baseline'].filter((m) => args.includes(m));
  if (modes.length > 1) {
    process.stderr.write('注释密度：' + modes.join(' 与 ') + ' 互斥，一次只能走一个模式\n');
    process.exit(2);
  }
  if (args.includes('--print') && modes.length > 0) {
    process.stderr.write(
      '注释密度：--print 只在默认模式下有输出，与 ' + modes[0] + ' 同时给出会被静默丢弃，故拒绝\n'
    );
    process.exit(2);
  }
}

/** 收集指定根目录下的 .js 文件（跳过 node_modules / 生成物） */
function collect(dir, acc = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'coverage') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) collect(full, acc);
    else if (e.name.endsWith('.js')) acc.push(full);
  }
  return acc;
}

/**
 * 单文件密度。
 * @param {string} text
 * @returns {{comment:number, code:number, total:number, ratio:number}}
 */
function measure(text) {
  const lines = String(text).split(/\r?\n/);
  let comment = 0;
  let code = 0;
  for (const line of lines) {
    if (line.trim() === '') continue;
    if (LINE_COMMENT.test(line)) comment += 1;
    else code += 1;
  }
  const total = comment + code;
  return { comment, code, total, ratio: total === 0 ? 0 : comment / total };
}

/** 全仓（src 下，含测试）逐文件度量，键为仓库相对路径 */
function survey(root = path.join(ROOT, 'src')) {
  const out = {};
  for (const file of collect(root)) {
    const rel = path.relative(ROOT, file).split(path.sep).join('/');
    const m = measure(fs.readFileSync(file, 'utf8'));
    if (m.total > 0) out[rel] = m;
  }
  return out;
}

/** 生产代码面：排除 src/tests/** */
function production() {
  return Object.fromEntries(
    Object.entries(survey()).filter(([rel]) => !rel.startsWith('src/tests/'))
  );
}

const totalsOf = (files) =>
  Object.values(files).reduce(
    (a, m) => ({ comment: a.comment + m.comment, code: a.code + m.code }),
    { comment: 0, code: 0 }
  );

/**
 * 基线比较。纯函数：真实基线与测试里的合成反例走同一条逻辑。
 *
 * 判定只看**注释行数**，不看 ratio 的四舍五入：同一文件里删代码会让 ratio 上升，
 * 但"注释体量不变"不是新增负债；反过来新增一行注释在任何 ratio 下都必须先还一行。
 *
 * @param {{files: Object<string,{comment:number}>}} baseline
 * @param {Object<string,{comment:number,ratio:number}>} current
 * @param {{newFileMax?: number}} [opts]
 */
function evaluate(baseline, current, opts = {}) {
  const newFileMax = opts.newFileMax ?? NEW_FILE_MAX;
  const baseFiles = baseline.files || {};
  const regressions = [];
  const stale = [];
  const newFiles = [];
  const newFilesOverCap = [];

  for (const [rel, m] of Object.entries(current)) {
    // 用 Object.hasOwn 而非 `baseFiles[rel]` 取真值。**真正可达的是下面 stale 那一处**：
    // 账本键来自任意 JSON，`toString`/`constructor` 这类键名会让 `current[rel]` 恒为真，
    // 已删文件永不进残留。本处不可达（只扫 `.js` ⇒ rel 必含点号），与 stale 同形保留。
    const base = Object.hasOwn(baseFiles, rel) ? baseFiles[rel] : undefined;
    if (!base) {
      newFiles.push({ file: rel, ratio: m.ratio });
      if (m.ratio > newFileMax) newFilesOverCap.push({ file: rel, ratio: m.ratio });
    } else if (m.comment > base.comment) {
      regressions.push({ file: rel, base: base.comment, now: m.comment });
    }
  }
  // 同上是存在性判定，不是真值判定：`!current[rel]` 对原型键名恒为假，
  // 于是登记了却已不存在的文件永不进清单残留 ⇒ 闸对那一面永久沉默。
  for (const rel of Object.keys(baseFiles)) {
    if (!Object.hasOwn(current, rel)) stale.push(rel);
  }

  const now = totalsOf(current);
  const baseTotal = baseline.total || { comment: 0, code: 0 };
  return {
    regressions,
    stale,
    newFiles,
    newFilesOverCap,
    totalRegressed: now.comment > baseTotal.comment,
    total: now,
    ok:
      regressions.length === 0 &&
      newFilesOverCap.length === 0 &&
      stale.length === 0 &&
      now.comment <= baseTotal.comment,
  };
}

function snapshot(files) {
  const total = totalsOf(files);
  const grand = total.comment + total.code;
  return {
    note:
      '注释密度棘轮基线（生产代码：src/** 排除 src/tests/**）。只许收紧；' +
      '新增文件密度上限见 scripts/commentDensity.js 的 NEW_FILE_MAX。',
    files,
    total: { ...total, ratio: grand === 0 ? 0 : Number((total.comment / grand).toFixed(4)) },
  };
}

/**
 * 读基线，返回三态而不是 null/对象二分。
 * 缺失与损坏必须分开：缺失是首次接入（可建账本），损坏只能拒绝——
 * 混为一谈时「文件坏掉」会退化成「首次接入」，一次重建就把损坏期间上升的
 * 注释静默洗成新地板，正是「只降不升」被绕过的路径（同仓 lint-ratchet 同口径）。
 */
/** 条目级形状：逐文件判据（`now > base`）唯一读的字段是 comment，故只校验它。
 *  条目畸形时取出的 base 是 undefined / 字符串 / 数组 ⇒ 比较得 NaN，而 `NaN > x` 恒为 false，
 *  于是「有回退」被判成「无回退」并写盘——同一真回退事实，只因 base 写坏就静默放行，
 *  正是本脚本要堵的「账本坏掉期间涨上去的注释被洗成新地板」，只是坏在更深一层。
 *  刻意**不**要求 code：它不参与回退判定，强制要求会把「只记 comment 的合法账本」误判成损坏
 *  （本仓真实夹具就是这种形态）——判据只该拦真正会让它失效的形态，多拦一个字段就是一次假红。
 *  @returns {string|null} 不合格原因，null 表示形状合格 */
function entryShapeFault(rel, entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry))
    return '条目 ' + rel + ' 不是对象';
  return Number.isFinite(entry.comment) ? null : '条目 ' + rel + ' 缺少数值 comment';
}

/** 顶层形状：files 必须是映射（数组不行），total.comment 必须是有限数值。
 *  `1e999` 经 JSON.parse 变 Infinity，`typeof === 'number'` 为真但 `now <= Infinity` 恒真 ⇒ 总量判据失效。
 *  @returns {string|null} 不合格原因，null 表示形状合格 */
function topShapeFault(parsed) {
  if (!parsed || typeof parsed !== 'object') return '顶层不是对象';
  if (!parsed.files || typeof parsed.files !== 'object') return '缺少 files 映射';
  if (Array.isArray(parsed.files)) return 'files 是数组而非映射';
  if (!parsed.total || !Number.isFinite(parsed.total.comment)) return '缺少 total.comment 数值';
  return null;
}

/** 账本内部自洽：total 必须等于各条目之和。
 *  只抬 total.comment 这一个数字（files 一字节不动）就能把总量判据的天花板顶高，
 *  同理删掉条目后 Σ 变小而 total 不变。两个方向都会让「只降不升」失去刻度，
 *  而 `commentDensityRatchet.test.js:37-44` 早已断言过这条不变量 —— 判据一直存在，
 *  只是没搬进产品路径（运行时不许有两把尺子）。
 *  @returns {string|null} 不自洽原因，null 表示自洽 */
function ledgerSelfFault(parsed) {
  const entries = Object.values(parsed.files);
  const sum = (pick) => entries.reduce((n, m) => n + (Number.isFinite(m[pick]) ? m[pick] : NaN), 0);
  for (const key of ['comment', 'code']) {
    if (!Number.isFinite(parsed.total[key])) continue; // 缺 code 的旧账本不因此判坏
    const total = sum(key);
    if (!Number.isFinite(total)) return '条目缺少数值 ' + key;
    if (total !== parsed.total[key]) {
      return 'Σfiles.' + key + '=' + total + ' 与 total.' + key + '=' + parsed.total[key] + ' 不符';
    }
  }
  return null;
}

function readBaseline() {
  if (!fs.existsSync(BASELINE_PATH)) return { state: 'missing' };
  let raw;
  try {
    raw = fs.readFileSync(BASELINE_PATH, 'utf8');
  } catch (err) {
    return { state: 'corrupt', reason: '读取失败：' + err.message };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { state: 'corrupt', reason: 'JSON 解析失败：' + err.message };
  }
  const topFault = topShapeFault(parsed);
  if (topFault) return { state: 'corrupt', reason: '结构不符：' + topFault };
  // 先逐条验形状，再验自洽：形状坏时求和会得 NaN，先报形状能给出更准确的原因。
  for (const [rel, entry] of Object.entries(parsed.files)) {
    const fault = entryShapeFault(rel, entry);
    if (fault) return { state: 'corrupt', reason: '结构不符：' + fault };
  }
  const selfFault = ledgerSelfFault(parsed);
  if (selfFault) return { state: 'corrupt', reason: '账本不自洽：' + selfFault };
  return { state: 'ok', baseline: parsed };
}

/** 账本与实测脱节时必须 fail-closed：账本里**没有任何一个键**能在实测文件里命中时，
 *  每个现存文件都被当成「新文件」，密度 ≤ NEW_FILE_MAX 的全部免检 ⇒ 逐文件判据整体失效。
 *  实测（第 26 轮）：`files:{}` 与 `files:{toString:{…}}` 都会让 --check 打印「通过」，
 *  随后 --update-baseline 按实测重建账本。
 *  ★刻意不用「Object.keys().length === 0」：那只看长度，一个 phantom 键（原型键名）就能骗过；
 *  判「有没有命中」才是这件事的本质。新增文件是正常的，但「零命中」不正常。
 *  @param {string} head 拒绝前缀（两个模式各自的措辞不同，故由调用方给）
 */
function refuseEmptyLedger(baseline, files, head) {
  const actual = Object.keys(files).length;
  if (actual === 0) return;
  if (Object.keys(files).some((rel) => Object.hasOwn(baseline.files, rel))) return;
  const registered = Object.keys(baseline.files).length;
  process.stderr.write(
    `${head}：账本与工作区无任何交集（${registered} 个登记项，工作区 ${actual} 个文件无一命中），` +
      '逐文件判据无从生效（fail-closed）\n' +
      '  这种账本会把全部现存文件当成新文件免检，按实测重建等于关掉棘轮。\n' +
      '  请人工修复（git 里有上一版）。\n'
  );
  process.exit(1);
}

/** 把 verdict 翻成可读的拒绝明细（两个模式共用同一套措辞） */
function refusalDetails(verdict, baseline) {
  return [
    ...verdict.regressions.map((r) => `回归 ${r.file}: ${r.base} → ${r.now}`),
    ...verdict.newFilesOverCap.map(
      (r) => `新文件超密度上限 ${r.file}: ${(r.ratio * 100).toFixed(1)}%`
    ),
    ...verdict.stale.map((f) => `清单残留 ${f}（文件已删除/改名，需同批更新基线）`),
    ...(verdict.totalRegressed ? [`总量回归：上限 ${baseline.total.comment} 行`] : []),
  ];
}

/** --check 模式：只判定，不写盘。返回 true 表示已处理完毕 */
function runCheck(files, total) {
  const read = readBaseline();
  if (read.state !== 'ok') {
    const why = read.state === 'missing' ? '基线文件缺失' : '基线不可解析（' + read.reason + '）';
    process.stderr.write('注释密度检查失败：' + why + '，无法判定回退（fail-closed）\n');
    process.exit(1);
  }
  const baseline = read.baseline;
  refuseEmptyLedger(baseline, files, '注释密度检查失败');
  const verdict = evaluate(baseline, files);
  if (!verdict.ok) {
    process.stderr.write(
      `注释密度检查失败：\n  ${refusalDetails(verdict, baseline).join('\n  ')}\n`
    );
    process.exit(1);
  }
  process.stdout.write(
    `注释密度检查通过：comment=${total.comment} 基线=${baseline.total.comment}\n`
  );
  return true;
}

function main() {
  assertKnownArgs(process.argv);
  const files = production();
  const total = totalsOf(files);
  const grand = total.comment + total.code;

  if (process.argv.includes('--check')) {
    runCheck(files, total);
    return;
  }

  if (process.argv.includes('--update-baseline')) {
    const current = snapshot(files);
    const read = readBaseline();
    // 损坏必须拒绝：把它当成「首次接入」再重建，等于把损坏期间上升的注释洗成新地板。
    // 缺失允许建账本（首次接入不得被拒绝），但输出必须与「合法收紧」可区分，
    // 否则删掉基线文件再跑一次就是一次无声的棘轮回退。
    if (read.state === 'corrupt') {
      process.stderr.write(
        '拒绝收紧基线：基线不可解析（' +
          read.reason +
          '）\n' +
          '  机器不许猜账本：按实测重建会把损坏期间新增或上升的注释静默洗成新地板。\n' +
          '  请人工修复（git 里有上一版）。\n'
      );
      process.exit(1);
    }
    const baseline = read.state === 'ok' ? read.baseline : null;
    // 同 --check：空账本 + 非空工作区不许被当成「合法收紧」而重建（那正是洗地板）。
    if (baseline) refuseEmptyLedger(baseline, files, '拒绝收紧基线');
    if (baseline) {
      const verdict = evaluate(baseline, current.files);
      if (!verdict.ok) {
        const details = [
          ...verdict.regressions.map((r) => `回归 ${r.file}: ${r.base} → ${r.now}`),
          ...verdict.newFilesOverCap.map(
            (r) => `新文件超密度上限 ${r.file}: ${(r.ratio * 100).toFixed(1)}%`
          ),
          ...verdict.stale.map((f) => `清单残留 ${f}（文件已删除/改名，需同批更新基线）`),
          ...(verdict.totalRegressed ? [`总量回归：上限 ${baseline.total.comment} 行`] : []),
        ];
        process.stderr.write(`拒绝收紧基线：\n  ${details.join('\n  ')}\n`);
        process.exit(1);
      }
    }
    fs.writeFileSync(BASELINE_PATH, `${JSON.stringify(current, null, 2)}\n`);
    const head = baseline ? '基线已收紧' : '基线文件不存在，已按当前实测首次建立';
    process.stdout.write(
      `${head} ${path.relative(ROOT, BASELINE_PATH)}：files=${Object.keys(files).length} ` +
        `comment=${total.comment} code=${total.code}\n`
    );
    return;
  }

  process.stdout.write(
    `files=${Object.keys(files).length} comment=${total.comment} code=${total.code} ` +
      `ratio=${((total.comment / grand) * 100).toFixed(1)}%\n`
  );
  if (process.argv.includes('--print')) {
    const rounded = {};
    for (const rel of Object.keys(files).sort()) {
      rounded[rel] = Math.floor(files[rel].ratio * 10000) / 10000;
    }
    process.stdout.write(`${JSON.stringify(rounded, null, 2)}\n`);
  }
}

if (require.main === module) main();

module.exports = {
  measure,
  survey,
  production,
  evaluate,
  totalsOf,
  collect,
  LINE_COMMENT,
  NEW_FILE_MAX,
  BASELINE_PATH,
  ENFORCEMENT,
};
