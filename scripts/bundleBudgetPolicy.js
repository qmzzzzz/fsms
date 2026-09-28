/**
 * 体积预算的纯判定层（scripts/check-bundle-budget.js 的基线结构与比对逻辑）
 *
 * 为什么单独成文件：CLI 侧要读 dist、写基线文件、打印表格、决定退出码；
 * 而「基线结构是否完整 / 实测是否越界 / 收紧后的基线长什么样」是纯函数，
 * 既能被单测直接调用，也不该被文件 IO 牵连。
 * 切分的直接动因：CLI 撞上体积棘轮 max-lines=300（实测 319），
 * 而棘轮只许降不许升（scripts/lint-ratchet.js）——故按这条既有边界拆，不收紧基线。
 *
 * 本模块零副作用：不读文件、不打印、不退出。
 */

'use strict';

const HEADROOM = 0.05; // 预算 = 实测 ×(1+HEADROOM)，向上取整到 ROUND_TO 字节
const ROUND_TO = 1000;
const FLOOR_RATIO = 0.6; // 防呆下限 = 实测分块数 ×FLOOR_RATIO；只拦「构建没产出」

const METRICS = [
  { key: 'entryJsGzip', section: 'budgets', unit: 'B' },
  { key: 'entryCssGzip', section: 'budgets', unit: 'B' },
  { key: 'totalRaw', section: 'budgets', unit: 'B' },
  { key: 'totalGzip', section: 'budgets', unit: 'B' },
  { key: 'maxChunkGzip', section: 'budgets', unit: 'B' },
  { key: 'jsChunks', section: 'floors', unit: '个' },
  { key: 'cssChunks', section: 'floors', unit: '个' },
];
const BUDGET_KEYS = METRICS.filter((m) => m.section === 'budgets').map((m) => m.key);
const FLOOR_KEYS = METRICS.filter((m) => m.section === 'floors').map((m) => m.key);
const isBudget = (metric) => metric.section === 'budgets';

const isPlainObject = (value) => !!value && typeof value === 'object' && !Array.isArray(value);

function validateBaseline(baseline) {
  if (!isPlainObject(baseline)) return ['基线内容不是 JSON 对象'];
  const problems = [];
  for (const section of ['budgets', 'floors']) {
    const group = baseline[section];
    if (!isPlainObject(group)) {
      problems.push(`缺少 ${section} 段`);
      continue;
    }
    for (const { key } of METRICS.filter((m) => m.section === section)) {
      const value = group[key];
      if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        problems.push(`${section}.${key} 缺失或非正数`);
      }
    }
  }
  return problems;
}

function compare(stats, baseline) {
  const violations = [];
  for (const metric of METRICS) {
    const { key, section } = metric;
    const limit = baseline[section][key];
    const broken = isBudget(metric) ? stats[key] > limit : stats[key] < limit;
    if (!broken) continue;
    const detail = isBudget(metric)
      ? `超预算：实测 ${stats[key]} B > 预算 ${limit} B（超出 ${stats[key] - limit} B）`
      : `低于防呆下限：实测 ${stats[key]} < 下限 ${limit}（构建可能未完整产出）`;
    const code = isBudget(metric) ? 'over-budget' : 'under-floor';
    violations.push({ code, metric: key, message: `${key} ${detail}` });
  }
  return violations;
}

function tighten(stats, previous) {
  const budgets = {};
  const floors = {};
  const raised = [];
  for (const key of BUDGET_KEYS) {
    budgets[key] = Math.ceil((stats[key] * (1 + HEADROOM)) / ROUND_TO) * ROUND_TO;
    const prev = previous.budgets ? previous.budgets[key] : undefined;
    if (typeof prev === 'number' && budgets[key] > prev)
      raised.push(`${key} ${prev} -> ${budgets[key]}`);
  }
  // 下限至少为 1：结构校验已保证入口 script 与 stylesheet 各存在一份，
  // 产物通过检查时 js/css 分块不可能为 0；若按 ×0.6 取整得出 0，
  // 写出的基线会被自己的 validateBaseline（要求正数）判为损坏。
  const floor = (value) => Math.max(1, Math.floor(value * FLOOR_RATIO));
  for (const key of FLOOR_KEYS) floors[key] = floor(stats[key]);
  const measured = {};
  for (const { key } of METRICS) measured[key] = stats[key];
  const measuredAt = new Date().toISOString().slice(0, 10);
  return { baseline: { ...previous, measuredAt, measured, budgets, floors }, raised };
}

/** CLI 接受的全部 token：两个开关 + 两个路径覆盖（后者必须写成 --名=值） */
const BUDGET_FLAGS = ['--update-baseline', '--allow-growth'];
const BUDGET_OPTS = ['--dist', '--baseline'];

/** 拼错时给出可照抄的正确写法：抹除非字母字符后比等值/双向前缀/字符集相同 */
const suggestFlag = (token) => {
  const shape = (s) => s.replace(/[^a-z]/gi, '').toLowerCase();
  const sorted = (s) => [...s].sort().join('');
  const s = shape(token);
  if (s.length < 2) return undefined;
  return [...BUDGET_FLAGS, ...BUDGET_OPTS].find((f) => {
    const k = shape(f);
    return k === s || k.startsWith(s) || s.startsWith(k) || sorted(k) === sorted(s);
  });
};

/**
 * 参数解析（严格）。CLI 侧原先有两处松判据：
 *   - `process.argv.includes('--update-baseline')`：手误得到的是检查模式（同族规矩的来由
 *     见 scripts/deployPolicy.js 里 --dryrun 那段注释）；
 *   - `readFlag` 只认 `--dist=`：于是 `--dist web-admin/dist-new` 两个 token **都不报错**，
 *     门禁量的是默认 dist，而操作者以为量的是刚构建出来的那一份——新产物超重灾区
 *     也能报「通过」。本门禁的全部价值是「量对的东西」，所以缺值 / 空格形态一律拒绝。
 *
 * 纯解析、不退出（本模块的既有约定）：errors 非空时由调用方以退出码 2 拒绝执行。
 * 若在此处 process.exit，单测 require 本模块时 jest 的 argv 会把测试进程直接打死。
 */
function parseCliArgs(tokens) {
  const cli = { updateMode: false, allowGrowth: false, dist: null, baseline: null, errors: [] };
  for (const token of tokens) {
    if (token === '--update-baseline') cli.updateMode = true;
    else if (token === '--allow-growth') cli.allowGrowth = true;
    else {
      const eq = token.indexOf('=');
      const name = eq === -1 ? token : token.slice(0, eq);
      if (!BUDGET_OPTS.includes(name)) {
        const hint = suggestFlag(token);
        cli.errors.push(
          `未知参数「${token}」（只接受 ${[...BUDGET_FLAGS, ...BUDGET_OPTS].join(' / ')}，` +
            `路径覆盖须写成 --名=值）${hint ? `；是否想写 ${hint}？` : ''}`
        );
        continue;
      }
      const value = eq === -1 ? '' : token.slice(eq + 1);
      if (!value) cli.errors.push(`--${name.slice(2)} 需要非空值（--${name.slice(2)}=<路径>）`);
      else cli[name.slice(2)] = value;
    }
  }
  return cli;
}

module.exports = {
  HEADROOM,
  ROUND_TO,
  FLOOR_RATIO,
  METRICS,
  BUDGET_KEYS,
  FLOOR_KEYS,
  BUDGET_FLAGS,
  BUDGET_OPTS,
  isBudget,
  isPlainObject,
  validateBaseline,
  compare,
  tighten,
  parseCliArgs,
};
