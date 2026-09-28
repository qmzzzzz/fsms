'use strict';

/**
 * 风险等级 / 严重程度的清单只能有一份（F-149 门禁）
 *
 * 缺陷类（与 F-120/F-121/F-137/F-138/F-139 同族，钉的是新的一条轴）：
 * `AUDIT_RISK_LEVELS` 是**有序**表（low→medium→high→critical），凡"某档及以上"的判据
 * 都是它的一个后缀切片。整改前这类判据在 6 处生产代码里各抄一份字面量
 * （审计查询的 level→条件、行为基线 highRisk、告警取数、概览高危次数、导出的 doc→标签），
 * 单侧漂移的后果不是报错而是**静默漏**：给等级表加一档（例如 'urgent' 插在 high 与
 * critical 之间）后，手抄的 `['high','critical']` 不含新档，而查询/导出侧的取值白名单
 * 引用的是同一份 AUDIT_RISK_LEVELS、已经放行 ⇒ 新档记录能落库、能在审计页筛出来，
 * 却不进任何高危聚合、不进告警取数、不进行为基线的 highRisk。安全侧的漏，且没人会说"这档没人管"。
 *
 * 本文件的三个判据（缺一不可，缺哪个都会退化成"当前恰好干净"的假绿）：
 *  ① 整树扫描：`src/`（不含 `src/constants/` 与测试）、`scripts/`、`migrations/` 里
 *     不允许出现"元素全是档位名的数组字面量"。
 *  ② 判据自证：把已改成派生的真实文件在内存里**改回**字面量，扫描必须报出来；
 *     扫描器跑在合成脏样本上时要抓到三种写法、且不被注释骗过；跑在真实声明目录上时
 *     必须数得出东西（否则"零违规"可能只是管道坏了）。
 *  ③ 三档划分完整性：审计页 info/warning/error 的查询条件必须把等级全集划分干净
 *     （每个档位恰好落在一个桶）。这条管的是 ① 看不到的那半边——warning 档至今写的是
 *     标量 `'medium'` 而不是集合，加一档时字面扫描不会红，只有这条会红。
 *
 * 巡检域（findings.severity）单列：取值与审计域恰好相同但语义不同，两边刻意不合并
 * （见 constants/inspection.js 头注释），所以本文件同时钉住"它们不是同一个数组对象"。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../..');
const SCAN_DIRS = ['src', 'scripts', 'migrations'];
// 声明处所在目录：这里出现档位数组是合法的（它就是单一事实来源本身），
// 但正因如此必须单独数一次（见 ② 的"扫描器在真实声明目录上抓得到东西"）
const DECLARATION_DIRS = [path.join('src', 'constants')];

const {
  AUDIT_RISK_LEVELS,
  AUDIT_ERROR_RISK_LEVELS,
  AUDIT_WARNING_OR_HIGHER_RISK_LEVELS,
  AUDIT_DISPLAY_LEVELS,
  riskLevelsAtLeast,
} = require('../constants/audit');
const { INSPECTION_FINDING_SEVERITIES } = require('../constants/inspection');
const { buildLevelCondition } = require('../utils/auditQuery');

// 词表本身从 AUDIT_RISK_LEVELS 派生：本门禁不许连"档位有哪些"再抄第四份
const LEVEL_SOURCE = AUDIT_RISK_LEVELS;
const WORD = `(?:${LEVEL_SOURCE.join('|')})`;
// 元素全部落在档位词表里、且至少两项（单元素不是"某档及以上"的复述）
const LEVEL_LIST = new RegExp(String.raw`\[\s*(?:'${WORD}'\s*,\s*)+'${WORD}'\s*,?\s*\]`, 'g');

/**
 * 剥注释，只留代码视图（同 zzqoder_auditCategoryLiteralWhitelist 的口径）。
 * 不剥的话本文件头注释里那句"手抄的 ['high','critical']"会被自己的门禁当成违规。
 * 块注释按等长空白替换以保住行号。
 */
function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/** 从一份源码文本里取出所有"档位列表字面量"，返回 Map(字面量 -> 出现文件) */
function collectLevelLiterals(text, relPath) {
  const found = new Map();
  for (const m of stripComments(text).matchAll(LEVEL_LIST)) {
    if (!found.has(m[0])) found.set(m[0], []);
    found.get(m[0]).push(relPath);
  }
  return found;
}

function scanTree(dirs, { skipDeclarations = true } = {}) {
  const hits = new Map();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'tests' || entry.name === '__tests__') continue;
        walk(full);
      } else if (/\.(js|cjs)$/.test(entry.name) && !/\.test\.(js|cjs)$/.test(entry.name)) {
        const rel = path.relative(ROOT, full);
        const inDeclDir = DECLARATION_DIRS.some((d) => rel.startsWith(d + path.sep));
        if (skipDeclarations && inDeclDir) continue;
        for (const [lit, files] of collectLevelLiterals(fs.readFileSync(full, 'utf8'), rel)) {
          if (!hits.has(lit)) hits.set(lit, []);
          hits.get(lit).push(...files);
        }
      }
    }
  };
  for (const d of dirs) {
    const abs = path.join(ROOT, d);
    if (fs.existsSync(abs)) walk(abs);
  }
  return hits;
}

/** 迷你 Mongo 条件求值器：只支持本门禁用到的 $or / $in / $nin / 多键 AND */
function matches(doc, cond) {
  if (Array.isArray(cond.$or)) return cond.$or.some((c) => matches(doc, c));
  return Object.entries(cond).every(([key, val]) => {
    if (val && typeof val === 'object' && Array.isArray(val.$in)) {
      return val.$in.includes(doc[key]);
    }
    if (val && typeof val === 'object' && Array.isArray(val.$nin)) {
      return !val.$nin.includes(doc[key]);
    }
    return doc[key] === val;
  });
}

/** 一条记录落在哪些展示档里（正常应当恰好一个） */
const bucketsOf = (doc) => AUDIT_DISPLAY_LEVELS.filter((l) => matches(doc, buildLevelCondition(l)));

describe('zzqoder 风险等级清单只能有一份', () => {
  const hits = scanTree(SCAN_DIRS);

  test('① 整树扫描：src/scripts/migrations 里没有私抄的档位清单', () => {
    const violations = [...hits.entries()].map(
      ([lit, files]) => `${lit} ← ${[...new Set(files)].join(', ')}`
    );
    expect(violations).toEqual([]);
  });

  test('② 判据自证：把一处真实生产代码改回字面量，扫描必须报出来', () => {
    const rel = path.join('src', 'utils', 'auditQuery.js');
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    // 前提：这处确实是派生写法（replace 空转的话自检就没有意义）
    expect(src).toContain('AUDIT_ERROR_RISK_LEVELS');
    const patched = src.replaceAll('AUDIT_ERROR_RISK_LEVELS', "['high', 'critical']");
    expect(patched).not.toContain('AUDIT_ERROR_RISK_LEVELS');
    expect([...collectLevelLiterals(patched, rel).keys()]).toEqual(["['high', 'critical']"]);
  });

  test('② 扫描器在真实声明目录上数得出东西（证明管道没坏，也证明排除是必要的）', () => {
    const inConstants = scanTree([path.join('src', 'constants')], { skipDeclarations: false });
    const files = new Set([...inConstants.values()].flat());
    // 审计域 + 巡检域两处声明；第一条用例正是靠排除这里才是绿的
    expect([...files].sort()).toEqual(
      [
        path.join('src', 'constants', 'audit.js'),
        path.join('src', 'constants', 'inspection.js'),
      ].sort()
    );
  });

  test('② 提取器抓到三种脏写法，且不被注释骗过', () => {
    const dirty = collectLevelLiterals(
      [
        `const a = { riskLevel: { $in: ['high', 'critical'] } };`,
        `const b = ['low', 'medium', 'high', 'critical'];`,
        `const c = ['medium', 'high', 'critical'].includes(x);`,
        `// 说明里写 ['high', 'critical'] 不算违规`,
        `/* 块注释里的 ['low', 'medium'] 也不算 */`,
        `const d = SOME_OTHER_LIST;`,
      ].join('\n'),
      'synthetic.js'
    );
    expect([...dirty.keys()].sort()).toEqual(
      [
        "['high', 'critical']",
        "['low', 'medium', 'high', 'critical']",
        "['medium', 'high', 'critical']",
      ].sort()
    );
  });

  test('② 提取器不把别的字面量当档位清单（防门禁变成噪音源）', () => {
    const clean = collectLevelLiterals(
      `const s = ['a', 'b'];\nconst n = [1, 2];\nconst one = ['low'];`,
      'x.js'
    );
    expect([...clean.keys()]).toEqual([]);
  });

  test('③ 派生器：档位找不到就抛，找得到就是后缀切片，结果冻结', () => {
    expect(() => riskLevelsAtLeast('urgent')).toThrow(/不在 AUDIT_RISK_LEVELS/);
    expect(() => riskLevelsAtLeast(undefined)).toThrow(/不在 AUDIT_RISK_LEVELS/);
    for (const [i, level] of LEVEL_SOURCE.entries()) {
      const slice = riskLevelsAtLeast(level);
      expect(slice[0]).toBe(level);
      expect(slice.length).toBe(LEVEL_SOURCE.length - i);
      expect(Object.isFrozen(slice)).toBe(true);
    }
    // 最低档＝全集，最高档＝只有它自己（否则"某档及以上"的语义就反了）
    expect(riskLevelsAtLeast(LEVEL_SOURCE[0])).toEqual(LEVEL_SOURCE);
    expect([...riskLevelsAtLeast(LEVEL_SOURCE[LEVEL_SOURCE.length - 1])]).toEqual([
      LEVEL_SOURCE[LEVEL_SOURCE.length - 1],
    ]);
  });

  test('③ 两个派生档带：error 带 ⊂ warning 及以上，且都由派生器现算', () => {
    expect(AUDIT_ERROR_RISK_LEVELS).toEqual(riskLevelsAtLeast('high'));
    expect(AUDIT_WARNING_OR_HIGHER_RISK_LEVELS).toEqual(riskLevelsAtLeast('medium'));
    expect(AUDIT_WARNING_OR_HIGHER_RISK_LEVELS.length).toBeGreaterThan(
      AUDIT_ERROR_RISK_LEVELS.length
    );
    for (const l of AUDIT_ERROR_RISK_LEVELS) {
      expect(AUDIT_WARNING_OR_HIGHER_RISK_LEVELS).toContain(l);
    }
  });

  test('③ 三档查询条件把等级全集划分干净：每档恰好落在一个桶', () => {
    // 迷你求值器自己的自检（否则"恰好一个桶"可能只是求值器算错）
    expect(matches({ riskLevel: 'low' }, { riskLevel: { $in: ['low'] } })).toBe(true);
    expect(matches({ riskLevel: 'low' }, { riskLevel: { $nin: ['low'] } })).toBe(false);
    expect(matches({ success: true, riskLevel: 'low' }, { success: true, riskLevel: 'high' })).toBe(
      false
    );

    const expected = { low: 'info', medium: 'warning', high: 'error', critical: 'error' };
    const actual = {};
    for (const level of AUDIT_RISK_LEVELS) {
      const buckets = bucketsOf({ success: true, riskLevel: level });
      expect(buckets.length).toBe(1); // 加一档而没人给它定档 ⇒ 这里红
      actual[level] = buckets[0];
    }
    expect(actual).toEqual(expected);

    // success=false 的记录整体归 error，且不再落进另外两档
    for (const level of AUDIT_RISK_LEVELS) {
      expect(bucketsOf({ success: false, riskLevel: level })).toEqual(['error']);
    }
  });

  test('③ riskLevel 缺失/为 null 的存量文档仍属 info（补集写法别被改成 $in 而漏掉它们）', () => {
    expect(bucketsOf({ success: true })).toEqual(['info']);
    expect(bucketsOf({ success: true, riskLevel: null })).toEqual(['info']);
  });

  test('巡检域：模型 enum 与路由校验共用一份，且刻意不与审计域合并', () => {
    const Inspection = require('../models/Inspection');
    expect(Inspection.schema.path('findings').schema.path('severity').enumValues).toEqual(
      INSPECTION_FINDING_SEVERITIES
    );
    // 取值相同、对象不同：合并成一份会让"只给审计加一档"连带放宽巡检校验（反之亦然）
    expect(INSPECTION_FINDING_SEVERITIES).not.toBe(AUDIT_RISK_LEVELS);

    const rel = path.join('src', 'routes', 'inspectionRoutes.js');
    const routeSrc = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    expect(routeSrc).toMatch(/isIn\(\s*INSPECTION_FINDING_SEVERITIES\s*\)/);
    // 自检：改回字面量必须同时被上面那条正则和本文件的扫描抓到
    const laundered = routeSrc.replace(
      /isIn\(\s*INSPECTION_FINDING_SEVERITIES\s*\)/,
      `isIn(['low', 'medium', 'high', 'critical'])`
    );
    expect(laundered).not.toMatch(/isIn\(\s*INSPECTION_FINDING_SEVERITIES\s*\)/);
    expect([...collectLevelLiterals(laundered, rel).keys()]).toEqual([
      "['low', 'medium', 'high', 'critical']",
    ]);
  });
});
