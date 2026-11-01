/**
 * 修复时限（SLA）：写下来的数字 ↔ 文档 ↔ 执行点 三方对账
 *
 * 【为什么需要本文件】SLA 全是"外面的世界什么时候给我补丁"这类承诺，仓库里没有任何代码能算出它。
 * 于是它最容易退化的形态是"文档里有一张表，数字与任何执行口径都无关"：改宽一倍没人拦，
 * 数据文件与文档分叉也没人发现。本文件做三件事：
 *   ① 数字的档位必须与判定 SDK 的严重度集合**逐一对应**（少一档就是漏一档没人修）；
 *   ② 文档表格与 `deployment/dependency-sla.json` 逐格相同（两边分叉即红）；
 *   ③ 硬上限写在本文件里 ⇒ 数字只许收紧：放宽需要改这份用例，等于一次显式评审。
 *
 * 【SLA 本身怎么被执行】三条都在本文件里点名（见用例 4）：未登记的 advisory 由
 * `scripts/check-audit-allowlist.js` + `deployment/audit-allowlist.json` 立刻阻断（严于 SLA）；
 * 已登记项的 `reviewBy` 到期即红；SAST findings 由 `.github/workflows/sast.yml` 的 `--error` 阻断。
 * 换句话说 SLA 管的是"已登记项与静态分析结果的处置期限"，不是另一套并行门禁。
 */

const fs = require('fs');
const path = require('path');
const { SEVERITY_RANK } = require('../../../scripts/check-audit-allowlist.js');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/\r\n?/g, '\n');

const SLA = JSON.parse(read('deployment/dependency-sla.json'));
const DOC = read('docs/security-dependency-watch.md');

/** 硬上限：数字只许收紧（放宽 = 改这里并在 PR 里说清理由） */
const HARD_CAPS = { info: 365, low: 180, moderate: 90, high: 30, critical: 7 };

/** 只看 SLA 小节里的表：文档别处的表格不许被误当成本表 */
function slaSection(text) {
  const from = text.indexOf('### 修复时限表');
  const to = text.indexOf('### 这些时限靠什么执行');
  expect(from).toBeGreaterThan(0);
  expect(to).toBeGreaterThan(from);
  return text.slice(from, to);
}

/** `| <严重度> | <数字> 天 | …` → `{严重度: 数字}`；同档出现两次直接抛错（两份口径并存是最坏的形态） */
function parseSlaTable(text) {
  const out = {};
  for (const m of text.matchAll(/^\|\s*([a-z]+)\s*\|\s*(\d+)\s*天\s*\|/gm)) {
    if (out[m[1]] !== undefined) throw new Error(`SLA 表里 ${m[1]} 出现了两次`);
    out[m[1]] = Number(m[2]);
  }
  return out;
}

describe('依赖/SAST 修复时限（SLA）', () => {
  test('1 档位与判定 SDK 的严重度集合逐一对应，且每个数字都在硬上限内', () => {
    expect(SLA.unit).toBe('days');
    expect(typeof SLA.note).toBe('string');
    expect(SLA.note.length).toBeGreaterThan(20);
    expect(Object.keys(SLA.windows).sort()).toEqual(Object.keys(SEVERITY_RANK).sort());
    for (const [sev, days] of Object.entries(SLA.windows)) {
      expect({ sev, positiveInt: Number.isInteger(days) && days > 0 }).toEqual({
        sev,
        positiveInt: true,
      });
      expect({ sev, withinCap: days <= HARD_CAPS[sev] }).toEqual({ sev, withinCap: true });
    }
  });

  test('2 档位单调：越严重时限越短（严格），否则"critical 也等 90 天"不算 SLA', () => {
    const byRank = Object.keys(SEVERITY_RANK).sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b]);
    expect(byRank).toEqual(['info', 'low', 'moderate', 'high', 'critical']);
    const days = byRank.map((s) => SLA.windows[s]);
    for (let i = 1; i < days.length; i += 1) expect(days[i - 1]).toBeGreaterThan(days[i]);
  });

  test('3 文档表格与数据文件逐格相同（改一边不改另一边即红）', () => {
    expect(parseSlaTable(slaSection(DOC))).toEqual(SLA.windows);
  });

  test('4 执行点必须在文档里点名：SLA 不是一句愿望，得说清谁在强制', () => {
    for (const p of [
      'scripts/check-audit-allowlist.js',
      'deployment/audit-allowlist.json',
      '.github/workflows/sast.yml',
      '.github/semgrep/rules.yml',
      'reviewBy',
    ])
      expect({ ref: p, seen: DOC.includes(p) }).toEqual({ ref: p, seen: true });
  });

  test('5 判据非空转：解析器对重复档 / 非数字 / 真实文档被改一格都必须显形', () => {
    const base = [
      '| 严重度 | 修复/缓解时限 | 口径 |',
      '| --- | --- | --- |',
      '| critical | 7 天 | a |',
      '| high | 30 天 | b |',
    ].join('\n');
    expect(parseSlaTable(base)).toEqual({ critical: 7, high: 30 });
    expect(() => parseSlaTable(`${base}\n| high | 31 天 | c |`)).toThrow(/两次/);
    expect(parseSlaTable('| critical | 七天 |')).toEqual({});
    expect(parseSlaTable('| critical | 7 days |')).toEqual({});
    // 真实文档改一格即可见：否则用例 3 只是跟一份硬编码期望值对账
    const mutated = DOC.replace(/\|\s*critical\s*\|\s*7\s*天/, '| critical | 99 天');
    expect(parseSlaTable(slaSection(mutated))).not.toEqual(SLA.windows);
  });
});
