'use strict';

/**
 * F-143（门禁）：审计 WAL 的"回收"动作不得被"追加是否启用"的开关门控
 *
 * 缺陷族（三处，同一次整改）：`flush()` 里原先写着
 *   - `if (wal.isEnabled()) wal.trimBySeqs(walSeqsOf(docs))`        —— 整批成功
 *   - `if (wal.isEnabled() && storedSeqs.size > 0) wal.trimBySeqs()`  —— 部分成功
 *   - `if (wal.isEnabled() && discardSeqs.size > 0) wal.discardBySeqs()` —— 毒批归档
 * `walEnabled` 表达的是**能不能往文件里追加**（`appendLine`/`assignSeq` 用它），
 * 而 trim/discard 表达的是**这条记录已经在库里、它的取证行该不该回收**。
 * 拿前者门控后者，在唯一"关闭但仍会落库"的窗口——`flushAndStop()` 排空预算用尽后
 * `stop()`（disable），而那一轮在途 insertMany 随后成功——就会关掉回收：
 *   · 已落库批次的行永久留在 WAL ⇒ 下次 `start()` 重放进缓冲，而重放文档的 `_id`
 *     是下一轮 flush 新分配的（WAL 行写于 push，那时还没有 `_id`）⇒
 *     **每重启一次就把这个已存在的批次再插一份**（本仓 `index.js` 的关停注释对
 *     同类时序的定性一模一样：B-L2）；
 *   · 毒批的内存副本按 `droppedCount` 计损、行却没归档 ⇒ 紧跟着的 error 日志
 *     （`doomedBatchMessage` 按 `discardSeqs.size > 0` 分支）照说"已归档…并从主 WAL
 *     移除"，而 `.discarded` 是"审计永久缺失了多少"的唯一凭据。
 *
 * 为什么是结构门禁而不是只靠行为用例：`auditBufferShutdownDrain.test.js` 的 ⑥/⑦
 * 已把两处 trim 钉住（各自实测可红），但毒批那一处的触发需要"关停之后那一轮恰好
 * 跨过内容计次阈值"，用例里能造、生产里更像噪声；三处共用同一个判据，
 * 就按判据一次性封死——恢复任意一处闸门都会让本文件红（下方"自检"行证明探测器
 * 不是空转，而不是指望读者相信它有效）。
 */

const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '../../services');

/** 整行注释 + 行尾注释都剥掉：判据必须只看代码，不能被注释满足、也不能被注释触发 */
const codeOnly = (src) =>
  src
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .map((l) => l.replace(/\/\/[^\n]*/g, ' '))
    .join('\n');

const countOf = (text, needle) => text.split(needle).length - 1;

const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** 每一处调用的起始下标（与 countOf 不同源：两条账对不上就说明有一处被注释吃掉） */
const callSites = (text, needle) =>
  [...text.matchAll(new RegExp(reEscape(needle), 'g'))].map((m) => m.index);
/** 删掉下标 idx 处的那一条调用语句（到最近的分号为止） */
const dropCallAt = (text, idx) => {
  const semi = text.indexOf(';', idx);
  return text.slice(0, idx) + text.slice(semi + 1);
};

/** 探测器：返回代码视图里"回收被 enable 开关门控"的形状，以及回收调用本身的条数 */
function survey(code) {
  return {
    enabledRefs: (code.match(/wal\.isEnabled\(\)/g) || []).length,
    gatedReclaim: (
      code.match(/if\s*\(\s*wal\.isEnabled\(\)[^)]*\)\s*wal\.(?:trimBySeqs|discardBySeqs)/g) || []
    ).map((s) => s.slice(0, 60)),
    trimCalls: countOf(code, 'wal.trimBySeqs('),
    discardCalls: countOf(code, 'wal.discardBySeqs('),
  };
}

const RECLAIM_NEEDLES = ['wal.trimBySeqs(', 'wal.discardBySeqs('];
const readCode = (file) => codeOnly(fs.readFileSync(path.join(DIR, file), 'utf8'));
/**
 * 所有"会碰 WAL 回收"的服务模块，文件名一个都不写死。
 *
 * 原先只读 auditBuffer.js 一个文件。2026-09-26 预铸造闸把"被拒文档按毒批口径记账"
 * 拆进了 services/auditBufferDocs.js，那一处的 `wal.discardBySeqs(` 从此既不进计数、
 * 也不受"回收不得被 isEnabled 门控"的约束——**拆出去的代码天然在闸外**，
 * 而这正是本闸门存在的理由（三处同族缺陷里就有两处是"账记在别的分支上"）。
 * 按目录扫，则它拆到哪一处都还在闸内。
 */
const reclaimModules = () =>
  fs
    .readdirSync(DIR)
    .filter((f) => f.endsWith('.js'))
    .filter((f) => RECLAIM_NEEDLES.some((n) => readCode(f).includes(n)))
    .sort();

describe('审计 WAL 回收与追加开关解耦（F-143 门禁）', () => {
  const files = reclaimModules();
  const surveyed = files.map((file) => ({ file, s: survey(readCode(file)) }));
  const sum = (key) => surveyed.reduce((n, x) => n + x.s[key], 0);

  test('扫描集合自证：非空、含主模块、成员各有一处真回收调用', () => {
    // 这条是**前提闸**：下面三条都建立在"扫到了东西"之上，扫空时它们会全部空转放行
    expect(files).toContain('auditBuffer.js');
    for (const { s: x } of surveyed) {
      expect(x.trimCalls + x.discardCalls).toBeGreaterThan(0);
    }
    // 反向对照：定义了 trimBySeqs 的那个模块不该被判成调用方（判据不是匹配到一切）
    expect(files).not.toContain('auditBufferWal.js');
  });

  test('回收调用条数与整改时的形状一致（少一条＝把某处回收整段删掉）', () => {
    // 用计数而不是 toContain：同一个名字出现两次时，toContain 看不见"其中一处被改回去"。
    // discard 从 1 涨到 2（2026-09-26 预铸造闸）：schema 预检被拒的文档走毒批同一口径记账，
    // 多一条回收调用点，而它落在 auditBufferDocs.js——单文件闸门当时看不见它。
    expect({ trim: sum('trimCalls'), discard: sum('discardCalls') }).toEqual({
      trim: 2,
      discard: 2,
    });
  });

  test('所有回收模块里没有任何回收动作被 wal.isEnabled() 门控', () => {
    const gated = surveyed.flatMap(({ file, s: x }) => x.gatedReclaim.map((g) => `${file}: ${g}`));
    expect(gated).toEqual([]);
  });

  test('全部回收模块加起来只剩一处 wal.isEnabled()，且它是对外暴露的只读包装', () => {
    // isWalEnabled() 给合规仪表盘用（"WAL 是否在写"），那是真正的读开关，允许存在；
    // 出现第二处就说明又有人拿它当回收判据。
    expect(sum('enabledRefs')).toBe(1);
    expect(readCode('auditBuffer.js')).toMatch(/return wal\.isEnabled\(\);/);
  });

  test('自检：探测器对"恢复闸门"与"删掉一处回收"的变异必须报红（否则上面几行都是空转）', () => {
    // 两类变异 × **每一处**调用点，跨所有模块：
    // 只在第一处上试的话，后加的那一处 discard 就只是把期望值抬高一格、
    // 谁把它整段删掉都没人管——这正是上一行从 1 改成 2 时必须一起补的证据。
    // 锚点一律从代码视图现取下标，不写死调用实参：原先 `code.replace('wal.trimBySeqs(walSeqsOf(docs));', …)`
    // 在实参改名（docs→landed）后静默匹配不上，而 mutant===code 的自证只挡"整条变异空转"，
    // 挡不住"锚点早已指向一个不存在的形状"。
    for (const { file, s: x } of surveyed) {
      const code = readCode(file);
      for (const needle of RECLAIM_NEEDLES) {
        const key = needle.includes('trim') ? 'trimCalls' : 'discardCalls';
        const sites = callSites(code, needle);
        expect(sites).toHaveLength(x[key]);
        for (const idx of sites) {
          expect(survey(dropCallAt(code, idx))[key]).toBe(x[key] - 1);
          const mutant = `${code.slice(0, idx)}if (wal.isEnabled()) ${code.slice(idx)}`;
          expect(mutant).not.toBe(code);
          const m = survey(mutant);
          expect(m.gatedReclaim).toHaveLength(1);
          expect(m.enabledRefs).toBe(x.enabledRefs + 1);
        }
      }
    }
  });
});
