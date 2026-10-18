/**
 * F-14（审计报告 2026-10-16）：被引用的 deliverables/ 必须逐条登记、且可被核对
 *
 * 问题不是"引用了仓库外的文件"本身——`deliverables/` 因含可利用细节而**刻意**不入库
 * （公开仓，见 .gitignore 与 CONTRIBUTING.md §9）。问题是引用**没有任何账**：
 * 干净 checkout 打不开、代码审查无法核对、旧文件被删或改名后没人知道引用已经悬空。
 *
 * 本用例把 `docs/internal-evidence-index.md` 变成可机器核对的双向台账：
 *   ① 源码里出现的每个 `deliverables/<文件>` 都必须在台账里登记；
 *   ② 台账里登记的每一项都必须仍被引用（防僵尸条目）；
 *   ③ 标为「已断链」的条目，磁盘上必须确实不存在（否则标签在撒谎）；
 *   ④ 不入库这个政策本身仍成立（.gitignore 仍忽略、CONTRIBUTING 仍有说明）。
 *
 * 为什么不用 git 命令核对"是否在历史里"：本项目在 jest 里 shell-out 会被沙箱拦，
 * 报错形态还伪装成语法错误。历史可复核性只能人工核对并写进台账的「可复核来源」列，
 * 本用例只核对**可自动判定的部分**（登记完整性 + 断链标签的真伪）。
 */

const fs = require('fs');
const path = require('path');

const { walk } = require('../../../scripts/check-utf8');

// 目录名与正则都由拼接得到，避免本文件自身被扫成"一处引用"
const DIR = 'deliverables';
const REF_RE = new RegExp(`${DIR}/[^\\s，。、；：""'\`（）()《》\\[\\]]+`, 'g');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const INDEX_FILE = path.join(REPO_ROOT, 'docs', 'internal-evidence-index.md');

/** 参与扫描的文本扩展名（其余是图片/二进制，读了也没意义） */
const TEXT_EXT = new Set([
  '.js',
  '.cjs',
  '.mjs',
  '.ts',
  '.md',
  '.json',
  '.yml',
  '.yaml',
  '.sh',
  '.html',
  '.css',
  '.vue',
  '.example',
  '.gitignore',
  '.dockerignore',
]);

/**
 * 扫描时必须跳过的路径前缀。
 *
 * 前四类是「不构成克隆后打不开」的本地态，判据是同一条：**clean checkout 里没有它们**
 * （`backups/`、`logs/`、`coverage/` 都在 .gitignore 里，`git ls-files backups` 实测为 0）。
 * 这条区分不是给自己开后门，而是本用例的命题边界：它要证明的是「仓库里写下的引用
 * 在克隆后指得到东西」。一份本地快照目录内部的互相引用（`backups/deliverables-*` 里
 * 旧报告引用旧台账）既不在 checkout 里，也不承担被外部跟读的义务——把它们也登记进台账，
 * 只会让 33 条里有 20 条是「快照对快照」，真正的活引用被淹没。
 * 代价如实写明：**若哪天有人把 `backups/` 纳入版本管理，这条豁免就失去依据**，
 * 本文件的注释与 skip 列表必须同时改。
 *
 * 后两类是自指（台账自己、本用例自己），理由见 `REF_RE` 上方的拼接写法。
 */
const LOCAL_ONLY_PREFIXES = ['backups/', 'logs/', 'coverage/'];

function isSkippedPath(rel) {
  const p = rel.replace(/\\/g, '/');
  return (
    p.startsWith(`${DIR}/`) ||
    LOCAL_ONLY_PREFIXES.some((prefix) => p.startsWith(prefix)) ||
    p.startsWith('.learnings/') ||
    p.startsWith('.lint-ratchet-selftest-') ||
    p === 'docs/internal-evidence-index.md' ||
    p === 'src/tests/docs/deliverablesReferenceIndex.test.js'
  );
}

/** 收集全仓被引用的 deliverables 路径 → 引用它的文件数 */
function collectReferences() {
  const files = [];
  walk(REPO_ROOT, files);
  const refs = new Map();
  for (const abs of files) {
    const rel = path.relative(REPO_ROOT, abs);
    if (isSkippedPath(rel)) continue;
    const ext = path.extname(abs).toLowerCase();
    const base = path.basename(abs);
    // 点开头的无扩展名文件（`.gitignore` / `.dockerignore`）：`path.extname` 返回 ''，
    // 而 `base` 本身已含前导点 ⇒ 原写法拼出 `..gitignore`，永远匹配不上。
    // 实测后果：`.gitignore:135` 那条「取回方式见 deliverables/审计与迭代汇总-…」的引用
    // 对本用例完全隐形——TEXT_EXT 里明明列了这两个名字，实际却一个都没扫到。
    // 故先按 base 原样匹配一次，再退回补点的写法。
    if (!TEXT_EXT.has(ext) && !TEXT_EXT.has(base) && !TEXT_EXT.has(`.${base}`)) continue;
    let src;
    try {
      src = fs.readFileSync(abs, 'utf8');
    } catch (_) {
      continue;
    }
    for (const m of src.matchAll(REF_RE)) {
      const ref = m[0].replace(/[.,;:]+$/, '');
      if (!/\.[A-Za-z0-9*]+$/.test(ref)) continue; // 目录提及（`deliverables/`、`deliverables/、docs/`）不算
      if (!refs.has(ref)) refs.set(ref, new Set());
      refs.get(ref).add(rel);
    }
  }
  return refs;
}

/** 解析台账表格的第一列，得到登记过的引用路径 → 该行的「可复核来源」列 */
function parseIndex(indexText) {
  const registered = new Map();
  for (const line of indexText.split('\n')) {
    const m = /^\|\s*`([^`]+)`\s*\|/.exec(line.trim());
    if (!m) continue;
    const cells = line
      .split('|')
      .slice(1, -1)
      .map((c) => c.trim());
    registered.set(m[1], { source: cells[cells.length - 1] || '', row: line.trim() });
  }
  return registered;
}

describe('F-14 内部留档引用台账', () => {
  const indexText = fs.readFileSync(INDEX_FILE, 'utf8');
  const registered = parseIndex(indexText);
  const refs = collectReferences();

  test('台账本身非空，且写明为什么该目录不入库', () => {
    expect(registered.size).toBeGreaterThanOrEqual(10);
    expect(indexText).toContain('公开仓库');
    expect(indexText).toContain('deliverablesReferenceIndex.test.js');
  });

  test('① 源码里引用的每个 deliverables 文件都已登记（新增引用必须入账）', () => {
    const unregistered = [...refs.keys()].filter((r) => !registered.has(r)).sort();
    expect(unregistered).toEqual([]);
  });

  test('② 台账里每一项仍被引用（防僵尸条目：文件不再被引用就删行）', () => {
    const zombies = [...registered.keys()].filter((r) => !refs.has(r)).sort();
    expect(zombies).toEqual([]);
  });

  test('③ 标为「已断链」的条目，磁盘上必须确实不存在（标签不得撒谎）', () => {
    const broken = [...registered].filter(([, meta]) => meta.source.includes('已断链'));
    // 这四份从未入库且当前磁盘不存在，是本轮审计的实测结论；若哪天被补回，
    // 本用例转红并提示更新台账——这正是"账目可证伪"该有的行为。
    expect(broken.length).toBeGreaterThanOrEqual(4);

    const appearedOnDisk = broken
      .map(([ref]) => ref)
      .filter((ref) => fs.existsSync(path.join(REPO_ROOT, ref)));
    // 非空 ⇒ 文件已出现在磁盘上，请把该行的「可复核来源」改成实际来源
    expect(appearedOnDisk).toEqual([]);
  });

  test('④ 不入库这个政策仍成立：.gitignore 仍忽略该目录，CONTRIBUTING 仍有说明', () => {
    const gitignore = fs.readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8');
    expect(gitignore).toMatch(new RegExp(`^${DIR}/$`, 'm'));

    // 豁免的前提自证：被跳过的本地态目录必须确实被 .gitignore 忽略。
    // 少了这条，`LOCAL_ONLY_PREFIXES` 就退化成"作者想跳过什么就跳过什么"——
    // 有人把 backups/ 纳入版本管理后，跳过仍在、依据已消失，而不会有任何东西响。
    for (const prefix of LOCAL_ONLY_PREFIXES) {
      const dir = prefix.replace(/\/$/, '');
      expect({ dir, ignored: new RegExp(`^${dir}/$`, 'm').test(gitignore) }).toEqual({
        dir,
        ignored: true,
      });
    }

    const contributing = fs.readFileSync(path.join(REPO_ROOT, 'CONTRIBUTING.md'), 'utf8');
    expect(contributing).toContain(DIR);
    // §9 是 .gitignore 注释里指向的那一节；指向不存在的小节等于引用又断了一条
    expect(contributing).toMatch(/^##+\s*9[.、\s]/m);
  });
});
