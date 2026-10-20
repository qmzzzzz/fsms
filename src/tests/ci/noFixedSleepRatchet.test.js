/**
 * 测试固定睡眠棘轮（2026-10-20，审计 T-2）
 *
 * 固定睡眠（`await new Promise(r => setTimeout(r, N))` / 本地 sleep(delay)）是
 * 测试 flake 的主要来源：机器快时白等，机器慢时照样超时；它等待的是"时间过去"，
 * 而测试真正需要的是"某个条件成立"。
 *
 * 本仓已把后端用例迁移到 `helpers/waitFor.js`（条件轮询 / 事件循环让步）与
 * 假定时器（`jest.useFakeTimers`），本闸负责把迁移结果钉住，禁止新代码退回
 * 固定睡眠。
 *
 * 判据只打三类**同步编排**形态：
 *   1. `new Promise(...setTimeout...)`——把定时器包成可 await 的睡眠；
 *   2. 本地 `sleep/delay/wait/waitMs/sleepMs` 包装器（含后续 `await sleep(...)`）；
 *   3. `timers/promises` 的 setTimeout。
 *
 * 有意放行（不是因为难改，而是它们不属于"等待测试完成"）：
 *   · 测试替身里模拟**被测延迟**的裸 `setTimeout`（如挂起连接、路由延迟）；
 *   · 子进程源码字符串里的定时器（loggerFlush 等）。
 * 逐文件豁免必须有理由，且本文件自身不参与扫描——自证夹具以字符串形式存在，
 * 与真实违规无法共存于同一视图（同 commentAnchorFreshness 的自证取舍）。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');

const ROOT = path.resolve(__dirname, '../../..');
const SELF = 'src/tests/ci/noFixedSleepRatchet.test.js';

const SCAN_ROOTS = [
  { dir: path.join(ROOT, 'src/tests'), suffix: '.test.js', label: '后端 jest' },
  { dir: path.join(ROOT, 'e2e'), suffix: '.spec.js', label: 'Playwright E2E' },
];

/**
 * 逐文件豁免：键为仓库相对路径（/ 分隔），值为理由。
 * 只允许"延迟本身是被测对象"或"模拟 I/O 延迟的测试替身"，不得用来放行同步等待。
 */
const ALLOWLIST = new Map([
  [
    'src/tests/auditBufferZombieDuplicate.test.js',
    '慢库测试替身：sleep(delayMs) 模拟慢速写入，制造读-写竞态窗口，不是等待测试完成',
  ],
  [
    'e2e/journey-fault-injection.spec.js',
    '路由层挂起 16s 以触发 axios 15s 客户端超时，延迟本身是被测行为',
  ],
  [
    'src/tests/observability/auditBufferShutdownDrain.test.js',
    'insertMany 桩延迟 40ms 后拒绝，模拟连接被重置的被测 I/O 延迟',
  ],
  [
    'src/tests/services/auditExportWriteLineAbort.test.js',
    'settleWithin 用 Promise.race 给条件等待设上限，定时器是超时判定而非固定睡眠',
  ],
  [
    'src/tests/utils/transactionTopology.test.js',
    'endSession 桩延迟到宏任务再拒绝，模拟异步清理超时，用于证明 withTransaction 确实持有 Promise',
  ],
]);

const PATTERNS = [
  {
    name: 'new Promise + setTimeout（可 await 的固定睡眠）',
    re: /\bnew\s+Promise\s*\([\s\S]{0,240}?\bsetTimeout\s*\(/,
  },
  {
    name: '本地 sleep/delay/wait 包装器',
    re: /\b(?:const|let|var)\s+(?:sleep|delay|wait|waitMs|sleepMs)\s*=\s*(?:\([^)]*\)|[\w$]+)\s*=>[\s\S]{0,160}?\bsetTimeout\s*\(/,
  },
  {
    name: 'await sleep/delay/wait(...)',
    re: /\bawait\s+(?:sleep|delay|wait|waitMs|sleepMs)\s*\(/,
  },
  {
    name: 'timers/promises 的 setTimeout',
    re: /(?:require\s*\(\s*['"]timers\/promises['"]\s*\)|from\s+['"]timers\/promises['"])/,
  },
];

/** 只返回"代码视图"上命中的模式名；注释里的反例不应触发。 */
function scanCode(src) {
  const code = jsCodeOnly(src);
  return PATTERNS.filter((pattern) => pattern.re.test(code)).map((pattern) => pattern.name);
}

/** 仓库相对路径（/ 分隔）→ 允许的违规名列表（豁免文件恒为空）。 */
function findFixedWaits(relPath, src) {
  if (ALLOWLIST.has(relPath)) return [];
  return scanCode(src);
}

function collectFiles() {
  const out = [];
  for (const { dir, suffix } of SCAN_ROOTS) {
    if (!fs.existsSync(dir)) continue;
    const stack = [dir];
    while (stack.length > 0) {
      const current = stack.pop();
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        if (entry.name === 'node_modules' || entry.name === 'coverage') continue;
        const full = path.join(current, entry.name);
        if (entry.isDirectory()) stack.push(full);
        else if (entry.isFile() && entry.name.endsWith(suffix)) out.push(full);
      }
    }
  }
  return out;
}

const toRepoPath = (abs) => path.relative(ROOT, abs).split(path.sep).join('/');

describe('测试固定睡眠棘轮', () => {
  const files = collectFiles();

  test('扫描面非空（防止路径写错导致闸空转）', () => {
    // 2026-10-20 实测 593 个后端用例 + 6 个 E2E spec；下限留出删减余量。
    expect(files.length).toBeGreaterThanOrEqual(500);
    expect(files.some((f) => toRepoPath(f).startsWith('e2e/'))).toBe(true);
    // 本文件在扫描面里，但违规扫描显式跳过它：自证夹具以字符串存在，必须与真违规分开
    expect(files.map(toRepoPath)).toContain(SELF);
  });

  test('所有测试文件不含固定睡眠（豁免清单逐条带理由）', () => {
    const violations = [];
    for (const file of files) {
      const rel = toRepoPath(file);
      if (rel === SELF) continue;
      const src = fs.readFileSync(file, 'utf8');
      for (const kind of findFixedWaits(rel, src)) violations.push(`${rel}：${kind}`);
    }
    expect(violations).toEqual([]);
  });

  test('豁免项必须真实命中扫描面且理由非空（防止豁免腐烂成永久白名单）', () => {
    const scanned = new Set(files.map(toRepoPath));
    for (const [rel, reason] of ALLOWLIST) {
      expect(scanned.has(rel)).toBe(true);
      expect(reason.trim().length).toBeGreaterThan(10);
      const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
      expect(scanCode(src).length).toBeGreaterThan(0);
      expect(findFixedWaits(rel, src)).toEqual([]);
    }
  });

  test('自证：合成违规必红、条件等待/注释反例不误伤', () => {
    const plantedPromise =
      'test("x", async () => { await new Promise((r) => set' + 'Timeout(r, 25)); });';
    expect(scanCode(plantedPromise)).toContain('new Promise + setTimeout（可 await 的固定睡眠）');

    const plantedHelper =
      'const sleep = (ms) => new Promise((r) => set' + 'Timeout(r, ms));\nawait sleep(10);';
    expect(scanCode(plantedHelper)).toEqual(
      expect.arrayContaining(['本地 sleep/delay/wait 包装器', 'await sleep/delay/wait(...)'])
    );

    const plantedTimers = "const { setTimeout: delay } = require('timers/promises');";
    expect(scanCode(plantedTimers)).toContain('timers/promises 的 setTimeout');

    // 注释里的反例不得触发（jsCodeOnly 的口径）
    const commentOnly = '// await new Promise((r) => set' + 'Timeout(r, 25));\n';
    expect(scanCode(commentOnly)).toEqual([]);

    // 条件等待（setImmediate 让步）不是固定睡眠
    expect(scanCode('await new Promise((r) => setImmediate(r));')).toEqual([]);
  });
});
