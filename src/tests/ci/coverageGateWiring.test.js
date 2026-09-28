/**
 * 覆盖率门禁接线自检（CI 侧）
 *
 * 【实证的洞】`.github/workflows/ci.yml` 的覆盖率步骤写的是
 *   `npm run test:coverage --if-present -- --forceExit`
 * `--if-present` 的语义是「脚本不存在就安静地跳过、退出码 0」。于是：
 *   · 有人把 `test:coverage` 改名（或删掉）⇒ 这一整步变成空操作，CI 仍全绿；
 *   · 而 jest.config.js 里那份 36 条逐文件阈值 + global 阈值从此**再也不执行**。
 * 危害不是"少一个数字"，是**已设防的错觉**：作业名、步骤名、阈值配置都还在，
 * 只有执行链断了。同一文件里 frontend-build 作业的同名步骤就没加这个标志，
 * 说明它并非有意为之，而是初始模板（`git log -S'if-present'` 只命中首个提交）。
 *
 * 【本文件钉住的四件事】
 *   ① CI 里任何 `npm run X` 的 X 必须存在于**该步骤实际执行的那个** package.json
 *      （根目录 / web-admin 两份，靠 working-directory 判定）⇒ 悬空脚本名直接红；
 *   ② 任何 `npm run` 都不得带 `--if-present`；
 *   ③ 后端覆盖率门确实被接线：存在一个非 web-admin 的步骤跑 `test:coverage`，
 *      且该 script 自身带 `--coverage`（否则 jest 不收集，阈值永远不触发）；
 *   ④ 阈值本身得是闸：global 四项齐全且 > 0，逐文件条目数量不塌方、
 *      值不得为 0（0 = 关阀），键必须是 `./src/**.js` 形态。
 *
 * 只读文件、不连 DB、不走网络 ⇒ 判定确定性。
 * 每条判据都配了反向对照，防止"正则退化让门禁空转"这类假绿。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const workflowFiles = () =>
  fs
    .readdirSync(path.join(ROOT, '.github', 'workflows'))
    .filter((f) => /\.(yml|yaml)$/.test(f))
    .sort();

const rootScripts = JSON.parse(read('package.json')).scripts || {};
const webScripts = JSON.parse(read('web-admin/package.json')).scripts || {};

/**
 * 抽出所有 `npm run <name>` 调用点，并带上它所属步骤的 working-directory。
 * 步骤边界按 `- name:` 划分（本仓工作流的统一写法）；找不到边界就停止回溯，
 * 宁可不分类，也不要把上一个作业的目录错配过来。
 */
const parseNpmRuns = () => {
  const items = [];
  for (const file of workflowFiles()) {
    const lines = read(`.github/workflows/${file}`).split(/\r?\n/);
    lines.forEach((line, i) => {
      const m = /npm\s+run\s+([a-zA-Z0-9:_-]+)(.*)$/.exec(line);
      if (!m) return;
      let workingDirectory = '';
      for (let j = i; j > i - 25 && j >= 0; j -= 1) {
        if (j < i && /^\s*-\s+name:/.test(lines[j])) break;
        const w = /working-directory:\s*(\S+)/.exec(lines[j]);
        if (w) {
          workingDirectory = w[1];
          break;
        }
      }
      items.push({
        file,
        no: i + 1,
        name: m[1],
        tail: m[2],
        workingDirectory,
        where: `${file}:${i + 1} ${line.trim()}`,
      });
    });
  }
  return items;
};

const scriptsFor = (workingDirectory) =>
  workingDirectory.includes('web-admin') ? webScripts : rootScripts;

describe('覆盖率门禁接线（CI 侧不得有静默跳过的闸）', () => {
  const runs = parseNpmRuns();

  test('前提自证：解析器真的抽到了调用点（抽空的正则会让下面每条判据恒绿）', () => {
    expect(runs.length).toBeGreaterThanOrEqual(10);
    const names = runs.map((r) => r.name);
    for (const expected of ['lint', 'test:coverage', 'build']) {
      expect(names).toContain(expected);
    }
    // working-directory 分类这条判据本身也要被走到：确有 web-admin 步骤
    expect(runs.filter((r) => r.workingDirectory.includes('web-admin')).length).toBeGreaterThan(0);
  });

  test('每条 npm run 的脚本名必须在它实际执行的 package.json 里存在', () => {
    const dangling = runs
      .filter((r) => !Object.prototype.hasOwnProperty.call(scriptsFor(r.workingDirectory), r.name))
      .map((r) => `${r.where} ⇒ ${r.workingDirectory || '(根目录)'}/${r.name} 未定义`);
    expect(dangling).toEqual([]);
  });

  test('判据可失败：把脚本名换成不存在的，同一判据必须报出来', () => {
    // 反向对照——否则"悬空脚本名"这条可能是恒真的文本匹配
    const bogus = [{ ...runs[0], name: 'no_such_script' }];
    const detected = bogus
      .filter((r) => !Object.prototype.hasOwnProperty.call(scriptsFor(r.workingDirectory), r.name))
      .map((r) => r.name);
    expect(detected).toEqual(['no_such_script']);
  });

  test('CI 里任何 npm run 都不得带 --if-present（脚本缺失必须硬失败）', () => {
    const found = runs.filter((r) => /--if-present/.test(r.tail)).map((r) => r.where);
    expect(found).toEqual([]);
  });

  test('判据可失败：历史原文（本批修掉的那一行）必须被 --if-present 判据抓到', () => {
    // 这条就是改动前的 ci.yml 第 122 行原文。没有它，上一条可能是"恒真的正则"。
    const legacy = {
      name: 'test:coverage',
      tail: ' --if-present -- --forceExit',
      where: 'ci.yml:122 run: npm run test:coverage --if-present -- --forceExit',
    };
    expect(/--if-present/.test(legacy.tail)).toBe(true);
  });

  test('后端覆盖率门已接线：非 web-admin 作业跑 test:coverage 且命令含 --coverage', () => {
    const backend = runs.filter((r) => r.name === 'test:coverage' && !r.workingDirectory);
    expect(backend.length).toBeGreaterThanOrEqual(1);
    // script 自身必须带 --coverage：`npm run test:coverage` 若退化成 `jest`，
    // 阈值配置再全也不会被求值（jest 只在收集覆盖率时才检查 coverageThreshold）
    expect(rootScripts['test:coverage']).toMatch(/--coverage/);
  });
});

describe('覆盖率阈值本身得是闸', () => {
  const cfg = require('../../../jest.config.js');
  const METRICS = ['branches', 'functions', 'lines', 'statements'];

  test('global 四项齐全且都 > 0（缺一项或取 0 = 该维度关阀）', () => {
    const globalThresholds = cfg.coverageThreshold.global;
    expect(Object.keys(globalThresholds).sort()).toEqual([...METRICS].sort());
    for (const metric of METRICS) {
      expect(typeof globalThresholds[metric]).toBe('number');
      expect(globalThresholds[metric]).toBeGreaterThan(0);
    }
  });

  test('逐文件阈值条目：数量不塌方、键形态正确、值不得为 0', () => {
    const entries = Object.entries(cfg.coverageThreshold).filter(([k]) => k !== 'global');
    // 下限刻意取宽松值：本仓有 30+ 个安全关键模块单独设阈，全被删掉才是这里要拦的
    expect(entries.length).toBeGreaterThanOrEqual(20);
    for (const [key, thresholds] of entries) {
      expect(key).toMatch(/^\.\/src\/.*\.js$/);
      expect(Object.keys(thresholds).length).toBeGreaterThan(0);
      for (const [metric, value] of Object.entries(thresholds)) {
        expect(METRICS).toContain(metric);
        expect(value).toBeGreaterThan(0);
      }
    }
  });

  test('判据可失败：值为 0 的条目必须被判为"关阀"（否则上一条可能恒绿）', () => {
    const zeroed = { branches: 0, functions: 90 };
    const isClosed = (v) => typeof v !== 'number' || v <= 0;
    expect(
      Object.entries(zeroed)
        .filter(([, v]) => isClosed(v))
        .map(([k]) => k)
    ).toEqual(['branches']);
  });
});
