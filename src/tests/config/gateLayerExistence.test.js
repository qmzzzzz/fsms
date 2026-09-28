/**
 * 门禁层存在性 + 用例文件去重
 *
 * 为什么需要这个文件：
 * 1) 门禁层（.github/workflows/、scripts/ 下的自检脚本）被删掉时，**没有任何测试会变红**——
 *    测试自己跑在本地/CI 里，不检查"谁来跑我"。一次误删（或一次把删除当重构的改动）
 *    会让质量门静默消失，之后所有轮次的"绿"都不再代表门禁通过。
 * 2) 用例文件被改名（拆分/重命名是常规重构）后，若旧名副本被恢复，同一批断言会跑两遍：
 *    测试计数虚高，且旧副本往往停留在改名前的弱断言上——它比后继文件更容易通过，
 *    于是"退化实现 + 旧副本"仍能全绿。旧副本各自带有一行改名沿革说明（`由 \`X.test.js\` 更名`），
 *    这条信息足以机判"旧名是否仍在树上"。
 *
 * 可证伪性：删掉任一 workflow 文件 / 复制一个 .test.js 换个名字 / 恢复一个改名前的旧副本，
 * 本文件对应用例即红。三条都不依赖数据库与网络。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const TESTS_DIR = path.join(ROOT, 'src/tests');

function listTestFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) listTestFiles(p, out);
    else if (entry.name.endsWith('.test.js')) out.push(p);
  }
  return out;
}

const rel = (p) => path.relative(ROOT, p).replace(/\\/g, '/');

/** 命令名按"整条命令"匹配：后面还接 \w / : / - 的都算另一条命令（lint ≠ lint:ratchet） */
const cmdRe = (cmd) => new RegExp(`${cmd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w:-])`);

describe('门禁层存在性（删掉门禁不会让任何东西变红 → 由本文件补上）', () => {
  // CI/CD 的入口定义。缺失 = 质量门与部署链路静默断裂。
  const WORKFLOWS = [
    '.github/workflows/ci.yml',
    '.github/workflows/deploy.yml',
    '.github/workflows/codeql.yml',
    '.github/workflows/dependency-review.yml',
    '.github/workflows/release.yml',
    '.github/workflows/scorecard.yml',
  ];

  test.each(WORKFLOWS)('%s 存在且带 jobs 段', (wf) => {
    const abs = path.join(ROOT, wf);
    expect(fs.existsSync(abs)).toBe(true);
    const source = fs.readFileSync(abs, 'utf8');
    expect(source).toMatch(/^jobs:/m);
  });

  test('ci 工作流真实调用本地四件套门禁（否则本地绿 ≠ CI 绿）', () => {
    const source = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
    // 这四条命令是仓库自身的门禁：格式、棘轮、UTF-8、合规自检
    // 必须按"整条命令"匹配：`npm run lint` 前缀命中 `npm run lint:ratchet`，
    // 于是把真正的 lint 作业整段删掉、只剩棘轮作业时，toContain 仍然为真——
    // 门禁在自评门禁，这就是假绿（与 toContain 前缀碰撞同族）。守卫 (?![\w:-])
    // 排除"命令名后面还接字符"的形态（`--` 之后的参数不算，所以 `npx jest --randomize` 照过）。
    for (const cmd of ['npx jest', 'npm run lint', 'npm run format:check', 'npm run check:utf8']) {
      expect(cmdRe(cmd).test(source)).toBe(true);
    }
    expect(source).toContain('scripts/compliance-check.js');

    // 抽取自证（两向）：证明这里防的是**真实存在于本仓的碰撞**，不是空转的正则。
    // 造一份"删掉所有 `run: npm run lint` 行"的副本——旧写法判它"门禁还在"（假绿），
    // 新写法判它"门禁没了"（抓到）。
    expect(source).toContain('npm run lint:ratchet');
    const stripped = source
      .split('\n')
      .filter((line) => !/^\s*run: npm run lint\s*$/.test(line))
      .join('\n');
    expect(stripped.includes('npm run lint')).toBe(true); // 旧断言在这里失效
    expect(cmdRe('npm run lint').test(stripped)).toBe(false); // 新断言不会
  });

  test('自检脚本齐备且可 require 期语法正确（空文件/半截改动同样要拦下）', () => {
    const scripts = [
      'scripts/lint-ratchet.js',
      'scripts/check-utf8.js',
      'scripts/compliance-check.js',
      'eslint.ratchet.json',
    ];
    for (const s of scripts) {
      const abs = path.join(ROOT, s);
      expect(fs.existsSync(abs)).toBe(true);
      const text = fs.readFileSync(abs, 'utf8');
      expect(text.trim().length).toBeGreaterThan(0);
      if (s.endsWith('.js')) {
        // node --check 按 CommonJS 语义解析（shebang、顶层 return 都合法），
        // 只编译不执行；比 new Function 更贴合"这个文件能否被 node 加载"。
        const r = spawnSync(process.execPath, ['--check', abs], { encoding: 'utf8' });
        expect({ file: s, status: r.status, stderr: (r.stderr || '').split('\n')[0] }).toEqual({
          file: s,
          status: 0,
          stderr: '',
        });
      } else {
        expect(() => JSON.parse(text)).not.toThrow();
      }
    }
  });
});

describe('用例文件去重（改名后的旧副本不得留在树上）', () => {
  const files = listTestFiles(TESTS_DIR);

  test('测试文件数量达到基线（整体被删时这里先红）', () => {
    // 基线取值留余量：合并/删除重复文件后允许下降，但整批消失必须报警。
    // 余量必须**小**：这里曾经是 230，而树上已有 335 个文件——删掉 105 个用例
    // （超过三分之一）这条门禁仍然绿，等于"整批被删先报警"的承诺是空的。
    // 现在按当前规模留 ~4% 余量；只许随仓库增长上调，下调要有明确理由。
    expect(files.length).toBeGreaterThanOrEqual(320);
  });

  test('改名沿革指向的旧文件已不在树上', () => {
    const pathByBase = new Map(files.map((f) => [path.basename(f), f]));
    const resurrected = [];
    for (const f of files) {
      const m = fs.readFileSync(f, 'utf8').match(/由 `([^`]+\.test\.js)` 更名/);
      if (m && pathByBase.has(m[1])) {
        resurrected.push({
          renamedFrom: m[1],
          oldStillAt: rel(pathByBase.get(m[1])),
          successor: rel(f),
        });
      }
    }
    expect(resurrected).toEqual([]);
  });

  test('不存在内容完全相同的两个测试文件（复制粘贴式"新增套件"）', () => {
    // 只比代码行：注释（含改名沿革、边界说明）允许不同，代码行集合相同即视为重复。
    const hashOf = (text) => {
      const code = text
        .split(/\r?\n/)
        .map((l) => l.replace(/\s+$/, ''))
        .filter((l) => {
          const t = l.trim();
          return t && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*');
        })
        .join('\n');
      return crypto.createHash('sha256').update(code).digest('hex').slice(0, 16);
    };
    const buckets = new Map();
    for (const f of files) {
      const h = hashOf(fs.readFileSync(f, 'utf8'));
      if (!buckets.has(h)) buckets.set(h, []);
      buckets.get(h).push(rel(f));
    }
    const duplicates = [...buckets.values()].filter((v) => v.length > 1);
    expect(duplicates).toEqual([]);
  });
});
