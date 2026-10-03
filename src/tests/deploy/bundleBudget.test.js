/**
 * 前端产物体积预算门禁（scripts/check-bundle-budget.js）的专项测试
 *
 * 三条被验证的性质（每条都能因真实退化而失败，无凑数用例）：
 *   1. 假绿防护：dist 为空 / index.html 缺失 / 入口 chunk 缺失时，必须失败。
 *      这是本门禁最危险的失效方式——「0 字节 < 预算」会让门禁在最需要它的
 *      场景（构建失败、产物被清理）反而全绿。
 *   2. 超预算真的红：构造一个确定超限的假产物 + 基线，断言非零退出且
 *      输出点名超限指标。
 *   3. 基线缺失/损坏 fail-closed：不能因为读不到基线就默认放行。
 *
 * 外加两项计量正确性检验（gzip 口径、入口解析），它们直接决定预算数字的
 * 可信度：解析漏掉一个入口文件，首屏预算就会系统性偏低（且永远绿）。
 *
 * 设计约束：所有劣化都在临时目录（os.tmpdir/codebudget-*）里构造，
 * 不触碰仓库真实产物；真实 dist 不可用（未构建）时明确失败而不是静默跳过。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const NODE = process.execPath;
const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts/check-bundle-budget.js');
const REAL_DIST = path.join(ROOT, 'web-admin/dist');
const REAL_BASELINE = path.join(ROOT, 'web-admin/bundle-budget.json');

const budget = require(SCRIPT);

/** 在临时目录里造一个最小可用的 dist（index.html + 指定资源） */
function makeFakeDist(name, { html, files = {}, extra = {} }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `codebudget-${name}-`));
  if (html !== null) fs.writeFileSync(path.join(dir, 'index.html'), html, 'utf8');
  for (const [rel, content] of Object.entries({ ...files, ...extra })) {
    const abs = path.join(dir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}

const runScript = (args) => {
  const result = require('child_process').spawnSync(NODE, [SCRIPT, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  return { code: result.status, out: (result.stdout || '') + (result.stderr || '') };
};

const tempDirs = [];
const trackDir = (dir) => {
  tempDirs.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
});

describe('体积预算门禁：假绿防护（最重要的一类失效）', () => {
  it('dist 目录不存在 → 必须失败，而不是「0 字节 < 预算」通过', () => {
    const missing = path.join(os.tmpdir(), 'codebudget-does-not-exist-zzkepler');
    fs.rmSync(missing, { recursive: true, force: true });
    const { code, out } = runScript([`--dist=${missing}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('构建产物不存在');
  });

  it('dist 存在但无 index.html（构建半途失败）→ 必须失败', () => {
    const dir = trackDir(makeFakeDist('nohtml', { html: null, files: { 'assets/a.js': 'x' } }));
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('构建产物不存在');
  });

  it('index.html 存在但无入口 script（模块入口缺失）→ 必须失败', () => {
    const dir = trackDir(
      makeFakeDist('noentry', {
        html: '<html><head><link rel="stylesheet" href="/assets/a.css"></head><body></body></html>',
        files: { 'assets/a.css': 'body{color:red}' },
      })
    );
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('没有 module 入口脚本');
  });

  it('index.html 引用不存在的入口 chunk → 必须失败（不得按缺失文件计 0 字节放行）', () => {
    const dir = trackDir(
      makeFakeDist('dangling', {
        html: '<html><head><script type="module" src="/assets/ghost.js"></script><link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: { 'assets/a.css': 'body{color:red}' },
      })
    );
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('引用的资源不存在');
    expect(out).toContain('/assets/ghost.js');
  });

  it('入口资源为空文件（0 字节）→ 必须失败', () => {
    const dir = trackDir(
      makeFakeDist('emptyentry', {
        html: '<html><head><script type="module" src="/assets/empty.js"></script><link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: { 'assets/empty.js': '', 'assets/a.css': 'body{color:red}' },
      })
    );
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('首屏资源为空文件');
  });

  it('分块数低于防呆下限 → 必须失败（构建只产出了少量文件）', () => {
    const dir = trackDir(
      makeFakeDist('fewchunks', {
        html: '<html><head><script type="module" src="/assets/index.js"></script><link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: { 'assets/index.js': 'console.log(1)', 'assets/a.css': 'body{color:red}' },
      })
    );
    // 真实基线要求 ≥40 个 JS 分块，这里只有 1 个 → 必须触发下限
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('jsChunks 低于防呆下限');
  });

  it('缺失入口资源检查可被观测：引用 ghost.js 时必须点名该文件', () => {
    // 上一条用例已断言语义，这里额外锁定「消息里出现具体文件名」——
    // 否则把消息改成空串、或把检查挪到不影响结构错误的位置，测试仍可能绿。
    const dir = trackDir(
      makeFakeDist('ghostname', {
        html:
          '<html><head><script type="module" src="/assets/ghost.js"></script>' +
          '<link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: { 'assets/a.css': 'body{color:red}' },
      })
    );
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toMatch(/index\.html 引用的资源不存在：\/assets\/ghost\.js/);
  });

  it('无 stylesheet 引用 → 必须失败（不能只看 script 入口）', () => {
    const dir = trackDir(
      makeFakeDist('nostyle', {
        html: '<html><head><script type="module" src="/assets/index.js"></script></head></html>',
        files: { 'assets/index.js': 'console.log(1)' },
      })
    );
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('没有 stylesheet 引用');
  });

  it('首屏引用非自托管 js/css（CSP 下不可执行）→ 必须失败', () => {
    const dir = trackDir(
      makeFakeDist('remote', {
        html:
          '<html><head><script type="module" src="/assets/index.js"></script>' +
          '<link rel="stylesheet" href="/assets/a.css">' +
          '<script src="https://cdn.example.com/analytics.js"></script></head></html>',
        files: { 'assets/index.js': 'console.log(1)', 'assets/a.css': 'body{color:red}' },
      })
    );
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('非自托管资源');
    expect(out).toContain('cdn.example.com/analytics.js');
  });

  it('同一入口资源被重复引用两次 → 只计一次（去重失效会虚增首屏预算）', () => {
    const entryJs = require('crypto').randomBytes(4000).toString('base64');
    const dir = trackDir(
      makeFakeDist('dup', {
        html:
          '<html><head><script type="module" src="/assets/index.js"></script>' +
          '<link rel="modulepreload" href="/assets/index.js">' +
          '<link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: { 'assets/index.js': entryJs, 'assets/a.css': 'body{color:red}' },
      })
    );
    const baselineObj = {
      budgets: {
        entryJsGzip: zlib.gzipSync(Buffer.from(entryJs)).length,
        entryCssGzip: 1e6,
        totalRaw: 1e7,
        totalGzip: 1e7,
        maxChunkGzip: 1e7,
      },
      floors: { jsChunks: 1, cssChunks: 1 },
    };
    // 预算恰好等于单次 gzip 值：若实现把同一文件算两遍，就会超预算红灯
    const baseDir = trackDir(
      makeFakeDist('dupbase', { html: null, files: { 'b.json': JSON.stringify(baselineObj) } })
    );
    const { code, out } = runScript([
      `--dist=${dir}`,
      `--baseline=${path.join(baseDir, 'b.json')}`,
    ]);
    expect(out).toContain('entryJsGzip');
    expect(code).toBe(0);
  });

  it('入口引用越出 dist 目录（../）→ 必须失败，不得去读 dist 之外的文件', () => {
    const dir = trackDir(
      makeFakeDist('escape', {
        html: '<html><head><script type="module" src="/../outside.js"></script><link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: { 'assets/a.css': 'body{color:red}' },
      })
    );
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${REAL_BASELINE}`]);
    expect(code).toBe(1);
    expect(out).toContain('越出 dist 目录');
  });
});

describe('体积预算门禁：超预算与基线 fail-closed', () => {
  it('总量超预算 → 非零退出，且输出点名超限指标与超出字节数', () => {
    const dir = trackDir(
      makeFakeDist('over', {
        html: '<html><head><script type="module" src="/assets/index.js"></script><link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: {
          'assets/index.js': 'console.log("entry")'.repeat(20),
          'assets/a.css': 'body{color:red}',
          // 一个 200KB 的大懒加载分块，把 totalRaw 顶过下面人写的低预算
          'assets/big.js': 'x'.repeat(200000),
        },
      })
    );
    const baseline = trackDir(
      makeFakeDist('baseline', {
        html: null,
        files: {
          'b.json': JSON.stringify({
            budgets: {
              entryJsGzip: 10,
              entryCssGzip: 10,
              totalRaw: 1000,
              totalGzip: 10,
              maxChunkGzip: 10,
            },
            floors: { jsChunks: 1, cssChunks: 1 },
          }),
        },
      })
    );
    const baselinePath = path.join(baseline, 'b.json');
    const { code, out } = runScript([`--dist=${dir}`, `--baseline=${baselinePath}`]);
    expect(code).toBe(1);
    expect(out).toContain('totalRaw 超预算');
    expect(out).toContain('totalGzip 超预算');
  });

  it('首屏超预算但总量在预算内 → 仍必须失败（首屏是独立指标，不被总量掩盖）', () => {
    const dir = trackDir(
      makeFakeDist('entryover', {
        html: '<html><head><script type="module" src="/assets/index.js"></script><link rel="stylesheet" href="/assets/a.css"></head></html>',
        files: {
          // 高熵内容：重复字符会被 gzip 压到近零，测不出「首屏变大」；
          // 真实回归是大依赖/组件被拽进首屏（不可压缩的代码+字面量）
          'assets/index.js': require('crypto').randomBytes(8000).toString('base64'),
          'assets/a.css': require('crypto').randomBytes(2000).toString('base64'),
        },
      })
    );
    // 总量预算给足（10MB），只有首屏卡死在 1KB
    const baseline = trackDir(
      makeFakeDist('baseline2', {
        html: null,
        files: {
          'b.json': JSON.stringify({
            budgets: {
              entryJsGzip: 1000,
              entryCssGzip: 1000000,
              totalRaw: 10000000,
              totalGzip: 10000000,
              maxChunkGzip: 10000000,
            },
            floors: { jsChunks: 1, cssChunks: 1 },
          }),
        },
      })
    );
    const { code, out } = runScript([
      `--dist=${dir}`,
      `--baseline=${path.join(baseline, 'b.json')}`,
    ]);
    expect(code).toBe(1);
    expect(out).toContain('entryJsGzip 超预算');
    expect(out).not.toContain('totalRaw 超预算');
  });

  it('基线文件缺失 → fail-closed，非零退出', () => {
    const missing = path.join(os.tmpdir(), 'codebudget-baseline-missing-zzkepler.json');
    fs.rmSync(missing, { force: true });
    const { code, out } = runScript([`--dist=${REAL_DIST}`, `--baseline=${missing}`]);
    expect(code).toBe(1);
    expect(out).toContain('基线文件不存在');
  });

  it('基线 JSON 损坏 → fail-closed，非零退出', () => {
    const dir = trackDir(
      makeFakeDist('badjson', { html: null, files: { 'b.json': '{ not json' } })
    );
    const { code, out } = runScript([
      `--dist=${REAL_DIST}`,
      `--baseline=${path.join(dir, 'b.json')}`,
    ]);
    expect(code).toBe(1);
    // 必须带上 JSON.parse 的原始错误详情——只打「解析失败」四个字会让运维无从下手
    // （此断言可证伪「吞掉 err.message 只留固定文案」的改动）
    expect(out).toMatch(/基线解析失败：\S+/);
  });

  it('基线缺指标（结构不完整）→ fail-closed，不得按缺省 0 放行', () => {
    const dir = trackDir(
      makeFakeDist('partial', {
        html: null,
        files: {
          'b.json': JSON.stringify({ budgets: { entryJsGzip: 1 }, floors: { jsChunks: 1 } }),
        },
      })
    );
    const { code, out } = runScript([
      `--dist=${REAL_DIST}`,
      `--baseline=${path.join(dir, 'b.json')}`,
    ]);
    expect(code).toBe(1);
    expect(out).toContain('基线结构不完整');
    expect(out).toContain('budgets.entryCssGzip');
  });
});

describe('体积预算门禁：计量正确性', () => {
  it('gzipSize 使用 zlib 等级 6（与 nginx 常规档位一致），高压缩内容显著小于原始', () => {
    const compressible = Buffer.alloc(100000, 0x61); // 100KB 的 'a'
    expect(budget.gzipSize(compressible)).toBeLessThan(1000);
    // 不可压缩内容会略膨胀：不是「不压缩」伪造的小体积
    const random = require('crypto').randomBytes(200000);
    expect(budget.gzipSize(random)).toBeGreaterThan(random.length);
  });

  it('gzipSize 精确等于等级 6（与等级 9 的差异必须可观测，否则预算口径会系统性偏离 nginx）', () => {
    // 实测：全 'a' 的 100KB 输入等级 6 与等级 9 输出完全相同（都是 133 B），
    // 用它做不出有效区分——必须选一个两级输出确有差异的输入，否则这条
    // 断言在「等级被改成 9」的变异下依然会通过（本文件已实测到该变异存活）。
    // 下面这段代码风格文本实测：等级 6 = 19442 B，等级 9 = 19266 B（差 176 B）。
    const chunks = [];
    for (let i = 0; i < 4000; i += 1) chunks.push(`function fn${i}(a,b){return a+b*${i};}`);
    const codeLike = Buffer.from(chunks.join('\n'), 'utf8');
    const level6 = zlib.gzipSync(codeLike, { level: 6 }).length;
    const level9 = zlib.gzipSync(codeLike, { level: 9 }).length;
    expect(level6).not.toBe(level9); // 前提：这个输入能区分等级（若不成立则测试本身失效）
    expect(budget.gzipSize(codeLike)).toBe(level6);
    expect(budget.gzipSize(codeLike)).not.toBe(level9);
  });

  it('parseEntryRefs 收全三类首屏引用（module script / modulepreload / stylesheet），忽略普通 link', () => {
    const html = [
      '<link rel="icon" href="/favicon.svg">',
      '<link rel="stylesheet" href="/assets/a.css">',
      '<link rel="modulepreload" href="/assets/vendor.js">',
      '<script type="module" src="/assets/index.js"></script>',
      '<link rel="manifest" href="/manifest.webmanifest">',
    ].join('\n');
    const refs = budget.parseEntryRefs(html);
    const hrefs = refs.map((r) => r.href).sort();
    expect(hrefs).toEqual(['/assets/a.css', '/assets/index.js', '/assets/vendor.js']);
    // 两类 link 必须可区分：stylesheet 计 CSS，modulepreload 计 JS
    expect(refs.find((r) => r.href === '/assets/a.css').rel).toBe('stylesheet');
    expect(refs.find((r) => r.href === '/assets/vendor.js').rel).toBe('modulepreload');
    expect(refs.find((r) => r.href === '/assets/index.js').isModule).toBe(true);
  });

  it('parseEntryRefs 不把普通 script（无 type=module，如 theme-bootstrap.js 需单列判定）误判为 ES 入口', () => {
    const refs = budget.parseEntryRefs('<script src="/theme-bootstrap.js"></script>');
    expect(refs).toHaveLength(1);
    expect(refs[0].isModule).toBe(false);
  });

  it('collectStats 只统计 .js/.css，且总量等于逐文件之和（口径可复算）', () => {
    const dir = trackDir(
      makeFakeDist('stats', {
        html: null,
        files: {
          'assets/a.js': 'a'.repeat(100),
          'assets/b.css': 'b'.repeat(200),
          'assets/logo.svg': 'c'.repeat(50),
        },
      })
    );
    const stats = budget.collectStats(dir);
    expect(stats.jsChunks).toBe(1);
    expect(stats.cssChunks).toBe(1);
    expect(stats.totalRaw).toBe(300);
    expect(stats.files.reduce((sum, f) => sum + f.raw, 0)).toBe(stats.totalRaw);
    expect(stats.files.reduce((sum, f) => sum + f.gzip, 0)).toBe(stats.totalGzip);
    expect(stats.files.some((f) => f.rel.endsWith('.svg'))).toBe(false);
  });

  it('maxChunkGzip 取最大分块而非首屏或总量（echarts 这类懒加载大块要被点名）', () => {
    const dir = trackDir(
      makeFakeDist('maxchunk', {
        html: null,
        files: { 'assets/small.js': 'a', 'assets/huge.js': 'b'.repeat(50000) },
      })
    );
    const stats = budget.collectStats(dir);
    expect(stats.maxChunkName).toBe('assets/huge.js');
    expect(stats.maxChunkGzip).toBe(stats.files[0].gzip);
  });
});

describe('体积预算门禁：收紧模式（--update-baseline，棘轮只许下调）', () => {
  /** 造一个结构完整的假 dist：入口 script + stylesheet + 一个懒加载大块 */
  // 分块数刻意取 11 个 JS + 6 个 CSS：只有数量足够大时，
  // 「下限 = 分块数 × 0.6」与「× 0.1」才会算出不同结果（6/3 vs 1/0），
  // 否则两种系数都被 max(1, …) 归一成同一下限，测试便区分不出系数被改坏。
  const buildCompleteDist = (name) => {
    const files = {};
    for (let i = 0; i < 10; i += 1) {
      files[`assets/chunk${i}.js`] = require('crypto').randomBytes(3000).toString('base64');
    }
    for (let i = 0; i < 5; i += 1) {
      files[`assets/chunk${i}.css`] = require('crypto').randomBytes(800).toString('base64');
    }
    files['assets/index.js'] = require('crypto').randomBytes(3000).toString('base64');
    files['assets/a.css'] = require('crypto').randomBytes(800).toString('base64');
    return trackDir(
      makeFakeDist(name, {
        html:
          '<html><head><script type="module" src="/assets/index.js"></script>' +
          '<link rel="stylesheet" href="/assets/a.css"></head></html>',
        files,
      })
    );
  };

  it('首次收紧：按实测 ×1.05 取整写出基线，且自检通过', () => {
    const dist = buildCompleteDist('upd-first');
    const target = trackDir(fs.mkdtempSync(path.join(os.tmpdir(), 'codebudget-updout-')));
    const baselinePath = path.join(target, 'b.json');
    expect(fs.existsSync(baselinePath)).toBe(false);

    const { code, out } = runScript([
      `--dist=${dist}`,
      `--baseline=${baselinePath}`,
      '--update-baseline',
    ]);
    expect(code).toBe(0);
    expect(out).toContain('基线已写入');

    const written = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    expect(budget.validateBaseline(written)).toEqual([]);
    expect(written.measuredAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    // 预算是实测的 1.05 倍并向上取整到 1000 — 对每个预算指标逐一复算
    for (const key of budget.BUDGET_KEYS) {
      const expected = Math.ceil((written.measured[key] * 1.05) / 1000) * 1000;
      expect(written.budgets[key]).toBe(expected);
    }
    // 防呆下限 = 实测分块数 ×0.6 向下取整，且至少为 1
    // （下限为 0 会让写出的基线被自己的结构校验判为损坏——实测过的真实缺陷）
    // 这里同时锁定「系数是 0.6」：11 个 JS 分块 → 6、6 个 CSS → 3 为确切值，
    // 系数被改成 0.1 之类会立刻失败（此前用 2 个分块时两种系数都归一到 1，测不出）。
    expect(written.measured.jsChunks).toBe(11);
    expect(written.measured.cssChunks).toBe(6);
    expect(written.floors.jsChunks).toBe(6);
    expect(written.floors.cssChunks).toBe(3);
    for (const key of budget.FLOOR_KEYS) {
      expect(written.floors[key]).toBe(Math.max(1, Math.floor(written.measured[key] * 0.6)));
      expect(written.floors[key]).toBeGreaterThan(0);
    }
    // 收紧后的基线必须能让同一产物通过检查模式（闭环）
    const recheck = runScript([`--dist=${dist}`, `--baseline=${baselinePath}`]);
    expect(recheck.code).toBe(0);
  });

  it('产物不完整时拒绝收紧基线（不得把「没产出」固化成预算）', () => {
    const dist = trackDir(
      makeFakeDist('upd-broken', { html: null, files: { 'assets/a.js': 'x' } })
    );
    const target = trackDir(fs.mkdtempSync(path.join(os.tmpdir(), 'codebudget-updout2-')));
    const baselinePath = path.join(target, 'b.json');
    const { code, out } = runScript([
      `--dist=${dist}`,
      `--baseline=${baselinePath}`,
      '--update-baseline',
    ]);
    expect(code).toBe(1);
    expect(out).toContain('构建产物不存在');
    expect(out).toContain('拒绝收紧基线');
    expect(fs.existsSync(baselinePath)).toBe(false);
  });

  it('上调已有预算（放宽门禁）必须显式 --allow-growth，否则拒绝写入', () => {
    const dist = buildCompleteDist('upd-growth');
    const target = trackDir(fs.mkdtempSync(path.join(os.tmpdir(), 'codebudget-updout3-')));
    const baselinePath = path.join(target, 'b.json');
    // 先写出一个基线，然后人为压低它（模拟「本次实测高于旧预算」）
    runScript([`--dist=${dist}`, `--baseline=${baselinePath}`, '--update-baseline']);
    const lowered = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    lowered.budgets.totalRaw = 1000;
    fs.writeFileSync(baselinePath, JSON.stringify(lowered, null, 2), 'utf8');
    const before = fs.readFileSync(baselinePath, 'utf8');

    const blocked = runScript([
      `--dist=${dist}`,
      `--baseline=${baselinePath}`,
      '--update-baseline',
    ]);
    expect(blocked.code).toBe(1);
    expect(blocked.out).toContain('将被上调');
    expect(blocked.out).toContain('totalRaw 1000 ->');
    // 关键：拒绝时不得改动基线文件（否则「拒绝」形同虚设）
    expect(fs.readFileSync(baselinePath, 'utf8')).toBe(before);

    const allowed = runScript([
      `--dist=${dist}`,
      `--baseline=${baselinePath}`,
      '--update-baseline',
      '--allow-growth',
    ]);
    expect(allowed.code).toBe(0);
    const after = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    expect(after.budgets.totalRaw).toBeGreaterThan(1000);
  });

  it('坏掉的旧基线不再被静默重写：需 --allow-growth 确认，但仍可修复（不卡死运维）', () => {
    const dist = buildCompleteDist('upd-corrupt');
    const target = trackDir(fs.mkdtempSync(path.join(os.tmpdir(), 'codebudget-updout4-')));
    const baselinePath = path.join(target, 'b.json');
    fs.writeFileSync(baselinePath, '{ 这不是合法 JSON', 'utf8');
    const before = fs.readFileSync(baselinePath, 'utf8');

    // 拒绝半边：原写法在这里直接 exit 0 并重建基线——而"是否放宽了预算"是与
    // previous.budgets 比较得出的，previous 读不出 ⇒ raised 恒空 ⇒
    // 「上调预算需显式确认」那道闸（上面一条用例）就变成可以先弄坏基线再绕开。
    const blocked = runScript([
      `--dist=${dist}`,
      `--baseline=${baselinePath}`,
      '--update-baseline',
    ]);
    expect(blocked.code).toBe(1);
    expect(blocked.out).toContain('无法作为「上一版预算」使用');
    // 断言必须落在**可执行指令**上，而不是解释性文案里顺带出现的同一个 flag 名：
    // 变异实测——删掉「请追加 --allow-growth 重跑」整行后，只写
    // `toContain('--allow-growth')` 的断言仍绿（上一行的成因说明里就有这个词）。
    expect(blocked.out).toContain('请追加 --allow-growth 重跑');
    expect(blocked.out).toContain('git checkout');
    // 拒绝时必须一字不动（否则"拒绝"只是句空话）
    expect(fs.readFileSync(baselinePath, 'utf8')).toBe(before);

    // 保留半边：确认可修，一条显式 flag 即可（原用例"不因解析失败卡死"的诉求）
    const fixed = runScript([
      `--dist=${dist}`,
      `--baseline=${baselinePath}`,
      '--update-baseline',
      '--allow-growth',
    ]);
    expect(fixed.code).toBe(0);
    // 出路必须在日志里说清楚（拒绝文案承诺的 flag 真要生效，否则是死胡同）
    expect(fixed.out).toContain('不与旧预算比较');
    const written = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    expect(budget.validateBaseline(written)).toEqual([]);
    // 闭环：修好的基线能让同一产物通过检查模式
    expect(runScript([`--dist=${dist}`, `--baseline=${baselinePath}`]).code).toBe(0);
  });

  it('JSON 合法但结构缺项的旧基线同样按「不可判定」处理（不能只防语法坏）', () => {
    // 只 parse 成功不等于能当基准：少一个 budgets 键就少一次比较，
    // 那个键的预算可以被无声放大——所以判据用 validateBaseline 而不是 JSON.parse。
    const dist = buildCompleteDist('upd-partial');
    const target = trackDir(fs.mkdtempSync(path.join(os.tmpdir(), 'codebudget-updout5-')));
    const baselinePath = path.join(target, 'b.json');
    runScript([`--dist=${dist}`, `--baseline=${baselinePath}`, '--update-baseline']);
    const partial = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    delete partial.budgets.entryJsGzip; // 首屏 JS 预算消失 = 最贵的那一格失去门禁
    fs.writeFileSync(baselinePath, JSON.stringify(partial, null, 2), 'utf8');

    const blocked = runScript([
      `--dist=${dist}`,
      `--baseline=${baselinePath}`,
      '--update-baseline',
    ]);
    expect(blocked.code).toBe(1);
    expect(blocked.out).toContain('budgets.entryJsGzip');
    expect(blocked.out).toContain('无法作为「上一版预算」使用');
    // 而同一份基线在**检查模式**下仍必须 fail-closed（这条闸不能只顾收紧侧）
    const check = runScript([`--dist=${dist}`, `--baseline=${baselinePath}`]);
    expect(check.code).toBe(1);
    expect(check.out).toContain('基线结构不完整');
  });

  it('基线文件不存在时首次收紧仍然可用（不带 --allow-growth 也应放行）', () => {
    // 负向对照：上面两条的拒绝不得外溢成「全新基线也要确认」，
    // 否则 CI 首次接入与本地初始化都要多传一个语义上没意义的 flag。
    const dist = buildCompleteDist('upd-missing-ok');
    const target = trackDir(fs.mkdtempSync(path.join(os.tmpdir(), 'codebudget-updout6-')));
    const baselinePath = path.join(target, 'b.json');
    expect(fs.existsSync(baselinePath)).toBe(false);
    const r = runScript([`--dist=${dist}`, `--baseline=${baselinePath}`, '--update-baseline']);
    expect(r.code).toBe(0);
    expect(r.out).toContain('基线已写入');
  });
});

describe('体积预算门禁：真实产物与基线', () => {
  it('真实 dist 已构建且真实基线存在（构建缺失必须显式失败，不得静默跳过）', () => {
    const indexPath = path.join(REAL_DIST, 'index.html');
    expect(fs.existsSync(indexPath)).toBe(true);
    expect(fs.existsSync(REAL_BASELINE)).toBe(true);
    const baseline = JSON.parse(fs.readFileSync(REAL_BASELINE, 'utf8'));
    expect(budget.validateBaseline(baseline)).toEqual([]);
  });

  it('真实产物通过真实基线（收紧后的门禁对当前代码为绿）', () => {
    const { code, out } = runScript([`--dist=${REAL_DIST}`, `--baseline=${REAL_BASELINE}`]);
    expect(out).toContain('通过');
    expect(code).toBe(0);
  });

  it('真实基线携带实测快照与测量日期（留痕，便于回溯漂移）', () => {
    const baseline = JSON.parse(fs.readFileSync(REAL_BASELINE, 'utf8'));
    expect(baseline.measuredAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    for (const key of budget.BUDGET_KEYS) {
      expect(typeof baseline.measured[key]).toBe('number');
      expect(baseline.measured[key]).toBeGreaterThan(0);
      // 预算是实测的 1.05~1.15 倍区间：太松等于没门禁，太紧会频繁误红
      expect(baseline.budgets[key]).toBeGreaterThanOrEqual(baseline.measured[key]);
      expect(baseline.budgets[key]).toBeLessThanOrEqual(
        Math.ceil((baseline.measured[key] * 1.15) / 1000) * 1000
      );
    }
  });
});

/**
 * 指标清单本身（F-167）：删掉 METRICS 的一行就静默少一道门禁
 *
 * 判定层 scripts/bundleBudgetPolicy.js 的 validateBaseline / compare / tighten
 * 和 CLI 的 printTable 全部按同一张表遍历，所以从表里删一行 `{key:'maxChunkGzip'}`
 * 会让「结构校验、超限比对、收紧写盘、表格打印」同步跳过这一格，而本文件此前
 * **没有一条用例要求这一格必须被比对**：出现 maxChunkGzip 的地方只有手写假基线
 * fixture（src/tests/deploy/bundleBudget.test.js:187、src/tests/deploy/bundleBudget.test.js:239、
 * src/tests/deploy/bundleBudget.test.js:276）和 collectStats 的计量断言
 * （src/tests/deploy/bundleBudget.test.js:409），二者都不过问比对集。
 * 上面两条真实基线用例（validateBaseline 返回 []、按 BUDGET_KEYS 复算）也是
 * 从同一张表派生的期望集合 —— 同义反复，删表行照样全绿。
 * 而「最大懒加载分块是否失控」恰是这套门禁唯一不可替代的信号：entryJsGzip 有首屏
 * 指标单独兜着，totalGzip 只反映累积量，一个 300KB 的 echarts 分块被拽大只能靠它。
 *
 * 三条判据，期望集合一律不抄自 METRICS（否则挡不住删行）：
 *   ① 基线 JSON 的键集 ⇄ 判定表键集双向相等：事实来源是 web-admin/bundle-budget.json
 *      （check-bundle-budget.js 头注释 :31 自己声明「数值以该文件为唯一事实来源」）；
 *   ② 逐项单独超限 / 单独抬下限，走 CLI 端到端，且必须「恰好 1 项」——
 *      只动这一格才红，证明它真的在比对集里，同时证明没牵连别格；
 *   ③ 计量层每测出一个数字，要么进清单，要么在豁免名单里写明为什么不进预算。
 */
describe('体积预算门禁：指标清单本身（删一行就静默失去一道门禁）', () => {
  const realBaseline = JSON.parse(fs.readFileSync(REAL_BASELINE, 'utf8'));

  const writeBaseline = (name, obj) =>
    trackDir(makeFakeDist(name, { html: null, files: { 'b.json': JSON.stringify(obj) } }));

  it('① 基线 JSON 键集与判定表双向一致', () => {
    expect(Object.keys(realBaseline.budgets).sort()).toEqual([...budget.BUDGET_KEYS].sort());
    expect(Object.keys(realBaseline.floors).sort()).toEqual([...budget.FLOOR_KEYS].sort());
    expect(Object.keys(realBaseline.measured).sort()).toEqual(
      [...budget.BUDGET_KEYS, ...budget.FLOOR_KEYS].sort()
    );
    // 表里每行必须归属两个段之一（section 写错 ⇒ baseline[section] 取不到，比对直接抛）
    expect(budget.METRICS.length).toBe(budget.BUDGET_KEYS.length + budget.FLOOR_KEYS.length);
  });

  it.each(Object.keys(realBaseline.budgets))('② 预算项 %s 单独被超过 → 恰好这一项红', (key) => {
    const cut = JSON.parse(JSON.stringify(realBaseline));
    cut.budgets[key] = 1; // 正数：过得了结构校验，且必定低于当前实测
    const dir = writeBaseline(`each-budget-${key}`, cut);
    const { code, out } = runScript([
      `--dist=${REAL_DIST}`,
      `--baseline=${path.join(dir, 'b.json')}`,
    ]);
    expect(code).toBe(1);
    expect(out).toContain(`${key} 超预算`);
    // 「恰好 1 项」才是重点：0 项＝这一格根本不在比对集里（删表行的表现），
    // 多于 1 项＝动了一格却牵连别格，两种都会让这条用例失去定位能力
    expect(out).toContain('未通过（1 项）');
  });

  it.each(Object.keys(realBaseline.floors))('② 下限项 %s 单独被抬高 → 恰好这一项红', (key) => {
    const cut = JSON.parse(JSON.stringify(realBaseline));
    cut.floors[key] = 1e9; // 只可能低于下限，不会与预算项混淆
    const dir = writeBaseline(`each-floor-${key}`, cut);
    const { code, out } = runScript([
      `--dist=${REAL_DIST}`,
      `--baseline=${path.join(dir, 'b.json')}`,
    ]);
    expect(code).toBe(1);
    expect(out).toContain(`${key} 低于防呆下限`);
    expect(out).toContain('未通过（1 项）');
  });

  it.each([...budget.BUDGET_KEYS, ...budget.FLOOR_KEYS])(
    '①b 基线缺 %s 一格 → 结构校验点名它（不得按 undefined 放行）',
    (key) => {
      // 与上一条互补：这里是「这一格没了」而不是「超了」。缺失若被放过，
      // compare 里 stats[key] > undefined 恒为 false ⇒ 该指标永久绿灯。
      const section = budget.BUDGET_KEYS.includes(key) ? 'budgets' : 'floors';
      const cut = JSON.parse(JSON.stringify(realBaseline));
      delete cut[section][key];
      const problems = budget.validateBaseline(cut);
      expect(problems).toEqual([`${section}.${key} 缺失或非正数`]);
    }
  );

  it('③ 计量层多出来的数字必须显式豁免，不得"测了但没人管"', () => {
    // 豁免名单是判据的一部分：新增一个量却不纳入预算的指标要红，写明理由才放行
    const UNBUDGETED = {
      entryRefCount: '首屏引用条数：结构性观测值，条数多不等于产物退化（体积才是）',
    };
    const { stats } = budget.inspect(REAL_DIST);
    const numeric = Object.keys(stats).filter((k) => typeof stats[k] === 'number');
    const governed = new Set([...budget.BUDGET_KEYS, ...budget.FLOOR_KEYS]);
    expect(numeric.filter((k) => !governed.has(k)).sort()).toEqual(Object.keys(UNBUDGETED));
    for (const key of Object.keys(UNBUDGETED)) {
      expect(numeric).toContain(key); // 豁免的对象真实存在
      expect(governed.has(key)).toBe(false); // 且真的没进清单（否则是重复声明）
    }
    // 反方向的空转防护：maxChunkGzip 必须由 compare 处理，而不只是被 collectStats 算出来
    expect(stats.maxChunkGzip).toBeGreaterThan(0);
    expect(governed.has('maxChunkGzip')).toBe(true);
  });
});
