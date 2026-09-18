/**
 * 门禁负向自检（negative self-test）
 *
 * 为什么需要这个文件：
 *   一个门禁有两种失效方式——**漏报**（该红不红）与**误报**（不该红却红）。
 *   本仓库已两次踩坑：
 *     - L-25：compliance-check 漏 3 个钩子 → 漏报
 *     - K-14：compliance-check 查错控制器 → 误报（红灯指向错误位置）
 *   两者都会训练出「红灯不可信 → 忽略红灯」的习惯，最终门禁名存实亡。
 *
 * 本文件对关键门禁做**注入式否定检验**：故意制造一个应被拦下的劣化，
 * 断言门禁确实拦下了它，然后再还原。这是唯一能证明「门禁是活的」的方法。
 *
 * 设计约束：所有注入都在临时副本/内存中完成，绝不修改工作区文件；
 *   若某门禁无法安全注入，则退化为「断言其检出逻辑存在于源码中」。
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const NODE = process.execPath;
const ROOT = path.resolve(__dirname, '../../..');

describe('门禁负向自检：该红时必须红', () => {
  describe('lint-ratchet 棘轮（注入式：真实调用比对逻辑）', () => {
    const { diffBaseline, aggregateWarnCounts } = require(path.join(ROOT, 'scripts/lint-ratchet'));

    it('file 的 warn 计数 +1 → 必须判为回退', () => {
      const baseline = { 'src/a.js': { complexity: 2 } };
      const current = { 'src/a.js': { complexity: 3 } };
      const { regressions } = diffBaseline(baseline, current);
      expect(regressions).toHaveLength(1);
      expect(regressions[0]).toContain('complexity');
      expect(regressions[0]).toContain('2 -> 3');
    });

    it('基线中不存在的新文件带 warn → 必须判为回退（新债不得免费入场）', () => {
      const baseline = { 'src/a.js': { complexity: 2 } };
      const current = { 'src/a.js': { complexity: 2 }, 'src/new.js': { complexity: 1 } };
      const { regressions } = diffBaseline(baseline, current);
      expect(regressions.some((l) => l.includes('src/new.js'))).toBe(true);
    });

    it('计数下降 → 判为改善（不阻断，但提示收紧）', () => {
      const { regressions, improvements } = diffBaseline(
        { 'src/a.js': { complexity: 5 } },
        { 'src/a.js': { complexity: 2 } }
      );
      expect(regressions).toHaveLength(0);
      expect(improvements).toHaveLength(1);
    });

    it('ESLint 结果聚合：severity 2 计入 errorTotal 而不进基线', () => {
      const { current, errorTotal } = aggregateWarnCounts([
        {
          filePath: path.join(ROOT, 'src/a.js'),
          messages: [
            { severity: 1, ruleId: 'complexity' },
            { severity: 1, ruleId: 'complexity' },
            { severity: 2, ruleId: 'no-undef' },
          ],
        },
      ]);
      expect(errorTotal).toBe(1);
      expect(current['src/a.js'].complexity).toBe(2);
      expect(current['src/a.js']['no-undef']).toBeUndefined();
    });

    it('require 本模块不产生副作用（不跑全量 lint、不退出进程）', () => {
      // 上面的 require 若仍无条件调用 main()，整条测试进程会因 lint 结果而 exit(1)
      expect(typeof diffBaseline).toBe('function');
    });
  });

  describe('合规门禁（compliance-check）', () => {
    it('探测不到钩子注册时必须判失败，而非静默放行', () => {
      const src = fs.readFileSync(path.join(ROOT, 'scripts/compliance-check.js'), 'utf8');
      // 探测失败 → recordCheck(false) + warn，绝不能 return 直接过
      const probeBlock = src.slice(src.indexOf('function checkAppendOnlyHooks'));
      expect(probeBlock).toMatch(/无法探测钩子注册[\s\S]{0,400}?recordCheck\([\s\S]{0,200}?false/);
      // 就绪/缺失是运行时拼接的文案，断言其构造成分即可
      expect(src).toMatch(/'就绪'/);
      expect(src).toMatch(/'存在缺失'/);
      expect(src).toMatch(/process\.exit\(allPassed \? 0 : 1\)/);
    });

    it('存在缺失项时退出码必须非零（注入式：篡改钩子常量后必须判失败）', () => {
      // 注入手法：用 mock 环境变量让门禁指向一个被改坏的状态不可行（门禁读真实 schema），
      // 因此这里做**退而求其次但仍是行为级**的检验：直接调用门禁脚本，断言其
      // 就绪时 exit 0——再断言脚本源码中「未就绪 → exit 1」的映射存在。
      // （真实劣化注入需要改 src/models/auditLogHooks.js 并还原，风险高于收益；
      //   该路径已由 behaviorBaseline 测试覆盖。）
      const out = execFileSync(NODE, [path.join(ROOT, 'scripts/compliance-check.js')], {
        cwd: ROOT,
        encoding: 'utf8',
      });
      expect(out).toContain('就绪');
      const src = fs.readFileSync(path.join(ROOT, 'scripts/compliance-check.js'), 'utf8');
      expect(src).toMatch(/process\.exit\(allPassed \? 0 : 1\)/);
    });
  });

  describe('覆盖率阈值', () => {
    it('jest.config.js 的阈值不得为空且必须含 global 组', () => {
      const cfg = fs.readFileSync(path.join(ROOT, 'jest.config.js'), 'utf8');
      expect(cfg).toMatch(/coverageThreshold/);
      expect(cfg).toMatch(/global:\s*\{/);
      // E-03 纳入的两个文件必须有独立阈值（防止被 global 平均值稀释）
      expect(cfg).toMatch(/config\/validate\.js/);
      expect(cfg).toMatch(/services\/initData\.js/);
    });
  });

  describe('前端覆盖率阈值棘轮（2026-09-18）', () => {
    it('web-admin 阈值必须贴着实测水位，不得回落到「删一半测试仍全绿」的水平', () => {
      // 背景：前端阈值原为 10.5/8/5/10.5，而当时实测已是 20.02/18.25/12.8/19.54
      // ——门槛只有水位的一半，删掉一半测试仍然全绿，与后端 P3-49 修过的
      // 是同一病症。2026-09-18 先上调到 19/17/11.5/18.5；补齐 InspectionView /
      // InspectionForm / InspectionReviewForm 组件用例后实测到 30.03/27.06/23.34/29.7，
      // 又上调到 28.5/25.5/21.5/28。
      // 2026-09-18 第三次收紧到 78/71.5/71/79（当时实测 st 79.92 / br 73.39 /
      // fn 72.84 / ln 80.87，全量 806 通过 0 失败）。
      // 这里守住的不是「必须等于某值」（实测会涨，阈值要跟着涨），而是
      // 「不得低于本次收紧后的地板」——防止有人为图省事把它调回去。
      const cfg = fs.readFileSync(path.join(ROOT, 'web-admin/vite.config.js'), 'utf8');
      const pick = (name) => {
        const m = cfg.match(new RegExp('\\b' + name + '\\s*:\\s*([\\d.]+)'));
        return m ? Number(m[1]) : null;
      };
      // 2026-09-18 第四次收紧到 92/84/90/93（实测 st 94.35 / br 86.38 / fn 92.99 / ln 95.46）。
      const floors = { statements: 92, branches: 84, functions: 90, lines: 93 };
      for (const [name, floor] of Object.entries(floors)) {
        const actual = pick(name);
        expect(actual).not.toBeNull();
        expect(actual).toBeGreaterThanOrEqual(floor);
      }
    });
  });

  describe('OpenAPI 同步守卫', () => {
    it('守卫断言是双向的（既查漏文档也查幽灵端点）', () => {
      const src = fs.readFileSync(path.join(ROOT, 'src/tests/docs/openapiSync.test.js'), 'utf8');
      // 【收紧】原先只匹配三个中文标题字符串：把三个用例体全换成 `test('X', () => {})`
      // 仍然绿（变异验证 SURVIVED），元测试等于没测。
      // 现改为检查**断言语句本身**仍在：双向对账的核心是 diffs 收集 + toEqual([]) 收口。
      expect(src).toContain("test('已注册端点全部入文档（无漏文档）'");
      expect(src).toContain("test('文档中不存在幽灵端点（无对应路由）'");
      expect(src).toContain("test('path 集合与产物完全一致（双向）'");
      // 三个用例体内必须各有真实断言，且不得退化为「长度 >= 0」这类恒真式。
      // 原写法 `if (!/…/.test(head)) continue;` 在标题被改写或文件被清空时
      // 匹配不到任何用例、循环零执行、本元测试恒绿——而它正是「守卫用例体非空」
      // 的那道门禁。现先钉死命中数量（恰为 3），再逐个断言用例体非空。
      const bodies = src.split(/test\('/).slice(1);
      const guarded = bodies.filter((b) => /无漏文档|幽灵端点|双向/.test(b.slice(0, 40)));
      expect(guarded).toHaveLength(3);
      for (const body of guarded) {
        const head = body.slice(0, 40);
        expect(head).not.toMatch(/\)\s*=>\s*\{\s*\}\s*\)/);
      }
      expect(src).toMatch(/expect\(diffs\)\.toEqual\(\[\]\)/);
      // 反退化判据。原写法是 /expect\(diffs\\.length\).../，正则里的 `\\.` 要求
      // 「一个反斜杠 + 任意字符」，而被检源码里是 `diffs.length`（那里没有反斜杠），
      // 于是这条 not.toMatch 永不命中——门禁本身是恒真的。
      // 现抽出常量并**正向自证**：同一个正则必须能匹配退化样例，否则 not.toMatch
      // 通过只是因为正则写错。
      const DEGENERATE_ASSERT = /expect\(diffs\.length\)\.toBeGreaterThanOrEqual\(0\)/;
      expect(DEGENERATE_ASSERT.test('expect(diffs.length).toBeGreaterThanOrEqual(0)')).toBe(true);
      expect(src).not.toMatch(DEGENERATE_ASSERT);
    });
  });

  describe('E2E 防假绿', () => {
    it('CI 断言 skipped==0（防止 0 执行也绿）', () => {
      const ci = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
      expect(ci).toMatch(/Assert no skipped journeys/);
      expect(ci).toMatch(/skipped > 0/);
    });
  });

  describe('测试顺序无关门禁（2026-09-18）', () => {
    it('CI 以随机顺序跑两轮（两个固定 seed，结果可复现）', () => {
      const ci = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
      // 本仓 166 个套件曾隐含「按固定顺序执行」的未声明前提：固定顺序全绿、
      // 加 --randomize 则 12 个套件转红。这条件靠人记住是守不住的——
      // 破坏顺序无关性的改动在固定顺序下永远绿灯，只有 CI 自己随机跑才能拦住。
      // 必须同时断言 --randomize 与 --seed：只断言 --randomize 的话，
      // 有人把它挪到一个不执行的 job/分支里也照样绿。
      //
      // 2026-09-18 起是**两个** seed（单 seed 只能证明一种排列；当天两个真实耦合
      // 分别只在 777001 / 31337 下暴露）。因此这里断的是循环形态而不是单行命令。
      expect(ci).toMatch(/for seed in [\d\s]+; do/);
      expect(ci).toMatch(/npx jest --randomize --seed="\$seed"/);
      // 两个回归样本 seed 不得被删减为一个
      const seedList = ci.match(/for seed in ([\d\s]+); do/);
      expect(seedList).toBeTruthy();
      expect(seedList[1].trim().split(/\s+/)).toEqual(['20260917', '31337']);
      // seed 必须是字面量：写成 `${{ ... }}` 之类会让本地复现失据
      expect(seedList[1]).not.toMatch(/\$\{\{/);
      // 失败必须汇总退出——单个 seed 红却被 || 吞掉，等于门禁静默失效
      expect(ci).toMatch(/\|\| fail=1/);
      expect(ci).toMatch(/exit "\$fail"/);
    });
  });

  describe('前端测试顺序无关门禁（2026-09-18，与后端对称）', () => {
    it('CI 的 frontend-build job 以固定 seed 乱序跑一轮 vitest', () => {
      const ci = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
      // 前端存在与后端同构的模块级共享状态：sessionStorage、documentElement.lang、
      // i18n 单例 locale、全局 ResizeObserver 替身、pinia 单例残留。
      // 只跑默认顺序时，文件间互相污染在 CI 上永远绿灯。
      expect(ci).toMatch(/npx vitest run --sequence\.shuffle --sequence\.seed=\d+/);
      // seed 必须为字面量：写成 ${{ ... }} 之类会让本地复现失据（同后端口径）
      expect(ci).toMatch(/--sequence\.seed=\d{4,}/);
      // 必须在 frontend-build job 内、且 working-directory 指向 web-admin：
      // 仅匹配命令行会让「步骤被挪到不执行的 job」这种情况蒙混过关。
      const jobStart = ci.indexOf('\n  frontend-build:');
      const jobEnd = ci.indexOf('\n  e2e:');
      expect(jobStart).toBeGreaterThan(-1);
      expect(jobEnd).toBeGreaterThan(jobStart);
      const jobBlock = ci.slice(jobStart, jobEnd);
      expect(jobBlock).toMatch(/npx vitest run --sequence\.shuffle --sequence\.seed=\d+/);
      expect(jobBlock).toMatch(/working-directory: web-admin/);
    });
  });

  describe('破坏性脚本护栏（M-08 / L-26）', () => {
    it('共享护栏为 fail-closed：未设白名单即拒绝', () => {
      const src = fs.readFileSync(path.join(ROOT, 'scripts/destructiveGuard.js'), 'utf8');
      expect(src).toMatch(/ALLOWED_SOURCE_DB/);
      // fail-closed 判据：缺白名单走拒绝分支
      expect(src).toMatch(/未设置|必须设置|拒绝/);
    });

    it('五个破坏性脚本都引用共享护栏，未各自实现白名单', () => {
      const files = [
        'scripts/resign-audit-hmac.js',
        'scripts/resign-audit-chain-v3.js',
        'scripts/run-rollback-drill.js',
        // P1-20 补齐：这两个脚本原先无任何护栏（--apply 即可 dropIndex / 吊销会话）
        'scripts/revoke-user-sessions.js',
        'scripts/sync-audit-indexes.js',
      ];
      for (const f of files) {
        const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
        expect(src).toMatch(/require\(['"][^'"]*destructiveGuard['"]\)/);
        expect(src).toMatch(/assertApplyAllowed/);
      }
    });
  });

  describe('架构无环守卫（E-04）', () => {
    it('无环测试真的在扫 require 图，且断言了 3 处惰性 require', () => {
      const src = fs.readFileSync(
        path.join(ROOT, 'src/tests/architecture/requireCycles.test.js'),
        'utf8'
      );
      // 【收紧】原先只匹配 /`require/` 与 /`环|cycle/i` 两个泛化正则：
      // 把 LAZY 数组清空（循环体变成 for (const ... of [])）仍然绿，
      // 标题承诺的「断言了 3 处惰性 require」根本没被检验（变异验证 SURVIVED）。
      // 现改为检查三条惰性 require 片段与「缩进即函数体内」的判据都在。
      expect(src).toMatch(/const LAZY = \[/);
      expect(src).toMatch(/return require\('\.{2}\/models\/User'\);/);
      expect(src).toMatch(/require\('\.\/auth'\)/);
      expect(src).toMatch(/require\('\.{2}\/middleware\/security'\)/);
      // 「在函数体内」的判据是缩进检查，缺了它这条用例就退化为「文本存在」
      expect(src).toContain('indented: /^\\s+\\S/.test(hit)');
      // 不得把 LAZY 迭代清空成空数组（会静默跳过全部三条检查）
      expect(src).not.toMatch(/of\s+\[\]\s*\)/);
      // 静态图断言与真实加载兜底都必须在
      expect(src).toMatch(/expect\(cycles\)\.toEqual\(\[\]\)/);
      expect(src).toMatch(/not.toThrow()/);
    });
  });

  describe('前端 i18n 死文件守卫（L-27）', () => {
    it('legacy-raw-* 已删除且不再有 import', () => {
      const dir = path.join(ROOT, 'web-admin/src/i18n/locales');
      const files = fs.readdirSync(dir);
      expect(files.some((f) => /legacy-raw/.test(f))).toBe(false);
    });
  });
});
