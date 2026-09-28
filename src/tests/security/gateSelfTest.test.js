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
const { execFileSync, spawnSync } = require('child_process');

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

    it('棘轮目标集必须覆盖 `npm run lint` 的每个目标（漏一个目录=一条旁路）', () => {
      const { LINT_TARGETS } = require(path.join(ROOT, 'scripts/lint-ratchet'));
      const lintScript = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'))
        .scripts.lint;
      // eslint <目标...> <配置文件> 里的非 flag 参数才是"目标集"
      const lintTargets = lintScript
        .split(/\s+/)
        .slice(1)
        .filter((a) => !a.startsWith('-'));

      // 前提自证：解析真的拿到东西。空数组会让下面的 every 恒真 ⇒ 假绿。
      expect(lintTargets.length).toBeGreaterThanOrEqual(3);
      const missing = lintTargets.filter((t) => !LINT_TARGETS.includes(t));
      // 实测过的一次真实缺漏：e2e 在 lint 里、却不在棘轮里 —— e2e 的 warn
      // 会被 npm run lint 打印、计入"45 warning"的观感，却永不进棘轮账本。
      expect(missing).toEqual([]);
    });

    it('--update-baseline 不得把回退或新增债务写成新基线（否则"只降不升"可被洗白）', () => {
      const { findBaselineIncreases } = require(path.join(ROOT, 'scripts/lint-ratchet'));
      const before = { 'src/a.js': { complexity: 2 }, 'src/b.js': { 'max-lines': 5 } };

      // ① 既有条目上升 ⇒ 拒
      expect(
        findBaselineIncreases(before, {
          'src/a.js': { complexity: 3 },
          'src/b.js': { 'max-lines': 5 },
        })
      ).toEqual([expect.stringMatching(/src\/a\.js \[complexity\] 2 -> 3（上升）/)]);
      // ② 基线里没有的新文件/新规则 ⇒ 同样拒（新债不得免费入场）
      expect(findBaselineIncreases(before, { ...before, 'src/new.js': { complexity: 1 } })).toEqual(
        [expect.stringMatching(/src\/new\.js \[complexity\] 基线无此项 -> 1（新增债务）/)]
      );
      // ③ 下降与清零是唯一允许的方向 ⇒ 放行
      expect(findBaselineIncreases(before, { 'src/a.js': { complexity: 1 } })).toEqual([]);
      // 自证：全等时也放行（否则"没变化"会误报，--update-baseline 就废了）
      expect(findBaselineIncreases(before, before)).toEqual([]);
    });

    it('端到端：真有回退时 --update-baseline 必须 exit 1 且不重写基线（接线级证明）', () => {
      // 纯函数单测证明不了 main() 里"先判拒绝、后落盘"的顺序——把守卫接在最后一步
      // 一样能过函数级断言（上一批刚因此把一条 SURVIVED 记成被杀）。这里真跑一次子进程。
      // 夹具放在仓库内的临时目录：脚本里 require('eslint') 需要向上找到仓库 node_modules；
      // 目录名以 . 开头且不在 lint 目标集里，不会污染任何真实门禁。
      const tmp = fs.mkdtempSync(path.join(ROOT, '.zzqoder-ratchet-'));
      const baselinePath = path.join(tmp, 'eslint.ratchet.json');
      try {
        fs.mkdirSync(path.join(tmp, 'scripts'), { recursive: true });
        fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
        fs.mkdirSync(path.join(tmp, 'e2e'), { recursive: true });
        fs.copyFileSync(
          path.join(ROOT, 'scripts/lint-ratchet.js'),
          path.join(tmp, 'scripts/lint-ratchet.js')
        );
        // 自带一份最小 flat config（只用 core 规则，不依赖仓库配置）：
        // max-lines 300 ⇒ 下面 320 行真代码必然产生 1 条 warn
        fs.writeFileSync(
          path.join(tmp, 'eslint.config.js'),
          'module.exports = [{ rules: { "max-lines": ["warn", { max: 300, skipBlankLines: true, skipComments: true }] } }];\n',
          'utf8'
        );
        fs.writeFileSync(
          path.join(tmp, 'src/big.js'),
          `${Array.from({ length: 320 }, (_, i) => `var v${i} = ${i};`).join('\n')}\n`,
          'utf8'
        );
        fs.writeFileSync(path.join(tmp, 'e2e/dummy.js'), 'var ok = 1;\n', 'utf8');
        // 基线声明该文件 max-lines 允许 0 ⇒ 当前实测 1 ⇒ 这是回退，收紧必须被拒
        const beforeContent = JSON.stringify({ 'src/big.js': { 'max-lines': 0 } }, null, 2);
        fs.writeFileSync(baselinePath, `${beforeContent}\n`, 'utf8');

        const r = spawnSync(
          NODE,
          [path.join(tmp, 'scripts/lint-ratchet.js'), '--update-baseline'],
          { cwd: tmp, encoding: 'utf8' }
        );
        // 前提自证：子进程确实跑到了棘轮逻辑（而不是 require 失败等无关退出）
        expect(r.stderr).toContain('src/big.js');
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('拒绝更新基线');
        // 关键：基线一个字节都没被改写（洗白通路确实被堵住）
        expect(fs.readFileSync(baselinePath, 'utf8')).toBe(`${beforeContent}\n`);
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('对照：纯改善时 --update-baseline 必须放行并落盘（守卫不得退化成"一律拒绝"）', () => {
      // 去掉这条对照，"任何情况都 exit 1"的写法也能让上面那条端到端保持绿色，
      // 而棘轮就此失去唯一合法的收紧通路。
      const tmp = fs.mkdtempSync(path.join(ROOT, '.zzqoder-ratchet-'));
      const baselinePath = path.join(tmp, 'eslint.ratchet.json');
      try {
        fs.mkdirSync(path.join(tmp, 'scripts'), { recursive: true });
        fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
        fs.mkdirSync(path.join(tmp, 'e2e'), { recursive: true });
        fs.copyFileSync(
          path.join(ROOT, 'scripts/lint-ratchet.js'),
          path.join(tmp, 'scripts/lint-ratchet.js')
        );
        fs.writeFileSync(
          path.join(tmp, 'eslint.config.js'),
          'module.exports = [{ rules: { "max-lines": ["warn", { max: 300, skipBlankLines: true, skipComments: true }] } }];\n',
          'utf8'
        );
        // 一个 warn 都没有：320 行的债已被消化成 5 行
        fs.writeFileSync(path.join(tmp, 'src/big.js'), 'var a = 1;\n', 'utf8');
        fs.writeFileSync(path.join(tmp, 'e2e/dummy.js'), 'var ok = 1;\n', 'utf8');
        fs.writeFileSync(
          baselinePath,
          JSON.stringify({ 'src/big.js': { 'max-lines': 1 } }, null, 2) + '\n',
          'utf8'
        );

        const r = spawnSync(
          NODE,
          [path.join(tmp, 'scripts/lint-ratchet.js'), '--update-baseline'],
          { cwd: tmp, encoding: 'utf8' }
        );
        expect(r.stderr).toBe('');
        expect(r.status).toBe(0);
        // 基线确实被收紧：清零的条目被移除
        expect(JSON.parse(fs.readFileSync(baselinePath, 'utf8'))).toEqual({});
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    // 夹具工厂：造一份"能被棘轮脚本当成仓库根跑起来"的最小副本。
    // 脚本必须落在 <fix>/scripts/lint-ratchet.js —— 它用 path.resolve(__dirname,'..')
    // 推导 repoRoot，放别处 ESLint 会指到错误目录，测出来的形态就是假的
    // （上一轮探针正是栽在这点上，把 ESLint 抛错误读成"账本被抹平"）。
    const makeFix = ({ baseline, lines = 320 }) => {
      const tmp = fs.mkdtempSync(path.join(ROOT, '.zzqoder-ratchet-'));
      const write = (rel, content) => {
        const p = path.join(tmp, rel);
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.writeFileSync(p, content, 'utf8');
      };
      write(
        'scripts/lint-ratchet.js',
        fs.readFileSync(path.join(ROOT, 'scripts/lint-ratchet.js'), 'utf8')
      );
      write(
        'eslint.config.js',
        'module.exports = [{ rules: { "max-lines": ["warn", { max: 300, skipBlankLines: true, skipComments: true }] } }];\n'
      );
      write(
        'src/big.js',
        `${Array.from({ length: lines }, (_, i) => `var v${i} = ${i};`).join('\n')}\n`
      );
      write('e2e/dummy.js', 'var ok = 1;\n');
      const baselinePath = path.join(tmp, 'eslint.ratchet.json');
      if (baseline !== null) write('eslint.ratchet.json', baseline);
      return { tmp, script: path.join(tmp, 'scripts/lint-ratchet.js'), baselinePath };
    };

    it('端到端：基线存在但解析失败时 --update-baseline 必须拒绝，且不重写文件', () => {
      // 原实现把"文件不存在"和"文件存在但读不出"合并成同一个 `!before`，两条都走
      // writeBaseline(current)：一份被合并冲突残留弄坏的基线，就此被**无条件按实测重建**，
      // 而 findBaselineIncreases（只降不升）因"没有可比对象"整段跳过、还 exit 0。
      // 于是账本坏掉期间涨的债直接成为新地板——这比"回退后手动收紧"更隐蔽，
      // 因为它连拒绝的余地都没给。机器不许猜账本，人来修（git 里有上一版）。
      const corrupt = '{\n<<<<<<< HEAD\n  "src/big.js": { "max-lines": 0 }\n=======\n}\n';
      const f = makeFix({ baseline: corrupt });
      try {
        const r = spawnSync(NODE, [f.script, '--update-baseline'], {
          cwd: f.tmp,
          encoding: 'utf8',
        });
        // 红必须来自这道守卫，而不是"ESLint 抛错/夹具跑不通"这类无关原因
        expect(r.stderr).not.toContain('执行失败');
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('拒绝按当前实测重建');
        // 关键：坏账本一个字节都没被改写（没有被"顺手"换成实测值）
        expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(corrupt);
      } finally {
        fs.rmSync(f.tmp, { recursive: true, force: true });
      }
    });

    it('对照：基线文件根本不存在时 --update-baseline 仍须建账本（拒绝不得扩大到首次接入）', () => {
      // 与上一条同一夹具，只差基线文件本身。去掉这条对照，"只要 !before 就 exit 1"
      // 的写法也能让上一条保持绿色，而首次接入就此卡死。
      const f = makeFix({ baseline: null });
      try {
        const r = spawnSync(NODE, [f.script, '--update-baseline'], {
          cwd: f.tmp,
          encoding: 'utf8',
        });
        expect(r.stderr).toBe('');
        expect(r.status).toBe(0);
        // 同时自证"夹具确实产出了 1 条 max-lines warn"：否则上一条用例的红
        // 可能来自"什么都没扫到"，而不是"拒绝重建"。
        const built = JSON.parse(fs.readFileSync(f.baselinePath, 'utf8'));
        expect(built['src/big.js']).toEqual({ 'max-lines': 1 });
      } finally {
        fs.rmSync(f.tmp, { recursive: true, force: true });
      }
    });

    it('参数手误不得静默降级成检查模式（--update-basline 曾 exit 0 而一个字节都没收紧）', () => {
      // 夹具刻意做成"干净文件 + 空基线"：这正是旧行为**报绿**的形态——
      // 手误被当成"没传参数"，于是跑完检查模式、exit 0、操作者以为基线已收紧。
      // 若夹具带债，旧行为本来就会因回退 exit 1，那条红证明不了这条守卫。
      const f = makeFix({ baseline: '{}\n', lines: 5 });
      try {
        const r = spawnSync(NODE, [f.script, '--update-basline'], {
          cwd: f.tmp,
          encoding: 'utf8',
        });
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('未知参数：--update-basline');
        expect(r.stderr).toContain('--update-baseline');
        expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe('{}\n');

        // 对照：不带参数（合法的检查模式）必须仍然走到 lint 并 exit 0，
        // 否则"任何参数都拒绝"的写法也能让上面那条保持绿色。
        const ok = spawnSync(NODE, [f.script], { cwd: f.tmp, encoding: 'utf8' });
        expect(ok.stderr).toBe('');
        expect(ok.status).toBe(0);
      } finally {
        fs.rmSync(f.tmp, { recursive: true, force: true });
      }
    });
  });

  describe('编码门禁（check-utf8）：扫描面缩水必须判失败', () => {
    // 扫描集向脚本自己要，不在这里抄第二份清单。上一版硬写了 8 个根目录名，于是
    // "给门禁加一条根"必须同时记得改这里；而忘了的方向更糟：夹具按旧清单生成，
    // 新根从来没被自证扫到过，对照用例照样绿（本仓"五份到期口径"同族的第二份真源）。
    const { roots: UTF8_ROOTS, rootFiles: UTF8_ROOT_FILES } = require(
      path.join(ROOT, 'scripts/check-utf8')
    );
    const dirNames = UTF8_ROOTS.map((r) => path.basename(r));
    const fileNames = UTF8_ROOT_FILES.map((f) => path.basename(f));
    // 夹具刻意放在系统临时目录而不是仓库根：脚本用 path.join(__dirname,'..')
    // 推导它的扫描根，跟 lint-ratchet 那种"必须在仓库内推导 repoRoot"的夹具不同，
    // 放外面就不需要往 .gitignore 里再加一条兜底规则。
    const makeUtf8Fix = ({ omitDirs = [], emptyDirs = [], omitFiles = [] } = {}) => {
      const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'fsms-utf8-gate-'));
      for (const r of dirNames) {
        if (omitDirs.includes(r)) continue;
        fs.mkdirSync(path.join(tmp, r), { recursive: true });
        // scripts/ 由下面拷进去的脚本自身贡献一个文件
        if (r === 'scripts' || emptyDirs.includes(r)) continue;
        fs.writeFileSync(path.join(tmp, r, 'a.txt'), 'hi\n', 'utf8');
      }
      for (const f of fileNames) {
        if (omitFiles.includes(f)) continue;
        // package.json 必须是合法 JSON：脚本被拷进 tmp/scripts/，Node 解析入口模块时
        // 会向上找到 tmp/package.json 并把它当作 package config —— 里面放 `hi` 会让
        // node 直接抛 ERR_INVALID_PACKAGE_CONFIG，门禁根本没跑，四条用例全部红成夹具故障。
        fs.writeFileSync(path.join(tmp, f), f === 'package.json' ? '{}\n' : 'hi\n', 'utf8');
      }
      fs.copyFileSync(
        path.join(ROOT, 'scripts/check-utf8.js'),
        path.join(tmp, 'scripts/check-utf8.js')
      );
      return { tmp, script: path.join(tmp, 'scripts/check-utf8.js') };
    };
    const runUtf8 = (script) => spawnSync(NODE, [script], { encoding: 'utf8' });
    const drop = (f) => fs.rmSync(f.tmp, { recursive: true, force: true });

    it('扫描集由脚本自己交出非空数组（夹具唯一的真源）', () => {
      // 前提自证：下面的夹具完全由这两份清单生成。若导出被改成空数组/别的类型，
      // 夹具会静默生成一座空城，而"每条用例都红"看起来像门禁坏了而不是夹具空转。
      // 与 lint-ratchet 那条 `require 本模块不产生副作用` 同一族。
      expect(Array.isArray(UTF8_ROOTS) && UTF8_ROOTS.length > 0).toBe(true);
      expect(Array.isArray(UTF8_ROOT_FILES) && UTF8_ROOT_FILES.length > 0).toBe(true);
    });

    it('根目录缺位时不得只留一行 [跳过] 就报绿', () => {
      // 原实现 `if (!fs.existsSync(r)) { console.warn('[跳过] …'); continue; }`：
      // 退出码仍是 0，于是根目录被改名/移走后门禁只检查剩下的那几个，
      // 而输出依然写着 ALL_FILES_ARE_UTF8——"看起来像验过了"。
      // 三条一起缺：两条旧根 + 本批新加的 docs。新根若没接进同一条判据，
      // 这条就只测到旧的两条 ⇒ 对 `docs` 的断言正是它的牙。
      const f = makeUtf8Fix({ omitDirs: ['web-admin', 'e2e', 'docs'] });
      try {
        const r = runUtf8(f.script);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('UTF8_CHECK_ROOTS_MISSING');
        expect(r.stderr).toContain(path.join(f.tmp, 'web-admin'));
        expect(r.stderr).toContain(path.join(f.tmp, 'e2e'));
        expect(r.stderr).toContain(path.join(f.tmp, 'docs'));
        expect(r.stdout).not.toContain('ALL_FILES_ARE_UTF8');
      } finally {
        drop(f);
      }
    });

    it('仓库根文件缺位同样判失败（新增的 25 条与目录共用一条判据，不是第二套）', () => {
      // 只加清单、不给判据的形状：目录走 missingRoots、文件走另一条"打一行警告"的老路，
      // 于是根文件被改名时门禁仍然 exit 0。这条按文件名点名，红在缺哪一条上。
      const f = makeUtf8Fix({ omitFiles: ['CHANGELOG.md'] });
      try {
        const r = runUtf8(f.script);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('UTF8_CHECK_ROOTS_MISSING');
        expect(r.stderr).toContain(path.join(f.tmp, 'CHANGELOG.md'));
        expect(r.stdout).not.toContain('ALL_FILES_ARE_UTF8');
      } finally {
        drop(f);
      }
    });

    it('根目录存在但没贡献任何文件时同样判失败（existsSync 判不出被搬空）', () => {
      const f = makeUtf8Fix({ emptyDirs: ['migrations'] });
      try {
        const r = runUtf8(f.script);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('UTF8_CHECK_ROOTS_EMPTY');
        expect(r.stderr).toContain(path.join(f.tmp, 'migrations'));
      } finally {
        drop(f);
      }
    });

    it('对照：扫描集全部就位且非空时必须放行（新判据不得一律拦死）', () => {
      // 与上面三条共用同一夹具工厂，只差 omit/empty 参数。缺了这条对照，
      // "无条件 exit 1"的写法也能让前三条保持绿色，而真实的 CI 步骤就此卡死。
      const f = makeUtf8Fix();
      try {
        const r = runUtf8(f.script);
        expect(r.stderr).toBe('');
        expect(r.status).toBe(0);
        // 自证夹具真的扫到了东西（否则"通过"可能来自空扫描集）
        expect(r.stdout).toMatch(/ALL_FILES_ARE_UTF8（扫描 [1-9]\d* 个文件/);
      } finally {
        drop(f);
      }
    });

    it('覆盖面一致性：format:check 管的每一条都必须在编码门禁的扫描集里', () => {
      // 这条才是本批缺陷的正面判据。此前 `npm run format:check` 参数表里的
      // docs 与 6 条根文件（CHANGELOG.md / README.md / docker-compose.yml / package.json /
      // migrate-mongo-config.js / playwright.config.js）被格式门禁管着、不被编码门禁管着：
      // 同一批文件一个门禁改编码格式、另一个门禁看不见它 ⇒ 错编码字符进了 ADR/README
      // 只能靠人眼。判据写成"覆盖面包含关系"而不是"根清单必须长这样"，
      // 因此它不会因加一条根而腐烂，只会因**少**一条根而红。
      const tokens = require(path.join(ROOT, 'package.json'))
        .scripts['format:check'].split(/\s+/)
        .slice(1) // 第一个 token 是命令名 `prettier`，不是路径
        .filter((t) => t && !t.startsWith('-'));
      const dirs = new Set(dirNames);
      const files = new Set(fileNames);
      const uncovered = tokens.filter((t) => {
        const [head, ...rest] = t.split('/');
        // 带分隔的 token（web-admin/src、web-admin/package.json）落在某个扫描根目录下即算覆盖
        if (rest.length > 0) return !dirs.has(head);
        return !(dirs.has(head) || files.has(head));
      });
      expect(uncovered).toEqual([]);
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
    const ci = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');

    /**
     * 抽出该步骤 `run: |` 里 `node -e "…"` 的**真实脚本体**（纯文本，不起子进程）。
     * 抽不到就抛——宁可直接红，也不要退化成「匹配了两个字符串就放行」的空转门禁。
     */
    const extractGateScript = (text) => {
      const at = text.indexOf('- name: Assert no skipped journeys');
      expect(at).toBeGreaterThanOrEqual(0);
      const lines = text.slice(at).split(/\r?\n/);
      const runIdx = lines.findIndex((l) => /^\s*run:\s*\|\s*$/.test(l));
      expect(runIdx).toBeGreaterThanOrEqual(0);
      const runIndent = lines[runIdx].search(/\S/);
      const body = [];
      for (let i = runIdx + 1; i < lines.length; i += 1) {
        const line = lines[i];
        if (line.trim() === '') {
          body.push('');
          continue;
        }
        if (line.search(/\S/) <= runIndent) break;
        body.push(line);
      }
      const indent = Math.min(...body.filter((l) => l.trim() !== '').map((l) => l.search(/\S/)));
      const shell = body
        .map((l) => l.slice(indent))
        .join('\n')
        .trim();
      const m = /^node\s+-e\s+"([\s\S]*)"$/.exec(shell);
      expect(m).not.toBeNull();
      return m[1];
    };

    /**
     * 在**进程内**跑抽出来的门禁脚本：把 `playwright-run.log` 的读取与
     * `process.exit` 换成桩，就能喂各种日志样例看它到底判红还是判绿。
     *
     * 为什么不起子进程：本机 `spawnSync` 返回 `status:null`（EBUSY），
     * 子进程根本没起来——那样的测试只会给出环境红，而不是门禁的真实行为。
     */
    const runGate = (logText) => {
      const script = extractGateScript(ci);
      const realRead = fs.readFileSync;
      const realExit = process.exit;
      const realErr = console.error;
      const realLog = console.log;
      const errors = [];
      let exitCode = null;
      fs.readFileSync = (p, ...rest) =>
        String(p).includes('playwright-run.log') ? logText : realRead(p, ...rest);
      process.exit = (code) => {
        exitCode = code;
        throw new Error('__GATE_EXIT__');
      };
      console.error = (...a) => errors.push(a.join(' '));
      console.log = () => {};
      try {
        // eslint-disable-next-line no-new-func
        new Function('require', script)((id) => (id === 'fs' ? fs : require(id)));
      } catch (e) {
        if (e.message !== '__GATE_EXIT__') throw e;
      } finally {
        fs.readFileSync = realRead;
        process.exit = realExit;
        console.error = realErr;
        console.log = realLog;
      }
      return { code: exitCode === null ? 0 : exitCode, errors };
    };

    it('CI 断言 skipped==0 且 passed 有下界（0 执行 / 静默裁剪都必须判红）', () => {
      // 原实现只匹配 `Assert no skipped journeys` 与 `skipped > 0` 两个字符串：
      // 把步骤体整个换成 `echo ok` 也照样绿（元测试等于没测）。
      // 现在改为「常量 + 行为」两路钉死。
      expect(ci).toMatch(/Assert no skipped journeys/);
      expect(ci).toMatch(/skipped > 0/);
      // 只断 skipped==0 时，「日志里根本没有汇总行」会被读成 skipped=0——
      // 跑崩 / 配置错 / 被 --project 过滤成空集时照样通过。必须同时断「汇总行存在」。
      expect(ci).toMatch(/hasSummary/);
      const m = ci.match(/MIN_PASSED\s*=\s*(\d+)/);
      expect(m).not.toBeNull();
      // 下界 = 16 条旅程 × 2 个 project。删旅程时这个数字必须在 diff 里可见。
      expect(Number(m[1])).toBe(32);
      expect(ci).toMatch(/passed < MIN_PASSED/);
    });

    it('门禁行为可复现：干净运行绿，空集 / 静默裁剪 / 跳过 / 失败全部红', () => {
      // 这是本套件的真判据：门禁**真的**会在这些输入上判红，而不是"文本里出现了关键字"。
      // 样例里的 `N skipped` / `N failed` 行只在计数非 0 时才由 Playwright 打印，
      // 所以「干净运行没有这两行」是正常态——下面第一个样例正是钉这一点的。
      const cases = [
        [
          '32 passed（干净运行，日志里没有 skipped 行）',
          'Running 32 tests using 1 worker\n  32 passed (12.3s)\n',
          0,
        ],
        ['16 passed（旅程被静默裁掉一半）', '  16 passed (6.1s)\n', 1],
        ['只有 Running 行（跑崩 / reporter 形态已变）', 'Running 32 tests using 1 worker\n', 1],
        ['32 passed + 2 skipped', '  32 passed (12.3s)\n  2 skipped (12.3s)\n', 1],
        ['32 passed + 1 failed', '  32 passed (12.3s)\n  1 failed (12.3s)\n', 1],
        ['空日志（什么都没跑）', '', 1],
        ['33 passed（新增旅程，下界不封顶）', '  33 passed (13.0s)\n', 0],
      ];
      for (const [name, log, expected] of cases) {
        const { code } = runGate(log);
        expect({ name, code }).toEqual({ name, code: expected });
      }
    });

    it('判据可失败：被修掉的那一版（只看 skipped）必须放行 16 passed', () => {
      // 反向对照。改动前的判据等价于「skipped 计数为 0 即通过」，
      // 它在"只跑了 16 条旅程"和"日志里一个汇总行都没有"两种输入上都会放行。
      const legacyVerdict = (log) => {
        const m = log.match(/(\d+)\s+skipped/);
        return (m ? Number(m[1]) : 0) > 0 ? 1 : 0;
      };
      expect(legacyVerdict('  16 passed (6.1s)\n')).toBe(0);
      expect(legacyVerdict('')).toBe(0);
      // 而新判据在同样两种输入上判红
      expect(runGate('  16 passed (6.1s)\n').code).toBe(1);
      expect(runGate('').code).toBe(1);
    });
  });

  describe('测试顺序无关门禁（2026-09-18）', () => {
    it('CI 以随机顺序跑多轮（固定 seed 列表，结果可复现）', () => {
      const ci = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
      // 本仓 166 个套件曾隐含「按固定顺序执行」的未声明前提：固定顺序全绿、
      // 加 --randomize 则 12 个套件转红。这条件靠人记住是守不住的——
      // 破坏顺序无关性的改动在固定顺序下永远绿灯，只有 CI 自己随机跑才能拦住。
      // 必须同时断言 --randomize 与 --seed：只断言 --randomize 的话，
      // 有人把它挪到一个不执行的 job/分支里也照样绿。
      //
      // 2026-09-18 起是**多个** seed（单 seed 只能证明一种排列；当天两个真实耦合
      // 分别只在 777001 / 31337 下暴露）。因此这里断的是循环形态而不是单行命令。
      expect(ci).toMatch(/for seed in [\d\s]+; do/);
      expect(ci).toMatch(/npx jest --randomize --seed="\$seed"/);
      // 回归样本 seed 不得被删减
      const seedList = ci.match(/for seed in ([\d\s]+); do/);
      expect(seedList).toBeTruthy();
      const seeds = seedList[1].trim().split(/\s+/);
      expect(seeds).toEqual(['20260917', '31337', '777001']);
      // 关键一条：说明文字里点名的"实测抓到过耦合的 seed"必须真的在执行列表里。
      // 曾经 777001 只存在于注释（"seed 也保留在这里当回归样本"），列表却是
      // 20260917 31337 —— 唯一能复现 assignRoles 顺序耦合的排列一次都没跑过，
      // 门禁在它声称覆盖那一条时完全失效。文字与执行必须由断言绑定，不能靠人读。
      const cited = [...ci.matchAll(/^\s*#\s+seed (\d{4,})\s*→/gm)].map((m) => m[1]);
      expect(cited.length).toBeGreaterThanOrEqual(2);
      for (const seed of cited) expect(seeds).toContain(seed);
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
