'use strict';

/**
 * 注释密度脚本的**命令行契约**（第 26 轮）
 *
 * 为什么需要这个文件：
 *   scripts/commentDensity.js 原先对用户输入有两处静默失效，二者都能让「只降不升」名存实亡：
 *     ① 未知参数被当成「没传」——`--chek` / `--update-basline` 走默认分支，打印总量并 exit 0。
 *        接进 CI 就是一个永远绿、什么都没查的步骤；操作者以为基线收紧了，而一个字节没变。
 *     ② 基线文件损坏时，`--update-baseline` 把「文件读不出」当成「首次接入」，整段回退判据
 *        被跳过并**无条件按实测重建**——账本坏掉期间涨上去的注释就此成为新地板。
 *   两类都属于「有闸的名字、没有那个闸」：闸门存在、名字正确、判据却不在路径上。
 *
 * 反向对照（去掉任一条都会让另一条失去意义）：
 *   · 合法调用（无参数 / --print / 首次建立 / 合法收紧）必须仍然放行——
 *     否则「一切参数都拒绝」「只要读不出就 exit 1」的写法也能让正向用例保持绿色；
 *   · 「首次建立」与「合法收紧」的输出必须可区分——否则删掉基线文件再跑一次
 *     就是一次无声的棘轮回退，而日志看起来与正常收紧逐字相同。
 *
 * 全部注入都在临时副本里完成，绝不修改工作区文件（同 gateSelfTest 的约定）。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const NODE = process.execPath;
const ROOT = path.resolve(__dirname, '..', '..', '..');
const SOURCE_SCRIPT = path.join(ROOT, 'scripts', 'commentDensity.js');

/** 造一个自包含夹具：临时根下 scripts/commentDensity.js + src/foo.js（+ 可选基线） */
function makeFixture({ baseline = null, foo = null } = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'density-cli-'));
  const scriptsDir = path.join(tmp, 'scripts');
  fs.mkdirSync(scriptsDir, { recursive: true });
  // 复制**真实**脚本：判据必须打在将被接线的那个文件上，不许测试里另抄一份
  fs.copyFileSync(SOURCE_SCRIPT, path.join(scriptsDir, 'commentDensity.js'));
  fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
  fs.writeFileSync(
    path.join(tmp, 'src', 'foo.js'),
    foo === null ? '// c1\nconst a = 1;\n// c2\n' : foo,
    'utf8'
  );
  const baselinePath = path.join(scriptsDir, 'commentDensity.baseline.json');
  if (baseline !== null) fs.writeFileSync(baselinePath, baseline, 'utf8');
  return { tmp, script: path.join(scriptsDir, 'commentDensity.js'), baselinePath };
}

/** 真实收紧（相对 foo.js 的两行注释无回退）的基线 */
const CLEAN_BASELINE = JSON.stringify({
  files: { 'src/foo.js': { comment: 2, code: 1 } },
  total: { comment: 2, code: 1, ratio: 0.6667 },
});

function withFixture(opts, fn) {
  const f = makeFixture(opts);
  try {
    return fn(f);
  } finally {
    fs.rmSync(f.tmp, { recursive: true, force: true });
  }
}

function run(f, args) {
  return spawnSync(NODE, [f.script].concat(args), { cwd: f.tmp, encoding: 'utf8' });
}

describe('注释密度脚本的命令行契约', () => {
  describe('未知参数不得被当成「没传」', () => {
    it('--chek / --update-basline 必须 exit 2，且基线一个字节都不许变', () => {
      // 夹具刻意用「干净基线 + 合法工作区」：这正是旧行为报绿的形态。
      // 若夹具本身带债，旧行为本来就会因回退 exit 1，那条红证明不了这条守卫。
      for (const typo of ['--chek', '--update-basline', '--print-']) {
        withFixture({ baseline: CLEAN_BASELINE }, (f) => {
          const r = run(f, [typo]);
          expect({ typo, status: r.status }).toEqual({ typo, status: 2 });
          expect(r.stderr).toContain('未知参数');
          expect(r.stderr).toContain(typo);
          expect(r.stderr).toContain('--update-baseline'); // 提示可用参数
          expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(CLEAN_BASELINE);
        });
      }
    });

    it('对照：合法调用不得被一起拒绝（否则「一律 exit 2」也能让上条保持绿色）', () => {
      withFixture({ baseline: CLEAN_BASELINE }, (f) => {
        const dflt = run(f, []);
        expect(dflt.status).toBe(0);
        expect(dflt.stdout).toMatch(/comment=2/);
        const printed = run(f, ['--print']);
        expect(printed.status).toBe(0);
        expect(printed.stdout).toContain('src/foo.js');
        const checked = run(f, ['--check']);
        expect(checked.status).toBe(0);
      });
    });

    it('模式互斥：--check 与 --update-baseline 同时给出必须拒绝', () => {
      withFixture({ baseline: CLEAN_BASELINE }, (f) => {
        const r = run(f, ['--check', '--update-baseline']);
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('互斥');
        expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(CLEAN_BASELINE);
      });
    });

    it('--print 与模式同时给出必须拒绝（否则输出被提前 return 静默吞掉）', () => {
      withFixture({ baseline: CLEAN_BASELINE }, (f) => {
        const r = run(f, ['--check', '--print']);
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('--print');
        // 自证「静默吞掉」是真的：默认模式下 --print 确实有输出
        expect(run(f, ['--print']).stdout).toContain('src/foo.js');
      });
    });
  });

  describe('基线损坏不得被当成「首次接入」', () => {
    it('损坏基线 + --update-baseline 必须拒绝，且不重写文件', () => {
      const corrupt = '{"files":{"src/foo.js":{"comment":1,"code":1}';
      withFixture({ baseline: corrupt }, (f) => {
        const r = run(f, ['--update-baseline']);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('拒绝收紧基线');
        expect(r.stderr).toContain('基线不可解析');
        // 关键：坏账本一个字都没被「顺手」换成实测值
        expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(corrupt);
      });
    });

    it('结构不符（合法 JSON 但缺 files）同样必须拒绝', () => {
      withFixture({ baseline: '{"total":{"comment":0}}' }, (f) => {
        const r = run(f, ['--update-baseline']);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('缺少 files');
      });
    });

    it('损坏基线 + --check 必须 fail-closed（不得当成「没有回退」放行）', () => {
      withFixture({ baseline: '{ 这不是合法 JSON' }, (f) => {
        const r = run(f, ['--check']);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('fail-closed');
      });
    });

    it('对照：基线文件不存在时 --update-baseline 仍须建账本（拒绝不得扩大到首次接入）', () => {
      withFixture({ baseline: null }, (f) => {
        const r = run(f, ['--update-baseline']);
        expect(r.status).toBe(0);
        // 断言可命名的事实（记账内容），而不是猜内部对象的完整形状：
        // 这条用例要证明的是「账本被真的按实测建出来了」，不是 ratio 保留几位。
        const built = JSON.parse(fs.readFileSync(f.baselinePath, 'utf8'));
        expect(built.files['src/foo.js'].comment).toBe(2);
        expect(built.files['src/foo.js'].code).toBe(1);
        expect(built.total.comment).toBe(2);
        expect(Object.keys(built.files)).toEqual(['src/foo.js']);
      });
    });
  });

  // 条目级畸形与半空账本：本轮对抗审计（work/audit-round26-density-cli.md §6.1/§6.2）逼出来的，
  // 修前实测：同一夹具、同一「真回退 0→2」事实，只因条目写成 "abc" / 缺字段 / 5 / [1,2]，
  // --check 从「回归 0 → 2」翻成「检查通过」，随后 --update-baseline 把账本按实测重写。
  // 根因：逐文件判据用 `now > base` 比较，畸形值取出 undefined/字符串 ⇒ NaN ⇒ 恒 false。
  describe('账本畸形不得被判成「无回退」', () => {
    // 账本必须内部自洽（Σfiles ≡ total），否则 readBaseline 会判「账本不自洽」而先于条目判据拒绝。
    // 自洽是脚本自己 snapshot() 的产物，真实账本恒满足（本仓 361 条：Σ=22509=total）。
    const withEntry = (entry) =>
      JSON.stringify({
        files: { 'src/foo.js': entry },
        total: { comment: 0, code: 1, ratio: 0 },
      });

    it('条目 comment 不是数值 / 条目不是对象：一律 corrupt 且不写盘', () => {
      const malformed = [
        ['comment 是字符串', { comment: 'abc', code: 1 }],
        ['缺 comment 字段', { code: 1 }],
        ['条目是数字', 5],
        ['条目是数组', [1, 2]],
      ];
      for (const [label, entry] of malformed) {
        const raw = withEntry(entry);
        withFixture({ baseline: raw }, (f) => {
          for (const mode of ['--check', '--update-baseline']) {
            const r = run(f, [mode]);
            expect({ label, mode, status: r.status }).toEqual({ label, mode, status: 1 });
            expect(r.stderr).toContain('基线不可解析');
          }
          // 坏账本一个字都不许被「顺手」换成实测值
          expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(raw);
        });
      }
    });

    it('对照：同夹具同回退事实，条目写成合法数值时必须报「回归」', () => {
      // 上面四条的反面对照：证明红的不是夹具本身，而是那个值的类型。
      withFixture({ baseline: withEntry({ comment: 0, code: 1 }) }, (f) => {
        const r = run(f, ['--check']);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('回归 src/foo.js: 0 → 2');
      });
    });

    it('空账本 files:{} 不得当成「全部文件都是新的」而放行', () => {
      // 用**自洽**的空账本（total 也清零），才能精确命中「账本与工作区无交集」这条判据；
      // 若写成 files:{} 配高 total，会先被「账本不自洽」那条拦下（另一条判据，另行覆盖）。
      const raw = JSON.stringify({ files: {}, total: { comment: 0, code: 0, ratio: 0 } });
      withFixture({ baseline: raw }, (f) => {
        for (const mode of ['--check', '--update-baseline']) {
          const r = run(f, [mode]);
          expect({ mode, status: r.status }).toEqual({ mode, status: 1 });
          expect(r.stderr).toContain('无任何交集');
        }
        expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(raw);
      });
    });

    // 第二轮对抗审计（work/audit-round26-density-cli-r2.md）逼出来的三个洞，见下方三条。
    it('phantom 键（原型键名）不得绕过「账本与工作区无交集」守卫', () => {
      // 只数 Object.keys().length 会被 toString/constructor 这类键名骗过：长度 1 看着「非空」，
      // 但工作区里没有一个文件命中它 ⇒ 真回退照样被当成「新文件」免检。
      for (const phantom of ['toString', 'constructor', 'valueOf', 'hasOwnProperty']) {
        const raw = JSON.stringify({
          files: { [phantom]: { comment: 0, code: 1 } },
          total: { comment: 0, code: 1, ratio: 0 },
        });
        withFixture({ baseline: raw }, (f) => {
          const r = run(f, ['--check']);
          expect({ phantom, status: r.status }).toEqual({ phantom, status: 1 });
          expect(r.stderr).toContain('无任何交集');
          expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(raw);
        });
      }
    });

    it('账本登记了已删除的文件（原形键名）必须报「清单残留」，不得被真值判定吞掉', () => {
      // 修前实测：键名是 src/gone.js 时报红，换成 toString 就静默通过并重写账本——
      // 根因是 `!current[rel]` 对原型链上的名字恒为假。
      const mk = (goneKey) =>
        JSON.stringify({
          files: { 'src/foo.js': { comment: 2, code: 1 }, [goneKey]: { comment: 9, code: 9 } },
          total: { comment: 11, code: 10, ratio: 0.52 },
        });
      // 对照面：普通文件名如实报「清单残留」
      withFixture({ baseline: mk('src/gone.js') }, (f) => {
        const r = run(f, ['--check']);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('清单残留 src/gone.js');
      });
      for (const goneKey of ['toString', 'constructor']) {
        const raw = mk(goneKey);
        withFixture({ baseline: raw }, (f) => {
          const r = run(f, ['--check']);
          expect({ goneKey, status: r.status }).toEqual({ goneKey, status: 1 });
          expect(r.stderr).toContain('清单残留 ' + goneKey);
        });
      }
    });

    it('total 与 Σfiles 不自洽（只手改一个数字）必须判 corrupt', () => {
      // 真实账本恒自洽（本仓 Σ=22509=total.comment），所以不自洽只可能来自手改或写坏。
      const raw = JSON.stringify({
        files: { 'src/foo.js': { comment: 0, code: 1 } },
        total: { comment: 22509, code: 1, ratio: 0.99 },
      });
      withFixture({ baseline: raw }, (f) => {
        for (const mode of ['--check', '--update-baseline']) {
          const r = run(f, [mode]);
          expect({ mode, status: r.status }).toEqual({ mode, status: 1 });
          expect(r.stderr).toContain('账本不自洽');
        }
        expect(fs.readFileSync(f.baselinePath, 'utf8')).toBe(raw);
      });
    });

    it('total.comment 写成 1e999（JSON 解析成 Infinity）必须判 corrupt', () => {
      // 必须写原始文本：JSON.stringify(Infinity) 会变成 null，那样测的是别的东西。
      // 这条用来钉住 Number.isFinite——换成 typeof === 'number' 时 Infinity 会穿透（对抗审计 M8 变异存活）。
      const raw =
        '{"files":{"src/foo.js":{"comment":0,"code":1}},"total":{"comment":1e999,"code":1,"ratio":0}}';
      withFixture({ baseline: raw }, (f) => {
        const r = run(f, ['--check']);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain('基线不可解析');
      });
    });

    it('对照：空仓（一个 .js 都没有）时空账本仍须放行——拒绝不得扩大到空仓', () => {
      // 公平性对照：空仓是合法的首次接入形态，加守卫时不得把它一起拒掉。
      withFixture(
        { baseline: JSON.stringify({ files: {}, total: { comment: 0, code: 0, ratio: 0 } }) },
        (f) => {
          fs.rmSync(path.join(f.tmp, 'src', 'foo.js'));
          const r = run(f, ['--check']);
          expect(r.status).toBe(0);
        }
      );
    });
  });

  describe('「首次建立」与「合法收紧」必须可区分', () => {
    it('两种结局的输出不同，且各自点名自己的语义', () => {
      withFixture({ baseline: null }, (f) => {
        const first = run(f, ['--update-baseline']);
        const tightened = run(f, ['--update-baseline']);
        expect(first.status).toBe(0);
        expect(tightened.status).toBe(0);
        expect(first.stdout).toContain('首次建立');
        expect(tightened.stdout).toContain('基线已收紧');
        expect(first.stdout).not.toBe(tightened.stdout);
      });
    });

    it('真回退必须拒绝（判据不是恒真）', () => {
      withFixture(
        {
          baseline: JSON.stringify({
            files: { 'src/foo.js': { comment: 1, code: 1 } },
            total: { comment: 1, code: 1, ratio: 0.5 },
          }),
        },
        (f) => {
          const r = run(f, ['--update-baseline']);
          expect(r.status).toBe(1);
          expect(r.stderr).toContain('回归 src/foo.js: 1 → 2');
        }
      );
    });
  });
});
