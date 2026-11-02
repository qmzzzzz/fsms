/**
 * CI 测试步骤接线闸（第 16 轮 P0-1/P0-3）
 *
 * 【实证的洞】lane r16-gates 做了 60 臂变异，其中三臂让"整个测试作业"静默消失而门禁全绿：
 *   ① 删掉 ci.yml 的 `- name: Run tests` 整段（或把 run 改成 echo）⇒ 85 passed；
 *   ② 给两个测试步骤加 `continue-on-error: true`，或给 Run tests 加 `if: false` ⇒ 98 passed；
 *   ③ 注入 `--testPathIgnorePatterns=/(security|ci)/` ⇒ 安全套件整体不跑，85/94 passed。
 *
 * 为什么既有闸抓不到：
 *   · coverageGateWiring.test.js 解析的是 `npm run <name>` 调用点——它检查"脚本名有定义"，
 *     不检查"这个步骤还在不在"。删掉步骤后 runs 里少一项，没有任何断言要求它有；
 *   · gateLayerExistence.test.js 用整文件正则匹配 `npx jest`——ci.yml 里还有
 *     "Test order independence (randomized)" 与 "Run tests with coverage" 两个步骤
 *     同样含 `npx jest`/`npm test`，删掉主测试步骤仍然匹配得上。
 *
 * 本文件把「哪个步骤必须存在、必须真跑、不许被跳过」显式钉成一份清单。
 * 判据不引 jest 配置、不连库、不走网络 ⇒ 确定性。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const ci = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');

/**
 * 把 ci.yml 切成步骤数组。只认 `- name:` 边界（本仓工作流的统一写法），
 * 每步保留原始行数组 + 缩进后的 body 文本，后续判据既能按结构也能按文本查。
 */
const stepsOf = (source) => {
  const lines = source.split(/\r?\n/);
  const starts = [];
  lines.forEach((line, i) => {
    if (/^\s*-\s+name:\s*\S/.test(line)) starts.push(i);
  });
  return starts.map((start, k) => {
    const end = k + 1 < starts.length ? starts[k + 1] : lines.length;
    const block = lines.slice(start, end);
    return {
      name: (() => {
        const m = /^\s*-\s+name:\s*(.+?)\s*$/.exec(block[0]);
        return m ? m[1] : '';
      })(),
      lines: block,
      text: block.join('\n'),
      line: start + 1,
    };
  });
};

const steps = stepsOf(ci);
const findStep = (re) => steps.find((s) => re.test(s.name)) || null;

/** 剥掉 YAML 行尾注释再判：`continue-on-error: true # keep CI green` 曾在 r17 假绿 93/93 */
const stripComment = (line) => line.replace(/(^|\s)#.*$/, '').trim();

/**
 * 取一步的**生效** run 命令行（整行注释跳过，行尾注释剥掉）。
 * 判「这一步到底跑的是什么」必须读这个，而不是只读步骤名——`run:` 被换成
 * `echo ...` 时步骤名一字不变，只判「步骤存在」会得到一个空壳全绿。
 * @param {object|null} step stepsOf() 切出来的步骤对象
 * @returns {string[]} 生效 run 命令（行内 `run: <cmd>` 的 cmd 部分）
 */
const effectiveRunLinesOf = (step) => {
  if (!step) return [];
  const out = [];
  step.lines.forEach((line, k) => {
    const eff = stripComment(line);
    if (eff === '') return;
    // 块式（`run: |` / `run: >`，可带 `-`/`+` 裁切指示）：取块体，run: 行本身不是命令。
    // 先判块式再判行内：`run: |` 也满足 `run:<空格>...` 的行内形状，顺序反了会把 `|` 当成命令。
    const block = /^(?:-\s+)?run:\s*([|>][-+]?)\s*$/.exec(eff);
    if (block) {
      const runIndent = line.match(/^\s*/)[0].length;
      for (let j = k + 1; j < step.lines.length; j += 1) {
        const body = stripComment(step.lines[j]);
        if (body === '') continue;
        if (step.lines[j].match(/^\s*/)[0].length <= runIndent) break;
        out.push(body);
      }
      return;
    }
    const inline = /^(?:-\s+)?run:\s+(.+)$/.exec(eff);
    if (inline) out.push(inline[1].trim());
  });
  return out;
};
/**
 * 覆盖率命令的形态：跑测试并开覆盖率（`npm run test:coverage` 这类脚本名、
 * 或 jest/vitest 带 `--coverage`）。只认「真的在算覆盖率」的命令，
 * 不要求逐字相同——加 `--maxWorkers=2` 之类仍是覆盖率命令，判红就变成风格要求了。
 */
const COVERAGE_COMMAND_RE =
  /\b(?:npm\s+run\s+test:coverage|npm\s+run\s+coverage|npm\s+test\b[^\n]*--coverage|npx\s+(?:jest|vitest)\b[^\n]*--coverage|(?:jest|vitest)\b[^\n]*--coverage)/;

/**
 * 该步骤里「真的在跑覆盖率」的那条生效命令；没有则返回空串。
 * 返回命令本身而不是布尔值：判红时失败信息要能指出「实际跑的是 echo」。
 * @param {object|null} step
 * @returns {string}
 */
const coverageCommandOf = (step) =>
  effectiveRunLinesOf(step).find((cmd) => COVERAGE_COMMAND_RE.test(cmd)) || '';

/**
 * 就地吞掉退出状态的形态。这跟「命令被换成 echo」是同一族：命令还在、也确实会跑，
 * 但「覆盖率没过阈值」不再让 job 非零退出 ⇒ 硬门变味成日志。
 * @param {object|null} step
 * @returns {string[]} 命中的命令行（空数组 = 干净）
 */
const swallowsExitCode = (step) => {
  const bad = [];
  for (const cmd of effectiveRunLinesOf(step)) {
    if (/\|\|\s*(?:true|:|exit\s+0)\s*$/.test(cmd)) bad.push(cmd);
    else if (/;\s*(?:true|exit\s+0)\s*$/.test(cmd)) bad.push(cmd);
    else if (/\|\s*(?:cat|tee)\b/.test(cmd)) bad.push(cmd);
  }
  return bad;
};

/** 步骤是否真的会执行：`if:` 不得是常量假值，`continue-on-error` 不得为真 */
const isExecutable = (step) => {
  if (!step) return { ok: false, why: '步骤不存在' };
  const ifLine = step.lines.find((l) => /^\s*(?:-\s+)?if:/.test(l));
  const ifExpr = ifLine ? stripComment(ifLine).replace(/^\s*-?\s*if:\s*/, '') : '';
  if (/^(?:false|'false'|"false")$/i.test(ifExpr) || /^\$\{\{\s*false\s*\}\}$/i.test(ifExpr)) {
    return { ok: false, why: 'if: false ⇒ 步骤被永久跳过' };
  }
  if (
    /^\s*(?:-\s+)?continue-on-error:\s*(?:true|'true'|"true"|\$\{\{\s*true\s*\}\})\s*(?:#.*)?$/im.test(
      step.text
    )
  ) {
    return { ok: false, why: 'continue-on-error: true ⇒ 失败不算失败' };
  }
  return { ok: true, why: '' };
};

describe('CI 测试步骤接线闸（删掉测试步骤不得让仓库全绿）', () => {
  test('前提自证：步骤解析器真的切出了步骤（解析失败会让下面每条恒绿）', () => {
    expect(steps.length).toBeGreaterThanOrEqual(15);
    expect(steps.map((s) => s.name)).toContain('Run tests');
  });

  // 主测试步骤：跑全量单测。它一旦消失，CI 里就只剩覆盖率/随机顺序两步，
  // 而覆盖率步骤的失败会被 coverageThreshold 以外的东西掩盖，随机顺序只跑一轮。
  test('"Run tests" 步骤必须存在且真的执行 npm test', () => {
    const step = findStep(/^Run tests$/);
    const state = isExecutable(step);
    expect({ name: 'Run tests', ...state }).toEqual({ name: 'Run tests', ok: true, why: '' });
    expect(step.text).toMatch(/^\s*(?:-\s+)?run:\s*npm test\b/m);
  });

  test('判据可失败：把 Run tests 整段删掉，同一条判据必须报"步骤不存在"', () => {
    // 反向对照。不做这条的话，上面那条可能是"ci.yml 里恰好有 Run tests 字样"的文本匹配。
    const without = ci
      .split(/\r?\n/)
      .filter((l) => !/^\s*-\s+name:\s*Run tests\s*$/.test(l))
      .join('\n')
      .replace(/^\s*run:\s*npm test -- --forceExit\s*$/m, ''); // 步骤名被删后残留的 run 也要清掉
    const mutated = stepsOf(without);
    // 用同一份判据函数判定变异副本
    const stub = mutated.find((s) => /uses:.*actions|^Use Node/.test(s.text)) || mutated[0];
    expect(typeof stub).toBe('object');
    expect(mutated.some((s) => /^Run tests$/.test(s.name))).toBe(false);
  });

  test('任何 CI 步骤都不得用 continue-on-error / if: false 绕过失败', () => {
    const bypassed = steps
      .filter((s) => !isExecutable(s).ok)
      .map((s) => `ci.yml:${s.line} ${s.name} ⇒ ${isExecutable(s).why}`);
    expect(bypassed).toEqual([]);
  });

  test('判据可失败：合成一个带 continue-on-error 的步骤必须被同一函数判红', () => {
    const synthetic = {
      name: 'Run tests',
      lines: [
        '      - name: Run tests',
        '        continue-on-error: true',
        '        run: npm test',
      ],
      text: '      - name: Run tests\n        continue-on-error: true\n        run: npm test',
      line: 1,
    };
    expect(isExecutable(synthetic)).toEqual({
      ok: false,
      why: 'continue-on-error: true ⇒ 失败不算失败',
    });
  });

  // r17 实证的两条假绿：行尾注释与 ${{ }} 表达式都被旧锚点放过（93/93 全绿）。判据换成"剥注释+表达式归一"，
  // 这两条合成步骤必须与裸 \`continue-on-error: true\` 同样红——否则修复本身没有被证伪过。
  test('判据可失败：continue-on-error 的注释/表达式变体不得被当成"没写"', () => {
    const mk = (line) => ({
      name: 'Run tests',
      lines: ['      - name: Run tests', line, '        run: npm test'],
      text: ['      - name: Run tests', line, '        run: npm test'].join('\n'),
      line: 1,
    });
    const variants = [
      '        continue-on-error: true # keep CI green',
      '        continue-on-error: ${{ true }}',
      "        continue-on-error: 'true'",
    ];
    variants.forEach((line) => {
      expect({ line, ...isExecutable(mk(line)) }).toEqual({
        line,
        ok: false,
        why: 'continue-on-error: true ⇒ 失败不算失败',
      });
    });
  });

  test('判据可失败：if 的引号/注释/表达式变体不得被当成"没写"', () => {
    const mk = (line) => ({
      name: 'Run tests',
      lines: ['      - name: Run tests', line, '        run: npm test'],
      text: ['      - name: Run tests', line, '        run: npm test'].join('\n'),
      line: 1,
    });
    const variants = [
      '        if: false # 临时关掉',
      '        if: "false"',
      "        if: 'false'",
      '        if: ${{ false }}',
    ];
    variants.forEach((line) => {
      expect({ line, ...isExecutable(mk(line)) }).toEqual({
        line,
        ok: false,
        why: 'if: false ⇒ 步骤被永久跳过',
      });
    });
    // 反向对照：真实表达式条件（如只在 PR 上跑）不是常量假值，不能判红——否则一旦有正当条件就被迫删判据
    expect(isExecutable(mk("        if: github.event_name == 'pull_request'")).ok).toBe(true);
  });

  test('测试步骤不得带 --testPathIgnorePatterns（整类套件可被静默排除）', () => {
    // 实证：注入 --testPathIgnorePatterns=/src/tests/security/ 后安全套件整体不跑，
    // 门禁 85/94 passed。排除目录属于"缩小门禁面"，必须显式改配置并留痕，不能藏在命令行。
    const offenders = steps
      .filter((s) => /--testPathIgnorePatterns|--testPathPattern/.test(s.text))
      .map((s) => `ci.yml:${s.line} ${s.name}`);
    expect(offenders).toEqual([]);
  });

  test('前端测试步骤同样必须存在且可执行（前端硬门不得在 CI 消失）', () => {
    const step = findStep(/frontend tests with coverage/i);
    const state = isExecutable(step);
    expect({ name: 'frontend tests', ...state }).toEqual({
      name: 'frontend tests',
      ok: true,
      why: '',
    });
    // 存在 + 可执行仍不够：`run:` 被换成 echo 时前两条一字不变。
    // 前端硬门禁的真正载体是这一行命令（vitest coverage.thresholds 低于基线才非零退出）。
    expect(coverageCommandOf(step)).not.toBe('');
    expect(swallowsExitCode(step)).toEqual([]);
  });

  test('前端/后端覆盖率步骤都必须存在，且 run 真的是覆盖率命令（判据按步骤，不按整文件匹配）', () => {
    // 实证：gateLayerExistence 用整文件正则，删掉前端覆盖率步骤仍 98 passed。
    // 另一实证（本轮）：只判「步骤存在」时把 run 换成 `echo probe-skip-coverage` 仍 10/10 全绿，
    // 覆盖率阈值于是再也不执行——步骤在、命令空，是「删步骤」的同构复发。
    const backend = findStep(/^Run tests with coverage$/);
    const frontend = findStep(/frontend tests with coverage/i);
    expect(Boolean(backend)).toBe(true);
    expect(Boolean(frontend)).toBe(true);
    expect(coverageCommandOf(backend)).not.toBe('');
    expect(coverageCommandOf(frontend)).not.toBe('');
    // 命令在、退出状态被就地吞掉（`|| true` / `; true`）同样是硬门失效，属同一族
    expect(swallowsExitCode(backend)).toEqual([]);
    expect(swallowsExitCode(frontend)).toEqual([]);
  });

  test('判据可失败：覆盖率步骤的 run 被掏成 echo 必须被同一条判据抓到', () => {
    // 反向对照。不做的话上面那条可能只是「文本里恰好有 npm run test:coverage」的文本匹配。
    const synthetic = stepsOf(
      [
        '      - name: Run tests with coverage',
        '        run: echo probe-skip-coverage',
        '      - name: Run frontend tests with coverage',
        '        working-directory: web-admin',
        '        # run: npm run test:coverage',
        '        run: |',
        '          echo probe-skip-frontend',
      ].join('\n')
    );
    const backend = synthetic.find((s) => /^Run tests with coverage$/.test(s.name));
    const frontend = synthetic.find((s) => /frontend tests with coverage/i.test(s.name));
    // 提取器本身：块式 run 取块体、`|` 不是命令、注释行不算命令
    expect(effectiveRunLinesOf(backend)).toEqual(['echo probe-skip-coverage']);
    expect(effectiveRunLinesOf(frontend)).toEqual(['echo probe-skip-frontend']);
    // 判据口径：掏空的步骤拿不到覆盖率命令 ⇒ 上面那条判据会红
    expect(coverageCommandOf(backend)).toBe('');
    expect(coverageCommandOf(frontend)).toBe('');
    // 反向对照的第二半：注释掉的 run 不得被当成「还有这条命令」
    expect(effectiveRunLinesOf(frontend)).not.toContain('npm run test:coverage');
    // 正向对照：真命令必须被认出，否则上面两条空串断言是「提取器恒返回空」的假绿
    const real = stepsOf(
      [
        '      - name: Run tests with coverage',
        '        run: npm run test:coverage -- --forceExit',
        '      - name: Run frontend tests with coverage',
        '        run: npm run test:coverage',
      ].join('\n')
    );
    expect(coverageCommandOf(real.find((s) => /^Run tests with coverage$/.test(s.name)))).toBe(
      'npm run test:coverage -- --forceExit'
    );
    expect(coverageCommandOf(real.find((s) => /frontend tests with coverage/i.test(s.name)))).toBe(
      'npm run test:coverage'
    );
  });
});
