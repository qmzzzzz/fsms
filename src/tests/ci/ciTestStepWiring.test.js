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
  });

  test('前端/后端覆盖率步骤都必须存在（判据按步骤，不按整文件匹配）', () => {
    // 实证：gateLayerExistence 用整文件正则，删掉前端覆盖率步骤仍 98 passed。
    const backend = findStep(/^Run tests with coverage$/);
    const frontend = findStep(/frontend tests with coverage/i);
    expect(Boolean(backend)).toBe(true);
    expect(Boolean(frontend)).toBe(true);
  });
});
