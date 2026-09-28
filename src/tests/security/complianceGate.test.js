/**
 * 合规门禁自检（L-25 同族：门禁自身不得误报）
 *
 * 背景：scripts/compliance-check.js 的「审计导出接口」检查曾长期误报
 * 「exportAuditLogs 未定义」——因为它查的是 securityController，
 * 而该函数实际位于 auditController.js（securityRoutes.js:248 引用）。
 *
 * 门禁指向错位置的红灯比没有门禁更危险：它会训练出「红灯可忽略」的习惯。
 * 本测试把「门禁必须能对真实代码判绿」固化为回归断言。
 *
 * 同一文件的第二格（本轮补）：门禁**不得被注释满足**。
 * 「审计监控已挂载」「导出接口已挂到路由」这两项只能靠读源码判定，而读原文跑正则的后果是
 * 把 `auditMonitor.start();` 前面加两个斜杠之后，检查项仍然报绿——
 * 门禁绿、代码里那个调用已经不存在，与 P3-46 修掉的「恒真检查」同族。
 * 现在判定统一走脚本导出的 `stripJsComments` 代码视图（本测试直接 import 那一份判据，
 * 不再在测试里复制正则——复制一份就是制造漂移）。
 *
 * 同一文件的第三格（F-164）：门禁**登记了几条就必须真跑几条**。`runAllChecks()` 原先手写
 * 七个调用，删掉其中一行只会让报告少一条、退出码照旧 0——"删掉门禁不会让任何东西变红"。
 * 现在登记表在脚本侧自证（抛出的、没交结论的检查器都被补成失败行），测试侧再对账
 * "登记表 = 源码声明的全部 check* 函数"，见文件末尾那个 describe。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');

const {
  stripJsComments,
  codeViews,
  mountSignals,
  exportRouteWired,
  COMPLIANCE_CHECKS,
  runRegisteredChecks,
  recordCheck,
} = require(path.join(ROOT, 'scripts/compliance-check.js'));
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

describe('合规门禁 · 审计导出接口检查（L-25 同族回归）', () => {
  it('auditController.exportAuditLogs 已定义', () => {
    const auditController = require(path.join(ROOT, 'src/controllers/auditController'));
    expect(typeof auditController.exportAuditLogs).toBe('function');
  });

  it('该函数确实挂在 GET /audit-logs/export 路由上', () => {
    expect(exportRouteWired(read('src/routes/securityRoutes.js'))).toBe(true);
  });

  it('门禁脚本检查的是路由实际挂载的控制器，而非同名函数的旧位置', () => {
    const gateSrc = fs.readFileSync(path.join(ROOT, 'scripts/compliance-check.js'), 'utf8');
    // 必须引用 auditController（正确位置）
    expect(gateSrc).toMatch(/require\(['"][^'"]*controllers\/auditController['"]\)/);
    // 不得再回退到 securityController 查这个函数
    expect(gateSrc).not.toMatch(/securityController\.exportAuditLogs/);
  });

  it('门禁脚本可独立执行且退出码为 0（就绪）', () => {
    const { execFileSync } = require('child_process');
    const out = execFileSync(process.execPath, [path.join(ROOT, 'scripts/compliance-check.js')], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(out).toContain('总体: 就绪');
  });
});

describe('合规门禁 · 源码形态判定不得被注释满足', () => {
  it('start/stop 只出现在注释里 ⇒ 判未挂载（require 在代码里，故仍为真）', () => {
    const src = [
      "const auditMonitor = require('./services/auditMonitor');",
      '// auditMonitor.start();',
      '/* auditMonitor.stop(); */',
      "console.log('boot'); // auditMonitor.start()",
    ].join('\n');
    expect(mountSignals(src)).toEqual({ hasRequire: true, hasStart: false, hasStop: false });
  });

  it('同样的语句不注释 ⇒ 判已挂载（证明上一条是"因为注释"，不是"因为剥多了"）', () => {
    const src = [
      "const auditMonitor = require('./services/auditMonitor');",
      'auditMonitor.start();',
      'auditMonitor.stop();',
    ].join('\n');
    expect(mountSignals(src)).toEqual({ hasRequire: true, hasStart: true, hasStop: true });
  });

  it('路由接线整块写在注释里 ⇒ exportRouteWired 为 false；解开注释即 true', () => {
    const wired =
      "router.get('/audit-logs/export', authenticate, auditController.exportAuditLogs);";
    expect(exportRouteWired(wired)).toBe(true);
    expect(exportRouteWired(`/**\n * @route ${wired}\n */`)).toBe(false);
  });

  it('剥注释只剥注释：字符串里的 // 原样保留，注释里的 URL 一并消失', () => {
    const stripped = stripJsComments(
      [
        "const url = 'https://example.com/a//b';",
        'const list = ["// 这不是注释"];',
        '// 参见 https://example.com/doc',
      ].join('\n')
    );
    expect(stripped).toContain("'https://example.com/a//b'");
    expect(stripped).toContain('"// 这不是注释"');
    expect(stripped).not.toContain('https://example.com/doc');
  });

  it('真实被检文件在代码视图下仍然判绿（过度剥离会以"红灯"暴露，不会静默放行）', () => {
    expect(mountSignals(read('src/index.js'))).toEqual({
      hasRequire: true,
      hasStart: true,
      hasStop: true,
    });
    expect(exportRouteWired(read('src/routes/securityRoutes.js'))).toBe(true);
  });
});

/**
 * 2026-09-25 审计补的第三格：上一轮只堵了注释，**字符串**是同一族的另一个入口。
 * 一行 `logger.error('auditMonitor.start() 未执行')` 就能让"已挂载"报绿，
 * 而那句调用其实不存在——门禁给出的仍是已设防的错觉。
 */
describe('合规门禁 · 源码形态判定不得被字符串满足', () => {
  it('start/stop 只活在字符串（含模板字面量）里 ⇒ 判未挂载', () => {
    const src = [
      "const auditMonitor = require('./services/auditMonitor');",
      "logger.error('auditMonitor.start() 没能执行');",
      'const doc = `记得调用 auditMonitor.stop()`;',
    ].join('\n');
    expect(mountSignals(src)).toEqual({ hasRequire: true, hasStart: false, hasStop: false });
  });

  it('对照：把调用真写出来 ⇒ 判已挂载（证明上一条是因为"在字符串里"，不是判据写死为假）', () => {
    const src = [
      "const auditMonitor = require('./services/auditMonitor');",
      "logger.error('auditMonitor.start() 没能执行');",
      'auditMonitor.start();',
      'auditMonitor.stop();',
    ].join('\n');
    expect(mountSignals(src)).toEqual({ hasRequire: true, hasStart: true, hasStop: true });
  });

  it('整条"路径 → 处理器"写成文档字符串 ⇒ exportRouteWired 为 false', () => {
    const doc = "const API_DOC = 'GET /audit-logs/export -> auditController.exportAuditLogs';\n";
    expect(exportRouteWired(doc)).toBe(false);
    // 同一段文档字符串 + 真实路由 ⇒ true：说明上一条红是因为"只有字符串"
    expect(
      exportRouteWired(
        `${doc}router.get('/audit-logs/export', authenticate, auditController.exportAuditLogs);\n`
      )
    ).toBe(true);
  });

  it('前提自证：text 与 code 逐位等长，而注释会让两份视图都短于原文', () => {
    const src = [
      "router.get('/audit-logs/export', a, b);",
      'const doc = `模板里的 /audit-logs/export 也算字符串`;',
      '// 注释里的 /audit-logs/export',
    ].join('\n');
    const { text, code } = codeViews(src);
    // 跨视图距离判据真正依赖的是这两份彼此对齐：打点不删字符
    expect(code.length).toBe(text.length);
    // 与原文**不**等长（注释整段删除，只保行数）⇒ 视图下标不能当原文行号用
    expect(text.length).toBeLessThan(src.length);
    expect(text.split('\n').length).toBe(src.split('\n').length);
    expect(text).toContain('模板里的');
    expect(code).not.toContain('模板里的');
    expect(text).not.toContain('注释里的');
  });

  it('路由前有一整块 jsdoc（文档里也写了路径与处理器名）⇒ 判据不受位移影响', () => {
    const lines = [
      '/**',
      ' * @api {get} /audit-logs/export 导出审计日志',
      ' * handler: auditController.exportAuditLogs',
      ' */',
      "router.get('/audit-logs/export', authenticate, auditController.exportAuditLogs);",
    ];
    // 真接线在最后一行：注释块造成的位移发生在视图内部，窗口仍要命中它
    expect(exportRouteWired(`${lines.join('\n')}\n`)).toBe(true);
    // 只留文档块 ⇒ 注释里那句"路径 → 处理器"既不算 text 也不算 code
    expect(exportRouteWired(`${lines.slice(0, 4).join('\n')}\n`)).toBe(false);
  });
});

describe('合规门禁 · 登记项必须真跑过（F-164）', () => {
  // 上面两格管的是"单条判定会不会被注释/字符串满足"；这一格管的是整份台账的完整性：
  // 合规检查**按条数**出结论，只要有哪一条从未被评估，退出码就还是 0。
  // 修前的形状：runAllChecks() 里手写七个调用 ⇒ 删掉任意一行（或哪个检查器新增一条不调
  // recordCheck 的早退分支）之后，checks 少一条、allPassed 仍为真、CI 全绿，
  // 而那条合规要求从此没人看过——与 F-161（删掉 ci.yml 里的门禁作业仍全绿）同族。
  // 现在两层各挡一种删法：A/B 跑脚本里的真不变量（行为级，不 grep 文本），
  // C/D 在测试侧对账"登记表 = 源码声明的全部 check* 函数"，E 端到端核对实际交付的报告。
  const gateCodeView = () => codeViews(read('scripts/compliance-check.js')).text;

  it('A 不变式：登记几条就出几条结论，抛出与「跑完不记结论」都被补成失败行', () => {
    const rows = runRegisteredChecks([
      function normalChecker() {
        recordCheck('正常检查项', true, '结论已产出');
      },
      function throwingChecker() {
        throw new Error('故意让检查器炸掉');
      },
      function silentChecker() {
        // 跑完什么都不记：修前这等价于"这条合规要求从未被评估"，而总体仍算就绪
      },
    ]);
    expect(rows.map((r) => [r.name, r.passed])).toEqual([
      ['正常检查项', true],
      ['throwingChecker 自身抛出', false],
      ['silentChecker 未产出结论', false],
    ]);
    // 抛出那条要留下原始异常信息，否则红灯指不出坏在哪
    expect(rows[1].detail).toContain('故意让检查器炸掉');
  });

  it('B 一个检查器抛出不得掀掉整份报告：它之后的登记项照样跑', () => {
    const rows = runRegisteredChecks([
      function boomChecker() {
        throw new Error('boom');
      },
      function afterChecker() {
        recordCheck('抛出之后的检查项', true, '仍在跑');
      },
    ]);
    expect(rows.map((r) => r.name)).toEqual(['boomChecker 自身抛出', '抛出之后的检查项']);
    // 修前的失效形态：未捕获异常直接终止进程 ⇒ 第二条根本没跑，JSON 报告一个字都没有
    expect(rows[1].passed).toBe(true);
  });

  it('C 登记表 = 源码里声明的全部 check* 函数（漏登记即红，判据走代码视图）', () => {
    const declared = [...gateCodeView().matchAll(/^function (check[A-Z]\w*)\b/gm)].map((m) => m[1]);
    // 抽取自身失效时不得退化成"两边都空 ⇒ 绿"
    expect(declared.length).toBeGreaterThan(0);
    expect(COMPLIANCE_CHECKS.map((f) => f.name).sort()).toEqual(declared.sort());
  });

  it('C2 注释里仿写一条 function checkFake 不算声明（代码视图判据自证）', () => {
    const faked = `${gateCodeView()}\n// function checkFakeInComment() {}\n`;
    const declared = [...codeViews(faked).text.matchAll(/^function (check[A-Z]\w*)\b/gm)].map(
      (m) => m[1]
    );
    expect(declared).not.toContain('checkFakeInComment');
    expect(faked).toContain('checkFakeInComment'); // 原文里确实在场——只有视图能排除它
  });

  it('D 钉住清单：八项合规要求逐项在场（整条连函数一起被删时 C 会静默放行）', () => {
    // 与 C 互补：C 是"两边一致"，删掉一个检查器会同时删掉两边 ⇒ C 仍绿；
    // 这里硬写八条名字，删任何一条都要先在这里留痕。顺序无关（故两侧都 sort）。
    expect(COMPLIANCE_CHECKS.map((f) => f.name).sort()).toEqual(
      [
        'checkRetention',
        'checkAppendOnlyHooks',
        'checkExportInterface',
        'checkMonitorMounted',
        'checkHashChainFields',
        'checkWalFallback',
        'checkShippingTransport',
        'checkAlertingDeliveryEndpoint',
      ].sort()
    );
  });

  it('E 端到端：真跑一次脚本，交付的 JSON 报告条数与登记表一致且逐条判绿', () => {
    const { execFileSync } = require('child_process');
    const out = execFileSync(process.execPath, [path.join(ROOT, 'scripts/compliance-check.js')], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(out).toContain('合规就绪度摘要');
    const report = JSON.parse(out.slice(out.indexOf('{'), out.indexOf('\n\n==========')));
    expect(report.checks.length).toBe(COMPLIANCE_CHECKS.length);
    expect(report.allPassed).toBe(true);
    for (const c of report.checks) {
      expect(c.name.trim()).not.toBe('');
      expect(c.detail.trim()).not.toBe('');
      expect(c.passed).toBe(true);
    }
    // 报告里不得出现 A/B 那两类补记行——它们一旦出现就是"有检查器没交结论"
    expect(report.checks.map((c) => c.name).join('\n')).not.toMatch(/自身抛出|未产出结论/);
  });
});
