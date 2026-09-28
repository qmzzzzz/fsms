'use strict';

/**
 * F-103：优雅关闭的**总时长**必须落在部署窗口之内
 *
 * 缺陷（台账 §14.21.5 / §16 记录，本轮独立复测三个输入后落地）：
 *  · `src/index.js` 的 HTTP 步骤自带 10 s 强制超时；
 *  · `stopReminderScheduler` 最长等 30 s；
 *  · `docker-compose.yml` 的 app 服务**没有** `stop_grace_period` ⇒ Docker 默认 **10 s** SIGKILL。
 * 于是"有持久化后果"的两步（审计缓冲排空、Mongo 关闭）排在链尾却永远轮不到执行，
 * 而且强退不留日志线索。修法两侧同时做：代码侧总预算（`src/utils/shutdownBudget.js`）
 * + 部署侧 `stop_grace_period`。**只建在其中一条链上等于没建**（同 F-94 的教训）。
 *
 * 本套件六道闸：
 *  ① compose 的 app 服务块必须声明 stop_grace_period，且要盖住代码侧总预算 + 余量；
 *  ② 关停链源码不得再出现"裸字面量超时"（防第 N 步悄悄越界）；
 *  ③ stepAllowMs 的钳制算术：未 begin ⇒ 不限制；预算用尽 ⇒ 恰好 0，且**永不为负**
 *     （负值会让 setTimeout/循环立刻判超时，把"还能等"变成"一秒都不等"）。
 *  ④ beginShutdownBudget 把总预算折算成绝对截止时间。
 *  ⑤⑥ ② 的**测量法**自检：判定必须走"只剩代码"的视图，而不是源文件文本。
 *
 * F-145（⑤⑥ 的来由，两向实测）：② 原先直接对 `src/index.js` 的**文本**做正则，
 * 于是两条闸都能被注释左右——
 *  · 假绿：把 :171 真实的 `flushAndStop(shutdownBudget.stepAllowMs(2500))` 改成
 *    `flushAndStop(Infinity)`（排空步骤退回无限等待，正是 ② 要拦的那个原始缺陷），
 *    再补一行提到 `stepAllowMs(` 的注释 ⇒ 计数仍是 3 ⇒ 实测 `Tests: 4 passed, 4 total`；
 *  · 假红：只在区域里加一行记录反例的注释 `// setTimeout(() => forceClose(), 10000)`
 *    （本仓注释惯例就是这样写下被删掉的坏写法，见 index.js 关停链注释里的 F-97 段），
 *    代码一行没动 ⇒ 实测 `Tests: 1 failed, 3 passed, 4 total`。
 * 与本文件 appServiceBlock() 顶部已经写明的同一条原则：注释能骗过的闸等于没有闸。
 */

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const shutdownBudget = require('../../utils/shutdownBudget');

/**
 * 取 docker-compose.yml 里 app 服务的块：按两空格缩进的服务名切块，再用 APP_IMAGE 认出它。
 * 先按 YAML 语义剥掉注释（整行 `#` 与值后面的 ` #`），否则**把键注释掉**就能骗过这条闸——
 * 那是"绿但不设防"，与本仓 nginx 契约闸踩过的同一类（改在代码视图上，不改在文本上）。
 */
function appServiceBlock() {
  const raw = fs.readFileSync(path.join(REPO_ROOT, 'docker-compose.yml'), 'utf8').split(/\r?\n/);
  const lines = raw.map((l) => (/^\s*#/.test(l) ? '' : l.replace(/\s+#(?![^'"]*')/, '')));
  const blocks = new Map();
  let current = null;
  for (const line of lines) {
    const head = /^ {2}([A-Za-z0-9_.-]+):\s*$/.exec(line);
    if (head) {
      current = head[1];
      blocks.set(current, []);
      continue;
    }
    if (current) blocks.get(current).push(line);
  }
  for (const [name, body] of blocks) {
    if (body.some((l) => l.includes('${APP_IMAGE'))) return { name, text: body.join('\n') };
  }
  throw new Error('docker-compose.yml 里找不到带 APP_IMAGE 的 app 服务块');
}

/**
 * 把 JS 源码剥成"只剩代码"的视图：先按行首/行尾形态整块抹掉块注释（保行号），
 * 再删整行注释，最后屏蔽行尾 `//…`。
 * 关停链的两条文本闸（②）必须走这个视图——否则注释既能把闸骗绿（在注释里
 * 补一个 `stepAllowMs(` 就把真实调用删掉），也能把闸骗红（在注释里写下
 * 本仓惯例要记录的反例 `setTimeout(..., 10000)`）。见 F-145 的两向实测。
 * 抹块注释的安全性前提由 ⑥ 钉住（区域内每个 `/*` 都独行起始，不存在跨语句的行内块注释）。
 */
function jsCodeOnly(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .map((l) => l.replace(/\/\/[^\n]*/g, ' '))
    .join('\n');
}

/** 关停链源码区域（gracefulShutdown 起、startServer 止）的原始文本 */
function shutdownRegionText() {
  const src = fs.readFileSync(path.join(REPO_ROOT, 'src/index.js'), 'utf8');
  const from = src.indexOf('const gracefulShutdown');
  const to = src.indexOf('const startServer');
  expect(from).toBeGreaterThan(-1);
  expect(to).toBeGreaterThan(from);
  return src.slice(from, to);
}

/** 同上，但先剥注释再定位边界：区域边界也不许被注释挪动 */
function shutdownRegionCode() {
  const code = jsCodeOnly(fs.readFileSync(path.join(REPO_ROOT, 'src/index.js'), 'utf8'));
  const from = code.indexOf('const gracefulShutdown');
  const to = code.indexOf('const startServer');
  expect(from).toBeGreaterThan(-1);
  expect(to).toBeGreaterThan(from);
  return code.slice(from, to);
}

/**
 * `runStep` 的定义体（F-202 起它在模块作用域，位于关停链区域之前 ⇒ 不能从区域里切）。
 * 切到第一个调用点为止：断言的对象是"链上真正在用那个 runStep"，
 * 定义与调用点之间的别处代码不算。
 */
function runStepDefinition() {
  const code = jsCodeOnly(fs.readFileSync(path.join(REPO_ROOT, 'src/index.js'), 'utf8'));
  const from = code.indexOf('const runStep');
  const to = code.indexOf('await runStep');
  expect(from).toBeGreaterThan(-1);
  expect(to).toBeGreaterThan(from);
  return code.slice(from, to);
}

/** 裸字面量超时闸：`setTimeout(fn, 10000)` 这类不受总预算约束的写法 */
const BARE_TIMEOUT = /setTimeout\([\s\S]{0,600}?,\s*\d{4,}\)/;

describe('关停链总预算与部署窗口的契约（F-103）', () => {
  afterEach(() => shutdownBudget.__setDeadlineForTest(0));

  test('① compose 的 app 服务声明了 stop_grace_period，且盖住代码侧总预算 + 余量', () => {
    const { name, text } = appServiceBlock();
    const m = /stop_grace_period:\s*(\d+)s\b/.exec(text);
    expect(m).not.toBeNull();
    const graceMs = Number(m[1]) * 1000;
    // 余量至少 3 s：预算判断之后的收尾（日志 transport 落盘 + process.exit）也要在窗口内
    expect(graceMs).toBeGreaterThanOrEqual(shutdownBudget.SHUTDOWN_TOTAL_BUDGET_MS + 3000);
    // 也不许把窗口无谓地放大：那会让每次发布/重启都白白多等
    expect(graceMs).toBeLessThanOrEqual(shutdownBudget.SHUTDOWN_TOTAL_BUDGET_MS + 15000);
    expect(name).toBe('app');
  });

  test('② 关停链源码里不得再出现裸字面量超时（每一步必须向 stepAllowMs 要额度）', () => {
    // F-145：判定走"只剩代码"的视图，区域边界同样从代码视图上定位。
    const region = shutdownRegionCode();
    // setTimeout( ... , 10000) 这类写法一律红：字面量上限不受总预算约束 ⇒ 会吃掉尾部的时间
    expect(region).not.toMatch(BARE_TIMEOUT);
    // 反向闸：确有步骤在领额度（HTTP + 调度器 + 审计排空 + SIEM 排空），
    // 防止"删光步骤"来骗过上一条。F-186 把第四步（排空 SIEM 转发缓冲）接进链尾时
    // 计数 3→4：这条闸只会在**步骤被删**时红，所以扩列是随实做随报，不是放水。
    // F-202 再 4→6：关 Redis 与关 Mongo 这两步此前既不领额度也没有硬闸，
    // 对端不可达时 `await` 永不返回 ⇒ 链尾的排空与 exit 全跑不到（见 runStep 的 capMs）。
    expect(region.match(/stepAllowMs\(/g) || []).toHaveLength(6);
  });

  test('③ stepAllowMs：未 begin 不限制、预算内给足、用尽归零且永不为负', () => {
    shutdownBudget.__setDeadlineForTest(0);
    expect(shutdownBudget.stepAllowMs(1000)).toBe(Infinity);

    const now = Date.now();
    shutdownBudget.__setDeadlineForTest(now + 5000);
    const allow = shutdownBudget.stepAllowMs(2000);
    expect(allow).toBeLessThanOrEqual(3000);
    expect(allow).toBeGreaterThan(2500); // 5 s 窗口 - 2 s 保留，只可能因流逝而略小

    // 已过截止点：必须是 0，不能是负数（负数会立刻触发所有超时）
    shutdownBudget.__setDeadlineForTest(now - 1);
    expect(shutdownBudget.stepAllowMs(6000)).toBe(0);
    expect(shutdownBudget.stepAllowMs(0)).toBe(0);
  });

  test('④ beginShutdownBudget 把总预算折算成绝对截止时间（默认值取自 env）', () => {
    const before = Date.now();
    const dl = shutdownBudget.beginShutdownBudget();
    expect(dl).toBeGreaterThanOrEqual(before + shutdownBudget.SHUTDOWN_TOTAL_BUDGET_MS - 50);
    expect(dl).toBeLessThanOrEqual(Date.now() + shutdownBudget.SHUTDOWN_TOTAL_BUDGET_MS + 50);
    // 尾部保留时间必须真的存在：它是"排空 + 关库"不被前面吃光的唯一保证
    expect(shutdownBudget.TAIL_RESERVE_MS).toBeGreaterThan(0);
  });

  test('⑤ ② 用的确实是代码视图：同一份反例在文本上骗得过、在代码上骗不过', () => {
    const text = shutdownRegionText();
    const step = 'shutdownBudget.stepAllowMs(shutdownBudget.TAIL_RESERVE_MS)';
    const textCalls = (text.match(/stepAllowMs\(/g) || []).length;
    const codeCalls = (shutdownRegionCode().match(/stepAllowMs\(/g) || []).length;
    expect(textCalls).toBeGreaterThanOrEqual(2);
    // 今天的源码里两种视图同数——下面的反例要制造的就是"文本同数、代码少一个"
    expect(codeCalls).toBe(textCalls);

    // 假绿反例：删掉一处真实调用（步骤退回硬上限 30 s，正是 F-103 的原始缺陷形态），
    // 只在注释里留个同名字面量。文本视图数得出同样的处数 ⇒ 骗过；代码视图少一个 ⇒ 抓住。
    const greenInText = `  // 本区曾向 stepAllowMs(TAIL_RESERVE_MS) 领额度\n${text.replace(
      step,
      '30000'
    )}`;
    expect(greenInText).not.toBe(text);
    expect((greenInText.match(/stepAllowMs\(/g) || []).length).toBe(textCalls);
    expect(jsCodeOnly(greenInText).match(/stepAllowMs\(/g)).toHaveLength(codeCalls - 1);

    // 同一条骗局的块注释形态（JSDoc 里写一句就够，行尾 `//` 屏蔽对它无效）
    const greenInBlock = `/* 说明：各步骤统一向 stepAllowMs(TAIL_RESERVE_MS) 领额度 */\n${text.replace(
      step,
      '30000'
    )}`;
    expect((greenInBlock.match(/stepAllowMs\(/g) || []).length).toBe(textCalls);
    expect(jsCodeOnly(greenInBlock).match(/stepAllowMs\(/g)).toHaveLength(codeCalls - 1);

    // 假红反例：代码一行没动，只在注释里写下被删掉的老写法。文本视图红；代码视图绿。
    const redInText = `  // 老写法：setTimeout(() => forceClose(), 10000)\n${text}`;
    expect(BARE_TIMEOUT.test(redInText)).toBe(true);
    expect(BARE_TIMEOUT.test(jsCodeOnly(redInText))).toBe(false);
  });

  test('⑥ 代码视图的前提成立：区域内没有 `://`，且块注释不吞语句', () => {
    // 前提一：jsCodeOnly 用 `//` 当行尾注释起始。若代码字符串里含 `://`（URL、协议名），
    // 屏蔽会把字符串后半截掉，"代码视图"就成了改坏源码的视图——故先只看非整行注释的行。
    const codeLines = shutdownRegionText()
      .split('\n')
      .filter((l) => !/^\s*\/\//.test(l));
    expect(codeLines.filter((l) => l.includes('://'))).toEqual([]);
    // 前提二：整块抹除按 `/* … */` 配对，只对本仓的 JSDoc 形态安全——`/*` 之前、`*/` 之后
    // 只许是空白。出现 `const x = 1; /* 备注 */` 这类行内块注释时，抹除会连着语句一起吃掉。
    const offenders = [];
    shutdownRegionText()
      .split('\n')
      .forEach((l, i) => {
        const open = l.indexOf('/*');
        if (open > -1 && l.slice(0, open).trim() !== '') offenders.push(`第 ${i} 行：/* 前有语句`);
        const close = l.indexOf('*/');
        if (close > -1 && l.slice(close + 2).trim() !== '')
          offenders.push(`第 ${i} 行：*/ 后有语句`);
      });
    expect(offenders).toEqual([]);
    // 反向对照：这条前提不是空转——区域里确实有块注释，形态就是上面允许的那种
    expect(codeLines.filter((l) => l.includes('/*'))).not.toHaveLength(0);
  });

  /**
   * 关停链的"无保护 await"闸（F-202）。
   *
   * 判据：链上每个 `runStep('名字' …)` 调用点，其步骤体要么自己领了预算
   * （体内出现 `stepAllowMs(`），要么落在下面这份**同步步骤**清单里。
   * 两边都是精确断言：新加一步而不领额度 ⇒ 红；把清单里某一步改成会 await 网络 ⇒ 红；
   * 给清单里某一步补上 cap ⇒ 也红（必须把名字从清单里划掉，一次看得见的决定）。
   *
   * 第二条断言管的是"装饰性参数"这个洞：`capMs` 传了但 runStep 根本不用，
   * 上面那条判据照样全绿。所以直接钉 runStep 的定义体确实在把 task 交给 guardStep。
   */
  const SYNC_ONLY_STEPS = [
    '停止告警清理定时器',
    '停止审计监控',
    '停止权限缓存清理定时器',
    '停止统计缓存清理定时器',
    '停止验证码清理定时器',
    '关闭 WebSocket',
  ];

  /**
   * 从 `(` 开始找配对的 `)`（跳过字符串字面量）。
   * 不能用 `indexOf(')')`：`runStep('名字', () => …)` 里第一个右括号关的是箭头函数的
   * 参数列表，切在那里就永远看不见第三个实参 capMs——实测这样切出来的 `call` 全空，
   * 于是"cap 到底有没有传给 runStep"这条断言成了空转（自己写出来时红过一次）。
   */
  function parenCallEnd(code, open) {
    let depth = 0;
    let quote = null;
    for (let i = open; i < code.length; i++) {
      const ch = code[i];
      if (quote) {
        if (ch === '\\') i++;
        else if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') quote = ch;
      else if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') {
        depth--;
        if (depth === 0) return i + 1;
      }
    }
    return code.length;
  }

  /** 从代码视图里取出每个 runStep 调用点：步骤名 + 该步的源码片段 + 整个调用实参区间 */
  function runStepSites(code) {
    const re = /runStep\(\s*'([^']+)'/g;
    const starts = [];
    let m;
    while ((m = re.exec(code)) !== null) starts.push({ name: m[1], index: m.index });
    return starts.map((s, i) => ({
      name: s.name,
      body: code.slice(s.index, i + 1 < starts.length ? starts[i + 1].index : code.length),
      call: code.slice(s.index, parenCallEnd(code, code.indexOf('(', s.index))),
    }));
  }

  test('⑦ 每一步要么自己领预算、要么是同步步骤（无保护的 await 会把关停链楔死）', () => {
    const region = shutdownRegionCode();
    const sites = runStepSites(region);
    // 反向闸：判据不能建立在"根本没几步"上，否则清空步骤同样算通过
    expect(sites.length).toBeGreaterThanOrEqual(12);
    const uncapped = sites
      .filter((s) => !/stepAllowMs\(/.test(s.body))
      .map((s) => s.name)
      .sort();
    expect(uncapped).toEqual([...SYNC_ONLY_STEPS].sort());
    // 清单本身不许长成药签不到名字的僵尸：每条都要在链上真实存在
    expect(uncapped).toHaveLength(SYNC_ONLY_STEPS.length);
    // 领了额度的步骤必须真的把额度交给 runStep 的第三个参数（只有 HTTP/调度器那种
    // "自带 setTimeout"的形态例外，它们把额度用在自己内部的超时上）
    const cappedByRunStep = sites.filter((s) => /,\s*\n?\s*Math\.min\(/.test(s.call));
    expect(cappedByRunStep.map((s) => s.name).sort()).toEqual([
      '关闭 MongoDB 连接',
      '关闭共享缓存',
    ]);
  });

  test('⑧ ⑦ 的牙是实的：同一段源码去掉 cap / 去掉 guardStep，判据必须转红', () => {
    const region = shutdownRegionCode();
    // 反例一：把 Mongo 那一步的 cap 参数抹掉 ⇒ 它必须落进"无保护的 await"
    const noCap = region.replace(/Math\.min\(2000, shutdownBudget\.stepAllowMs\(500\)\)/, '');
    expect(
      runStepSites(noCap)
        .filter((s) => !/stepAllowMs\(/.test(s.body))
        .map((s) => s.name)
    ).toContain('关闭 MongoDB 连接');
    // 反例二：runStep 收了 capMs 却不用（"参数只是个装饰"）⇒ 定义体断言必须转红
    const def = runStepDefinition();
    expect(def).toMatch(/shutdownBudget\.guardStep\(\s*task\s*,\s*capMs\s*\)/);
    expect(def.replace('shutdownBudget.guardStep(task, capMs)', 'task')).not.toMatch(
      /shutdownBudget\.guardStep\(/
    );
  });

  test('⑨ guardStep 行为：卡死不 settle 会被放弃、做完不谎报超时、迟到 reject 不成 unhandledRejection', async () => {
    const { guardStep } = shutdownBudget;

    // ①永不 settle：放弃等待，且如实报 timedOut（这正是 Redis/Mongo 半开时的形态）
    const hung = await guardStep(new Promise(() => {}), 20);
    expect(hung.timedOut).toBe(true);
    expect(hung.error).toBeNull();
    expect(hung.elapsedMs).toBeLessThan(2000);

    // ②预算用尽（allowMs=0）但步骤早就做完了 ⇒ 不许谎报"放弃等待"
    expect((await guardStep(Promise.resolve(), 0)).timedOut).toBe(false);

    // ③还在跑但没到 0ms ⇒ 判超时（与②对照：区分点是"有没有 settle"，不是时长）
    expect((await guardStep(new Promise(() => {}), 0)).timedOut).toBe(true);

    // ④未 begin 预算（Infinity）⇒ 不设闸，但异常仍然只走返回值
    const boom = new Error('boom');
    expect((await guardStep(Promise.reject(boom), Infinity)).error).toBe(boom);

    // ⑤⑥异常不得变成 unhandledRejection：正在关停的进程会被自己的兜底杀掉，
    //    危害比"卡住"更大（退出码与日志都变了），所以这条按"零漏网"断言。
    const seen = [];
    const onHideal = (reason) => seen.push(reason);
    process.on('unhandledRejection', onHideal);
    try {
      const err = new Error('步骤抛错');
      const r = await guardStep(Promise.reject(err), 1000);
      expect(r).toMatchObject({ timedOut: false, error: err });

      // 放弃等待**之后**才 reject：Promise.race 早已消费不到它，
      // 若 guardStep 没有当场给 task 挂上处理器，这一条会在下面被进程事件捕获
      let rejectLate;
      const late = new Promise((_, rej) => {
        rejectLate = rej;
      });
      const abandoned = await guardStep(late, 5);
      expect(abandoned.timedOut).toBe(true);
      rejectLate(new Error('late rejection after abandonment'));
      await new Promise((r2) => setTimeout(r2, 50));
      await new Promise((r2) => setImmediate(r2));
      expect(seen).toEqual([]);
    } finally {
      process.removeListener('unhandledRejection', onHideal);
    }
  });
});
