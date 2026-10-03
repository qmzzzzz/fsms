/**
 * 门禁：连了内存 Mongo 的套件必须自己关连接，且"关"不能是空壳。
 *
 * 起因（2026-10-03 实测）：全量跑时反复出现
 *   "A worker process has failed to exit gracefully and has been force exited."
 * 机理不是超时也不是未 unref 的定时器：mongodb-memory-server 是所有套件共用的同一个 mongod，
 * 一个套件 connect 之后不关，就留下 2 个 hasRef()===true 的 Socket；jest-worker 在最后一个
 * 测试文件之后 500ms（node_modules/jest-worker/build/base/BaseWorkerPool.js:27
 * FORCE_EXIT_DELAY）把 worker 强杀。强杀本身只是难看，**真正贵的是它会吞掉该套件的输出**，
 * 于是"这轮门禁到底过没过"在最需要看结果的时候看不见。
 *
 * 普查（纯 node，可复跑：见交付文档里的脚本）：249 个套件调用 mongoose.connect，
 * 228 个自己关，**21 个从不关**；本轮把其中 17 个干净的补齐（含 1 个"空壳守卫"），
 * 剩 4 个是他人脏文件，登记在下方 LEDGER，由本人修。
 *
 * 本闸的射程与它的下界（第 21 轮补测，全部实测）：采集口径只有
 * `CONNECTS = /mongoose\.connect\s*\(/` 一条，所以 ① 经 helper 连库的套件看不见，
 * 249/228/4 都是**下界**；② 其它句柄族不在射程内。逐类量过的结果：直接 `new Redis(` 且未
 * `jest.mock('ioredis')` 的套件 0 个；`.listen(` 而无 `.close/.stop` 的 0 个；
 * `setInterval` 而无 `clearInterval` 的唯一命中是 `jest.spyOn(global,'setInterval')`（spy 不启定时器）。
 * ⇒ "目前一条 mongoose 口径就够"是测出来的事实，不是巧合；将来谁引入真实 Redis 或自建 http server
 * 的套件，CONNECTS 必须同步扩口径，否则第 1 条用例（漏关集合 == LEDGER 逐字相等）会对新句柄族静默失明。
 *
 * 为什么"空壳守卫"单独成条（src/tests/services/alarmDispatchScopeMatrix.test.js:46 原文）：
 *   if (mongoose.connection.readyState !== 0) {
 *     // 与其它套件共用内存 Mongo：只有本套件建立的连接才关
 *   }
 * 注释承诺关闭、块里零条语句。它的危害大于纯粹的遗漏：**静态 grep 'readyState' 命中、
 * 人眼扫过认为有收尾**，于是这个洞在两轮全量审计里都活着。这类"自我 documenting 的假绿"
 * 是第 6 族，本闸第 4 条用例封它。
 *
 * 为什么不用"一步到位"的修法（把收尾塞进 jest.config.js 的 setupFilesAfterEnv）：
 * jest-circus 的 afterAll 按**注册顺序**跑（node_modules/jest-circus/build/run.js:153
 * `for (const hook of afterAll)`，钩子来自 utils.js:159-177 对 describe.hooks 的顺序 push），
 * setup 文件先于测试文件被 require ⇒ 全局那条**第一个**跑 ⇒ 连接在套件自己的 afterAll
 * 之前就被关掉。实测有 172/228 个套件在自己的 afterAll 里还要用 DB（deleteMany/dropDatabase/
 * findOne…），那就是那个修法的爆炸半径。所以本闸第 5 条把"全局 setup 里关连接"钉成红灯，
 * 并附这条理由——它拦的不是 setupFilesAfterEnv 这个键本身，而是"在那里关连接"这个动作。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SELF = 'src/tests/ci/mongooseTeardownLedger.test.js';

const slash = (p) => path.relative(ROOT, p).split(path.sep).join('/');
function listTestFiles(dir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) listTestFiles(full, acc);
    else if (name.endsWith('.test.js')) acc.push(slash(full));
  }
  return acc;
}
const SCANNED = listTestFiles(path.join(ROOT, 'src/tests'))
  .filter((rel) => rel !== SELF)
  .sort();
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** 采集口径①：这个套件连库了吗 */
const CONNECTS = (text) => /mongoose\.connect\s*\(/.test(text);
/** 采集口径②：这个套件关连接了吗（close / disconnect 两种写法同价） */
const CLOSES = (text) =>
  /connection\.close\s*\(/.test(text) || /mongoose\.disconnect\s*\(/.test(text);

/**
 * 采集口径③：`if (readyState !== 0) { … }` 的块里除了注释还有没有语句。
 * 只认 `!==`（正向守卫=建连那一侧，空块只是没建连，无害）；`===0` 那种空块不在本条射程内，
 * 第 4 条用例把这个边界写成断言，防止将来有人把判据悄悄扩到另一侧去凑数字。
 */
function emptyReadyStateShells(text) {
  const RE = /if\s*\(\s*mongoose\.connection\.readyState\s*!==\s*0\s*\)\s*\{/g;
  const shells = [];
  let m;
  while ((m = RE.exec(text)) !== null) {
    let i = RE.lastIndex;
    let depth = 1;
    while (i < text.length && depth > 0) {
      if (text[i] === '{') depth++;
      else if (text[i] === '}') depth--;
      i++;
    }
    const body = text.slice(RE.lastIndex, i - 1);
    const code = body
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('//') && !l.startsWith('*') && !l.startsWith('/*'));
    if (code.length === 0) shells.push(text.slice(0, m.index).split(/\r?\n/).length);
  }
  return shells;
}

/**
 * 欠账台账：他人脏文件，逐条绑"现在仍然没关"。补好了就必须把条目删掉——
 * 留着会在"站点已修"这条用例里红，防止台账变成可以无限堆积的豁免筐。
 */
const LEDGER = [
  {
    rel: 'src/tests/ci/fieldErrorsEgressGate.test.js',
    owner: '他人 staged（A）',
    note: '并行 agent 本轮新建的门禁套件，不代改；在文件末尾补 root 级 afterAll 内 await mongoose.connection.close()',
  },
  {
    rel: 'src/tests/controllers/reportExportRowOrderAndCells.test.js',
    owner: '他人脏文件（M）',
    note: '同族漏关：在文件末尾补 root 级 afterAll，内 await mongoose.connection.close()',
  },
  {
    rel: 'src/tests/services/auditUsernameCastGate.test.js',
    owner: '他人脏文件（M）',
    note: '同族漏关：在文件末尾补 root 级 afterAll，内 await mongoose.connection.close()',
  },
  {
    rel: 'src/tests/services/observabilityWritesNeverReject.test.js',
    owner: '他人脏文件（AM）',
    note: '同族漏关：在文件末尾补 root 级 afterAll，内 await mongoose.connection.close()',
  },
];

/**
 * 判据（唯一一份）：关连接只能出现在最后一条 root 级 afterAll 里。
 * 循环和下面的合成反例必须共用这个函数——上一版把断言直接写在 for 里、另外单独断言
 * `CLOSES(bad…)` 的子串，于是把循环里那句改成恒真，反例照样绿（T7 实测存活）：
 * 反例证明的是尺子能分辨，不是那条规则还在生效。
 *
 * 切片按"每条 root 钩子一段"来切，而不是"看最后一段有没有 close"。
 * 后者是上一版的写法，它问错了问题：close 只要不在最后一段就直接返回"不违规"，
 * 于是"close 写在第一条、后面那条不 close"这个本条要禁的形状反而漏网（baseline 实测 got=false）。
 * 正确的问法是：除去最后一段，前面的任何一段里出现 close 就是违规。
 */
function rootCloseNotLast(text) {
  const starts = [...text.matchAll(/^afterAll\(/gm)].map((x) => x.index);
  if (starts.length < 2) return false; // 零条/一条 root 钩子 ⇒ 无从谈"位置"
  const segs = starts.map((s, i) =>
    text.slice(s, i + 1 < starts.length ? starts[i + 1] : text.length)
  );
  return segs.slice(0, -1).some((seg) => CLOSES(seg));
}

const offenders = SCANNED.filter((rel) => {
  const text = read(rel);
  return CONNECTS(text) && !CLOSES(text);
}).sort();

describe('套件级 mongoose 收尾：连了必关，关不能是空壳', () => {
  test('漏关集合与台账逐字相等：新增漏关红，补好赖着不删条目也红', () => {
    expect(offenders).toEqual(LEDGER.map((e) => e.rel).sort());
    expect(new Set(LEDGER.map((e) => e.rel)).size).toBe(LEDGER.length);
  });

  test('台账每条都还欠着，且 owner 不是空话（晋升目标预登记）', () => {
    for (const e of LEDGER) {
      expect(fs.existsSync(path.join(ROOT, e.rel))).toBe(true);
      expect(CONNECTS(read(e.rel))).toBe(true);
      expect(CLOSES(read(e.rel))).toBe(false);
      expect(e.owner.length).toBeGreaterThanOrEqual(4);
      expect(/他人/.test(e.owner)).toBe(true);
      // 归属要能被别人复核：括号里必须带 git 状态码（A / M / AM），
      // 否则"他人脏文件"这四个字既可能是真的，也可能是条目烂在台账里的借口。
      expect(/（[AM]{1,2}[ ）]/.test(e.owner)).toBe(true);
      expect(e.note.length).toBeGreaterThanOrEqual(8);
      // 条目必须写出**怎么晋升**：只写"漏关"的条目等于把活儿留给下一个读它的人，
      // 而本闸要的是"删掉这条的唯一路径是照 note 改文件"。
      expect(/afterAll/.test(e.note)).toBe(true);
      expect(/close|disconnect/.test(e.note)).toBe(true);
    }
    // 上限：豁免位不能长成一个合法的盲区。本轮实测 4，留 2 位余量给并行开发。
    expect(LEDGER.length).toBeLessThanOrEqual(6);
  });

  test('已修的一侧不是空集合：证明这条判据认得出"有关闭"（否则恒假也能全绿）', () => {
    const fixed = SCANNED.filter((rel) => {
      const t = read(rel);
      return CONNECTS(t) && CLOSES(t);
    });
    // 地板取实测下方一档（本轮 245）；采集器被改成恒假/恒真都会在这里露出来
    expect(fixed.length).toBeGreaterThanOrEqual(240);
    expect(SCANNED.length).toBeGreaterThanOrEqual(500);
  });

  test('第 6 族：readyState 守卫不许是"注释承诺、块里空的"空壳', () => {
    const hit = SCANNED.flatMap((rel) =>
      emptyReadyStateShells(read(rel)).map((ln) => `${rel}:${ln}`)
    );
    expect(hit).toEqual([]);
    // 合成反例：判据必须认得出空壳（把真修法文件逐条核之前，先确认这把尺子不是假的）
    const shell = [
      'afterAll(async () => {',
      '  if (mongoose.connection.readyState !== 0) {',
      '    // 只有本套件建立的连接才关',
      '  }',
      '});',
    ].join('\n');
    expect(emptyReadyStateShells(shell)).toEqual([2]);
    // 正向对照：同样的守卫里有真语句 ⇒ 不算空壳
    const real = shell.replace('  }', '    await mongoose.connection.close();\n  }');
    expect(emptyReadyStateShells(real)).toEqual([]);
    // 边界：反向守卫（===0 时建连）的空块不在本条射程内，别被顺手扩成判据
    const reverse = 'if (mongoose.connection.readyState === 0) {\n  // 交给 globalSetup\n}';
    expect(emptyReadyStateShells(reverse)).toEqual([]);
  });

  test('一步到位的修法被钉住：不得在 setupFilesAfterEnv 指向的文件里关连接', () => {
    // 判据抽成纯函数，真配置和合成反例走同一条尺子（否则"现在没有这个键"会让这条变成死断言）
    const globalClosers = (cfgText) => {
      const m = cfgText.match(/setupFilesAfter(?:Each|Env)\s*:\s*\[([\s\S]*?)\]/);
      if (!m) return [];
      return [...m[1].matchAll(/'([^']*\.js)'/g)]
        .map((x) => x[1].replace(/<rootDir>\//, ''))
        .filter((rel) => {
          const abs = path.join(ROOT, rel);
          return fs.existsSync(abs) && CLOSES(fs.readFileSync(abs, 'utf8'));
        });
    };
    const cfg = read('jest.config.js');
    expect(globalClosers(cfg)).toEqual([]);
    // 控制组①：加了键、指向一个不关连接的文件 ⇒ 仍然放行（本条不拦这个键本身）
    fs.writeFileSync(
      path.join(ROOT, 'src/tests/ci/__ctrl_noop.js'),
      'module.exports = async () => {};\n'
    );
    try {
      expect(
        globalClosers("setupFilesAfterEnv: ['<rootDir>/src/tests/ci/__ctrl_noop.js'],")
      ).toEqual([]);
    } finally {
      fs.unlinkSync(path.join(ROOT, 'src/tests/ci/__ctrl_noop.js'));
    }
    // 控制组②： planted 那个"在 setup 里关连接"的修法 ⇒ 必须红
    fs.writeFileSync(
      path.join(ROOT, 'src/tests/ci/__ctrl_close.js'),
      "const mongoose = require('mongoose');\nafterAll(async () => mongoose.connection.close());\n"
    );
    try {
      expect(
        globalClosers("setupFilesAfterEnv: ['<rootDir>/src/tests/ci/__ctrl_close.js'],")
      ).toEqual(['src/tests/ci/__ctrl_close.js']);
    } finally {
      fs.unlinkSync(path.join(ROOT, 'src/tests/ci/__ctrl_close.js'));
    }
  });

  test('收尾的位置：root 级 afterAll 关连接时，它必须是最后一条 root 钩子', () => {
    // 根块 afterAll 按注册顺序跑（jest-circus run.js 用 getAllHooksForDescribe 顺序遍历
    // describe.hooks，utils.js 按注册顺序 push）⇒ 谁写在最后谁最后执行。
    // close 写在前面，就会在本套件其它 afterAll 还在用 DB 时把连接掐掉——这正是"全局 setup"修法的翻车点。
    const candidates = SCANNED.filter((rel) => {
      const t = read(rel);
      return CONNECTS(t) && CLOSES(t) && /^afterAll\(/m.test(t);
    });
    // 真数据一侧只证明"不误伤"：实测全仓连库套件里没有第二条 root 级 afterAll（probe-root-close-order.js:
    // 连库且多条 root 钩子=0），所以这一圈循环不可能抓出现行违规，鉴别力全部由下面的合成反例承担。
    // 把这句当作"已经证明位置规则有效"是自欺；将来出现多条 root 钩子的套件时，循环才会开始有牙。
    for (const rel of candidates) expect(rootCloseNotLast(read(rel))).toBe(false);

    // 判据的鉴别力：同一条规则喂四种形状，答案必须各不相同、且不是"只看最后一段"。
    const close = 'afterAll(async () => { await mongoose.connection.close(); });';
    const cleanup = 'afterAll(async () => { await User.deleteMany({}); });';
    const head = 'const mongoose = require("mongoose");';
    const cases = [
      // close 在第一条、最后一条不 close ⇒ 上一版判据在这里漏网（它先看最后一段有没有 close）
      {
        text: [head, close, cleanup].join('\n'),
        want: true,
        why: 'close 抢在最后一条清理钩子之前',
      },
      // 三条 root 钩子，close 在中间 ⇒ 只检查首/尾两种位置都抓不到
      { text: [head, cleanup, close, cleanup].join('\n'), want: true, why: 'close 夹在中间' },
      // 前后都 close ⇒ 仍然违规（前那次会提前掐断）
      { text: [head, close, cleanup, close].join('\n'), want: true, why: '重复收尾' },
      // close 就在最后一条 ⇒ 合法
      { text: [head, cleanup, close].join('\n'), want: false, why: 'close 是最后一条 root 钩子' },
      // 只有一条 root 钩子 ⇒ "位置"不适用，判据必须闭嘴（否则它退化成"见到 close 就报"）
      { text: [head, close].join('\n'), want: false, why: '单条 root 钩子无所谓先后' },
      // describe 内的缩进 afterAll 不是 root 钩子：本判据的射程只有 root 级，
      // 把锚 `^` 去掉就会把它也算进来（T11 实测）。内层钩子的执行顺序是另一条线，本闸不认领。
      {
        text: [
          head,
          'describe("x", () => {',
          '  afterAll(async () => { await mongoose.connection.close(); });',
          '});',
          close,
        ].join('\n'),
        want: false,
        why: '缩进的钩子不在 root 级',
      },
    ];
    for (const c of cases) expect(rootCloseNotLast(c.text)).toBe(c.want);
    // 尺子不是常量：同一批输入必须同时给出 true 和 false
    expect(new Set(cases.map((c) => rootCloseNotLast(c.text))).size).toBe(2);
    expect(candidates.length).toBeGreaterThanOrEqual(16);
  });
});
