/**
 * WAL 串行链上的「无人持有的拒绝」闸（第 15 轮，A 线 catch 裸读普查回收）
 *
 * 【为什么单独一条闸，而不是并进 observabilityWritesNeverReject】
 * 那条闸的对象是「观测写入永不 reject」；这里的对象是**一条链的尾巴**：
 * `walChain = walChain.then(fn).catch(handle)` —— handle 就是链的最后一个 handler。
 * handle 自己一抛，被重新赋值的 walChain 就是一个**没有 handler 的 rejected promise**，
 * 而生产侧 src/index.js 的 unhandledRejection 在**所有**环境都 process.exit(1)。
 * 也就是说：一行"把被拒值当 Error 读"的日志语句，足以让整台服务下线，
 * 并且是在审计正要落盘的时刻下线。
 *
 * 【原缺陷（本文件每条用例都先证明它存在过）】
 * 本模块 12 处 catch/链尾 handler 全是裸读 `e.message` / `e.code`。被拒值为非 Error 时
 * （undefined / null / 字符串 / 无 message 的对象）这些语句自己抛 TypeError。后果分三档，
 * 本文件按档给判据：
 *   · 最重：`serialize()` 的默认兜底臂（:521）—— 抛出的 TypeError 让 walChain 变成孤儿
 *     ⇒ 全进程下线；
 *   · 次重：链中断（append 失败后 `.then(() => cap.afterAppend)` 被跳过 ⇒ 这一轮的大小
 *     抽查与裁剪没做）；
 *   · 最隐蔽：病因被改写——值班看到「Cannot read properties of undefined
 *     (reading 'insertedDocs'/'code')」，而真实故障原因（磁盘满 / 文件读不回）被顶掉。
 *     这一档连"拒绝值恰好是 Error"时也会发生（logger 自己在别处抛 ⇒ 日志串已成型）。
 *
 * 【判据层次，缺一层就是假绿】
 *   L7-行为：用 jest.spyOn 把 `fs.promises.appendFile` / `readFile` 真的改成
 *     「以 undefined 拒绝」，跑真实 WAL 路径，断言
 *       ① 探针没抓到孤儿拒绝；
 *       ② 计数器照走（walAppendFailures === 1）；
 *       ③ 第一条日志文本真的发出去了（不是只剩第二条链尾日志）；
 *       ④ 任何一条日志里都不许出现 V8 裸读文本（`Cannot read propert` / `is not a function`）。
 *   L7-前提自证：每轮操作前先 `await expect(桩(...)).rejects.toBe(undefined)`，
 *     证明桩确实在 reject 那个值；操作后再证明对应的告警文本出现了——否则 ① 的空转看不出来。
 *   L7-反向自证：「孤儿拒绝 ⇒ 用例变红」这个前提是被实测钉住的，不是想当然。
 *     第一版这里写的是自己 `process.on('unhandledRejection')` 挂探针——实测收不到：
 *     jest-environment-node 每个测试文件是一个独立 vm context，原生事件挂在**真** process 上，
 *     context 里的 listener 永远不会被调用（探针恒空 ⇒ 三条行为用例的 toHaveLength(0) 全假绿）。
 *     真正在起作用的是 jest-circus：它把用例执行窗口内的孤儿拒绝作为该用例的额外错误抛出
 *     （控制实验：`Promise.reject(new Error('orphan-control'))` 不接 handler ⇒ 该用例直接变红，
 *     错误行号指向 reject 那一行）。本文件因此**不需要**自建探针，且这一条断言由测试框架兜住；
 *     台账 22 的 M1（把 errText 退回裸读）就是这条前提的实证：链尾一抛 ⇒ serialize 那条用例变红。
 *   L7-结构闸：整文件（剥注释视图）里 `e|err|error . message|code|name|stack` 必须为 0 命中；
 *     全总化只认一处实现（不许自带 `const errText = (`）；`${errText(e)}` 恰好 10 处
 *     （计数写成容忍 prettier 折行的形式：第一版写死 `${errText(e)}`，被 prettier 把
 *     超长那处拆成 `errText(\n e\n )` 后立刻少了一个，正是这条计数该抓的形态漂移）；
 *     `.catch((e) =>` 恰好 5 处、`.catch(` 恰好 7 处（形态漂移时"扫不到东西"和
 *     "本来就干净"在 toEqual([]) 上不可区分，只有计数能分开）。扫描器对植入的反例字符串
 *     必须命中，否则空判据。
 *
 * 【够不着的一处，写明而非静默】utils/auditWriteFailure.js:37 的
 * `err && err.message ? err.message : err` 本身就是裸读——它是全总化的**唯一实现**，
 * 短路条件就是它的护栏。全仓推广这条结构闸时它必须进豁免名单，豁免理由即此句。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const wal = require('../../services/auditBufferWal');
const logger = require('../../utils/logger');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');

const SRC = path.resolve(__dirname, '..', '..');
const tick = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 两条尺子的唯一定义（结构闸与同族扩展集共用；此前各写一份，收窄任一份都是静默缩覆盖）。
 *
 * 为什么必须只有一份：反例（planted）要证明的是"**这把尺子量得出裸读**"。
 * 反例若另抄一条正则，把下面任一 alternation 收窄（例如去掉 `|error`，或把
 * `(?:e|err|error)` 改成只认 `e`）时，两条用例照绿、扫描面积静默变小——
 * 那是"用判据给自己作证"的同一种假绿，本仓已为它立过判例。
 */
const BARE_READ = /\b(?:e|err|error)\.(?:message|code|name|stack)\b/g;
const TOTALIZED_SITE = /\$\{errText\(\s*(?:e|err|error)\s*\)\}/g;

describe('WAL 串行链：链尾 handler 自己抛 = 全进程下线', () => {
  let dir;
  let warnSpy;
  let errorSpy;
  let observed;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-wal-orphan-'));
  });

  beforeEach(() => {
    observed = [];
    // 两个级别都要收：removeWalLinesBySeqs 的"读不回文件"是 error，链尾兜底是 warn
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation((m) => {
      observed.push(String(m));
    });
    errorSpy = jest.spyOn(logger, 'error').mockImplementation((m) => {
      observed.push(String(m));
    });
    // 每个用例一份独立 WAL 文件：walPath 是模块级状态，跨用例复用会把上一轮的
    // 待裁剪行留在原地，"这一轮 0 命中"这类判据就不再唯一。
    wal.startup(path.join(dir, `chain-${process.hrtime.bigint()}.wal`));
    wal.resetCounters();
  });

  afterEach(async () => {
    wal.disable();
    wal.resetCounters();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
    await wal.drain();
    await tick(0);
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const text = () => observed.join('\n');
  const V8_BARE_READ = /Cannot read propert|is not a function|reading '/;

  test('serialize 的默认兜底臂：被拒值为 undefined 时不得留下孤儿拒绝', async () => {
    // 与生产调用点同形：auditBuffer.start() 拿到返回值就地丢掉，不接 .catch
    // （它接的是 serialize 的第二个参数 onError，而 onError 缺省才走本模块的兜底臂）
    wal.serialize(async () => {
      throw undefined;
    });
    await tick(60);
    expect(text()).toContain('审计 WAL 链上操作失败'); // 前提自证：兜底臂真的跑了
    expect(text()).not.toMatch(V8_BARE_READ);
  });

  test('appendFile 以非 Error 拒绝：追加计数照走，链尾不留孤儿', async () => {
    const spy = jest.spyOn(fs.promises, 'appendFile').mockRejectedValue(undefined);
    try {
      // 前提自证：桩确实在 reject undefined（不是 resolve，也不是抛 Error）
      await expect(fs.promises.appendFile(path.join(dir, 'p'), 'x', 'utf8')).rejects.toBe(
        undefined
      );
      wal.appendLine('{"action":"probe.append"}\n');
      await wal.drain();
      await tick(30);

      // 计数器必须走：它是"磁盘写不进去"在面板上唯一的可见形态
      expect(wal.getStats().walAppendFailures).toBe(1);
      // 第一条日志必须真的发出去（原缺陷里它在拼字符串时就抛了，只剩第二条链尾日志）
      expect(text()).toContain('审计 WAL 追加失败（累计 1 次）');
      expect(text()).not.toMatch(V8_BARE_READ);
    } finally {
      spy.mockRestore();
    }
  });

  test('readFile 以非 Error 拒绝：裁剪/归档臂的真实原因不许被换成 TypeError', async () => {
    const spy = jest.spyOn(fs.promises, 'readFile').mockRejectedValue(undefined);
    try {
      await expect(fs.promises.readFile(path.join(dir, 'nope'), 'utf8')).rejects.toBe(undefined);
      wal.trimBySeqs(new Set(['run-x-1']));
      wal.discardBySeqs(new Set(['run-x-2']));
      await wal.drain();
      await tick(30);

      // 前提自证：走到了「读不回文件」那条 error 分支，而不是在外面就早退
      expect(text()).toContain('读不回文件');
      expect(text()).toContain('READ_ERROR');
      expect(text()).not.toMatch(V8_BARE_READ);
    } finally {
      spy.mockRestore();
    }
  });

  test('结构闸：本模块每个 catch 臂都不许裸读被拒值，全总化只认一处实现', () => {
    const src = jsCodeOnly(fs.readFileSync(path.join(SRC, 'services/auditBufferWal.js'), 'utf8'));
    expect(src.length).toBeGreaterThan(1000); // 空视图 ⇒ 读取或剥注释坏了

    // 唯一实现 + 不许自带副本（判据归一处）
    expect(src).toContain("const { errText } = require('../utils/auditWriteFailure');");
    expect(src).not.toMatch(/const (?:errText|failureText)\s*=\s*\(/);

    // 整文件零裸读：`?.` 形式不匹配这条模式，所以 err?.code 这类安全写法不会被误伤。
    // 尺子取自模块级 BARE_READ（与同族扩展集同一份，与下面的反例同一份）。
    expect(src.match(BARE_READ) || []).toEqual([]);

    // 站点计数钉死。形式容忍 prettier 折行（`${errText(\n e\n )}`）：
    // 第一版写死单行形式，prettier 把超长那处拆行后计数从 10 掉到 9 —— 那是格式不是判据，
    // 所以尺子要卡在"语义站点"上，而不是卡在换行上。尺子同样取自模块级（只有一份定义）。
    expect((src.match(TOTALIZED_SITE) || []).length).toBe(10);
    expect((src.match(/\.catch\(\(e\) =>/g) || []).length).toBe(5);
    expect((src.match(/\.catch\(/g) || []).length).toBe(7);

    // 扫描器反向自证：**同一把尺子**对植入的反例必须命中。旧写法在这里另抄一条正则
    // （`(?:e|err)`，既不含 error 也不是 BARE_READ），于是把模块级两条尺子的 alternation 收窄
    // ——比如去掉 `|error`——本用例与下面的同族扩展集都照绿，扫描面积静默缩水没人看见。
    // 反例文本因此刻意覆盖三种被拒值名（e / err / error）与两类判据（裸读、全总化站点）。
    const planted =
      'function f(err) { logger.warn(`x：${err.message}`); }' +
      ' const g = (e) => h(e.code, e.name);' +
      ' const p = (error) => logger.warn(`z：${error.name}`);' +
      ' const k = (error) => `${errText(error)}`;' +
      ' const m = (e) => `${errText(\n  e\n)}`;';
    expect(planted.match(BARE_READ)).toEqual(['err.message', 'e.code', 'e.name', 'error.name']);
    expect(planted.match(TOTALIZED_SITE)).toEqual(['${errText(error)}', '${errText(\n  e\n)}']);
    // 判据不许宽到误伤：`?.` 安全写法与别的 errText(...) 调用形态都不该被算成站点
    expect('const q = (e) => `${errText(e.message)}`;'.match(TOTALIZED_SITE)).toBeNull();
  });

  test('结构闸·同族扩展集：WAL/锁/权限推送的 catch 臂同样零裸读，站点计数逐个钉', () => {
    // 这份清单来自第 15 轮 A 线普查：auditBufferWal 是链上最重的一个，其余是它的兄弟模块。
    // 逐个给**站点计数**，因为"这个文件本来就没什么可扫的"和
    // "扫描器扫不到东西"在零命中断言上长得一模一样。
    //
    // scope: 'file' —— 整个文件都是同族臂，可以按全文件零裸读判；
    // scope: 'arm'  —— 该文件只有这一条臂属于本类，其余 `err.message` 是另一回事：
    //   middleware/errorHandler.js 是全局错误处理器，它的 `err` 由路由代码同步 throw 而来
    //   （必然是 Error），它读 err.status/err.name 是在**整形响应**，不是在观测写入的
    //   catch 体里。把整文件塞进零裸读名单会把两种契约混成一条判据（实测第一版就是这么红的：
    //   18 处命中全是响应整形那一路），所以按臂切段判。
    const REGISTRY = [
      { rel: 'services/auditBufferWal.js', scope: 'file', sites: 10 },
      { rel: 'services/auditWalCap.js', scope: 'file', sites: 2 },
      { rel: 'services/sharedCacheLocks.js', scope: 'file', sites: 3 },
      { rel: 'utils/permissionSync.js', scope: 'file', sites: 1 },
      {
        rel: 'middleware/errorHandler.js',
        scope: 'arm',
        anchor: '截断响应的更正审计写入失败',
        sites: 1,
      },
    ];
    const bad = [];
    for (const { rel, scope, sites, anchor } of REGISTRY) {
      const src = jsCodeOnly(fs.readFileSync(`${SRC}/${rel}`, 'utf8'));
      let view = src;
      if (src.length <= 200) bad.push(`${rel}：代码视图过短（读取或剥注释坏了）`);
      // 相对路径按目录层级不同（同目录是 './'），只认模块名
      if (!/require\(['"][^'"]*auditWriteFailure['"]\)/.test(src)) {
        bad.push(`${rel}：没有 require 那个唯一实现`);
      }
      if (scope === 'arm') {
        const at = src.indexOf(anchor);
        const open = src.lastIndexOf('catch (', at);
        // 段尾取"这条语句的 `);`"而不是第一个 `}`：模板串里的 `${errText(err)}` 自己就带
        // 一个右花括号，第一版拿 `}` 当锚，切出来的段刚好在下标处截断 ⇒ 站点数 0（红在计数上，
        // 而不是红在"这个文件没有裸读"上——这正是站点计数存在的意义）。
        const close = at < 0 || open < 0 ? -1 : src.indexOf(');', at);
        // 锚点失配必须报，不能让"切出空串"变成一条恒真的零命中
        if (at < 0 || open < 0 || close < 0) bad.push(`${rel}：臂锚点失配（判据切不出段）`);
        else view = src.slice(open, close);
      }
      const bare = view.match(BARE_READ) || [];
      if (bare.length) bad.push(`${rel}：残留裸读 ${bare.join(', ')}`);
      const n = (view.match(TOTALIZED_SITE) || []).length;
      if (n !== sites) bad.push(`${rel}：全总化站点数 ${n} ≠ 钉住的 ${sites}`);
    }
    // 逐文件收集后一次断言：红的时候直接读出是哪个文件、哪一格坏了
    expect(bad.join('\n')).toBe('');
  });
});
