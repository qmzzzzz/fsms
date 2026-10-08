/**
 * 「观测性写入永不 reject」契约闸（第 14 轮）
 *
 * 为什么值得写：本仓 src/index.js 的 unhandledRejection 兜底在**所有环境**都
 * process.exit(1)（第 12 轮的 WS 监听器、第 13 轮的 transaction 清理臂都是同一条等式）。
 * 而热路径上有两处**故意不 await 的裸调用**，它们的"吞错"完全靠被调方的注释承诺：
 *   1. src/middleware/auth.js 的 assertSessionUsable ⇒ sessionService.touchSession(sid, req)
 *      （每个已认证请求都会打一次；注释明写"touchSession 的契约是永不 reject"，因此不挂 .catch）；
 *   2. src/index.js 启动期 ⇒ wsServiceInstance.initSharedAdapter()
 *      （注释明写"失败仅告警降级，不阻断服务"）。
 * 注释承诺一旦失实，表现不是"某个功能坏了"，而是**整个进程下线**——而且是在最繁忙的路径上下线。
 *
 * 本闸原来就有的洞：touchSession 的 catch 体写的是 `${err.message}`。上游抛 Error 时没事；
 * 但**非 Error 形态的拒绝**（`Promise.reject(undefined)` / reject 字符串）会让这行本身抛
 * TypeError，而它位于 catch 内 ⇒ async 函数转为 reject ⇒ 那条裸调用变成无人持有的拒绝。
 * 也就是说"永不 reject"这个契约**曾经是条件成立的**（只在上游守规矩时成立），
 * 而契约类注释的正确写法是无条件成立。现已修成 `${err?.message ?? err}`。
 *
 * 四层判据，缺一层就是假绿：
 *   L1 行为：五种拒绝形态（Error / undefined / null / 字符串 / 普通对象）都必须 resolve(false)；
 *   L2 前提自证：桩**确实会 reject**（否则 L1 的 resolves 断言恒真），且形态里含非 Error
 *      （原缺陷只在非 Error 形态暴露——只测 Error 就等于没测）；
 *   L3 结构闸：touchSession 体内 `try {` 之前不得有任何语句
 *      （把 key 计算/节流表读写提出 try 就会破坏契约，而 L1 完全测不出来——L1 只覆盖 try 内的失败）；
 *   L4 调用点闸：两处裸调用的处置必须与契约配套——auth.js 依赖契约，因此那行注释必须还在；
 *      index.js 的 initSharedAdapter 必须**持有** promise（.catch 或 await）。
 *
 * L5（同轮追加，第 3 个实例）：`src/services/deviceReminder.js` 的调度器。
 *   setTimeout/setInterval 的回调是**同步**函数：回调 return 时里面发起的 promise 还在飞，
 *   无人持有 ⇒ 一次拒绝 = 全进程下线。实测两处 `markOverdueInspections()` 都是裸调用，
 *   而三条 `.catch((err) => logger.error(\`${err.message}\`))` 处理器自身可抛（处理器抛错
 *   产生的是**第二个**无人持有的拒绝——兜底等于没有）。修法是调用点一律 `.catch` + 形参一律
 *   `err?.message ?? err`；判据做成"扫描该文件全部 async 调用点并按 after 分类"，
 *   并钉住站点数（6）——形态漂移时扫描器会静默返回空，只有计数能发现它。
 *
 * L6（同轮追加，第 4 个实例）：`auditBuffer.flush` 的失败处置臂与判定层的两条文案。
 *   与前几层的差别在于它是**两层串联**的：`collectDurableIds` 裸读 `err.insertedDocs` 会先把
 *   nullish 拒绝换成一个 TypeError，于是下游 `outageMessage(err)` 的裸读永远走不到——
 *   只修任一层都测不出另一层，实测（第 21 轮台账 V1/V2）两层各修一次才都变红。
 *   同时"全总化"在本文件不再自带副本：唯一实现是 `utils/auditWriteFailure.js` 的 `errText`
 *   （本仓已有第三份副本 loggerFlush.js:215 的 errText 是 console 兜底路径，够不着这里）。
 */
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const SRC = path.resolve(__dirname, '..', '..');
const readSrc = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');
/** 剥注释（块注释 + 整行 //），保持行号不变 */
const blank = (s) =>
  s
    .replace(/\/\*[\s\S]*?\*\//g, (m) => '\n'.repeat((m.match(/\n/g) || []).length))
    .replace(/^[ \t]*\/\/.*$/gm, '');

describe('观测性写入的「永不 reject」契约', () => {
  let sessionService;
  let UserSession;
  const fakeReq = (ip = '10.0.0.1') => ({ get: () => '', ip });
  let seq = 0;
  /** 每个用例独立 sid：touchSession 有 60s 节流表，同 sid 第二次直接 return false 会绕开写路径 */
  const freshSid = () => `sid-neverreject-${Date.now()}-${(seq += 1)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    sessionService = require('../../services/sessionService');
    UserSession = require('../../models/UserSession');
  });

  afterEach(() => jest.restoreAllMocks());

  describe('L1+L2 行为：任何拒绝形态都必须被就地吞掉', () => {
    // 关键设计：拒绝值**不能只有 Error**。原缺陷只在非 Error 形态下暴露。
    const REJECTION_SHAPES = [
      ['Error', new Error('write failed')],
      ['undefined', undefined],
      ['null', null],
      ['字符串', 'boom'],
      ['普通对象', { code: 'EWRITE' }],
    ];

    test.each(REJECTION_SHAPES)(
      'updateOne 以 %s 拒绝 ⇒ touchSession 必须 resolve(false)',
      async (_label, reason) => {
        jest.spyOn(UserSession, 'updateOne').mockRejectedValue(reason);
        await expect(sessionService.touchSession(freshSid(), fakeReq())).resolves.toBe(false);
      }
    );

    test('前提自证：桩确实处于 rejected 状态（否则上面五条恒真）', async () => {
      for (const reason of [undefined, new Error('x')]) {
        jest.spyOn(UserSession, 'updateOne').mockRejectedValue(reason);
        const state = await UserSession.updateOne({ sid: 'probe' }, { $set: {} }).then(
          () => 'fulfilled',
          () => 'rejected'
        );
        expect(state).toBe('rejected');
      }
    });

    test('前提自证：拒绝形态里必须包含非 Error（只测 Error 就测不到本闸要防的洞）', () => {
      const nonError = REJECTION_SHAPES.filter(([, r]) => !(r instanceof Error)).map(([l]) => l);
      expect(nonError.length).toBeGreaterThanOrEqual(3);
      expect(nonError).toEqual(expect.arrayContaining(['undefined', 'null', '字符串', '普通对象']));
    });

    test('反向自证：把 catch 体退回 err.message 的形态，非 Error 拒绝就会 reject（证明 L1 有牙）', async () => {
      // 这一段不碰生产码，只在本地复刻缺陷形状，用来证明"契约只在 Error 时成立"不是空话
      const broken = async () => {
        try {
          await Promise.reject(undefined);
          return true;
        } catch (err) {
          return `失败：${err.message}`; // 缺陷形状：非 Error 拒绝时这行抛 TypeError
        }
      };
      const fixed = async () => {
        try {
          await Promise.reject(undefined);
          return true;
        } catch (err) {
          return `失败：${err?.message ?? err}`;
        }
      };
      await expect(broken()).rejects.toBeInstanceOf(TypeError);
      await expect(fixed()).resolves.toBe('失败：undefined');
    });
  });

  describe('L3 结构闸：契约成立是因为整个函数体都在 try 内', () => {
    test('touchSession 的 try 之前不得有任何语句（锚点失配必须抛，不许静默通过）', () => {
      const src = blank(readSrc('services/sessionService.js'));
      const m = /const touchSession\s*=\s*async\s*\([^)]*\)\s*=>\s*\{([\s\S]*?)\btry\s*\{/.exec(
        src
      );
      if (!m) throw new Error('touchSession 形状变了，本闸的切片失效——先修闸再改码');
      // try 之前只允许空白（注释已被剥掉；原先的注释块讲的就是这条契约）
      expect(m[1].trim()).toBe('');
      // 且函数确实有 catch：否则"try 内"也救不了 reject
      const fnEnd = src.indexOf('const revokeSession');
      expect(fnEnd).toBeGreaterThan(m.index);
      const body = src.slice(m.index, fnEnd);
      expect(/catch\s*\(/.test(body)).toBe(true);
      expect(body).toMatch(/return false;\s*\}/);
    });

    test('catch 体内不得裸读被拒值的属性（非 Error 拒绝会把 catch 自己变成拒绝源）', () => {
      const src = blank(readSrc('services/sessionService.js'));
      const start = src.indexOf('const touchSession');
      if (start < 0) throw new Error('touchSession 锚点未命中');
      const body = src.slice(start, src.indexOf('const revokeSession', start));
      const catchArm = /catch\s*\(\s*(\w+)\s*\)\s*\{([\s\S]*?)\n {2}\}/.exec(body);
      if (!catchArm) throw new Error('catch 臂切片失效');
      const [, name, armText] = catchArm;
      const bareRead = new RegExp(`\\b${name}\\.\\w`); // 形如 err.message —— 未加 ?. 的直接属性读
      expect(bareRead.test(armText)).toBe(false);
      // 前提自证：这个臂里确实读到了被拒值（否则上面那条断言可能只是切片切空）
      expect(armText).toMatch(new RegExp(`\\b${name}\\s*\\?\\.\\s*message`));
      expect(armText).toMatch(/logger\.warn\(/);
    });
  });

  describe('L4 调用点闸：裸调用必须与契约配套', () => {
    test('auth.js 的裸调用仍在，且紧邻的注释仍声明"永不 reject"（注释即事实）', () => {
      const src = readSrc('middleware/auth.js');
      const callIdx = src.indexOf('sessionService.touchSession(decoded.sid, req);');
      expect(callIdx).toBeGreaterThan(-1);
      // 这行确实是裸调用（前面没有 await/return）——它之所以允许裸，唯一理由就是下一条
      const lineStart = src.lastIndexOf('\n', callIdx - 1) + 1;
      expect(src.slice(lineStart, callIdx).trim()).toBe('');
      // 契约声明必须写在调用点上方（往上取 8 行；删掉注释而不改代码，本条必须响）
      const above = src.slice(0, lineStart).split(/\r?\n/).slice(-8).join('\n');
      expect(above).toMatch(/永不\s*reject/);
      // 反向自证：同一判据对"没有契约声明"的样本必须判 false（否则本条恒真）
      expect(/永不\s*reject/.test('  sessionService.touchSession(a, b);\n  return null;\n')).toBe(
        false
      );
    });

    /**
     * 一行里对某个 async 调用的处置是"持有"还是"浮动"（L4/L5 与反向自证共用同一个判据，
     * 不让两处各写一份规则——本仓吃过"扫描器与判据口径不一致"的亏）。
     * 简化口径：同一行出现 await/return/void 即视为持有；`)` 后紧跟 .catch(/.then( 也算持有。
     */
    const classifyCallLine = (line, name = 'initSharedAdapter') => {
      const m = new RegExp(`\\b${name}\\s*\\(\\s*\\)`).exec(line);
      if (!m) return 'absent';
      const before = line.slice(0, m.index);
      if (/(?:^|[^.\w])(?:await|return|void)\b/.test(before)) return 'held';
      if (/^\s*\.\s*(?:catch|then)\s*\(/.test(line.slice(m.index + m[0].length))) return 'held';
      if (/^\s*;/.test(line.slice(m.index + m[0].length))) return 'floating';
      return 'unknown';
    };

    test('index.js 的 initSharedAdapter 调用必须被持有（await 或 .catch），且只有一个调用点', () => {
      const lines = blank(readSrc('index.js')).split(/\r?\n/);
      const sites = lines
        .map((l, i) => [i + 1, classifyCallLine(l)])
        .filter(([, k]) => k !== 'absent');
      expect(sites.length).toBe(1);
      expect(sites[0][1]).toBe('held');
    });

    test('反向自证：四种写法必须被分到 floating / unknown / held / held（否则上一条恒真）', () => {
      expect(classifyCallLine('  wsServiceInstance.initSharedAdapter();')).toBe('floating');
      expect(classifyCallLine('  wsServiceInstance.initSharedAdapter()')).toBe('unknown');
      expect(classifyCallLine('  wsServiceInstance.initSharedAdapter().catch(() => {});')).toBe(
        'held'
      );
      expect(classifyCallLine('  await wsServiceInstance.initSharedAdapter();')).toBe('held');
      expect(classifyCallLine('  initSharedAdapter(otherThing);')).toBe('absent');
    });
  });

  describe('L5 调度器：定时器回调里的每个 promise 都必须就地持有', () => {
    // 为什么单独立一层：setTimeout/setInterval 的回调是**同步**函数，它 return 时
    // 回调里发起的 promise 还在飞；此时无人持有 ⇒ 一次拒绝就是全进程下线。
    // 第 14 轮实测 `markOverdueInspections()` 在这两处都是裸调用（首次扫描 + 周期扫描）。
    const FILE = 'services/deviceReminder.js';
    const ASYNC_NAMES = ['scanDeviceReminders', 'markOverdueInspections'];

    /** 括号配平地找出 `name(` 的调用点，返回其后紧跟的文本（用于判 .catch / ;） */
    function callSites(src, name) {
      const out = [];
      const re = new RegExp(`\\b${name}\\s*\\(`, 'g');
      for (let m = re.exec(src); m !== null; m = re.exec(src)) {
        // await/return/void 领头的算"持有"，但仍要计入站点数：
        // 浮动判据只看 after，而"扫描器有没有失灵"要看总数，两者不能共用一次 continue
        const keywordHeld = /(?:await|return|void)\b[^;{}]*$/.test(src.slice(0, m.index));
        let i = m.index + m[0].length - 1; // 停在开括号
        let depth = 0;
        do {
          if (src[i] === '(') depth += 1;
          else if (src[i] === ')') depth -= 1;
          i += 1;
        } while (depth > 0 && i < src.length);
        out.push({
          line: src.slice(0, m.index).split(/\r?\n/).length,
          after: src.slice(i, i + 20),
          text: src.slice(m.index, i),
          held: keywordHeld,
        });
      }
      return out;
    }

    test('前提自证：扫描器在本文件真的找到调用点，且能区分持有/浮动', () => {
      const src = blank(readSrc(FILE));
      const all = ASYNC_NAMES.flatMap((n) => callSites(src, n));
      // 钉死站点数：掉了说明书写形态变了（或有人删了调度器）——锚点失配必须响，不能静默返回空
      expect(all.length).toBe(6);
      expect(all.filter((s) => s.held).length).toBe(2); // 两处 return await
      expect(all.filter((s) => /^\s*\.catch\(/.test(s.after)).length).toBe(4); // 调度器四处
      // 反向自证：拿一个已知的浮动样本，扫描器必须判它浮动
      expect(callSites('  markOverdueInspections();\n', 'markOverdueInspections')[0].after).toBe(
        ';\n'
      );
      expect(
        callSites('  markOverdueInspections().catch(() => {});\n', 'markOverdueInspections')[0]
          .after
      ).toMatch(/^\s*\.catch\(/);
    });

    test('浮动调用必须为 0：每个 promise 都被 await / .catch / .then 接住', () => {
      const src = blank(readSrc(FILE));
      const floating = ASYNC_NAMES.flatMap((n) => callSites(src, n)).filter(
        (s) => !s.held && /^\s*;/.test(s.after)
      );
      expect(floating.map((s) => `${s.line}: ${s.text}`)).toEqual([]);
    });

    test('catch 臂与 .catch 处理器都不得裸读被拒值（非 Error 拒绝会把"吞错"变成"再抛"）', () => {
      const src = blank(readSrc(FILE));
      const start = src.indexOf('const markOverdueInspections');
      if (start < 0) throw new Error('markOverdueInspections 锚点未命中');
      const body = src.slice(start, src.indexOf('const getDeviceReminders', start));
      expect(/catch\s*\(/.test(body)).toBe(true);

      // 全文件的 catch 形参（`catch (err)`）与 .catch 箭头形参（`(err) =>`）逐个判：
      // 只要出现 `${name.prop}` 形态的裸读就算失守（正确形态是 `${name?.prop ?? name}`）。
      const params = new Set();
      for (const m of src.matchAll(/catch\s*\(\s*(\w+)\s*\)/g)) params.add(m[1]);
      for (const m of src.matchAll(/\.catch\(\(\s*(\w+)\s*\)\s*=>/g)) params.add(m[1]);
      expect([...params].sort()).toEqual(['err']); // 钉住形态集合：新增别的形参名要先解释
      for (const name of params) {
        // 不加 /g：jest 的 toMatch 走 RegExp.test，带 lastIndex 状态会让两条断言互相污染
        const bare = new RegExp(`\\$\\{\\s*${name}\\s*\\.\\s*\\w`);
        expect(`${FILE} 裸读 ${name}.x`).not.toMatch(bare);
        // 前提自证：同一条正则对缺陷样本必须命中（否则上面是恒真断言）。
        // `\${` 是字面量 ${ —— 样本必须和缺陷形态逐字符同形，光写 err.message 测不到 `${` 那一半
        expect(`失败：\${${name}.message}`).toMatch(bare);
      }
      // 修法必须在场（不是"没有裸读"就等于"有可选链"——切片切空也会两皆为零）
      expect((src.match(/\?\.\s*message\s*\?\?\s*err/g) || []).length).toBe(5);

      // 调度器里四条 .catch 处理器：数目钉死，摘掉一条必须响
      const sched = src.slice(src.indexOf('const startReminderScheduler'));
      expect((sched.match(/\.catch\(/g) || []).length).toBe(4);
    });

    test('行为（真跑）：五种拒绝形态下 markOverdueInspections 都必须 resolve(0)', async () => {
      const Inspection = require('../../models/Inspection');
      const { markOverdueInspections } = require('../../services/deviceReminder');
      const shapes = [
        ['Error', new Error('driver down')],
        ['undefined', undefined],
        ['null', null],
        ['字符串', 'boom'],
        ['普通对象', { code: 'EWRITE' }],
      ];
      for (const [_label, reason] of shapes) {
        const spy = jest
          .spyOn(Inspection, 'updateMany')
          .mockImplementation(() => Promise.reject(reason));
        // 前提自证：桩确实在 reject（否则下面的 resolves 恒真）
        await expect(Inspection.updateMany({}, {})).rejects.toBe(reason);
        await expect(markOverdueInspections()).resolves.toBe(0);
        spy.mockRestore();
      }
      expect(shapes.length).toBe(5);
    });
  });

  /**
   * L6（同轮追加，第 4 个实例）：`auditBuffer.flush` 的 catch 体 + `auditBufferDocs` 的对账读。
   *
   * 这里的缺陷是**两层串联**的，实测顺序本身就是判据（只修上层会被下一层继续挡住）：
   *
   *  A. `auditBufferDocs.collectDurableIds(err, docs)` 裸读 `err.insertedDocs`
   *     （src/services/auditBufferDocs.js:144）。它跑在 flush 内层 `catch (insertErr)` 里，
   *     被拒值是 undefined 时这一句自己抛 TypeError ⇒ 真实失败原因被顶掉：运维看到的是
   *     「Cannot read properties of undefined (reading 'insertedDocs')」而不是「落库为什么失败」。
   *     观测代码把病因改了，等于观测面说谎（且 B 被 A 掩盖，单独看 B 永远测不到）。
   *  B. 修掉 A 之后 nullish 才真的走到 `else` 支的 `logger.error(outageMessage(err))`，
   *     而 `outageMessage` 读的是裸 `err.name`。走进这一支的**恰好就是非 Error 拒绝**——
   *     `isContentAttributableFailure` 的第一行是 `if (!err || typeof err !== 'object') return false`
   *     （src/utils/mongoFailureAttribution.js:224），于是 undefined/null/字符串一律落到 else 分支。
   *     catch 体内再抛三连后果：
   *     ① flush() 返回一个新的 rejection，"落库失败不阻断主流程"的契约破裂；
   *     ② catch 体后半段的 `unshiftChunked(retryDocs)` 再也不执行 ⇒ 这批文档的**内存副本消失**
   *        （WAL 未启用的窗口里连崩溃重放这层保险也没有，droppedCount 还不计）；
   *     ③ 同 A：真实原因被顶掉。
   *
   * 判据取"终态"：四种拒绝形态下 flush 都不 reject、批次都回到缓冲、**且任何一条观测日志里
   * 都不许出现 V8 的裸读报错字样**（出现即说明原因被观测代码自己的抛错顶掉了）。
   */
  describe('L6 auditBuffer.flush：catch 体的观测与回退都不能被非 Error 拒绝打断', () => {
    const STAMP = `${Date.now()}`.slice(-7);
    /** action/category/username 是仅有的三个 required（形态对齐 auditBufferPrecastGate） */
    const doc = (tag) => ({
      action: `nr_${tag}_${STAMP}`,
      category: 'auth',
      username: `u_${STAMP}`,
      ip: '127.0.0.1',
      path: '/api/audit',
      statusCode: 200,
      success: true,
    });

    test('四种非 Error 拒绝形态：flush 不 reject、批次回到缓冲、outage 告警照发', async () => {
      const auditBuffer = require('../../services/auditBuffer');
      const wal = require('../../services/auditBufferWal');
      const AuditLog = require('../../models/AuditLog');
      const logger = require('../../utils/logger');
      const shapes = [
        ['undefined', undefined],
        ['null', null],
        ['字符串', 'boom'],
        ['无 message 的普通对象', { code: 11000 }],
      ];
      const errSpy = jest.spyOn(logger, 'error').mockImplementation(() => {});
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      let outageLogged = 0;
      for (const [tag, reason] of shapes) {
        await wal.drain();
        auditBuffer.__resetForTest();
        const insertSpy = jest
          .spyOn(AuditLog, 'insertMany')
          .mockImplementation(() => Promise.reject(reason));
        // 前提自证：桩确实在 reject 这个值（否则下面的 resolves 恒真）
        await expect(AuditLog.insertMany([{ action: 'probe' }], { ordered: false })).rejects.toBe(
          reason
        );
        for (let i = 0; i < 3; i += 1) auditBuffer.push(doc(tag));
        // 反向自证：文档得真的进得了缓冲，且预铸造闸没把它们提前拒掉
        // （整批被拒时 flush 会在 withChainLock 里 `docs.length === 0` 早退，那样本用例就空转）
        expect(auditBuffer.getStats().bufferLength).toBe(3);

        await expect(auditBuffer.flush()).resolves.toBeUndefined();
        // 数据不丢：回退发生在 catch 体后半段，它不许被观测代码的抛错带走
        expect(auditBuffer.getStats().bufferLength).toBe(3);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('审计日志批量落库失败'));
        // A 层的判据：观测日志里不许出现 V8 裸读报错——出现就说明真实原因被顶掉了
        const observed = [...warnSpy.mock.calls, ...errSpy.mock.calls].map((c) => String(c[0]));
        expect(observed.join('\n')).not.toMatch(/Cannot read propert|is not a function/);
        if (String(errSpy.mock.calls[0]?.[0]).includes('不可归因于文档内容')) outageLogged += 1;

        insertSpy.mockRestore();
        errSpy.mockClear();
        warnSpy.mockClear();
      }
      /**
       * "不丢弃"告警全程只响一次：auditBuffer 自己按 `outageFailures === 1 || %5 === 0` 节流
       * （src/services/auditBuffer.js 的 else 分支），本文件里 outageFailures 从 0 起、
       * 四轮依次 1/2/3/4 ⇒ 只有首轮可闻。计数写成 1 而不是 >=1：
       * 谁把节流放宽或收紧都会在这里响，而不是悄悄改变观测面。
       */
      expect(outageLogged).toBe(1);
      expect(shapes.length).toBe(4);
    });

    test('结构闸：失败处置臂里不许出现裸 `.message`，且全总化只认一处实现', () => {
      const src = blank(readSrc('services/auditBuffer.js'));
      // 失败处置臂自 flush 的 catch 外提到 handleFlushFailure（棘轮在这里是"该拆了"的信号）。
      // 锚点失配必须抛——切片切空/切穿会让下面每条断言都"零命中=通过"
      // （注意 end 锚只能取代码行：blank() 已把注释抹成空行，拿 JSDoc 当锚必失配）
      const from = src.indexOf('function handleFlushFailure(');
      const to = src.indexOf('async function flush()', from);
      if (from < 0 || to < from) {
        throw new Error(
          `结构闸锚点失配：auditBuffer.js 的处置臂边界没找到（from=${from}, to=${to}）`
        );
      }
      const arm = src.slice(from, to);
      expect(arm).toContain('consecutiveFailures += 1');
      expect(arm).toContain('unshiftChunked(retryDocs)');
      expect(/\$\{err\.message\}|err\.name|err\.message/.test(arm)).toBe(false);
      // 全总化只有一处实现：本文件不许自带第二份箭头（判据归一处）
      expect(src).not.toMatch(/const (?:errText|failureText)\s*=\s*\(/);
      expect(src).toContain("const { errText } = require('../utils/auditWriteFailure');");
      // 五处观测调用点（处置臂头 / 收尾 drain 循环 / push 满额 / 定时器 / WAL 重放）
      // 全部走同一个全总化。这条计数刚抓过一次：第 15 轮把 drain 循环里的
      // `${e.message}` 换成 errText 时 4→5 立刻变红——裸读复发或新增裸读都会在这里响。
      expect((src.match(/\$\{errText\((?:err|e)\)}/g) || []).length).toBe(5);
      // A 层：判定层的对账读也不许裸读被拒值（它跑在 flush 内层 catch 里）
      const docs = blank(readSrc('services/auditBufferDocs.js'));
      const probe = docs.indexOf('function collectDurableIds');
      if (probe < 0)
        throw new Error('结构闸锚点失配：auditBufferDocs.js 里找不到 collectDurableIds');
      expect(docs.slice(probe, probe + 900)).not.toMatch(/err\.(insertedDocs|writeErrors)/);
      // 文案层同理：两条 message builder 的 `err` 就是被拒值，裸读会把"记账"变成"再抛"，
      // 而毒批分支的可达性取决于服务端返回什么——判据不能只压在"这条分支今天走不走得到"。
      for (const name of ['doomedBatchMessage', 'outageMessage']) {
        const at = docs.indexOf(`function ${name}(`);
        if (at < 0) throw new Error(`结构闸锚点失配：判定层找不到 ${name}`);
        expect(docs.slice(at, at + 1500)).not.toMatch(/err\.(name|message|codeName|code)\b/);
      }
    });
  });

  /**
   * L7（2026-10-08 补，第 5 个实例）：`middleware/auth.js` 的 `invalidateUserCache` 广播臂。
   *
   * 与 L5 是同一条等式：`sharedCache.publishInvalidate` 是 async，而 `invalidateUserCache`
   * 是**同步**函数，调用点（roleController / rolePermissionController / initData）都不 await
   * 它 ⇒ 那条 promise 只能由这个 `.catch` 持有。ccddabc 补上了它（并把 `err.message` 写成
   * `err?.message ?? err`），但当时**没有任何用例驱动过它**——覆盖它的
   * `controllers/roleStatusInvalidatesUserCache.test.js` 把整个 `invalidateUserCache`
   * `jest.mock` 掉了（只断言"被调用"，不碰函数体）。
   *
   * 后果是可量化的：auth.js 的函数覆盖从 14/15（93.33%）掉到 14/16（**87.5%**），低于
   * jest.config 里那条 90 的阈值——这正是 CI `#13 Run tests with coverage` 的红。
   * 本层把"持有关系"从注释承诺升级为行为判据：拒绝必须被吞、处理器必须真的被走到、
   * 非 Error 拒绝不得把"吞错"变成"再抛"。
   *
   * 三种拒绝形态里前两种是分支覆盖的必需项（`err?.message` 一侧 + `?? err` 一侧），
   * 第三种（无 message 的普通对象）钉住 `?? err` 的兜底确实回落到被拒值本身。
   */
  describe('L7 auth.invalidateUserCache：广播臂的 .catch 必须真的接住拒绝', () => {
    test.each([
      ['Error', new Error('redis down'), 'redis down'],
      ['undefined（非 Error 形态）', undefined, 'undefined'],
      ['无 message 的普通对象', { code: 'ECONNREFUSED' }, '[object Object]'],
    ])('publishInvalidate 以 %s 拒绝 ⇒ 不抛，且 warn 打印被拒值', async (_label, reason, shown) => {
      const auth = require('../../middleware/auth');
      const sharedCache = require('../../services/sharedCache');
      const logger = require('../../utils/logger');
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      const pubSpy = jest
        .spyOn(sharedCache, 'publishInvalidate')
        .mockImplementation(() => Promise.reject(reason));

      const userId = `l7-${shown}`;
      // 同步函数 + 调用点不 await：所以"调用本身不抛"是契约的第一半
      expect(() => auth.invalidateUserCache(userId)).not.toThrow();
      await new Promise((resolve) => setImmediate(resolve)); // 让 .catch 微任务跑完

      // 前提自证：广播确实发出去了，且发的是 **auth 那条键**。
      // 不能断言 toHaveBeenCalledTimes(1)：invalidateUserCacheLocal → User.invalidatePermissionCache
      // → userPermissionService.invalidatePermissionCache 自己也会广播一条 `permcache:` 键
      //（src/services/userPermissionService.js:191），两条键同源但前缀不同、各有各的 .catch。
      const keys = pubSpy.mock.calls.map((c) => String(c[0]));
      const authCall = keys.indexOf(`auth:user:${userId}`);
      expect(authCall).toBeGreaterThan(-1);
      // 该调用的返回值确实 reject（否则下面的 warn 断言可能只是"什么都没发生"）
      await expect(pubSpy.mock.results[authCall].value).rejects.toBe(reason);
      // 处理器真的被走到了：文案逐字（含 `：${err?.message ?? err}` 的取值形态）
      expect(warnSpy.mock.calls.map((c) => String(c[0]))).toContain(
        `缓存失效广播异常（不阻断本次操作）：${shown}`
      );

      pubSpy.mockRestore();
    });
  });
});
