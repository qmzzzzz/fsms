/**
 * 桩返回类型对拍：测试里的桩必须长成「真 API 的返回值形状」
 *
 * 【这条门禁的失效形态：测试全绿，而绿的那条断言根本不可能失败】
 *
 * 第 13 轮的真实缺陷就是这一型：`src/utils/transaction.js` 的 finally 臂原先丢弃
 * `session.endSession()` 的拒绝，而测试里的桩写成
 *     endSession: jest.fn()        // 同步桩：调用返回 undefined
 * ⇒ 桩**永远不会拒绝** ⇒ "拒绝没人接"这条缺陷在测试里没有任何可达路径 ⇒ 用例在
 * 缺陷存在的每一版上都是绿的。修完之后桩改成 `mockResolvedValue(undefined)`，那条
 * 断言才第一次具备"能被这个缺陷打红"的能力。
 *
 * 也就是说：桩的形状决定了用例的可达域。与真 API 返回值形状不符的桩不是"简化"，
 * 而是**把一段真实失败路径从测试空间里删掉**。这类缺陷不报错、不变红，只会让覆盖率
 * 数字继续涨——所以它必须被机器钉住，而不是靠注释自律。
 * （transactionProbe.test.js:69 已经写下了 `mongodb.d.ts:2351 endSession → Promise<void>`
 *  这条登记，但登记没有闸；本文件把登记变成判据，并顺带核那条注释里的行号还成不成立。）
 *
 * 【判据归一处：真 API 的返回值形状不抄在本文件里，跑时从 node_modules 的类型声明读】
 *
 * 如果把 `Promise<void>` 抄进测试，本门禁就退化成了"抄对的注释"：升级驱动、换库之后
 * 声明变了，测试仍然绿（抄的那份不会跟着变）。所以层 1 是一台**解析器**：按
 * `名称 + 形参锚点` 在 .d.ts 里定位声明，读它的实际返回值，再和登记表比对。
 * 锚点失配 ⇒ 报"未命中"，而不是断言空集（testTreePurity 的同一课：静默空扫描和
 * 本来干净长得一模一样）。
 *
 * 【为什么登记表只有 6 条，而不是"所有 async API"】
 *
 * 判据不是"凡 async 的桩都得返回 Promise"——那会把几百个 `deleteOne: jest.fn()` 全判成
 * 违规，只能靠批量豁免，门禁当场退化成仪式。真正的判据窄得多也硬得多：
 * **只有当"桩能不能拒绝"决定某个分支可达不可达时，形状才是判据。** 所以登记的口径是
 * "本仓的桩打了它的失败路径 / 或它的返回值被生产代码接住"，落到机器上就是**每条 promise 型
 * 登记都带一个生产持有点**（层 2 实测 await / .catch / 丢弃 三态，与注册不符即红）；同步型
 * （void / this / 对象）不带持有点是合法的——它的返回值压根没有拒绝路径。
 * 新增登记的正确姿势：先在生产里指出"这个返回值被谁接住"，再来登记。
 * （第 16 轮 F 线实测到这条主张当时并不成立：`mongoose/Connection.close` 登记了 promise
 * 形状却写着 `hold:null`，而层 2 是 `if (entry.hold)` —— 于是它整条不跑，摘掉生产里的
 * `await` 也不会红。这就是"登记即接线"没做到的样子，所以补了一条结构闸：promise 型 + 无
 * 持有点 = 直接红，而不是靠人记得给每条登记补 hold。）
 *
 * 【豁免必须绑死在会失效的前提上】
 *
 * 今天唯一需要豁免的桩是 `websocketCorsAndReauthGuards.test.js:149`——它把 async 的
 * `io.close()` 桩成"同步抛错"，因为生产 `websocketService.dispose()` 用**同步 try**
 * 包住它（移交项 F4 / B 线 #2），只有同步抛错才打得到那条 catch 臂。豁免不是长期许可证：
 * 每条豁免必须声明一个 binding 谓词（读生产源码实时求值），谓词一旦不再成立（F4 被修掉）
 * ⇒ 豁免自动失效 ⇒ 变红并指名去把桩改诚实。反方向也拦：豁免条目没被任何站点用到，同样
 * 变红。这样"缺陷修好但豁免留着"和"豁免留着但缺陷没修"两种状态都不许静止。
 *
 * 【已知边界（与既有文本型闸门同一口径）】
 *  - 站点识别是文本级：认 `name: <桩>` 与 `obj.name = <桩>`，首行未闭合时多看两行续行
 *    （prettier 会把 `jest.fn(` 折断）；简写属性 `{ close }` 与解构重命名不认。
 *  - 必须先过 jsCodeOnly 再扫：注释里写一个 `close: jest.fn()` 就能把纯文本闸门骗红
 *    （F-145 两向实测）。层 3 拿种植源把这条双向都验一遍。
 *  - 右值必须"像桩"（jest.fn / mock* / 箭头函数 / function）才计入，否则
 *    `{ close: 5000 }`、`show-close=false` 这类同名键会被误判成同步桩。
 *  - 本文件自身不参与扫描：它含有拼接出来的反例串，留在扫描集里就无法区分"门禁自己的
 *    自证"和"一处真违规"。排除自身由层 3 最后一条用例显式钉住，不是偷懒。
 */

const fs = require('fs');
const path = require('path');
// 用**保行号**的那个视图：本门禁要报 `file:line`，而 jsCodeOnly 会把整行注释删掉，
// 报出来的行号比真实行号小（小多少取决于前面有多少行注释）——写这一版时实测偏了 55 行。
// 下面「报出来的行号必须真的指向那个桩」一条把这个前提钉住。
const { jsCodeOnlyKeepingLines: jsCodeOnly } = require('../helpers/jsCodeOnly');

const ROOT = path.resolve(__dirname, '../../..');
const NM = path.join(ROOT, 'node_modules');

/** 两棵会被 testMatch / vitest include 扫到的测试树 */
const TEST_TREES = [path.join(ROOT, 'src', 'tests'), path.join(ROOT, 'web-admin', 'src', 'tests')];

const read = (p) => fs.readFileSync(p, 'utf8');
const slash = (p) => path.relative(ROOT, p).replace(/\\/g, '/');
// 用例里一律按 id 取登记项：下标会因为新增登记而整体错位（本文件第一版就是这么红的）
const byId = (id) => {
  const hit = DECL.find((d) => d.id === id);
  if (!hit) throw new Error(`登记表里没有 ${id} ⇒ 用例引用的登记项被删了，请连用例一起改`);
  return hit;
};

/** 登记了"会拒绝"却没登记"谁接住"的条目 —— 层 2 对它们整条不跑，所以单独成判据 */
const promiseOrphans = (list) =>
  list.filter((d) => d.kind === 'promise' && !d.hold).map((d) => d.id);

// ==================== 登记表：真 API 的返回值形状 ====================
// kind 由解析器实测比对（promise / void / self / object），不是手写死的断言值
// hold：生产里这个返回值被谁接住 —— await / chain（.catch|.then|.finally）/ drop（丢弃）
const DECL = [
  {
    id: 'mongodb/ClientSession.endSession',
    pkg: 'mongodb',
    rel: 'mongodb.d.ts',
    name: 'endSession',
    argsAnchor: 'options?',
    kind: 'promise',
    hold: { rel: 'utils/transaction.js', re: /session\.endSession\(\)/g, is: 'await' },
    note: 'finally 臂的拒绝必须能被打出来（第 13 轮真实缺陷）',
  },
  {
    id: 'mongodb/AbstractCursor.close',
    pkg: 'mongodb',
    rel: 'mongodb.d.ts',
    name: 'close',
    argsAnchor: 'timeoutMS',
    kind: 'promise',
    hold: { rel: 'services/auditExportService.js', re: /cursor\.close\(\)/g, is: 'await' },
    note: '导出流中断路径；同步桩让「close 失败」这一支不可达',
  },
  {
    id: 'mongodb/ClientSession.abortTransaction',
    pkg: 'mongodb',
    rel: 'mongodb.d.ts',
    name: 'abortTransaction',
    argsAnchor: 'timeoutMS',
    kind: 'promise',
    hold: { rel: 'utils/transaction.js', re: /session\.abortTransaction\(\)/g, is: 'await' },
    note: 'catch 臂里的 abort：退回裸调用 = 事务清理失败变成无人持有的拒绝（第 16 轮按 F 线补登记）',
  },
  {
    id: 'mongoose/Connection.close',
    pkg: 'mongoose',
    rel: 'types/connection.d.ts',
    name: 'close',
    argsAnchor: 'force?:',
    kind: 'promise',
    // 第 16 轮 F 线实测：这条登记先前是 hold:null —— 登记了"真 API 会拒绝"却没登记
    // "谁接住它"，于是层 2 对它整条不跑，摘掉 index.js 的 await 也不会红。
    hold: { rel: 'index.js', re: /mongoose\.connection\.close\(/g, is: 'await' },
    note: '关停链第 4 步；桩它是为了凑齐 mongoose 的 mock，形状仍须可拒绝',
  },
  {
    id: 'socket.io/Server.close',
    pkg: 'socket.io',
    rel: 'dist/index.d.ts',
    name: 'close',
    argsAnchor: 'fn?:',
    kind: 'promise',
    hold: { rel: 'services/websocketService.js', re: /this\.io\.close\(\)/g, is: 'drop' },
    note: '同步 try 接不到它 —— 移交 F4/B#2，豁免就绑在这个事实上',
  },
  {
    id: 'socket.io/Socket.disconnect',
    pkg: 'socket.io',
    rel: 'dist/socket.d.ts',
    name: 'disconnect',
    argsAnchor: 'close?:',
    kind: 'self',
    hold: { rel: 'services/websocketService.js', re: /socket\.disconnect\(true\)/g, is: 'drop' },
    note: '反向对照：真 API 同步（返回 this）。桩长成 Promise 同样是不符',
  },
  {
    id: 'ioredis/Redis.disconnect',
    pkg: 'ioredis',
    rel: 'built/Redis.d.ts',
    name: 'disconnect',
    argsAnchor: 'reconnect?:',
    kind: 'void',
    hold: { rel: 'services/websocketService.js', re: /client\.disconnect\(\)/g, is: 'drop' },
    note: '反向对照：立即断开、无返回',
  },
  {
    id: 'mongodb/MongoClient.startSession',
    pkg: 'mongodb',
    rel: 'mongodb.d.ts',
    name: 'startSession',
    argsAnchor: 'options?: ClientSessionOptions',
    kind: 'object',
    hold: null,
    note: '反向对照：返回对象而非 Promise（解析器若把一切判成 promise 会在这里露馅）',
  },
];

// ==================== 豁免（每条必须绑一个实时求值的失效谓词） ====================
const EXEMPT = [
  {
    rel: 'src/tests/services/websocketCorsAndReauthGuards.test.js',
    name: 'close',
    wantShape: 'sync',
    binding: 'io-close-still-sync-try',
    reason:
      '生产 dispose() 用同步 try 包住 async 的 io.close()（移交 F4/B#2），只有同步抛错的桩打得到那条 catch 臂。F4 修好后请把这个桩改成 mockRejectedValue + await 断言，并删掉本条豁免。',
  },
];

const BINDINGS = {
  'io-close-still-sync-try': (prod) =>
    /try\s*\{\s*this\.io\.close\(\);/.test(jsCodeOnly(prod.get('services/websocketService.js'))),
};

// ==================== 声明解析（返回值跑时读，不抄） ====================

function classifyRet(ret) {
  const t = ret.trim().replace(/^:\s*/, '');
  if (/^Promise\s*</.test(t)) return 'promise';
  if (t === 'void') return 'void';
  if (t === 'this') return 'self';
  return 'object';
}

/** 从 openPos 处的 `(` 起做圆括号配平，返回 {args, ret}；不是声明则 null */
function signatureAt(buf, openPos) {
  let depth = 0;
  for (let k = openPos; k < buf.length; k += 1) {
    const c = buf[k];
    if (c === '(') {
      depth += 1;
      continue;
    }
    if (c !== ')') continue;
    depth -= 1;
    if (depth > 0) continue;
    const args = buf.slice(openPos + 1, k);
    let end = -1;
    for (let j = k + 1; j < Math.min(buf.length, k + 200); j += 1) {
      if (buf[j] === ';' || buf[j] === '{' || buf[j] === '}') {
        end = j;
        break;
      }
    }
    return end < 0 ? null : { args, ret: buf.slice(k + 1, end) };
  }
  return null;
}

function parseDecls(text, name) {
  const lines = text.split(/\r?\n/);
  const head = new RegExp(`^\\s*(?:static\\s+|readonly\\s+|abstract\\s+)?${name}\\s*\\(`);
  const out = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (!head.test(lines[i])) continue;
    const sig = signatureAt(lines.slice(i, i + 14).join('\n'), lines[i].indexOf('('));
    if (sig && sig.ret.trim())
      out.push({ args: sig.args, kind: classifyRet(sig.ret), line: i + 1 });
  }
  return out;
}

const declPath = (entry) => path.join(NM, entry.pkg, entry.rel);

/** 该登记项在 .d.ts 里的**唯一**命中（按形参锚点消歧）—— 一处实现，层 1 与层 4 共用 */
function anchorHits(entry) {
  return parseDecls(read(declPath(entry)), entry.name).filter((d) =>
    d.args.includes(entry.argsAnchor)
  );
}

/** 返回 null（一致）或一条能直接照着改的问题描述 */
function validateDecl(entry) {
  const file = declPath(entry);
  if (!fs.existsSync(file)) return `${entry.id}：类型声明文件不存在 ${file}`;
  const hits = anchorHits(entry);
  if (hits.length === 0) {
    return (
      `${entry.id}：在 ${slash(file)} 里按形参锚点「${entry.argsAnchor}」找不到 ` +
      `${entry.name}(…) 声明 ⇒ 登记表已漂移。请重新核对真 API 的返回值形状后再改登记，` +
      `不要删掉这条登记（删了就等于把这条判据静默下线）`
    );
  }
  if (hits.length > 1) {
    return `${entry.id}：锚点命中 ${hits.length} 处（行 ${hits.map((h) => h.line).join(',')}），锚点必须唯一`;
  }
  if (hits[0].kind !== entry.kind) {
    return `${entry.id}：登记的返回值形态是 ${entry.kind}，实测是 ${hits[0].kind}（${slash(file)}:${hits[0].line}）`;
  }
  return null;
}

// ==================== 生产持有点（决定"桩能不能拒绝"是否影响可达域） ====================

function deriveHolds(entry, prod) {
  const src = prod.get(entry.hold.rel);
  if (src === undefined) throw new Error(`层 2 缺少生产文件 src/${entry.hold.rel}`);
  const code = jsCodeOnly(src);
  const re = new RegExp(entry.hold.re.source, 'g');
  const holds = [];
  let m = re.exec(code);
  while (m) {
    const before = code.slice(Math.max(0, m.index - 40), m.index).replace(/\s+$/, '');
    const after = code.slice(m.index + m[0].length, m.index + m[0].length + 14);
    if (/^\s*\.(?:catch|then|finally)\s*\(/.test(after)) holds.push('chain');
    else if (/\b(?:await|yield|return)$/.test(before)) holds.push('await');
    else holds.push('drop');
    re.lastIndex = m.index + Math.max(1, m[0].length);
    m = re.exec(code);
  }
  return holds;
}

function validateHold(entry, prod) {
  const holds = deriveHolds(entry, prod);
  if (holds.length === 0) {
    return ` 生产里找不到 ${entry.hold.rel} 中的 ${entry.hold.re.source} ⇒ 持有点锚点漂移`;
  }
  const odd = [...new Set(holds.filter((h) => h !== entry.hold.is))];
  if (odd.length === 0) return null;
  return (
    `${entry.id}：${entry.hold.rel} 里 ${holds.length} 个调用点的返回值处置与登记不符` +
    `（登记 ${entry.hold.is}，实测多出 ${odd.join('/')}）。` +
    (entry.hold.is === 'drop'
      ? '若这是刻意改动（例如把"丢弃"改成 await）：请把登记的 is 改成实测值，并把该 API 的测试桩' +
        '改成能拒绝的形状——对应的豁免条目会同时失效，那是预期的连带修改。'
      : '请核对桩形状是否需要随之更新。')
  );
}

// ==================== 测试树桩站点 ====================

const STUB_RHS =
  /jest\.fn|mockResolvedValue|mockRejectedValue|\bspyOn\b|=>|^\s*(?:async\s+)?function\b/;
const PROMISE_MARK =
  /mockResolvedValue|mockRejectedValue|\.resolves|\.rejects|=>\s*Promise\b|Promise\.(?:resolve|reject)\b|\basync\b/;

const shapeOfStub = (rhs) => (PROMISE_MARK.test(rhs) ? 'promise' : 'sync');
const asyncName = (n) => DECL.some((d) => d.name === n && d.kind === 'promise');

/**
 * 首行括号未闭合时才看续行（prettier 会把 `jest.fn(` 折断）。
 * 判据是**圆/方/花括号的净开口数**，不是"行尾有没有逗号"：写完第一版时我用行尾
 * `[{(,]$` 当续行信号，结果 `{ a: jest.fn(), b: jest.fn().mockResolvedValue() }`
 * 这种逐行属性里，a 的形状被 b 的 mock 标记污染（种植用例当场把这件事抓出来了）。
 * 累积到净开口数归零即停，多一行都不看。
 */
function stubWindow(lines, i) {
  let win = lines[i];
  let open = 0;
  const delta = (s) => (s.match(/[({[]/g) || []).length - (s.match(/[)\]}]/g) || []).length;
  open += delta(win);
  for (let k = i + 1; open > 0 && k <= i + 3; k += 1) {
    const next = lines[k];
    if (next === undefined) break;
    win += ` ${next}`;
    open += delta(next);
  }
  return win;
}

function scanStubSites(code, relPath) {
  const lines = code.split('\n');
  const out = [];
  for (const name of [...new Set(DECL.map((d) => d.name))]) {
    const re = new RegExp(`(?:^|[{,;\\s])(?:[\\w$.]+\\.)?${name}\\s*[:=]\\s*([^\\n]*)`, 'g');
    for (let i = 0; i < lines.length; i += 1) {
      const hit = re.exec(lines[i]);
      if (!hit || !STUB_RHS.test(hit[1].trim())) continue;
      out.push({
        rel: relPath,
        name,
        line: i + 1,
        shape: shapeOfStub(stubWindow(lines, i)),
        rhs: hit[1].trim().slice(0, 60),
      });
    }
  }
  return out;
}

function listTestFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  const stack = [dir];
  while (stack.length > 0) {
    const cur = stack.pop();
    for (const e of fs.readdirSync(cur, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name === 'coverage') continue;
      const full = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (
        e.isFile() &&
        e.name.endsWith('.test.js') &&
        path.resolve(full) !== path.resolve(__filename)
      )
        out.push(full);
    }
  }
  return out;
}

const violationText = (site) =>
  `${site.rel}:${site.line} 的桩 ${site.name} 是 ${site.shape} 形状，而真 API 返回 ` +
  `${asyncName(site.name) ? 'Promise' : '同步值'}（登记：${DECL.filter((d) => d.name === site.name)
    .map((d) => d.id)
    .join(' + ')}）。` +
  (asyncName(site.name)
    ? '同步桩 = 该 API 的失败路径在测试里不可达；请改成 mockResolvedValue/mockRejectedValue，' +
      '或在 EXEMPT 里写清「为什么今天只能这样」并绑一个会失效的谓词。'
    : '同步 API 的桩返回 Promise 会打断链式用法（Socket.disconnect 返回 this），请改回同步形状。');

let SITES;
let PROD;
let TREE_FILES;

beforeAll(() => {
  TREE_FILES = TEST_TREES.flatMap(listTestFiles);
  PROD = new Map(
    [...new Set(DECL.filter((d) => d.hold).map((d) => d.hold.rel))].map((rel) => [
      rel,
      read(path.join(ROOT, 'src', rel)),
    ])
  );
  SITES = TREE_FILES.flatMap((f) => scanStubSites(jsCodeOnly(read(f)), slash(f)));
});

// ==================== 层 1：声明真相 ====================

describe('层 1 · 真 API 返回值形状（跑时从 node_modules 类型声明读）', () => {
  test('每条登记都必须按锚点在 .d.ts 里唯一命中，且返回值形态与登记一致', () => {
    expect(DECL.length).toBeGreaterThanOrEqual(6);
    expect(DECL.map(validateDecl).filter(Boolean).join('\n')).toBe('');
  });

  test('登记表必须同时含 promise 型与同步型真值（单一方向无从证伪）', () => {
    const kinds = DECL.map((d) => d.kind);
    expect(kinds.filter((k) => k === 'promise').length).toBeGreaterThanOrEqual(2);
    expect(kinds.filter((k) => k !== 'promise').length).toBeGreaterThanOrEqual(2);
  });

  /**
   * 结构闸：登记了"真 API 会拒绝"就必须登记"谁接住它"。
   * 为什么单独成一条（而不是靠层 2 顺带发现）：层 2 是 `if (entry.hold)` —— hold 为 null
   * 时它整条不跑，于是"登记了形状、没登记持有点"的条目**永远绿**，而它的存在恰恰让
   * "把 await 退回裸调用"这一类改动失去检测（第 16 轮 F 线实测：mongoose/Connection.close
   * 就是这么一条，生产 `index.js:227` 明明有 await 持有点）。
   * 只有 promise 型需要持有点：同步 API 的返回值不产生拒绝路径，形状判据与它无关。
   */
  test('每条 promise 型登记都必须指名一个生产持有点（hold:null 只允许同步型）', () => {
    expect(promiseOrphans(DECL).join('/')).toBe('');
    // 反向自证：这条判据对"promise 型 + 无持有点"必须真的报警，对同步型必须真的放行
    expect(
      promiseOrphans([...DECL, { id: 'synthetic/promise', kind: 'promise', hold: null }])
    ).toContain('synthetic/promise');
    expect(promiseOrphans([{ id: 'synthetic/sync', kind: 'void', hold: null }])).toEqual([]);
  });

  test('持有点本身有牙：每条 promise 登记的实测处置必须与登记一字不差', () => {
    const promiseWithHold = DECL.filter((d) => d.kind === 'promise' && d.hold);
    expect(promiseWithHold.length).toBeGreaterThanOrEqual(4);
    for (const d of promiseWithHold) {
      expect(validateHold(d, PROD) || '').toBe('');
    }
    const cur = byId('mongodb/AbstractCursor.close');
    expect(validateHold({ ...cur, hold: { ...cur.hold, is: 'drop' } }, PROD)).toContain(
      '与登记不符'
    );
    const mongo = byId('mongoose/Connection.close');
    expect(validateHold({ ...mongo, hold: { ...mongo.hold, is: 'drop' } }, PROD)).toContain(
      '与登记不符'
    );
  });

  test('解析器有牙：锚点漂移 / 文件缺失 / 形态翻转都要产出问题，不许静默空集', () => {
    expect(
      validateDecl({ ...byId('mongodb/ClientSession.endSession'), argsAnchor: 'noSuchParam-zzz' })
    ).toContain('找不到');
    expect(
      validateDecl({ ...byId('mongodb/ClientSession.endSession'), pkg: 'no-such-pkg-zzz' })
    ).toContain('不存在');
    expect(validateDecl({ ...byId('mongodb/ClientSession.endSession'), kind: 'void' })).toContain(
      '实测是 promise'
    );
    expect(validateDecl({ ...byId('socket.io/Socket.disconnect'), kind: 'void' })).toContain(
      '实测是 self'
    );
    // 三种类别各自可辨：Promise<void> / void / this
    const sample = [
      'declare class A {',
      '    close(options?: { timeoutMS?: number }): Promise<void>;',
      '    disconnect(reconnect?: boolean): void;',
      '    leave(): this;',
      '}',
    ].join('\n');
    expect(parseDecls(sample, 'close')[0].kind).toBe('promise');
    expect(parseDecls(sample, 'disconnect')[0].kind).toBe('void');
    expect(parseDecls(sample, 'leave')[0].kind).toBe('self');
  });
});

// ==================== 层 2：生产持有点 ====================

describe('层 2 · 生产持有点与登记一致', () => {
  test('每个调用点的返回值处置（await / .catch / 丢弃）实测必须等于登记值', () => {
    const held = DECL.filter((d) => d.hold);
    expect(held.length).toBeGreaterThanOrEqual(4);
    expect(
      held
        .map((d) => validateHold(d, PROD))
        .filter(Boolean)
        .join('\n')
    ).toBe('');
  });

  test('持有点派生本身有牙：翻转登记值必须变红，而不是跟着实测走', () => {
    const drop = byId('socket.io/Server.close');
    const flipped = { ...drop, hold: { ...drop.hold, is: 'chain' } };
    expect(validateHold(flipped, PROD)).toContain('与登记不符');
    const end = byId('mongodb/ClientSession.endSession');
    const missing = { ...end, hold: { rel: end.hold.rel, re: /noSuchCall\(\)/g, is: 'await' } };
    expect(validateHold(missing, PROD)).toContain('锚点漂移');
    expect(() => deriveHolds(missing, new Map())).toThrow('缺少生产文件');
  });

  test('注释里的假持有点不算数：transaction.js 的注释支必须被 jsCodeOnly 抹掉', () => {
    // transaction.js:97 的注释里就写着 `session.endSession().catch(() => {})`。
    // 不剥注释的扫描器会在这里派生出 'chain'，与登记的 'await' 冲突 ⇒ 误红。
    const raw = PROD.get('utils/transaction.js');
    expect(raw).toContain('session.endSession().catch(');
    expect(jsCodeOnly(raw)).not.toContain('session.endSession().catch(');
    expect(deriveHolds(byId('mongodb/ClientSession.endSession'), PROD)).toEqual(['await']);
  });
});

// ==================== 层 3：桩形状 ====================

describe('层 3 · 桩形状必须匹配真 API 的返回值形状', () => {
  test('扫描集非空且规模可核对（否则「零违规」只是「零扫描」）', () => {
    expect(TREE_FILES.length).toBeGreaterThan(200);
    const byName = (n) => SITES.filter((s) => s.name === n);
    expect(byName('endSession').length).toBeGreaterThanOrEqual(2);
    expect(byName('abortTransaction').length).toBeGreaterThanOrEqual(2);
    expect(byName('close').length).toBeGreaterThanOrEqual(9);
    expect(byName('disconnect').length).toBeGreaterThanOrEqual(18);
  });

  test('async 真 API 的桩必须 promise 形状；同步真 API 的桩不得 promise 形状', () => {
    const used = new Set();
    const bad = [];
    for (const s of SITES) {
      const isAsyncTruth = asyncName(s.name);
      const wrong = isAsyncTruth ? s.shape === 'sync' : s.shape === 'promise';
      if (!wrong) continue;
      const ex = isAsyncTruth
        ? EXEMPT.find((e) => e.rel === s.rel && e.name === s.name && e.wantShape === s.shape)
        : undefined;
      if (!ex) {
        bad.push(violationText(s));
        continue;
      }
      used.add(ex);
      const predicate = BINDINGS[ex.binding];
      if (!predicate) bad.push(`${s.rel}:${s.line} 豁免引用的谓词「${ex.binding}」不存在`);
      else if (!predicate(PROD)) {
        bad.push(
          `${s.rel}:${s.line} 豁免已失效（谓词 ${ex.binding} 不再成立）：生产前提改掉之后，` +
            `这个桩必须长成真 API 的形状。${ex.reason}`
        );
      }
    }
    for (const ex of EXEMPT) {
      if (!used.has(ex)) {
        bad.push(`豁免条目 ${ex.rel}（${ex.name}）没被任何站点用到 ⇒ 缺陷修掉了就该连豁免一起删`);
      }
    }
    expect(bad.join('\n')).toBe('');
  });

  test('形状判据有牙：种植同步桩 / promise 桩，扫描器必须分开；注释形态必须整体不可见', () => {
    const planted = [
      'const fake = {',
      ['    endSes', 'sion: jest.fn(),'].join(''),
      ['    close: jest.fn().mockResolvedValue(undefined),'].join(''),
      '    disconnect: () => undefined,',
      '};',
    ].join('\n');
    expect(
      scanStubSites(planted, 'planted://source')
        .map((s) => `${s.name}:${s.shape}`)
        .sort()
    ).toEqual(['close:promise', 'disconnect:sync', 'endSession:sync']);
    // 反向：同样这段文本换成注释后必须一条都扫不到（否则注释能把闸门骗红）
    const commented = planted.replace(/\n/g, '\n// ') + '\n';
    expect(scanStubSites(jsCodeOnly(commented), 'planted://comment')).toEqual([]);
    // 两个方向都要成立：续行里才出现 promise 标记的（prettier 折断形态）必须认成 promise，
    // 而"行尾逗号 + 邻居是 promise"不许串味（上面 endSession:sync 那条就是这条的串味反例）。
    const wrapped = [
      'const fake = {',
      '      close: jest.fn(',
      '        async () => undefined',
      '      ),',
      '      disconnect: jest.fn(),',
      '    };',
    ].join('\n');
    expect(scanStubSites(wrapped, 'planted://wrapped').map((s) => `${s.name}:${s.shape}`)).toEqual([
      'close:promise',
      'disconnect:sync',
    ]);
  });

  test('报出来的行号必须真的指向那个桩（视图换了不保行号的实现就会全体错位）', () => {
    expect(SITES.length).toBeGreaterThan(20);
    const bad = [];
    for (const s of SITES) {
      const at = read(path.join(ROOT, s.rel)).split(/\r?\n/)[s.line - 1];
      if (!at || !new RegExp(`\\b${s.name}\\s*[:=]`).test(at)) {
        bad.push(
          `${s.rel}:${s.line} 声称是 ${s.name} 的桩，该行实际是「${(at || '').trim().slice(0, 50)}」`
        );
      }
    }
    expect(bad.join('\n')).toBe('');
  });

  test('本文件确实被排除在扫描集之外（排除是判据前提，不是偷懒）', () => {
    const selfRel = slash(__filename);
    expect(TREE_FILES.map(slash)).not.toContain(selfRel);
    expect(listTestFiles(TEST_TREES[0]).length).toBeGreaterThan(100);
  });
});

// ==================== 层 4：注释即事实 ====================

describe('层 4 · 测试里写下的 *.d.ts:行号 引用必须仍指向它所称的声明', () => {
  const CITE = /([\w.-]+\.d\.ts):(\d+)/g;

  function citations() {
    const out = [];
    for (const f of TREE_FILES) {
      const src = read(f);
      let m = CITE.exec(src);
      while (m) {
        out.push({ rel: slash(f), base: m[1], line: Number(m[2]), cite: m[0] });
        CITE.lastIndex = m.index + m[0].length;
        m = CITE.exec(src);
      }
      CITE.lastIndex = 0;
    }
    return out;
  }

  /** null = 引用仍然成立；字符串 = 人可读的漂移说明 */
  function validateCitation(c) {
    // 判据是"这个行号落在该文件**任一**条已登记声明上"，不是"落在按 basename 找到的第一条上"：
    // mongodb.d.ts 现在登记了 endSession/close/abortTransaction 三条，只取第一条会把
    // 一个本来正确的引用报成漂移，并把人指向不相干的那条（第 16 轮 F 线实测到这点）。
    const entries = DECL.filter((d) => path.basename(d.rel) === c.base);
    if (entries.length === 0) {
      return `${c.rel} 引用了 ${c.cite}，但 ${c.base} 不在登记表里 ⇒ 请登记它或删掉行号`;
    }
    let lineText = '';
    const truth = [];
    for (const entry of entries) {
      const file = declPath(entry);
      if (!fs.existsSync(file)) return `${c.rel} 的 ${c.cite} 指向不存在的 ${file}`;
      // 成立的判据是"这个行号就是**这条登记声明**自己"，不是"那一行恰好有个同名声明"：
      // mongodb.d.ts 里 `close(` 有十几处，光比名字会把 AbstractCursor.close 的引用
      // 判在 MongoClient.close 上（同名不同物，报错方向就错了）。
      const hits = anchorHits(entry);
      if (!lineText) {
        lineText = (read(file).split(/\r?\n/)[c.line - 1] || '').trim().slice(0, 40);
      }
      if (hits.some((h) => h.line === c.line)) return null;
      truth.push(
        `${entry.name}(锚点 ${entry.argsAnchor}) 在 ${c.base}:${hits.map((h) => h.line).join(',') || '（锚点找不到）'}`
      );
    }
    return (
      `${c.rel} 的 ${c.cite} 已漂移：那一行现在是「${lineText}」，` +
      `而该文件里登记的声明实测为 ${truth.join('；')} ⇒ 请把注释里的行号改成实测值`
    );
  }

  test('每个行号都要落到一条已登记的声明上，且行号未漂移', () => {
    const found = citations();
    expect(found.length).toBeGreaterThanOrEqual(1);
    expect(found.map(validateCitation).filter(Boolean).join('\n')).toBe('');
  });

  test('行号引用扫描本身有牙：漂移与未登记都要被抓出，而不是恒过', () => {
    expect(
      validateCitation({ rel: 'p.js', base: 'mongodb.d.ts', line: 1, cite: 'mongodb.d.ts:1' })
    ).toContain('已漂移');
    expect(
      validateCitation({
        rel: 'p.js',
        base: 'no-such-pkg.d.ts',
        line: 1,
        cite: 'no-such-pkg.d.ts:1',
      })
    ).toContain('不在登记表里');
    // 正向对照：真实那条引用确实成立（否则上面的红可能只是解析器坏了）
    const real = citations()[0];
    expect(real).toBeDefined();
    expect(validateCitation(real)).toBeNull();
  });

  /**
   * 同文件多登记的判据精度：mongodb.d.ts 里登记了不止一条声明，**每一条**的实测行号
   * 都必须被认成"成立"。先前按 basename 取第一条，第二条及之后的正确引用会被报成漂移，
   * 并把修改者指向不相干的声明 —— 那是"报错比缺陷更难查"的假红。
   */
  test('同文件多条登记时，每条自己的行号都成立（不许拿第一条去判第二条）', () => {
    const sameBase = new Map();
    for (const d of DECL) {
      const base = path.basename(d.rel);
      if (!sameBase.has(base)) sameBase.set(base, []);
      sameBase.get(base).push(d);
    }
    const multi = [...sameBase.entries()].filter(([, list]) => list.length > 1);
    // 前提自证：这个用例确实覆盖到了多登记文件，而不是在空集上恒过
    expect(multi.map(([base]) => base)).toContain('mongodb.d.ts');
    for (const [, list] of multi) {
      for (const entry of list) {
        const hits = anchorHits(entry);
        expect(hits.length).toBe(1);
        expect(
          validateCitation({
            rel: 'p.js',
            base: path.basename(entry.rel),
            line: hits[0].line,
            cite: `${path.basename(entry.rel)}:${hits[0].line}`,
          })
        ).toBeNull();
      }
    }
    // 反向自证（这一条才是牙）：**同名但不是那条登记**的声明行号必须判成漂移。
    // mongodb.d.ts 里 `close(` 有十几处，按名字判的旧写法会把它们全部认成有效引用 ⇒ 恒真。
    const closeEntry = byId('mongodb/AbstractCursor.close');
    const registered = anchorHits(closeEntry).map((h) => h.line);
    const sameNameElsewhere = parseDecls(read(declPath(closeEntry)), 'close')
      .map((d) => d.line)
      .filter((l) => !registered.includes(l));
    expect(sameNameElsewhere.length).toBeGreaterThan(0);
    expect(
      validateCitation({
        rel: 'p.js',
        base: 'mongodb.d.ts',
        line: sameNameElsewhere[0],
        cite: `mongodb.d.ts:${sameNameElsewhere[0]}`,
      })
    ).toContain('已漂移');
  });
});
