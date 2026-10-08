/**
 * 错误码默认消息里的占位符闸（第 28 轮）
 *
 * 缺陷形状（本轮普查实测：18 处）：src/utils/errorCodes.js 的默认 message 用的是**单引号或
 * 双引号**字符串，里面写着 `${format}`、`${lacking.join('、')}`、`${BATCH_DELETE_MAX}` 这类
 * 占位符。引号不是模板字符串 ⇒ 这些占位符是**字面文本**，一旦被发出去，客户端看到的就是
 * `不支持的导出格式: ${format}` —— 既坏 UX 又把内部变量名送到响应里。
 *
 * 18 这个数字本身是被对账逼出来的：文本扫描器先数到 15，独立口径（加载码表看真值）数到 18。
 * 差集里那 3 条（`IP_FULL_RANGE_SUPER_ADMIN_ONLY`/`IP_COVERED_BY_WHITELIST`/
 * `IP_FULL_RANGE_REMOVE_SUPER_ADMIN_ONLY`）写成
 *     message:
 *       '全网段（${normalizedIP}）…',
 * 即 `message:` 本行没有值。旧实现按行取"行尾剩下的部分"，content 取成空串——**条数照样等于
 * message 行数**（196==196），所以"解析不遗漏"的那条自洽检查抓不到它：它检查的是数量，不是
 * 内容。这就是 #6 现在要拿第二套口径（真值）做双向差集的理由：同一条不变式必须有两条通路，
 * 一条数量自洽的文本解析不能自证。
 *
 * 为什么今天是安全的（已核实，不是推断）：src/utils/apiResponse.js 的 codeError 取
 * `options.message || (def && def.message)` ⇒ 只要调用点自己传了 message，那条占位符默认值
 * 就永远不生效。实测：18 个占位符码的**全部**生产调用点都传了会真正生效的 message（#11）。
 *
 * "会真正生效"这四个字是本轮补的：响应侧用的是 `||`，所以 `message: undefined`、`message: null`、
 * `message: ''` 三种"写了但等于没写"的赋值**照样**回退到占位符默认消息，而旧分类器只看
 * "`message:` 这个键在不在"就把它们判成安全——一条正好会泄漏的调用点被仪器读成绿灯（第 3 族）。
 * 实测本仓生产代码今天零处这种写法（改动前后：站点/索引/泄漏/孤儿四项逐字节同值），所以这一格
 * 修的是仪器的牙；牙齿长在 #14 的 falsy 臂上，真树侧由 #11 继续守"今天仍然没有"。
 *
 * 本轮还暴露了一个此前看不见的面：动态 code 站点。普查实测 5 处 `codeError(res, 非纯字面量)`，
 * 其中 4 处是纯变量/属性访问（opaque），1 处是字面量分支
 * （`src/middleware/logoutAuth.js:45` 的 `accessTokenExpired ? 'AUTH_TOKEN_EXPIRED' :
 * 'AUTH_TOKEN_MISSING'`）。这处正是旧"整段参数正则取第一个 UPPER_SNAKE"口径**吞掉一个码**的
 * 现场（只收到 AUTH_TOKEN_EXPIRED），也是它能伪造调用点的现场：`codeError(res, dyn, { message:
 * 'SOME_CODE' })` 会被读成"SOME_CODE 有个传了 message 的调用点"——既能把泄漏判成安全，也能把
 * 孤儿压掉。现在按**码槽**（第二参数段）取码：纯字面量 ⇒ 进索引；字面量分支 ⇒ 槽内码全部进索引
 * （#11 覆盖得到）；纯变量 ⇒ opaque，"能取到哪些码"根本不在调用点文本里，只能靠登记 + 现采对账。
 * opaque 的 4 处里 3 处没传 message，其可达码集由 #16–#18 变成机器可判：登记必须覆盖每一个
 * 不传 message 的 opaque 站点（#16，双向），登记的闭合集合必须与**现采**结果双向相等（#17，
 * 现采口径见 helpers/codeErrorCallScan 的 literalValuesForProps——属性名逐字赋值的字面量，与
 * src/tests/emittedErrorCodeCoverage.test.js 的"第四通道"同源），值被换成变量时现采会报
 * nonLiteral 而不是沉默，登记集合与占位符面积必须零交且每个码仍在码表里（#18）。
 * 第 4 处（`userController.js` 的 `membershipError.code`）自己传了 message ⇒ 无需登记，#16 按
 * "不传 message 的 opaque 站点"双向核对，多登记与漏登记都会红。
 *
 * 站点键用 `文件|码槽` 而不是 `文件:行号`：本闸这一轮已经被别人的行号漂移打过两次（见第 28 轮
 * 交付），而槽文本本身就是登记的本体，行号只在红讯里做定位用。
 *
 * 为什么还要一把闸（"今天没漏"不等于"不会漏"）：这条正确性完全依赖调用点的自觉，而码表里
 * 那 18 条文本长得像"已经写好的模板"——新调用点最容易犯的正是 `codeError(res, 'ROLE_IN_USE')`
 * 这种"反正码表里有消息"的写法；一次就漏，且只在那条错误分支被走到时才看得见（恰是测试
 * 覆盖最稀的地方）。本闸把"调用点必须传 message"从口头纪律变成判据，并钉住四件让判据
 * 不至于空转的前提：
 *   ① 判据面积非空（确实存在占位符默认消息，点名三条已知码，其中一条是换行排版形状）；
 *   ② 扫描器不空转（调用点数/文件数/码数/动态站点数有下界，合成样例上有牙）；
 *   ③ 威胁模型锚还在（`options.message ||` 的优先级没被反过来写）；
 *   ④ 索引看不见的 opaque 站点逐条登记，且登记与源码现采双向对得上（#16–#18）。
 * ③ 最关键：若有人改成 `def.message || options.message`，18 条占位符**立刻**全部开始泄漏，
 * 而"调用点有没有传 message"这个判据照样全绿——这类"判据的前置条件消失了"的漂移，只能靠
 * 锚点腿看见。
 *
 * 扫描器不在本文件里抄一份：全部来自 helpers/codeErrorCallScan（单点实现）。理由见该文件头
 * ——判据面积完全由"扫描得到什么"决定，扫描器一错就错得无声无息（第 3 族）。靶因此打在
 * 辅助件上（instrument-self 变异），而不是打在被复制的正文里。
 *
 * 视图纪律：所有判据跑在 helpers/jsCodeOnly 的"只剩代码"视图上（"什么算注释"的口径单点
 * 持有，不在本文件复制一份）；取 KeepingLines 视图是因为红讯要报 file:line。
 */
const path = require('path');
const S = require('../helpers/codeErrorCallScan');
const { jsCodeOnlyKeepingLines } = require('../helpers/jsCodeOnly');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const REL_REGISTRY = 'src/utils/errorCodes.js';
const REL_RESPONDER = 'src/utils/apiResponse.js';

/**
 * 占位符前缀。写成两个字符拼接是为了本文件自身不含该字面量——
 * 否则本闸的文本判据会把自己的源码当靶（实测踩过：判据面积里冒出一条来自测试文件的"泄漏"）。
 */
const PH = '$' + '{';
const BACKTICK = S.BACKTICK;

/* --------------------------- 真实数据 --------------------------- */

const registryText = S.codeOnlyFrom(ROOT, REL_REGISTRY);
const registry = S.parseRegistry(registryText);
const registryLines = registryText.split('\n');

const PRODUCTION_FILES = S.listProductionFiles(ROOT);
const calls = S.indexProductionCalls({ root: ROOT, files: PRODUCTION_FILES, placeholder: PH });

/**
 * 本闸允许"有占位符默认消息但没有任何字面量调用点"的清单。两条都是本轮对账时现形的**真**
 * 死码：码表里有定义、web-admin 的 code→i18n 映射里也有（`web-admin/src/utils/api.js:123/126`），
 * 但生产侧零调用——实际走的是 `FULL_RANGE_FORBIDDEN` 那条无占位符的码。
 * 留在这里而不是顺手删：删生产码表项要过归属方（它们是"给全网段配置"这条被拒路径预留的文案），
 * 且本闸的职责是记录欠账不是代作决定。**新增必须写理由。**
 */
const DECLARED_DEAD = ['IP_FULL_RANGE_REMOVE_SUPER_ADMIN_ONLY', 'IP_FULL_RANGE_SUPER_ADMIN_ONLY'];

/**
 * 动态 code 站点（`codeError(res, 变量)`）的登记表：站点 -> 该变量能取到的**闭合**码集。
 * 站点键用 `文件|码槽文本` 而不是行号——行号会让本闸对"别人在它上方加了一行"敏感（本轮已被
 * 同类漂移打过两次），而槽文本就是这条登记的本体。
 * `trace` 说明这份闭合集**从哪里现采**：`corpus:'production'` = 全生产代码里该属性名被赋的
 * 字符串字面量；`file:` = 只在该文件里采（表就定义在该文件时用它，别处的同名属性不算）。
 * 登记的 codes 必须与现采结果双向相等（#16），所以"表加了条目而登记没跟上"会红，
 * "登记写了源码里已经没有的码"也会红——手抄的登记表自己不会失效，对账才会。
 * userController.js 的 `membershipError.code` 不在表内：它自己传了 message。
 */
const DECLARED_DYNAMIC = [
  {
    site: 'src/controllers/roleGuards.js|forbiddenCode',
    trace: { props: ['forbiddenCode'] },
    codes: ['ROLE_DELETE_FORBIDDEN', 'ROLE_UPDATE_FORBIDDEN'],
  },
  {
    site: 'src/controllers/roleGuards.js|higherLevelCode',
    trace: { props: ['higherLevelCode'] },
    codes: ['ROLE_DELETE_HIGHER_LEVEL_FORBIDDEN', 'ROLE_UPDATE_HIGHER_LEVEL_FORBIDDEN'],
  },
  {
    site: 'src/controllers/securityController.js|targetViolation.code',
    trace: { file: 'src/controllers/securityController.js', props: ['notFound', 'outOfScope'] },
    codes: [
      'ALARM_NOT_FOUND',
      'ALARM_VIEW_FORBIDDEN',
      'DEVICE_NOT_FOUND',
      'DEVICE_VIEW_FORBIDDEN',
      'USER_NOT_FOUND',
      'USER_SCOPE_FORBIDDEN',
    ],
  },
];

/** 站点身份：文件 + 码槽文本（见上注释：为什么不用行号） */
const siteKey = (c) => `${c.file}|${c.slot}`;

const placeholderCodes = () => S.placeholderCodesOf(registry.messages, PH).map((m) => m.key);

/**
 * 现采一条登记的闭合集：该属性名（在指定文件或全生产代码里）被赋的字符串字面量码集，
 * 外加"有没有把值换成变量"——后者一旦非空，这条登记就不再是机器可判的，#17 会响。
 */
const tracedCodes = (trace) => {
  const texts = trace.file
    ? [S.codeOnlyFrom(ROOT, trace.file)]
    : PRODUCTION_FILES.map((rel) => S.codeOnlyFrom(ROOT, rel));
  const values = new Set();
  const nonLiteral = [];
  for (const text of texts) {
    const one = S.literalValuesForProps(text, trace.props);
    for (const v of one.values) values.add(v);
    for (const w of one.nonLiteral) nonLiteral.push(w);
  }
  return { values: [...values].sort(), nonLiteral };
};

/* --------------------------- 合成样例 --------------------------- */

const SAMPLE = [
  "ApiResponse.codeError(res, 'PASS_OK', { message: '这里传了' });",
  "ApiResponse.codeError(res, 'LEAK_MISS');",
  'ApiResponse.codeError(res, "LEAK_LITERAL", { message: "字面量 ' + PH + 'oops}" });',
  'ApiResponse.codeError(res, "DECOY_PAREN", { params: { note: "a)b}" }, message: "real" });',
  'ApiResponse.codeError(res, "DECOY_TPL", { params: { note: `x${\'y}\'}` }, message: "real" });',
  'static codeError(res, "NOT_A_CALL")',
  'ApiResponse.codeError(res, runtimeCode, { params: {} });',
  "ApiResponse.codeError(res, flag ? 'BRANCH_A' : 'BRANCH_B');",
  "ApiResponse.codeError(res, 'FALSY_UNDEF', { message: undefined });",
  "ApiResponse.codeError(res, 'FALSY_NULL', { message: null });",
  "ApiResponse.codeError(res, 'FALSY_EMPTY', { message: '' });",
].join('\n');

/** 合成注册表文本：一条反引号默认消息（本闸必须把它标成"非纯数据"） */
const FAKE_REGISTRY = [
  'const ERROR_CODES = {',
  '  PURE: {',
  '    status: 400,',
  "    message: 'ok',",
  '  },',
  '  IMPURE: {',
  '    status: 400,',
  '    message: `x${1}`,',
  '  },',
  '};',
].join('\n');

const sampleCalls = S.scanCalls(SAMPLE, PH);
const sampleOf = (code) => sampleCalls.find((c) => c.code === code);
const syntheticIndex = new Map([
  ['LEAKS', [{ passesMessage: false, line: 1, file: 'x.js' }]],
  ['OK', [{ passesMessage: true, line: 2, file: 'x.js' }]],
]);

describe('第 0 组 · 扫描器与分类器自检（判据有牙的前提）', () => {
  test('#1 传了 message 判为安全、没传判为泄漏——方向不能反', () => {
    expect(sampleOf('PASS_OK').passesMessage).toBe(true);
    expect(sampleOf('LEAK_MISS').passesMessage).toBe(false);
    expect(sampleOf('LEAK_MISS').line).toBe(2);
  });

  test('#2 字符串与模板里的假括号不得破坏参数配对，定义点不得算调用', () => {
    expect(sampleOf('DECOY_PAREN').passesMessage).toBe(true);
    expect(sampleOf('DECOY_TPL').passesMessage).toBe(true);
    expect(sampleOf('NOT_A_CALL')).toBeUndefined();
  });

  test('#3 单/双引号里的占位符字面量必须报出来，模板串与表达式不算', () => {
    expect(sampleOf('LEAK_LITERAL').literalPlaceholder).toBe(true);
    expect(sampleOf('PASS_OK').literalPlaceholder).toBe(false);
    expect(sampleOf('DECOY_TPL').literalPlaceholder).toBe(false);
  });

  test('#4 孤儿分类器必须能报出"有占位符默认消息、零调用点"的码', () => {
    expect(S.orphansOf(['LEAKS', 'OK', 'DEAD'], syntheticIndex)).toEqual(['DEAD']);
  });

  test('#5 泄漏清单只收"没传 message"的调用点，并带上可定位的 code/file/line', () => {
    const rows = S.leaksOf(['LEAKS', 'OK', 'DEAD'], syntheticIndex);
    expect(rows.map((r) => r.code)).toEqual(['LEAKS']);
    expect(rows[0].file).toBe('x.js');
    expect(rows[0].line).toBe(1);
  });
});

describe('第 1 组 · 注册表侧前提', () => {
  /**
   * 两条通路必须给出**同一个**占位符集合：
   *  - 文本解析（parseRegistry 跑在只剩代码的视图上）；
   *  - 真值（require 码表，看加载后的 message 字符串）。
   * 为什么"条数 == message 行数"不够：本轮实测旧文本实现数到 15、真值数到 18，而条数检查
   * 196==196 照样通过——数量自洽不能自证内容取对了（换行排版的 3 条取值取成了空串）。
   * 曾经这里还有第三条 `status 行数 >= message 行数`，实测被否（178 < 196）：码表有 18 条把
   * `status:` 内联写在 `message:` 之前，那条"直觉不变式"根本不成立。
   * 记下来：给文本解析器配对照腿时，先跑一遍再写预测，不要按码表"应该长什么样"来推。
   */
  test('#6 解析不遗漏：文本面积与真值面积双向相等，码数有下界', () => {
    expect(registry.messages.filter((m) => !m.key)).toEqual([]);
    const messageLines = registryLines.filter((l) => /\bmessage:/.test(l)).length;
    expect(registry.messages.length).toBe(messageLines);
    const textArea = [...placeholderCodes()].sort();
    const truthArea = S.loadedPlaceholderCodes(ROOT, REL_REGISTRY, PH);
    expect(textArea.filter((k) => !truthArea.includes(k))).toEqual([]);
    expect(truthArea.filter((k) => !textArea.includes(k))).toEqual([]);
    expect(textArea.length).toBeGreaterThan(15);
    expect(registry.keys.length).toBeGreaterThan(150);
  });

  test('#7 码表必须是纯数据：默认消息不许是插值模板（合成样例先证明分类器有牙）', () => {
    const fake = S.parseRegistry(jsCodeOnlyKeepingLines(FAKE_REGISTRY));
    expect(fake.messages.filter((m) => m.quote === BACKTICK).map((m) => m.key)).toEqual(['IMPURE']);
    expect(registry.messages.filter((m) => m.quote === BACKTICK)).toEqual([]);
  });

  /**
   * 三条点名各有分工：前两条是"内联排版"的已知占位符码，第三条
   * `IP_COVERED_BY_WHITELIST` 是**换行排版**那一条形状的代表——文本解析器一旦退回按行取值，
   * 它第一个从面积里消失（本轮就是这么被抓到的）。
   */
  test('#8 判据面积非空，且点名的三个已知占位符码都在集合里', () => {
    const codes = placeholderCodes();
    expect(codes.length).toBeGreaterThan(0);
    expect(codes).toContain('BATCH_DELETE_LIMIT_EXCEEDED');
    expect(codes).toContain('PARAM_MUST_BE_VALID_OBJECT_ID');
    expect(codes).toContain('IP_COVERED_BY_WHITELIST');
  });
});

describe('第 2 组 · 调用点侧前提', () => {
  /**
   * 下界取实测值（367 个调用点 / 26 个文件 / 188 个不同字面量码 / 5 个动态站点 / 4 个 opaque
   * 站点）留出的余量，而不是拍一个"看起来合理"的数。五条都要：只卡总数会被"某个文件解析失败
   * 但别处放大"蒙过；只卡文件数会被"一个文件里塞满假调用"蒙过；卡索引基数是为了让"码表还在但
   * 调用点全丢"这种扫描器空转立刻现形；卡动态站点与 opaque 站点下界是为了让"动态站点不再被收
   * 进数组"这种**收窄面积**的退化现形——opaque 数掉了，#16/#17 的登记核对就会静默空转，所以
   * 必须先在这里响。
   */
  test('#9 全仓 codeError 调用点扫描不空转（数量/文件数/码数/动态/opaque 下界）', () => {
    expect(calls.total).toBeGreaterThanOrEqual(300);
    expect(calls.files).toBeGreaterThanOrEqual(20);
    expect(calls.index.size).toBeGreaterThanOrEqual(150);
    expect(calls.dynamic.length).toBeGreaterThanOrEqual(3);
    expect(calls.opaque.length).toBeGreaterThanOrEqual(3);
  });

  test('#10 威胁模型锚：codeError 仍优先用调用方 message，回退顺序不许反', () => {
    const responder = S.codeOnlyFrom(ROOT, REL_RESPONDER);
    expect(/const message = options\.message \|\| \(def && def\.message\)/.test(responder)).toBe(
      true
    );
  });
});

describe('第 3 组 · 判据', () => {
  test('#11 占位符码的每个生产调用点都必须自己传 message', () => {
    const leaks = S.leaksOf(placeholderCodes(), calls.index);
    expect(leaks.map((r) => `${r.code} @ ${r.file}:${r.line}`)).toEqual([]);
  });

  test('#12 不许有未声明的"占位符码没人调用"', () => {
    expect(S.orphansOf(placeholderCodes(), calls.index).sort()).toEqual(DECLARED_DEAD);
  });

  test('#13 调用点自拼的 message 里不许有单/双引号占位符字面量', () => {
    const rows = [];
    for (const list of calls.index.values()) {
      for (const call of list) {
        if (call.literalPlaceholder) rows.push(`${call.code} @ ${call.file}:${call.line}`);
      }
    }
    expect(rows).toEqual([]);
  });
});

describe('第 4 组 · 动态码槽侧（按码建的索引看不见的那两面）', () => {
  /**
   * 三分法（定义在 helpers/codeErrorCallScan 的 scanCalls 头）：
   *  纯字面量槽 `'CODE'` ⇒ 进索引；字面量分支槽 `flag ? 'A' : 'B'` ⇒ A/B 都进索引，
   *  于是 #11 的泄漏判据覆盖得到它们；纯变量槽 ⇒ opaque，索引无从谈起，交给 #16–#18 登记。
   * 这里还要证明**接线**而不是只证明分类：`buildIndex` 走的是真树同一条函数，所以
   * "槽内码进索引"这一步能被合成样例打到（第 2 族的收口）。
   * `leaksOf(['runtimeCode'])` 故意不出一条泄漏——opaque 站点在索引里根本没有条目，
   * 这条断言把"看不见"与"安全"区分开写清楚：它绿不是因为分支安全，而是因为判据够不着，
   * 够不着的那一面由登记腿负责。
   */
  test('#14 码槽三分法与索引接线：分支码进索引，只有纯变量才是 opaque', () => {
    const dyn = sampleCalls.filter((c) => c.dynamic);
    expect(dyn.map((c) => c.slot)).toEqual(['runtimeCode', "flag ? 'BRANCH_A' : 'BRANCH_B'"]);
    expect(dyn.map((c) => c.opaque)).toEqual([true, false]);
    expect(dyn[1].slotCodes).toEqual(['BRANCH_A', 'BRANCH_B']);
    const idx = S.buildIndex([{ file: 'syn.js', calls: sampleCalls }]);
    expect([...idx.index.keys()].sort()).toEqual([
      'BRANCH_A',
      'BRANCH_B',
      'DECOY_PAREN',
      'DECOY_TPL',
      'FALSY_EMPTY',
      'FALSY_NULL',
      'FALSY_UNDEF',
      'LEAK_LITERAL',
      'LEAK_MISS',
      'PASS_OK',
    ]);
    expect(idx.opaque.map((c) => c.slot)).toEqual(['runtimeCode']);
    expect(
      S.leaksOf(['BRANCH_A', 'BRANCH_B', 'runtimeCode'], idx.index)
        .map((r) => `${r.code}@${r.file}:${r.line}`)
        .sort()
    ).toEqual(['BRANCH_A@syn.js:8', 'BRANCH_B@syn.js:8']);
  });

  /**
   * `options.message || def.message` 里的 `||` 让"写了 message"不等于"message 会生效"。
   * 三种 falsy 字面量都必须被当成没传；正向对照（PASS_OK）同腿保留，否则把判据改成
   * `passesMessage = false` 也能让这条腿全绿。
   */
  test('#15 falsy 的 message（undefined/null/空串）等于没传', () => {
    expect(sampleOf('FALSY_UNDEF').passesMessage).toBe(false);
    expect(sampleOf('FALSY_NULL').passesMessage).toBe(false);
    expect(sampleOf('FALSY_EMPTY').passesMessage).toBe(false);
    expect(sampleOf('PASS_OK').passesMessage).toBe(true);
    const idx = S.buildIndex([{ file: 'syn.js', calls: sampleCalls }]);
    expect(
      S.leaksOf(['FALSY_UNDEF', 'FALSY_NULL', 'FALSY_EMPTY', 'PASS_OK'], idx.index)
        .map((r) => r.code)
        .sort()
    ).toEqual(['FALSY_EMPTY', 'FALSY_NULL', 'FALSY_UNDEF']);
  });

  test('#16 不传 message 的 opaque 站点必须逐条登记（双向，多登记同样红）', () => {
    const keys = calls.opaque.map(siteKey);
    const notPassing = calls.opaque.filter((c) => !c.passesMessage).map(siteKey);
    // 站点键必须良定义：同文件同槽文本会让"漏登记"藏在去重里
    expect(new Set(keys).size).toBe(keys.length);
    expect(new Set(notPassing).size).toBe(notPassing.length);
    expect([...new Set(notPassing)].sort()).toEqual(DECLARED_DYNAMIC.map((d) => d.site).sort());
  });

  /**
   * 一腿一判据：这条只管"登记抄得对不对"（与源码现采双向相等 + 闭合集仍然闭合）。
   * `nonLiteral` 非空意味着有人把值换成了变量/表达式 ⇒ 现采说不出可达集，登记不再是机器
   * 可判的，必须响而不是静默放行。
   */
  test('#17 登记的码集必须与源码现采双向相等，且不许被非字面量赋值破闭', () => {
    for (const d of DECLARED_DYNAMIC) {
      const traced = tracedCodes(d.trace);
      expect({ site: d.site, nonLiteral: traced.nonLiteral }).toEqual({
        site: d.site,
        nonLiteral: [],
      });
      expect({ site: d.site, values: traced.values }).toEqual({
        site: d.site,
        values: [...d.codes].sort(),
      });
    }
  });

  /**
   * 这条才是"动态站点不会漏出占位符"的结论本身：登记的可达码集与占位符面积必须零交；
   * 顺带要求每个码仍在码表里（登记里的码被改名/删除 ⇒ 运行期走 `'操作失败'` 兜底，
   * 那是另一类缺陷，但同样说明这份登记已经陈旧）。
   */
  test('#18 登记的可达码集与占位符面积零交，且每个码都还在码表里', () => {
    const area = new Set(placeholderCodes());
    const known = new Set(registry.keys);
    const bad = [];
    for (const d of DECLARED_DYNAMIC) {
      for (const code of d.codes) {
        if (area.has(code)) bad.push(`${d.site} → ${code}：默认消息带占位符`);
        if (!known.has(code)) bad.push(`${d.site} → ${code}：不在码表里（登记陈旧或拼错）`);
      }
    }
    expect(bad).toEqual([]);
  });

  /**
   * 现采器自己的牙（第 3 族的收口）：`nonLiteral` 那一臂在真树上**今天没有对手输入**——
   * 全仓没有一处 `forbiddenCode: 变量` 的写法，所以它不可能被任何真树腿打到；把它写成
   * "登记值与现采值不等就会红"是不成立的：等式腿只覆盖删除，覆盖不了"新增一个动态分支"
   * （`notFound: pick(req)` 加入表里时，其余字面量照旧，等式仍然成立，而闭合集已经不再闭合）。
   * 所以这里**制造**对手输入，并双向断言：字面量赋值必须被收进 values，非字面量赋值必须
   * 被报进 nonLiteral（且不再进 values）。变异 ph-trace-nonliteral-swallow 只红这一条。
   */
  test('#19 现采器有牙：字面量进 values，非字面量必须报 nonLiteral', () => {
    expect(
      S.literalValuesForProps("{ a: 'X_CODE', b: 'y' }, { forbiddenCode: 'Z_CODE' }", [
        'forbiddenCode',
      ])
    ).toEqual({
      values: ['Z_CODE'],
      nonLiteral: [],
    });
    expect(S.literalValuesForProps('{ forbiddenCode: pickCode(req) }', ['forbiddenCode'])).toEqual({
      values: [],
      nonLiteral: ['forbiddenCode: pickCode(req)'],
    });
  });
});

/* ============================== 变异台账（2026-10-04 第 29 轮全量重测）==============================
 * 跑法：node <工作区>/tools/ledger.js <被测文件> src/tests/ci/errorCodePlaceholderDefault.test.js <模式=预测>
 * 腿编号按文件里的声明顺序（19 腿）：
 *   #1-#5 第 0 组（扫描器/分类器自检）｜#6-#8 第 1 组（注册表侧前提）
 *   #9-#10 第 2 组（调用点下界 + 威胁模型锚）｜#11-#13 第 3 组（判据）
 *   #14-#19 第 4 组（码槽三分法与索引接线 / falsy message / opaque 登记三腿 / 现采器有牙）
 * 基线：19 采集 / 19 绿 / 0 红（四次开跑各带一次基线，四次同值）；被测文件
 * （辅助件 / apiResponse / errorCodes / userController）22 条模式跑完，每条恢复校验均"与被测开始时
 * 逐字节相同"，0 条 MUT-ABORT。
 *
 * 【为什么整套重测而不是只补新腿】仪器在本轮动了五处：码槽口径（splitArgs/codeSlotOf）、
 * 字面量分支进索引（slotCodes）、opaque 单列（dynamic/opaque 两个数组 + buildIndex 拆成纯函数）、
 * falsy message（falsyLiteral）、泄漏行的 code 覆盖顺序（leaksOf）。任何一处都会改变"哪些腿吃
 * 这条退化"（第 26 轮偏差八的形状），旧颜色整批作废。实测结果：22/22 全部被杀（零存活），
 * 其中 3 条的实测红腿集合比预测**多**——都是"腿变严了"的方向，见偏差①②。
 *
 *   ── 被测 src/tests/helpers/codeErrorCallScan.js（仪器侧，19 条）──
 *   ph-scan-passes-blind      预测 红:#1,#14,#15,#16      实测 同 ✓（#11 全程绿=空转）
 *   ph-scan-line-blind        预测 红:#1,#14              实测 同 ✓
 *   ph-pairing-blind          预测 红:#2                  实测 同 ✓
 *   ph-call-prefix-blind      预测 红:#2,#14,#16          实测 同 ✓（定义点 static codeError 变成
 *                                                            一个不传 message 的 opaque 站点）
 *   ph-literal-blind          预测 红:#3                  实测 同 ✓（#13 全程绿=空转）
 *   ph-orphan-blind           预测 红:#4                  实测 红:#4,#12 ← 偏差①
 *   ph-leak-builder-blind     预测 红:#5,#14,#15          实测 同 ✓（#11 全程绿=空转）
 *   ph-registry-parse-empty   预测 红:#6,#7,#8            实测 红:#6,#7,#8,#12 ← 偏差①
 *   ph-quote-type-blind       预测 红:#7                  实测 同 ✓
 *   ph-placeholder-blind      预测 红:#6,#8,#12           实测 同 ✓
 *   ph-callsite-scan-empty    预测 红:#1,#2,#3,#9,#12,#14,#15,#16  实测 同 ✓（8 红）
 *   ph-parse-newline-blind    预测 红:#6,#8,#12           实测 同 ✓（本轮真实踩过的洞：15 vs 18）
 *   ph-slot-first-seg         预测 红:#1,#2,#3,#9,#12,#14,#15,#16  实测 同 ✓（8 红；索引被清空）
 *   ph-slotcode-not-indexed   预测 红:#14                 实测 同 ✓（#11 对分支站点失明只有合成腿抓得到）
 *   ph-dynamic-not-collected  预测 红:#9,#14,#16          实测 同 ✓（#9 的下界先响，登记核对随后）
 *   ph-falsy-blind            预测 红:#15                 实测 同 ✓（真树零处 falsy ⇒ 判据腿全绿，
 *                                                            这正是"牙齿必须长在合成腿上"的形状）
 *   ph-leak-row-clobber       预测 红:#14                 实测 同 ✓（红讯把码名报成 null）
 *   ph-trace-collector-empty  预测 红:#17,#19             实测 同 ✓
 *   ph-trace-nonliteral-swallow 预测 红:#19               实测 同 ✓（真树上这条是等价变异：全仓
 *                                                            没有一处 `属性名: 变量` ⇒ 只有 #19 的
 *                                                            合成对手输入能杀它——第 3 族的收口）
 *   ── 被测 src/utils/apiResponse.js（威胁模型侧，1 条）──
 *   ph-fallback-priority-flip 预测 红:#10                 实测 同 ✓（#11 照绿=判据的前置条件消失）
 *   ── 被测 src/utils/errorCodes.js（码表侧，1 条）──
 *   ph-default-becomes-template 预测 红:#7                实测 红:#6,#7 ← 偏差②
 *   ── 被测 src/controllers/userController.js（判据侧，1 条）──
 *   ph-call-message-dropped   预测 红:#11                 实测 同 ✓（唯一让判据腿自己红的变异）
 *
 * 偏差①（登记非空会把原本空转的判据腿变成有牙）：DECLARED_DEAD 从"上一轮的 []"变成"两条真死码"
 * 之后，任何让占位符面积变空的变异都会连带红 #12——上一轮台账写的是"ph-orphan-blind 红:#4
 * （#12 全程绿=空转）"，那条"空转"已经不存在了。推论：**空登记的判据腿没有牙，填了理由的登记
 * 让两侧都能红**；同理 ph-registry-parse-empty 多红了 #12。旧颜色里凡是写"某腿空转绿"的，
 * 都要在新基线上重看一遍，不能沿用。
 * 偏差②（"码表改成真模板"会连带打断真值口径）：#6 的第二套口径是 require 码表后看加载真值，
 * 而模板串里的 `${format}` 在码表作用域中是未定义变量 ⇒ 加载直接抛 ReferenceError ⇒ #6 也红。
 * 这不是坏事（纯数据前提被两条腿分别守住：#7 看引号类型，#6 看能不能加载），但它让 #6 的红讯
 * 形状是"抛异常"而不是"差集非空"，读台账时容易误判成解析器坏了。
 *
 * 观察①（本闸为什么要第 0 组与第 4 组的合成腿）：六条"仪器失明/收窄"变异
 * （passesMessage 恒 true、leaksOf 恒空、literalPlaceholder 恒 false、orphansOf 恒空、
 * slotCodes 不进索引、dynamic 不收集）里，判据腿 #11/#13/#12 **从未**因为仪器退化而变红——
 * 它们只会变得更绿（清单恒空）。第 3 族的定义性特征就是这个，所以牙齿全部长在合成腿上。
 * 观察②（为什么 #10 必须独立存在）：把回退优先级翻转成 `def.message || options.message` 之后，
 * 18 条占位符默认消息**立刻**全部开始对外泄漏，而 #11 的判据（调用点有没有传 message）一字不改
 * 地全绿。"判据的前置条件消失了"只有锚点腿能看见——它不参与判据，也不该参与。
 * 观察③（本轮真正被合成腿抓到的两个缺陷，都不是仓库的 bug 而是仪器的）：
 *  (a) 码槽取错：旧实现"整段参数里正则取第一个 UPPER_SNAKE"，把 `flag ? 'A' : 'B'` 读成只有 A，
 *      把 `codeError(res, dyn, { message: 'X' })` 读成"X 有个安全的调用点"。前者是本轮在
 *      src/middleware/logoutAuth.js:45 现场抓到的（AUTH_TOKEN_MISSING 被吞），后者今天还没人写。
 *  (b) 泄漏行被 `...call` 覆盖成 `code: null`：今天泄漏集为空所以从没打印过这个字段，
 *      是 #14 的合成分支样例把它逼出来的。两处都已改成有牙的形状并各自配了变异。
 *
 * 近似（本闸管不到的面，逐条写清"这里没有腿，别当已覆盖"）：
 *   1) 只审 `codeError`，不审 `ApiResponse.error`/`success` 之类的其他出口——它们没有"回退到
 *      注册表默认消息"这条路径，占位符泄漏面不存在（已读 src/utils/apiResponse.js 核实）。
 *   2) 注册表里非占位符的默认消息（178 条）本闸不看：调用点不传 message 时发出去的是正常文案，
 *      不是缺陷。若要审"文案与码义是否相符"，那是需要语义的另一类判据，不在文本闸能力内。
 *   3) #13 只看调用点**字面量**里的占位符；变量拼接进来的字符串看不见（需要数据流）。
 *      ph-literal-blind 红:#3 证明分类器有牙，但牙的长度止于字面量。
 *   4) `message:` 的值是**变量**时（实测 1 处：userController.js 的 membershipError.message），
 *      本闸按 passesMessage=true 放过——那份变量文案里有没有占位符是数据流问题，文本闸判不了。
 *      这是"opaque message"面，与本轮修掉的"opaque code"面同形但更小，暂不登记（登记不了闭合集）。
 *   5) 现采器（literalValuesForProps）按"属性名逐字赋字符串字面量"取闭合集。若将来可达集改成
 *      计算式（`notFound: cond ? 'A' : 'B'`），现采会把它报成 nonLiteral ⇒ #17 红，逼作者显式
 *      处理（不是静默放行），但闸不会替你算出那个闭合集。
 *   6) 与 src/tests/emittedErrorCodeCoverage.test.js（并行 agent 的门禁）有重叠面：它的"第四通道"
 *      与本轮的现采口径同源（都是 forbiddenCode/higherLevelCode 的属性赋值），它的死码清单与
 *      本闸 DECLARED_DEAD 是同两条码。两边规则并不相同（它不跑注释剥离视图、覆盖全部码而不止
 *      占位符面积），今天结论一致；谁改了口径要来看对方一眼——两条闸互不引用是最大的隐患。
 * ========================================================================================== */
