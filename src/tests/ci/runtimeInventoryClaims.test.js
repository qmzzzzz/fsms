/**
 * 运行期单进程依赖清单（constants/runtime.js SINGLE_PROCESS_DEPENDENCIES）的"声称 vs 代码"对拍。
 *
 * 为什么要有这个门禁：这份清单是运维据以决定"能不能多实例部署"的唯一入口，
 * 而它此前只是散文——清单里给 services/reportDashboardService.js 写着"配失效广播"
 * 并 `redisExternalized: true`，那个模块自己的头注释（src/services/reportDashboardService.js:18-22）
 * 写的却是**刻意不做跨实例失效广播**。后果不是文档不准：`assertSingleProcessAssumptions`
 * 在 REDIS_URL 就绪时会把 `redisExternalized` 的条目从"仍按单进程假设运行"的清单里滤掉，
 * 于是多实例部署看不到这块缓存的不一致，只看得到它想让你看到的。
 *
 * 判据的牙（每条都有反向自证，见下面的用例）：
 *  - 声称"广播"⇒ 模块代码里必须同时有发布端和消费端（只在注释里提到 publishInvalidate 不算）；
 *  - 声称某个键前缀（反引号里的 `xxx:`）⇒ 该前缀必须作为代码字面量存在于模块里；
 *  - `module` 指向的文件必须存在；
 *  - 声称与 `redisExternalized` 互相矛盾的组合，逐条钉住今天修的那一处。
 */
const fs = require('fs');
const path = require('path');
const { SINGLE_PROCESS_DEPENDENCIES } = require('../../constants/runtime');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');

const SRC = path.join(__dirname, '..', '..');

/**
 * 「只剩代码」视图：只判"代码里真的写了"，不判"注释里提到了"（本门禁抓的正是这个区别）。
 * 口径刻意不在这里重写一遍——`tests/helpers/jsCodeOnly` 是本仓唯一一份"什么算注释"的实现，
 * 自己抄一份就会和它漂移（哪天它修了块注释/行尾注释的边界，我这份仍然按旧口径放行）。
 */
const codeOf = (abs) => jsCodeOnly(fs.readFileSync(abs, 'utf8'));

const absOf = (rel) => path.join(SRC, rel);
const claimText = (e) => `${e.mechanism || ''} ${e.impact || ''}`;

/**
 * 只算**肯定式**声称：先把"…不…广播"这种同一子句内的否定形态整段摘掉，再看还剩不剩"广播"。
 * 不做这一步，"刻意不接失效广播"这句真话会被当成声称，判据就对否定句失明；
 * 反过来，把措辞改窄（只认某几个词）也会让下一句换个写法的假声称静默过关。
 */
const broadcastClaimed = (text) =>
  /广播/.test(text.replace(/[^，；。)）]*(?:不|未|无|没)[^，；。)）]*广播[^，；。)）]*/g, ''));

/**
 * 「代码里两端都接了」的判据本体——单一来源：真清单和反向自证都走它。
 *
 * 为什么要单独抽出来：只拿真实文件测的话，"两端都要"和"两端任其一"在现网形状上**不可区分**
 * （真接广播的模块本来就两端齐全），把 `&&` 写成 `||` 不会有的用例变红——那这条判据就是
 * 装饰。抽成吃代码文本的函数后，可以喂合成代码把三种形状各钉一次。
 */
const missingBroadcastPairIn = (code) => {
  const publishes = /publishInvalidate\s*\(/.test(code);
  const consumes = /(onInvalidate|subscribe)\s*\(/.test(code);
  if (publishes && consumes) return null;
  return `声称广播但代码里${publishes ? '缺消费端' : consumes ? '缺发布端' : '两端都没有'}`;
};

/** 条目形状判据（同上：正反两向共用一份定义，不在用例里另抄一遍条件） */
const missingFields = (entries) =>
  entries
    .filter((e) => !e.module || !e.mechanism || !e.impact || !/\.js$/.test(e.module))
    .map((e) => `${e.module} :: ${e.mechanism}`);

const duplicateModules = (entries) => {
  const mods = entries.map((e) => e.module);
  return mods.filter((m, i) => mods.indexOf(m) !== i);
};

/** 声称"广播"的条目：要求模块代码里同时存在发布端与消费端 */
function broadcastPairMissing(e) {
  const abs = absOf(e.module);
  if (!fs.existsSync(abs)) return `module 文件不存在：${e.module}`;
  return missingBroadcastPairIn(codeOf(abs));
}

/** 反引号里声称的键前缀（`sesscache:`）必须作为代码字面量存在 */
function claimedPrefixMissing(e) {
  const prefixes = [...(e.mechanism || '').matchAll(/`([\w.-]+: ?)`/g)].map((m) => m[1].trim());
  const abs = absOf(e.module);
  const code = fs.existsSync(abs) ? codeOf(abs) : '';
  return prefixes.filter((p) => !code.includes(`'${p}'`) && !code.includes(`\`${p}\``));
}

/**
 * 「impact 里写了 N 秒 TTL ⇒ 模块代码里必须真有这个 TTL」的判据本体。
 * 真清单与反向自证都走它——否则自证只是把结论重算一遍，改坏判据的人不必动它，
 * 用例照样全绿（变异台账第 28 轮实测：判据里那行 `if (!code.includes(...))` 掏空后无人转红）。
 */
const ttlClaimsUnbacked = (entries) => {
  const offenders = [];
  for (const e of entries) {
    const m = claimText(e).match(/(\d+)\s*s(?:econds?)?\b/);
    if (!m) continue;
    const abs = absOf(e.module);
    if (!fs.existsSync(abs)) continue;
    const code = codeOf(abs);
    if (!code.includes(`${m[1]} * 1000`) && !code.includes(`${m[1]}000`)) {
      offenders.push(`${e.module}：impact 写了 ${m[1]}s，代码里找不到对应的 TTL`);
    }
  }
  return offenders;
};

const broadcastClaims = () =>
  SINGLE_PROCESS_DEPENDENCIES.filter((e) => broadcastClaimed(claimText(e)));

/**
 * 「声称广播的条目里，代码两端没接齐的」采集器。
 *
 * 接线本身也要有牙：反向自证必须**走这条接线**，而不是直接调 broadcastPairMissing。
 * 否则把 `.filter((x) => x.why)` 换成 `() => false`，真清单那条断言和自证都还是绿的——
 * 判据留在，接线没了，门禁静默减质（变异台账第 28 轮实测出来的同族盲区）。
 */
const broadcastPairOffenders = (entries) =>
  entries
    .map((e) => ({ e, why: broadcastPairMissing(e) }))
    .filter((x) => x.why)
    .map((x) => `${x.e.module} :: ${x.why}`);

/** 同上：键前缀判据的接线采集器，正反两向都从这里过 */
const prefixOffenders = (entries) =>
  entries
    .map((e) => ({ e, missing: claimedPrefixMissing(e) }))
    .filter((x) => x.missing.length > 0)
    .map((x) => `${x.e.module} 声称用了 ${x.missing.join('/')}，代码里没有`);

describe('单进程依赖清单：声称必须落到代码上', () => {
  test('声称识别不许对否定句失明（"不接广播"是真话的形状，不是声称）', () => {
    expect(
      broadcastClaimed('缓存本体在进程内，靠 sharedCache 广播失效；Redis 未就绪时不跨进程')
    ).toBe(true);
    expect(broadcastClaimed('配失效广播')).toBe(true);
    expect(broadcastClaimed('仪表盘缓存（dashboardCache Map，刻意不接失效广播）')).toBe(false);
    expect(broadcastClaimed('无跨实例失效广播')).toBe(false);
  });

  test('清单本体不许塌缩，且每条都要有 module/mechanism/impact', () => {
    expect(SINGLE_PROCESS_DEPENDENCIES.length).toBeGreaterThanOrEqual(18);
    expect(missingFields(SINGLE_PROCESS_DEPENDENCIES)).toEqual([]);
    expect(duplicateModules(SINGLE_PROCESS_DEPENDENCIES)).toEqual([]);
    // 反向自证：现网清单是全绿的，所以判据本身可能是恒真的空转——自己造缺项/重复的形状。
    expect(missingFields([{ module: 'a.js', mechanism: 'm', impact: 'i' }])).toEqual([]);
    expect(missingFields([{ module: 'a.js', mechanism: 'm' }])).toHaveLength(1); // 缺 impact
    expect(missingFields([{ mechanism: 'm', impact: 'i' }])).toHaveLength(1); // 缺 module
    expect(missingFields([{ module: 'a.txt', mechanism: 'm', impact: 'i' }])).toHaveLength(1); // 非 .js
    expect(duplicateModules([{ module: 'a.js' }, { module: 'b.js' }])).toEqual([]);
    expect(duplicateModules([{ module: 'a.js' }, { module: 'a.js' }])).toEqual(['a.js']);
  });

  test('每条 module 指向的文件真实存在（清单不许挂在空气上）', () => {
    const gone = SINGLE_PROCESS_DEPENDENCIES.filter((e) => !fs.existsSync(absOf(e.module))).map(
      (e) => e.module
    );
    expect(gone).toEqual([]);
  });

  test('声称"失效广播"的条目，模块代码里必须真的有发布端 + 消费端', () => {
    const claims = broadcastClaims();
    // 现网真有广播的是三条（权限、会话、统计）；低于这个数说明有人删了判据
    expect(claims.length).toBeGreaterThanOrEqual(2);
    expect(broadcastPairOffenders(claims)).toEqual([]);
    // 反向自证 1：注释里把两条腿都写出来，也不等于接了广播——必须走同一条接线报出来。
    // （这条同时钉住"判据跑在代码视图上"：全文匹配会判它两端齐全，于是自证转绿。）
    expect(
      broadcastPairOffenders([
        { module: 'services/reportDashboardService.js', mechanism: '配失效广播' },
      ])
    ).toHaveLength(1);
    // 反向自证 2：判据不是恒真——把一条真接了的模块拿来判，接线必须判得出"没毛病"
    const real = claims.find((e) => !broadcastPairMissing(e));
    expect(real).toBeTruthy();
    expect(broadcastPairOffenders([real])).toEqual([]);
    // 反向自证 3：四种代码形状各钉一次。只跑真实文件的话，"两端都要"与"任其一"不可区分
    // （真接广播的模块两端都齐），把 && 改成 || 会一声不响地过关。
    expect(missingBroadcastPairIn('a.publishInvalidate(k);\nb.onInvalidate(h);')).toBeNull();
    expect(missingBroadcastPairIn('a.publishInvalidate(k);')).toMatch(/缺消费端/);
    expect(missingBroadcastPairIn('a.onInvalidate(h);')).toMatch(/缺发布端/);
    expect(missingBroadcastPairIn('const x = 1;')).toMatch(/两端都没有/);
    // 反向自证 4：注释里把两条腿都写出来，也不能算"接了广播"。
    // （services/reportDashboardService.js:18-23 的改法说明本来就该写全：只接发布端等于没接。）
    // 这一条钉的是"判据跑在代码视图上"这件事本身：全文匹配会判它两端齐全 ⇒ 下面第一行为真、
    // 第二行必须仍然报"两端都没有"。
    const dashAbs = absOf('services/reportDashboardService.js');
    const dashSrc = fs.readFileSync(dashAbs, 'utf8');
    expect(missingBroadcastPairIn(dashSrc)).toBeNull();
    expect(missingBroadcastPairIn(codeOf(dashAbs))).toMatch(/两端都没有/);
  });

  test('反引号里写出的键前缀必须是模块代码里的真字面量', () => {
    expect(prefixOffenders(SINGLE_PROCESS_DEPENDENCIES)).toEqual([]);
    // 判据有牙，且自证走的是同一条接线：现网确实有一条真声称（`sesscache:` ⇒
    // src/services/sessionService.js:219），编一个不存在的前缀必须被这套接线挑出来。
    expect(
      prefixOffenders([{ module: 'services/sessionService.js', mechanism: '配 `zzzcache:` 广播' }])
    ).toHaveLength(1);
    expect(
      prefixOffenders([{ module: 'services/sessionService.js', mechanism: '配 `sesscache:` 广播' }])
    ).toEqual([]);
    // 没写反引号前缀的条目不参与这条判据（否则它会成为噪声，把真正的失声称淹没）
    expect(
      prefixOffenders([{ module: 'services/sessionService.js', mechanism: '进程内会话表' }])
    ).toEqual([]);
  });

  test('今天修的那一条：仪表盘缓存既不声称广播，也不许借 redisExternalized 躲开体检', () => {
    const dash = SINGLE_PROCESS_DEPENDENCIES.find((e) =>
      e.module.endsWith('reportDashboardService.js')
    );
    expect(dash).toBeTruthy();
    expect(broadcastClaimed(claimText(dash))).toBe(false);
    expect(dash.redisExternalized).toBeUndefined();
    // 体检口径：Redis 就绪后它仍必须出现在"单进程假设"清单里（runtime.js 的过滤条件
    // 是 `!(redisReady && d.redisExternalized)` ⇒ 这个旗标就是"多实例安全"这句话本身）
    expect(
      SINGLE_PROCESS_DEPENDENCIES.filter((d) => d.redisExternalized).some((d) =>
        d.module.endsWith('reportDashboardService.js')
      )
    ).toBe(false);
    // 反向自证：把条目改回"靠广播失效 + 已外置"的形态，判据必须立刻判它不成立
    const revived = { ...dash, mechanism: '仪表盘缓存（配失效广播）', redisExternalized: true };
    expect(broadcastPairMissing(revived)).not.toBeNull();
    expect(broadcastClaimed(claimText(revived))).toBe(true);
  });

  test('清单里凡写"最长 N 秒/一个 N TTL"的，模块里必须真有那个 TTL 常量', () => {
    expect(ttlClaimsUnbacked(SINGLE_PROCESS_DEPENDENCIES)).toEqual([]);
    // 反向自证：走同一个函数——"声称 99s 但模块里没有 99 * 1000"必须被挑出来，
    // "声称 30s 且 reportDashboardService 真有 30 * 1000"必须放行（判据不是恒真也不是恒假）。
    expect(
      ttlClaimsUnbacked([{ module: 'services/sessionService.js', impact: '最长滞后一个 99s TTL' }])
    ).toHaveLength(1);
    expect(
      ttlClaimsUnbacked([
        { module: 'services/reportDashboardService.js', impact: '最长滞后一个 30s TTL' },
      ])
    ).toEqual([]);
    // 没写秒数的条目不参与这条判据（否则任何条目都会被判）
    expect(
      ttlClaimsUnbacked([{ module: 'services/statsCache.js', impact: '无 TTL 声称' }])
    ).toEqual([]);
  });
});
