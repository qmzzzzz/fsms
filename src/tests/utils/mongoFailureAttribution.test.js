/**
 * `isContentAttributableFailure` 真值表 + 依赖派生的漂移门禁
 *
 * 这条判据决定 auditBuffer 要不要把审计从 WAL 里删掉，且误判方向不可逆：
 * 判成"内容级"⇒ 达阈值即归档丢弃（一次抖动 = 一条永久缺失的合规记录）；
 * 判成"基础设施"⇒ 只是重试不收敛。所以每一个分支都必须可证伪，
 * 尤其是"两边都像"时的优先级——基础设施特征必须先赢。
 *
 * 三张特征表由被测模块自己导出，这里**遍历**它们而不是抄一份清单：
 * 新增一项就自动多一条断言，删一项则断言集自动收缩（抄清单会立刻过期）。
 *
 * 【F-183：为什么"遍历清单"本身还不够】
 * 原用例形如"`for (const name of INFRA_ERROR_NAMES) expect(judge({name})).toBe(false)`"，
 * 而判据对**任何它不认识的名字**都返回 false（保守分支）。于是这行断言对任意编造的名字
 * 都成立：清单里 14 个名字有 9 个是 driver 3/4 时代手写却根本不存在的类名，
 * 全绿，一条都没在防。删掉任意一项也不会红（清单自己就是遍历对象）。
 * 现在补三条派生门禁，把"清单内容"与"清单效果"分别钉住：
 *   ① 名字必须真的可能是 `err.name`（从 node_modules 的驱动/Mongoose 源码推导）；
 *   ② 每一项都必须**有效果**：infra 名 + code 121 仍须 false（漏一项即转红）；
 *   ③ 依赖里其余错误类名**不得**被认成内容级（驱动新增一个 infra 类而这里没补 ⇒ 转红）。
 */

const path = require('path');
const fs = require('fs');
const { createRequire } = require('module');
const mongoose = require('mongoose');
const {
  isContentAttributableFailure,
  INFRA_ERROR_NAMES,
  INFRA_ERROR_CODES,
  INFRA_ERROR_CODE_NAMES,
  CONTENT_ERROR_NAMES,
  CONTENT_ERROR_CODES,
  CONTENT_ERROR_CODE_NAMES,
  CARRIER_ERROR_NAMES,
} = require('../../utils/mongoFailureAttribution');

/** 构造一个只带指定特征的错误，避免用例间互相污染 */
const mk = (props = {}) => Object.assign(new Error(props.message || 'x'), props);

/** 服务端逐条拒绝的条目（实测形状：码嵌在 .err 下，条目自身只有 {index, err}） */
const entry = (code) => ({
  index: 0,
  err: { index: 0, code, errmsg: 'from server', op: { _id: 'a' } },
});

// ---------------------------------------------------------------------------
// 依赖真名：从**实际会被使用的那份驱动**推导
// ---------------------------------------------------------------------------

/**
 * ⚠️ 不能直接 `require('mongodb')`：jest/Node 会解析到**顶层被提升的 mongodb**
 * （本仓它是 mongodb-memory-server / migrate-mongo 的 7.x），而运行期真正用的是
 * mongoose 自带的那份（`node_modules/mongoose/node_modules/mongodb`，6.20.0）。
 * 拿错版本推出来的名字集合会把判据锁到一个生产上不会出现的类名空间上。
 */
const mongooseEntry = require.resolve('mongoose');
const driverRequire = createRequire(mongooseEntry);
const driverLib = path.join(path.dirname(driverRequire.resolve('mongodb/package.json')), 'lib');
const mongooseLib = path.join(path.dirname(mongooseEntry), 'lib');
/**
 * 驱动的错误码表与"瞬态/可续传"名单在 `lib/error.js` 里，且**不在包的公开导出面上**
 * （实测 `require('mongodb').MONGODB_ERROR_CODES` 为 undefined），所以按绝对路径 require 该文件。
 * 这是派生门禁的独立真值来源：它不属于被测模块，因此"删掉判据表里的一项"不会让它跟着收缩。
 */
const driverErrorMod = require(path.join(driverLib, 'error.js'));

const NAME_PATTERNS = [
  /class\s+([A-Z]\w*Error)\s+extends/g, // 未显式覆盖 name 时，原生 err.name 就是类名
  /defineProperty\(\s*\w+\.prototype,\s*['"]name['"]\s*,\s*\{[^}]*?value:\s*['"]([A-Z]\w*Error)['"]/g,
];

function namesFromDir(dir) {
  const found = new Set();
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const abs = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!/^(test|scripts|types|dist|helpers)$/.test(e.name)) walk(abs);
      } else if (e.name.endsWith('.js')) files.push(abs);
    }
  };
  walk(dir);
  for (const f of files) {
    const src = fs.readFileSync(f, 'utf8');
    for (const rx of NAME_PATTERNS) {
      for (const m of src.matchAll(rx)) found.add(m[1]);
    }
  }
  return found;
}

/** 导出面上再核对一遍 `Class.prototype.name || Class.name`（= 实例化后 err.name 的真实取值规则） */
function namesFromExports(mod) {
  const found = new Set();
  for (const [k, v] of Object.entries(mod)) {
    if (typeof v === 'function' && /Error$/.test(k)) found.add(String(v.prototype.name || v.name));
  }
  return found;
}

const KNOWN_ERROR_NAMES = new Set([
  ...namesFromDir(driverLib),
  ...namesFromDir(mongooseLib),
  ...namesFromExports(driverRequire('mongodb')),
]);

describe('依赖派生的漂移门禁（F-183：清单必须既真实又有效果）', () => {
  test('推导本身非空且包含已实测到的类名（防止扫描器哪天扫出 0 条而让下面两条变成空遍历）', () => {
    expect(KNOWN_ERROR_NAMES.size).toBeGreaterThan(20);
    for (const n of ['MongoBulkWriteError', 'MongooseServerSelectionError', 'ValidationError']) {
      expect({ n, known: KNOWN_ERROR_NAMES.has(n) }).toEqual({ n, known: true });
    }
  });

  test('① INFRA_ERROR_NAMES 每一项都必须是依赖里真的会出现的 err.name', () => {
    // 反向说明：driver 3/4 的 MongoNotPrimaryError / MongoInterrupted*Error / MongoTimeoutError
    // 在 6.x 已被 MongoServerError + code/codeName 取代；MongoPoolClearedError 尤其阴——
    // 类名带 Mongo 前缀，但 prototype.name 是**没有前缀**的 'PoolClearedError'。
    const dead = [...INFRA_ERROR_NAMES].filter((n) => !KNOWN_ERROR_NAMES.has(n));
    expect(dead).toEqual([]);
  });

  test('② 每个 infra 名都真的起效：带着内容级 code 也必须判 false', () => {
    // ① 只证明名字真实；判据对"不认识的名字"同样返回 false，所以必须有这条：
    // 漏配一项 INFRA_ERROR_NAMES ⇒ code 121 直接胜出 ⇒ 整批审计被归档丢弃。
    const ineffective = [...INFRA_ERROR_NAMES].filter((name) => {
      return isContentAttributableFailure(mk({ name, code: 121, writeErrors: [entry(121)] }));
    });
    expect(ineffective).toEqual([]);
  });

  test('② 每个内容级类名都真的起效：只凭名字就判 true（否则该项是死条目）', () => {
    const ineffective = [...CONTENT_ERROR_NAMES].filter(
      (name) => isContentAttributableFailure(mk({ name })) === false
    );
    expect(ineffective).toEqual([]);
    for (const n of CONTENT_ERROR_NAMES) expect(KNOWN_ERROR_NAMES.has(n)).toBe(true);
  });

  test('③ 否决名单恰好等于 INFRA：其余任何依赖类名都不得压住 code 121', () => {
    // 反向防的是"把未知名字一律当基础设施"这种偷懒收紧——那会让毒判据永久失效，
    // 而永久失效的表现是缓冲涨到硬上限后挤掉最老的审计，跟"没人配 infra 名"一样没人察觉。
    const silentlyInfra = [...KNOWN_ERROR_NAMES]
      .filter((n) => !INFRA_ERROR_NAMES.has(n))
      .filter((n) => isContentAttributableFailure(mk({ name: n, code: 121 })) === false);
    expect(silentlyInfra).toEqual([]);
  });

  test('④ 名字里带基础设施字样的依赖类名必须显式处置（新驱动加一个就转红）', () => {
    const infraFlavored =
      /[Nn]etwork|[Tt]imeout|PoolCleared|PoolClosed|WaitQueue|Selection|TopologyClosed|ServerClosed|NotConnected|WriteConcern|StalePrimary/;
    // 命中字样但**不**进 INFRA 的三个，各自都有明确理由，逐个钉在这里而不是把正则调窄：
    const EXCLUDED = new Map([
      // 客户端已关闭：连接都没了，压根不会有 insertMany 在途，也就没有批次可归档
      ['MongoClientClosedError', '无在途批次'],
      // CSFLE 的 KMS 侧超时：走的是加解密外呼，不是写库返回码
      ['MongoCryptKMSRequestNetworkTimeoutError', 'KMS 外呼而非写库'],
      // 所有超时类的**基类**，name 被派生类逐层覆盖；按基类否决会把一切超时都吞掉
      ['TimeoutError', '基类，被派生名覆盖'],
    ]);
    const unhandled = [...KNOWN_ERROR_NAMES].filter(
      (n) => infraFlavored.test(n) && !INFRA_ERROR_NAMES.has(n) && !EXCLUDED.has(n)
    );
    expect(unhandled).toEqual([]);
    // EXCLUDED 也必须仍然真实：驱动改名后不能留一条没人认领的白名单
    const staleExclusions = [...EXCLUDED.keys()].filter((n) => !KNOWN_ERROR_NAMES.has(n));
    expect(staleExclusions).toEqual([]);
  });

  test('⑤ 驱动自己列为"瞬态/可续传"的码必须全在 INFRA_ERROR_CODES（删一项即转红）', () => {
    // 遍历自己的表看不见自己的删除（表就是遍历对象），所以这张名单必须从**驱动**推导：
    // 规则是"驱动都会换节点重试/续传的码，不可能是服务端针对某一条文档的内容裁决"。
    const transient = driverErrorMod.GET_MORE_RESUMABLE_CODES;
    expect(transient.size).toBeGreaterThan(10); // 驱动改了导出名就变成空遍历 ⇒ 先红在这里
    expect([...transient].filter((c) => !INFRA_ERROR_CODES.has(c))).toEqual([]);
    // 反向自证：派生名单与内容级码没有交集（否则这条门禁会把 121 也当成基础设施）
    expect([...transient].filter((c) => CONTENT_ERROR_CODES.has(c))).toEqual([]);
  });

  test('⑥ 基础设施的码表与码名表必须成对（驱动码表给了名字而这里没配＝只命中一半）', () => {
    const catalog = driverErrorMod.MONGODB_ERROR_CODES;
    expect(Object.keys(catalog).length).toBeGreaterThan(15); // 同上：防派生源变空
    const orphan = Object.entries(catalog)
      .filter(([, code]) => INFRA_ERROR_CODES.has(code))
      .filter(([name]) => !INFRA_ERROR_CODE_NAMES.has(name))
      .map(([name, code]) => `${name}=${code}`);
    expect(orphan).toEqual([]);
  });

  test('⑦ 码表收缩检测：一份**故意抄写**的清单（唯一职责是"少了一项就转红"）', () => {
    // ⑤⑥ 已经覆盖驱动码表能命名的那 20 个码；剩下这些（102/107/112/116/378/408/11601）
    // 驱动没给名字，派生门禁打不到 ⇒ 只能靠显式清单盯收缩。
    // 这与"用抄清单代替派生"不同：每一项的**行为**由上面的逐码否决效果用例各自钉住，
    // 这份清单只防"静默删除"，所以它过期了也只是多一条红，不会造成假绿。
    const EXPECTED_INFRA_CODES = [
      6, 7, 43, 64, 89, 91, 102, 107, 112, 116, 189, 234, 262, 378, 408, 9001, 63, 133, 134, 150,
      10107, 11600, 11601, 11602, 13388, 13435, 13436,
    ];
    expect([...INFRA_ERROR_CODES].sort((a, b) => a - b)).toEqual(
      [...EXPECTED_INFRA_CODES].sort((a, b) => a - b)
    );
    // 这份清单自身也必须非空且与码数一致（防止哪天两边同时被清空而双向通过）
    expect(EXPECTED_INFRA_CODES.length).toBeGreaterThan(20);
    expect(new Set(EXPECTED_INFRA_CODES).size).toBe(EXPECTED_INFRA_CODES.length);
  });

  test('⑧ 码名表的成员集合是"已评审过的否决面"，增删都要显式改这份清单', () => {
    // 与 ⑦ 同理但方向互补：⑥ 只防"码表认领了名字而名字缺席"（漏否决），
    // 防"多一个没人评审过的否决名"必须靠成员集合本身——多一项就等于悄悄削弱毒判据
    // （表现是缓冲涨到硬上限后挤掉最老的审计，和漏配一样没人察觉）。
    const EXPECTED_INFRA_CODE_NAMES = [
      'CursorNotFound',
      'ExceededTimeLimit',
      'FailedToSatisfyReadPreference',
      'HostNotFound',
      'HostUnreachable',
      'ElectionInProgress',
      'Interrupted',
      'InterruptedAtShutdown',
      'InterruptedDueToReplStateChange',
      'MaxTimeMSExpired',
      'NamespaceExists',
      'NetworkTimeout',
      'NodeNotPrimary',
      'NotPrimary',
      'NotPrimaryNoSecondaryOk',
      'NotPrimaryOrSecondary',
      'NotWritablePrimary',
      'OperationAborted',
      'PrimarySteppedDown',
      'ReadConcernMajorityNotAvailableYet',
      'ReplicationStateChange',
      'RetryChangeStream',
      'SecondaryReadOnly',
      'ShutdownInProgress',
      'SocketException',
      'StaleConfig',
      'StaleEpoch',
      'StaleShardVersion',
      'TransactionConflict',
      'WriteConcernFailed',
      'WriteConcernTimeout',
    ];
    expect([...INFRA_ERROR_CODE_NAMES].sort()).toEqual([...EXPECTED_INFRA_CODE_NAMES].sort());
    expect(EXPECTED_INFRA_CODE_NAMES.length).toBeGreaterThan(20);
    expect(new Set(EXPECTED_INFRA_CODE_NAMES).size).toBe(EXPECTED_INFRA_CODE_NAMES.length);
    // 清单里每一项都要么来自驱动码表、要么登记在下面这份"驱动枚举不到"的名单里。
    // 说清楚这份名单的证据强度：它们**没有**实测来源（6.20 上写类错误压根不带 codeName，
    // 整张码名表在当前依赖上都打不到），只是沿用改造前既有清单里的服务端码名，
    // 方向是保守（多一票否决）。哪天要清理死条目，就得同时改这里，属有意识的动作。
    const catalogNames = new Set(Object.keys(driverErrorMod.MONGODB_ERROR_CODES));
    const UNVERIFIED_SERVER_SIDE_NAMES = [
      'Interrupted', // 11601/116：驱动码表没枚举，服务端码表里有
      'NodeNotPrimary',
      'NotPrimary',
      'SecondaryReadOnly',
      'ElectionInProgress',
      'ReplicationStateChange',
      'OperationAborted',
      'TransactionConflict',
      'NamespaceExists',
      'WriteConcernFailed', // 102：驱动码表只有 64 的 WriteConcernTimeout
    ];
    const notExplainable = EXPECTED_INFRA_CODE_NAMES.filter(
      (n) => !catalogNames.has(n) && !UNVERIFIED_SERVER_SIDE_NAMES.includes(n)
    );
    expect(notExplainable).toEqual([]);
    expect(UNVERIFIED_SERVER_SIDE_NAMES.length).toBeGreaterThan(5);
    // 反向：驱动码表给了名字的那些必须真在清单里（否则这份"可证"的部分被悄悄换成了"不可证"）
    const droppedFromCatalog = EXPECTED_INFRA_CODE_NAMES.filter(
      (n) => UNVERIFIED_SERVER_SIDE_NAMES.includes(n) && catalogNames.has(n)
    );
    expect(droppedFromCatalog).toEqual([]);
  });

  test('载体类名不得进 INFRA：MongoServerError / MongoBulkWriteError 就是 11000/121 的载体', () => {
    // 一旦把它们当基础设施，所有逐条内容错误都会被顶层名字否决 ⇒ 毒判据永久失效（且无人察觉）。
    for (const n of [...CARRIER_ERROR_NAMES, 'MongoServerError']) {
      expect({ n, known: KNOWN_ERROR_NAMES.has(n) }).toEqual({ n, known: true });
      expect({ n, inInfra: INFRA_ERROR_NAMES.has(n) }).toEqual({ n, inInfra: false });
      expect({ n, inContent: CONTENT_ERROR_NAMES.has(n) }).toEqual({ n, inContent: false });
    }
  });

  test('Mongo 前缀不存在的池/队列错误名必须按真实 name 写（driver 6 去掉了前缀）', () => {
    for (const n of ['PoolClearedError', 'PoolClosedError', 'WaitQueueTimeoutError']) {
      expect({ n, known: KNOWN_ERROR_NAMES.has(n) }).toEqual({ n, known: true });
      expect(INFRA_ERROR_NAMES.has(n)).toBe(true);
      expect(INFRA_ERROR_NAMES.has(`Mongo${n}`)).toBe(false);
    }
  });
});

/**
 * 三张 infra 表的"有效载体"：`writeErrors` 非空本身就足以判 true，
 * 所以往里塞一条内容级拒绝，就得到一个"没有否决权就会被判 true"的基线。
 * 只有这一项真的进了否决表，结论才会被压回 false——这才是遍历断言该有的形状。
 * （改前的遍历形如 `judge({code: 43}) === false`：判据对**任何**它不认识的东西都返回
 *  false（保守分支），于是这行对任意编造的码都成立，删掉清单里任意一项也不会红。）
 */
const infraCarrier = (props) =>
  mk({ name: 'MongoBulkWriteError', writeErrors: [entry(121)], ...props });

describe('基础设施三张表：每一项都必须扭转一个本会判 true 的结论', () => {
  test('夹具自证：不带任何 infra 特征的载体本身判 true（否则下面的否决效果全是空转）', () => {
    expect(isContentAttributableFailure(infraCarrier({}))).toBe(true);
  });

  test('每个 INFRA_ERROR_CODES 成员都能压住一批真实的内容级拒绝', () => {
    expect(INFRA_ERROR_CODES.size).toBeGreaterThan(5);
    const ineffective = [...INFRA_ERROR_CODES].filter((code) =>
      isContentAttributableFailure(infraCarrier({ code }))
    );
    expect(ineffective).toEqual([]);
  });

  test('每个 INFRA_ERROR_CODE_NAMES 成员都拥有否决权', () => {
    expect(INFRA_ERROR_CODE_NAMES.size).toBeGreaterThan(5);
    const ineffective = [...INFRA_ERROR_CODE_NAMES].filter((codeName) =>
      isContentAttributableFailure(infraCarrier({ codeName }))
    );
    expect(ineffective).toEqual([]);
  });

  test('报文特征命中即拥有否决权（只测判据依赖的代表性片段）', () => {
    const msgs = [
      'connect ECONNREFUSED 127.0.0.1:27017',
      'getaddrinfo ENOTFOUND mongo',
      'getaddrinfo EAI_AGAIN mongo',
      'connection 0 to 127.0.0.1:27017 timed out',
      'topology was reset',
      'topology is closed',
      'topology re-scanning',
      'server selection in progress',
      'no primary in replica set',
      'node is going to stepdown',
      'shutdown in progress',
      'operation was interrupted',
      'replication state change',
      'write concern failed',
      'waiting for a connection',
    ];
    const ineffective = msgs.filter((message) =>
      isContentAttributableFailure(infraCarrier({ message }))
    );
    expect(ineffective).toEqual([]);
  });

  test('每个 CONTENT_* 表成员都真的能把结论扳成 true（反向空转）', () => {
    // 与上面同构：若某项只是"写着好看"，它既压不住也扳不动，清单等于没有。
    const deadCodes = [...CONTENT_ERROR_CODES].filter(
      (code) => isContentAttributableFailure(mk({ name: 'MongoServerError', code })) === false
    );
    expect(deadCodes).toEqual([]);
    const deadNames = [...CONTENT_ERROR_CODE_NAMES].filter(
      (codeName) => isContentAttributableFailure(mk({ codeName })) === false
    );
    expect(deadNames).toEqual([]);
  });

  test('每个 CONTENT_* 表成员都不与 infra 表重叠（重叠=一项永远打不到）', () => {
    expect([...CONTENT_ERROR_CODES].filter((c) => INFRA_ERROR_CODES.has(c))).toEqual([]);
    expect([...CONTENT_ERROR_CODE_NAMES].filter((c) => INFRA_ERROR_CODE_NAMES.has(c))).toEqual([]);
    expect([...CONTENT_ERROR_NAMES].filter((n) => INFRA_ERROR_NAMES.has(n))).toEqual([]);
  });

  test('报文特征命中即 false（只测判据依赖的代表性片段）', () => {
    const msgs = [
      'connect ECONNREFUSED 127.0.0.1:27017',
      'getaddrinfo ENOTFOUND mongo',
      'getaddrinfo EAI_AGAIN mongo',
      'connection 0 to 127.0.0.1:27017 timed out',
      'topology was reset',
      'topology is closed',
      'topology re-scanning',
      'server selection in progress',
      'no primary in replica set',
      'node is going to stepdown',
      'shutdown in progress',
      'operation was interrupted',
      'replication state change',
      'write concern failed',
      'waiting for a connection',
    ];
    for (const message of msgs) {
      expect({ message, got: isContentAttributableFailure(mk({ message })) }).toEqual({
        message,
        got: false,
      });
    }
  });
});

describe('内容级特征：只有这些形状允许计入毒文档次数', () => {
  test('writeErrors 非空 ⇒ true（服务端逐条拒绝本身就是内容级证据）', () => {
    const err = mk({
      name: 'MongoBulkWriteError',
      code: 121,
      writeErrors: [{ index: 0, err: { code: 121 } }],
    });
    expect(isContentAttributableFailure(err)).toBe(true);
  });

  test('code 121 / DocumentValidationFailure ⇒ true', () => {
    expect(isContentAttributableFailure(mk({ code: 121 }))).toBe(true);
    expect(isContentAttributableFailure(mk({ codeName: 'DocumentValidationFailure' }))).toBe(true);
  });

  test('11000 / DuplicateKey ⇒ true：记录已在库中，归档它的 WAL 行不丢任何审计', () => {
    // F-183 的前提反转：原用例断言 11000 ⇒ false（"重复键不是毒文档"）。
    // 但"不是毒文档"不等于"该按基础设施处理"：混合批次 [dup, 121] 里 121 才是真原因，
    // 判 false 就永远进不了毒判据 ⇒ 缓冲涨到硬上限后**先挤掉最老的那批审计**。
    // 判 true 的代价为零：本仓 AuditLog 除 _id 外无 unique 索引（见 auditWalReplayIdempotency
    // 用例 2 的实测断言），11000 只可能是 _id 冲突 ⇒ 该记录已经在库里。
    expect(isContentAttributableFailure(mk({ code: 11000 }))).toBe(true);
    expect(isContentAttributableFailure(mk({ codeName: 'DuplicateKey' }))).toBe(true);
    expect(INFRA_ERROR_CODES.has(11000)).toBe(false);
    expect(CONTENT_ERROR_CODES.has(11000)).toBe(true);
  });

  test('Mongoose 层按文档报的校验类类型名 ⇒ true', () => {
    for (const name of CONTENT_ERROR_NAMES) {
      expect({ name, got: isContentAttributableFailure(mk({ name })) }).toEqual({
        name,
        got: true,
      });
    }
  });

  test('空 writeErrors 数组不算内容级（否则任何批次都能被判毒）', () => {
    expect(isContentAttributableFailure(mk({ writeErrors: [] }))).toBe(false);
  });

  test('载体类名自身不算内容级：MongoBulkWriteError + 空 writeErrors ⇒ false', () => {
    // 实测形状（单节点上 w:2）：name=MongoBulkWriteError, code=2, codeName='BadValue',
    // writeErrors=[] ——整批根本没写进去，判 true 等于把这批永久归档。
    expect(
      isContentAttributableFailure(
        mk({ name: 'MongoBulkWriteError', code: 2, codeName: 'BadValue', writeErrors: [] })
      )
    ).toBe(false);
  });
});

describe('顺序无关：判定必须遍历每个错误站点，而不是只看顶层回显（F-183）', () => {
  const dup = entry(11000);
  const bad = entry(121);
  const notPrimary = entry(10107);

  test('服务端只把第一条 code 回显到顶层，且不回显 codeName（这就是"只看顶层"会顺序相关的根因）', () => {
    const dupFirst = mk({ name: 'MongoBulkWriteError', code: 11000, writeErrors: [dup, bad] });
    const badFirst = mk({ name: 'MongoBulkWriteError', code: 121, writeErrors: [bad, dup] });
    expect(dupFirst.code).not.toBe(badFirst.code); // 同一批内容，顶层回显不同
    expect(isContentAttributableFailure(dupFirst)).toBe(isContentAttributableFailure(badFirst));
  });

  test('[121,10107] 与 [10107,121] 都必须 false：批次里有一条抖动就不许删任何审计', () => {
    const contentFirst = mk({
      name: 'MongoBulkWriteError',
      code: 121,
      writeErrors: [bad, notPrimary],
    });
    const infraFirst = mk({
      name: 'MongoBulkWriteError',
      code: 10107,
      writeErrors: [notPrimary, bad],
    });
    // 改前：contentFirst ⇒ true（顶层 121 说话，10107 那条被忽略）⇒ 整批 WAL 归档 .discarded，
    // 而这批里根本没写进去的文档从此永久缺失——正是本模块开头禁止的不可逆方向。
    expect(isContentAttributableFailure(contentFirst)).toBe(false);
    expect(isContentAttributableFailure(infraFirst)).toBe(false);
  });

  test('顶层回显是 infra 码 ⇒ 一票否决，即使每一条 writeError 都是内容级', () => {
    expect(
      isContentAttributableFailure(
        mk({ name: 'MongoBulkWriteError', code: 10107, writeErrors: [bad, bad] })
      )
    ).toBe(false);
  });

  test('嵌套与非嵌套两种条目形状都要读到（collectDurableIds 在 w.code 上踩过一次）', () => {
    const nested = mk({
      name: 'MongoBulkWriteError',
      writeErrors: [{ index: 0, err: { code: 1 } }],
    });
    expect(isContentAttributableFailure(nested)).toBe(true); // 空档：只有 infra 才否决
    const infraNested = mk({
      name: 'MongoBulkWriteError',
      writeErrors: [{ index: 0, err: { code: 11600, codeName: 'Interrupted' } }],
    });
    expect(isContentAttributableFailure(infraNested)).toBe(false); // 嵌在 .err 下的 infra 特征也要看到
    const flat = mk({ name: 'MongoBulkWriteError', writeErrors: [{ index: 0, code: 10107 }] });
    expect(isContentAttributableFailure(flat)).toBe(false); // 条目自带 code 的写法同样要看到
  });

  test('writeConcernError 站点参与否决（整批写关注未达成与文档内容无关）', () => {
    const err = mk({
      name: 'MongoBulkWriteError',
      writeErrors: [bad],
      writeConcernError: {
        code: 102,
        codeName: 'WriteConcernFailed',
        errmsg: 'waiting for replication timed out',
      },
    });
    expect(isContentAttributableFailure(err)).toBe(false);
  });
});

describe('方向性：两边都像时基础设施必须赢（丢弃是不可逆的）', () => {
  test('infra 类型名 + writeErrors ⇒ false', () => {
    expect(
      isContentAttributableFailure(
        mk({ name: 'MongoStalePrimaryError', writeErrors: [{ index: 0, err: { code: 121 } }] })
      )
    ).toBe(false);
  });

  test('infra 报文 + writeErrors ⇒ false（bulk 失败原因常写在 message/errmsg 里）', () => {
    expect(
      isContentAttributableFailure(
        mk({
          name: 'MongoBulkWriteError',
          message: 'write concern failed',
          writeErrors: [entry(121)],
        })
      )
    ).toBe(false);
  });

  test('errmsg 优先于 message：errmsg 是 infra 时不再看 message', () => {
    expect(
      isContentAttributableFailure(
        mk({ errmsg: 'operation interrupted', message: 'document failed validation', code: 121 })
      )
    ).toBe(false);
  });

  test('反向前提：把判据反过来（内容优先 / 只看顶层）时这几条必须转红', () => {
    const both = mk({ name: 'MongoWriteConcernError', writeErrors: [entry(121)], code: 121 });
    expect(isContentAttributableFailure(both)).toBe(false);
    const echoOnly = mk({ name: 'MongoBulkWriteError', code: 121, writeErrors: [entry(10107)] });
    expect(isContentAttributableFailure(echoOnly)).toBe(false);
  });
});

describe('认不出来一律按基础设施（保守分支）', () => {
  test.each([
    ['普通 Error', new Error('some unknown failure')],
    ['只有 message 的裸对象', { message: 'disk quota exceeded' }],
    ['空对象', {}],
    ['null', null],
    ['undefined', undefined],
    ['字符串', 'MongoBulkWriteError'],
    ['数字', 11000],
    ['writeErrors 是对象不是数组', { writeErrors: { 0: { err: { code: 121 } } } }],
  ])('%s ⇒ false', (_label, input) => {
    expect(isContentAttributableFailure(input)).toBe(false);
  });

  test('字符串形态的 code 不参与任何一侧匹配（typeof 收紧）', () => {
    // { code: '121' } 既不算内容码也不算基础设施码 ⇒ 保守 false
    expect(isContentAttributableFailure(mk({ code: '121' }))).toBe(false);
    expect(isContentAttributableFailure(mk({ code: '11000' }))).toBe(false);
  });
});

describe('判据只有一处实现', () => {
  const codeOnly = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  test('消费方必须 require 本模块，且不得再抄一份特征表', () => {
    const consumers = ['src/services/auditBuffer.js'];
    for (const rel of consumers) {
      const code = codeOnly(fs.readFileSync(path.join(__dirname, '..', '..', '..', rel), 'utf8'));
      expect({ rel, refs: /utils\/mongoFailureAttribution/.test(code) }).toEqual({
        rel,
        refs: true,
      });
    }
    // 全仓（判据模块自身除外）不得出现第二份特征表/错误名常量。
    // 采样名字从模块自己的表里取：改表⇒门禁自动跟着换锚点，抄死清单会过期。
    const self = path.join(__dirname, '..', '..', '..', 'src/utils/mongoFailureAttribution.js');
    const sampled = [...INFRA_ERROR_NAMES]
      .sort()
      .slice(0, 3)
      .map((n) => new RegExp(n));
    const banned = [/INFRA_ERROR_NAMES\s*=/, /CONTENT_ERROR_CODES\s*=/, ...sampled];
    const files = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (e.name !== 'node_modules' && !abs.includes(`${path.sep}.git`)) walk(abs);
        } else if (e.name.endsWith('.js')) files.push(abs);
      }
    };
    walk(path.join(__dirname, '..', '..', '..', 'src'));
    const offenders = [];
    for (const abs of files) {
      if (path.resolve(abs) === path.resolve(self)) continue;
      if (abs.includes(`${path.sep}tests${path.sep}`)) continue; // 本套用例自身要引用这些名字
      const code = codeOnly(fs.readFileSync(abs, 'utf8'));
      for (const rx of banned) if (rx.test(code)) offenders.push({ file: abs, rx: String(rx) });
    }
    expect(offenders).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 真库：用实际驱动跑出来的形状做终验（夹具是"人写的形状"，这里才是"驱动写的形状"）
// ---------------------------------------------------------------------------
describe('真库形状（driver 实跑，非夹具）', () => {
  const COL = 'f183AttributionProbe';
  const db = () => mongoose.connection.db;
  /** 同一个集合再挂一层 Model：auditBuffer 走的是 Model.insertMany，条目形状与裸驱动不同 */
  const model = () =>
    mongoose.models.F183AttributionProbe ||
    mongoose.model(
      'F183AttributionProbe',
      new mongoose.Schema({ _id: String, n: Number }, { versionKey: false }),
      COL
    );

  beforeAll(async () => {
    // 与同仓其它真库用例同一写法（本文件其余用例纯 CPU，不依赖连接）
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    try {
      await db().collection(COL).drop();
    } catch {
      /* 首次运行集合不存在 */
    }
    // 服务端 $jsonSchema 校验：mongoose 层不拦，让驱动真的收到 code 121
    await db().createCollection(COL, {
      validator: { $jsonSchema: { properties: { n: { maximum: 5 } } } },
      validationLevel: 'strict',
      validationAction: 'error',
    });
    await db().collection(COL).insertOne({ _id: 'seed', n: 1 });
  });

  afterAll(async () => {
    await mongoose.connection
      .collection(COL)
      .drop()
      .catch(() => {});
  });

  const bulkError = async (docs) => {
    try {
      await db().collection(COL).insertMany(docs, { ordered: false });
    } catch (e) {
      return e;
    }
    throw new Error('预期批量写失败，但实际成功了（夹具前提已失效）');
  };

  test('前提自证：驱动确实只回显第一条的 code（顶层判定的顺序依赖是真实存在的）', async () => {
    const dupFirst = await bulkError([
      { _id: 'seed', n: 1 },
      { _id: 'a121', n: 99 },
    ]);
    const badFirst = await bulkError([
      { _id: 'b121', n: 99 },
      { _id: 'seed', n: 1 },
    ]);
    expect(dupFirst.code).toBe(11000);
    expect(badFirst.code).toBe(121);
    expect(dupFirst.codeName).toBeUndefined(); // 实测：写类错误顶层没有 codeName
    expect(dupFirst.name).toBe('MongoBulkWriteError');
    expect(dupFirst.writeErrors.map((w) => w.err.code)).toEqual([11000, 121]);
    expect(badFirst.writeErrors.map((w) => w.err.code)).toEqual([121, 11000]);
    // 裸驱动 collection.insertMany 的条目**两层都有**（w.code 与 w.err.code）；
    // 而 Model.insertMany（auditBuffer 实际用的那条路）只填 w.err.code。
    // 这条差异就是 sitesOf 两种形状都要读的理由——只按其中一种写，换一层就静默读不到码。
    expect(dupFirst.writeErrors.map((w) => w.code)).toEqual([11000, 121]);
    const viaModel = await model()
      .insertMany([{ _id: 'seed', n: 1 }], { ordered: false })
      .catch((e) => e);
    expect(viaModel.name).toBe('MongoBulkWriteError');
    expect(viaModel.writeErrors.map((w) => w.code)).toEqual([undefined]);
    expect(viaModel.writeErrors.map((w) => w.err.code)).toEqual([11000]);
    expect(isContentAttributableFailure(dupFirst)).toBe(true);
    expect(isContentAttributableFailure(viaModel)).toBe(true);
  });

  test('同一批文档、两种服务端返回顺序 ⇒ 判定必须一致且为 true', async () => {
    const dupFirst = await bulkError([
      { _id: 'seed', n: 1 },
      { _id: `c${Date.now()}`, n: 99 },
    ]);
    const badFirst = await bulkError([
      { _id: `d${Date.now()}`, n: 99 },
      { _id: 'seed', n: 1 },
    ]);
    expect(isContentAttributableFailure(dupFirst)).toBe(true);
    expect(isContentAttributableFailure(badFirst)).toBe(true);
  });

  test('真 bulk 错误里掺一条选举中失败 ⇒ false（改前：掺在哪一条决定会不会永久丢审计）', async () => {
    const real = await bulkError([{ _id: `e${Date.now()}`, n: 99 }]);
    expect(isContentAttributableFailure(real)).toBe(true); // 先自证真库形状判得出内容级
    for (const pos of [0, real.writeErrors.length]) {
      const mixed = mk({ name: real.name, code: real.code, writeErrors: [...real.writeErrors] });
      mixed.writeErrors.splice(pos, 0, entry(10107));
      expect({ pos, got: isContentAttributableFailure(mixed) }).toEqual({ pos, got: false });
    }
  });

  test('真库单条写失败（MongoServerError + code，无 writeErrors）也要判对', async () => {
    const dupOne = await db()
      .collection(COL)
      .insertOne({ _id: 'seed', n: 1 })
      .catch((e) => e);
    expect(dupOne.name).toBe('MongoServerError');
    expect(dupOne.code).toBe(11000);
    expect(isContentAttributableFailure(dupOne)).toBe(true); // 记录已在库 ⇒ 归档不丢审计

    const badOne = await db()
      .collection(COL)
      .insertOne({ _id: `f${Date.now()}`, n: 77 })
      .catch((e) => e);
    expect(badOne.code).toBe(121);
    expect(isContentAttributableFailure(badOne)).toBe(true);
  });

  test('真库形状：整批因写关注/用法错误失败时 writeErrors 为空 ⇒ false', async () => {
    const e = await db()
      .collection(COL)
      .insertMany([{ _id: `g${Date.now()}`, n: 1 }], {
        ordered: false,
        writeConcern: { w: 2, wtimeout: 2000 },
      })
      .catch((x) => x);
    expect(e).toBeInstanceOf(Error);
    expect(e.writeErrors).toHaveLength(0);
    expect(isContentAttributableFailure(e)).toBe(false);
  });
});

// 收尾必须关连接：mongodb-memory-server 是所有套件共用的同一个 mongod，
// 不关的套件会让 jest worker 在 FORCE_EXIT_DELAY(500ms) 后被强杀
// （"A worker process has failed to exit gracefully"），强杀会吞掉该套件的输出。
// readyState 守卫是为了不关别人建立的连接；本条挂在根作用域，故在本套件所有
// describe 自己的 afterAll 之后才跑。这里就地 require('mongoose')：本仓有 3 个套件
// 只在 describe 体内 require，从根作用域引用那个名字会 ReferenceError。
afterAll(async () => {
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});
