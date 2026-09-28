'use strict';

/**
 * 「这次写库失败能不能归因到文档内容」的唯一判据
 *
 * 为什么单独成模块：这条判据决定 `auditBuffer` **要不要把审计从 WAL 里删掉**，
 * 而误判方向是不可逆的——被判成"毒文档"的批次会按 `__walSeq` 归档进 `.discarded`
 * 且永不再回灌（一次 10 秒的 Mongo 抖动 = 一条永久缺失的合规记录）；
 * 反过来误判成"基础设施问题"只是重试不收敛（缓冲有硬上限、WAL 原样保留、重启可重放）。
 * 所以判据必须：① 保守（认不出来就归到基础设施一侧）；② 可被直接断言（不靠间接推断）。
 *
 * 【F-183：判定必须遍历"每一个错误站点"，而不是只看顶层】
 * 真库实跑（同仓 `tests/zzqoder_auditBufferZombieDuplicate.test.js:144-168` 把形状钉成了断言）：
 *   服务端 bulk 错误只把**第一条** writeError 的 code 回显到顶层，且**不回显 codeName**：
 *     `[dup, 121]` ⇒ `err.code=11000`；`[121, dup]` ⇒ `err.code=121`。
 *   于是"只看顶层"等价于**按服务端返回顺序**做判定——同一批文档换个顺序就得出相反结论。
 *   实测的两个方向里，`[121, 10107]`（批次里混了一条选举中失败）被判成内容级 ⇒
 *   整批 WAL 行归档 `.discarded` 永不重放 ⇒ 正是本模块开头禁止的那个不可逆方向。
 *   服务端逐条码嵌在 `writeErrors[i].err`；条目自身的 `w.code` 是否存在**取决于哪一层抛的**
 *   （真库实测：`Model.insertMany` 的条目只有 `{index, err}`，`w.code` 为 undefined；
 *    裸 `collection.insertMany` 两层都填）。只按其中一种写，换一层就静默读不到码。
 *
 * 其余实测形状（driver = mongoose 解析到的那份，见测试里的"依赖真名"漂移门禁）：
 *   连不上端口 → name='MongooseServerSelectionError'，`code`/`codeName`/`writeErrors` 全 undefined
 *   DNS 失败   → 同上，errmsg='getaddrinfo ENOTFOUND …'
 *   单条写失败 → name='MongoServerError'，`code` 有值、**`codeName` 在 6.20 上恒为 undefined**
 *                （只有命令级失败才有 codeName，如 w>1 打在单节点上 → code=2, codeName='BadValue'）
 *   写关注未达成/用法错误 → `writeErrors` 是**空数组**（"有没有逐条拒绝记录"本身就是内容级证据）
 * 驱动若改了类型名/码，`mongoFailureAttribution.test.js` 的真值表与漂移门禁会先红。
 */

/**
 * 明确属于"连不上 / 选不到节点 / 池被清空 / 写关注未达成 / 被中断"的错误类型。
 * 每一项都必须是依赖里**真的会出现**的 `err.name`——这一点由测试从 node_modules 推导核对，
 * 不靠这里的注释自证。F-183 之前这份清单里有 9 个手写却不存在的名
 * （`MongoTimeoutError`、`MongoNotPrimaryError`、`MongoInterrupted*Error` 等都是 driver 3/4 时代的
 * 类名，driver 6 早已把服务端码统一成 `MongoServerError` + `code`/`codeName`），
 * 而唯一真正会撞上的 `PoolClearedError` 反倒写成了带 Mongo 前缀的不存在形式。
 * 服务端的 NotPrimary/Interrupted 那一类现在由 INFRA_ERROR_CODES / _CODE_NAMES 覆盖。
 */
const INFRA_ERROR_NAMES = new Set([
  'MongooseServerSelectionError',
  'MongoServerSelectionError',
  'MongoNetworkError',
  'MongoNetworkTimeoutError',
  'MongoTopologyClosedError',
  'MongoServerClosedError',
  'MongoNotConnectedError',
  'MongoOperationTimeoutError',
  'MongoWriteConcernError',
  'MongoStalePrimaryError',
  'PoolClearedError',
  'PoolClearedOnNetworkError',
  'PoolClosedError',
  'WaitQueueTimeoutError',
]);

/**
 * 服务端错误码：选举中 / 降级 / 被中断 / 写关注未达成 / 游标被杀等，均与文档内容无关。
 *
 * 【F-183：这张表的边界是一条可推导的规则，不是逐条手感】
 * "驱动自己都会换节点重试/续传的错误码，不可能是服务端针对某一条文档作出的内容裁决"。
 * 该规则的具体名单由测试从**运行期那份驱动的** `lib/error.js` 推导（`GET_MORE_RESUMABLE_CODES`
 * ∪ 驱动码表里已有的瞬态码），删掉这里任意一项都会让派生门禁转红——原来"遍历自己这张表"
 * 的断言做不到这一点（表就是遍历对象，删一项只是少一条断言，正是 F-183 一直在收的"绿但不设防"）。
 *
 * 11000 不在这里（F-183）：它是**服务端看完这一条文档之后**给出的逐条裁决，
 * 与 121 同类，见 CONTENT_ERROR_CODES。把它当基础设施的代价不是"多试一次"，而是
 * 永不收敛——`[dup, 121]` 这种混合批次里 121 才是真原因，判成基础设施就永远进不了
 * 毒判据，缓冲一路涨到硬上限后**先挤掉最老的（最有价值的）记录**。
 */
const INFRA_ERROR_CODES = new Set([
  43, 64, 89, 91, 102, 107, 112, 13435, 13436, 189, 262, 378, 408, 9001, 10107,
  // Interrupted 家族的数字码：与下面 INFRA_ERROR_CODE_NAMES 里那三个 *Interrupted* 同名同义。
  // 两张表原本一张有名、一张有码，另一张没有 ⇒ 只命中一半（6.20 实测写类错误**没有** codeName，
  // 也就是说光有名的那半张表在 bulk 条目上根本打不到，码才是真正会命中的那一半）。
  // 64=Timeout、102=WriteConcernFailed 同属写关注未达成，实测在单节点上跑不出这两个码
  // （w>1 直接 BadValue=2），这里按服务端码表收，判据方向是保守（多一票 infra）。
  116, 11600, 11601, 11602,
  // 驱动自己列为"瞬态/可续传"的一族（分片路由过期、选不到满足读偏好的节点、副本集尚未就绪…）：
  // 这些码全部来自上面那条规则，由派生门禁钉住，不要手工增删。
  6, 7, 63, 133, 134, 150, 234, 13388,
]);

/**
 * 同上的码名形式。与 INFRA_ERROR_CODES 的对应关系由门禁强制：凡是驱动码表里给了名字的
 * 基础设施码，这里必须有那个名字（否则就是"两张表只命中一半"，F-183 的原始缺陷形状）。
 * 注意：6.20 实测**写类错误的 codeName 恒为 undefined**，这一张表在当前依赖上打不到——
 * 留着是因为服务端码名是协议层常量，驱动哪天补上就该立即生效；
 * 不能反过来拿"它命中不了"当作删掉判据的理由。
 */
const INFRA_ERROR_CODE_NAMES = new Set([
  'CursorNotFound',
  'MaxTimeMSExpired',
  'OperationAborted',
  'Interrupted',
  'InterruptedAtShutdown',
  'InterruptedDueToReplStateChange',
  'NotPrimary',
  'NodeNotPrimary',
  'SecondaryReadOnly',
  'ElectionInProgress',
  'ReplicationStateChange',
  'WriteConcernFailed',
  'TransactionConflict',
  'HostUnreachable',
  'NetworkTimeout',
  'StaleShardVersion',
  'NamespaceExists', // 与内容无关的并发建集，重放即成功
  // 以下全部由驱动码表反推（码在此表内 ⇒ 名也必须在此），不是手写手感
  'HostNotFound',
  'NotWritablePrimary',
  'NotPrimaryNoSecondaryOk',
  'NotPrimaryOrSecondary',
  'PrimarySteppedDown',
  'ShutdownInProgress',
  'SocketException',
  'ExceededTimeLimit',
  'WriteConcernTimeout',
  'StaleEpoch',
  'StaleConfig',
  'RetryChangeStream',
  'FailedToSatisfyReadPreference',
  'ReadConcernMajorityNotAvailableYet',
]);

// `timed out`（F-183 补）：用例清单里早就写着这条报文会被否决，而原判据的正则只有 `ETIMEDOUT`，
// 于是那条断言是靠"保守分支默认 false"蒙过去的（驱动真实的超时错误本来也有类名兜住，所以这次
// 补上不改任何实测结论——但"第二条防线其实没装弹"这件事必须在这里写清楚，别再被注释掩盖）。
const INFRA_MESSAGE_RE =
  /(ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|EPIPE|socket hang up|timed out|network|topology (was reset|switched|re-?scanning|is closed)|server (selection|monitoring in progress)|no (primary|reachable)|election|not primary|secondary (is )?(read )?only|stepdown|shutdown|interrupted|replication (state )?change|write concern|waiting for a (client|connection))/i;

/**
 * positively 说明"服务端针对某一条文档作了拒绝裁决"的码。
 *
 * 11000 归到内容级的理由不是"它长得像内容错误"，而是**丢弃它的代价为零**：
 * 本仓 AuditLog 除 `_id` 外没有任何 unique 索引（这条前提由
 * `tests/observability/auditWalReplayIdempotency.test.js:240-241` 实测钉住，加索引即转红），
 * 所以 11000 只可能是 `_id` 冲突 ⇒ 该记录**已经在库里** ⇒ 归档它的 WAL 行不丢任何审计。
 * `auditBuffer.collectDurableIds` 早就是按同一个前提将冲突条目判为"已落库"的。
 */
const CONTENT_ERROR_CODES = new Set([121, 11000]);

/**
 * 同上的 codeName 形式。注意：6.20 实测**写类错误的 codeName 恒为 undefined**，
 * 这一张表在当前依赖上打不到——留着是因为服务端码名是协议层常量，
 * 驱动哪天补上就该立即生效；不能反过来拿"它命中不了"当作删掉判据的理由。
 */
const CONTENT_ERROR_CODE_NAMES = new Set(['DocumentValidationFailure', 'DuplicateKey']);

/** 类型名本身就能确定内容级（Mongoose 层就按文档报的校验失败） */
const CONTENT_ERROR_NAMES = new Set(['ValidationError', 'MongooseBulkWriteError']);

/**
 * "载体"类批量写错误：既可能装着逐条内容错误，也可能装着 BadValue / 写关注失败
 * （实测后者：`writeErrors: []` + `code=2, codeName='BadValue'`）。
 * 所以它的名字**不进任何一侧**——内容级证据必须来自 writeErrors 条目或 code。
 * 同理 `MongoServerError` 也绝不能加进 INFRA_ERROR_NAMES：它就是 11000/121 的载体，
 * 一旦当成基础设施，整个毒判据就永久失效。导出给漂移门禁用。
 */
const CARRIER_ERROR_NAMES = new Set(['MongoBulkWriteError', 'MongoClientBulkWriteError']);

/**
 * 判据能看到的一个"错误位置"。
 * @param {boolean} perDocument true = 这一格来自 `writeErrors`，即服务端**针对某一条文档**的回话
 */
function shapeOf(err, perDocument = false) {
  return {
    perDocument,
    name: String(err.name || ''),
    code: typeof err.code === 'number' ? err.code : undefined,
    codeName: typeof err.codeName === 'string' ? err.codeName : undefined,
    message: String(err.errmsg || err.message || ''),
  };
}

/**
 * 列出全部站点：顶层 + 每个 writeErrors 条目（含嵌套的 `.err`，两种写法都收）+ writeConcernError。
 *
 * 条目为什么要把 `w` 和 `w.err` 都当站点：实测服务端码嵌在 `w.err` 下、`w.code` 为 undefined，
 * 而 `collectDurableIds` 首次实跑就是按 `w.code` 取值取到空集、幂等识别静默失效。
 * 这里两种形状都读，驱动换形状最坏是"多一个空白站点"（空白既不 infra 也不 content，不改结论）。
 */
function sitesOf(err) {
  const sites = [shapeOf(err)];
  const entries = Array.isArray(err.writeErrors) ? err.writeErrors : [];
  for (const w of entries) {
    if (!w || typeof w !== 'object') continue;
    sites.push(shapeOf(w, true));
    if (w.err && typeof w.err === 'object') sites.push(shapeOf(w.err, true));
  }
  if (err.writeConcernError && typeof err.writeConcernError === 'object') {
    sites.push(shapeOf(err.writeConcernError));
  }
  return { sites, hasPerDocumentRejections: entries.length > 0 };
}

/** 类型名 / 错误码 / 报文任一命中基础设施特征 */
function looksInfra({ name, code, codeName, message }) {
  const infraChecks = [
    () => INFRA_ERROR_NAMES.has(name),
    () => code !== undefined && INFRA_ERROR_CODES.has(code),
    () => codeName !== undefined && INFRA_ERROR_CODE_NAMES.has(codeName),
    () => INFRA_MESSAGE_RE.test(message),
  ];
  return infraChecks.some((c) => c());
}

/** 这一格自身 positively 认出"文档内容被拒" */
function looksContentShape({ name, code, codeName }) {
  const contentChecks = [
    () => code !== undefined && CONTENT_ERROR_CODES.has(code),
    () => codeName !== undefined && CONTENT_ERROR_CODE_NAMES.has(codeName),
    () => CONTENT_ERROR_NAMES.has(name),
  ];
  return contentChecks.some((c) => c());
}

/**
 * @param {Error|{name?:string,code?:number,codeName?:string,message?:string,errmsg?:string,writeErrors?:Array,writeConcernError?:Object}} err
 * @returns {boolean} true=可归因于文档内容（允许计入毒文档次数）；false=按基础设施/未知处理，不得删审计
 */
function isContentAttributableFailure(err) {
  if (!err || typeof err !== 'object') return false;
  const { sites, hasPerDocumentRejections } = sitesOf(err);

  // 基础设施一票否决：整批里只要有一格是抖动/选举/写关注，就不许把任何一条判成毒文档。
  // 遍历全部站点而不是只看顶层，正是为了不让"服务端先返回哪一条"影响结论。
  if (sites.some((s) => looksInfra(s))) return false;

  // 走到这里：没有任何一处像基础设施。
  // 非空的 writeErrors 本身就是"服务端看过这些文档后逐条拒绝"——整批未写入（ordered:false
  // 下失败条目确实没落库），按内容级处理只是让这几条开始计次，不是删除。
  if (hasPerDocumentRejections) return true;
  return sites.some((s) => looksContentShape(s));
}

module.exports = {
  isContentAttributableFailure,
  INFRA_ERROR_NAMES,
  INFRA_ERROR_CODES,
  INFRA_ERROR_CODE_NAMES,
  CONTENT_ERROR_NAMES,
  CONTENT_ERROR_CODES,
  CONTENT_ERROR_CODE_NAMES,
  CARRIER_ERROR_NAMES,
};
