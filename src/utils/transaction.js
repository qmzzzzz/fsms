/**
 * MongoDB 事务封装（第二轮审计，修复 B-1 的基础设施）
 *
 * 背景：全仓 51 处写点中，设备删除（deleteDevice）等少数路径存在真实的
 * 跨集合多步写；无事务时任一步失败会残留悬空引用（幽灵告警/巡检数据）。
 *
 * 设计约束：MongoDB 事务要求副本集（或 mongos），而开发/测试环境是
 * standalone（mongodb-memory-server 单节点）。强制事务会让全部测试与单机
 * 部署直接不可用，因此本封装做**拓扑能力感知**：
 * - 副本集/分片集群：session 事务（startTransaction → fn(session) → commit，
 *   失败 abort 并原样上抛）；
 * - standalone（拓扑类型 Single）：降级为顺序执行 fn(null)——与修复前行为
 *   一致，并告警一次提示多集合一致性此时依赖应用层写入顺序。
 *
 * 能力判定用 hello 命令探测（评价报告 #14）：原实现读
 * client.topology.description.type——driver 6 的内部属性，不稳定且可能读不到，
 * 读不到时按支持处理（fail-loud）会把 standalone 误判为支持事务。
 * 改为向 admin 库发一次 hello：副本集成员响应含 setName、mongos 含
 * msg='isdbgrid'，standalone 两者皆无——这是驱动公开契约，跨版本稳定。
 * 探测失败（含未连库 client 缺失）仍按支持处理，让真实错误自然暴露而非静默降级。
 *
 * 调用约定：fn 接收 session（可能为 null），所有写操作必须透传
 * `{ session }`（session 为 null 时传空对象即可，Mongoose 会忽略）。
 */

const mongoose = require('mongoose');
const logger = require('./logger');

// 降级告警只发一次（每次部署/进程一条，避免刷日志）
let degradeWarned = false;

// 探测结果缓存：hello 是一次网络往返，进程内只需探一次（连接拓扑不会热切换）
let cachedSupport = null;

// 最近一次探测到的拓扑（供启动告警与 /readyz 标记消费；未探测过为 unknown）
let topology = 'unknown';

/**
 * 探测当前拓扑是否支持事务。
 *
 * 缓存策略是这里的要点：**只缓存成功探测，不缓存失败探测。**
 * 原实现把探测异常也写成 `cachedSupport = true` 并永久缓存，声称"按支持处理、真实错误自然暴露"。
 * 方向（fail-loud，不静默降级）是对的，但"永久"把一个瞬时抖动变成了不可自愈的故障：
 * standalone 部署上只要那一次 `hello` 超时/抖动，之后**每一次** withTransaction 都会走事务分支，
 * 在第一个写上抛 IllegalOperation → 删除设备这类操作持续 500 直到进程重启，
 * 而本该可用的降级顺序写路径再也不会被尝试。
 * 现在失败仍按"支持"处理并让真实错误暴露（保持 fail-loud），但下次调用会重新探测，
 * 拓扑恢复后即自愈；健康副本集首次成功即缓存，不增加稳态开销。
 */
const detectTransactionSupport = async () => {
  if (cachedSupport !== null) return cachedSupport;
  try {
    const hello = await mongoose.connection.client.db('admin').command({ hello: 1 });
    cachedSupport = Boolean(hello.setName) || hello.msg === 'isdbgrid';
  } catch (err) {
    logger.warn(
      `事务能力探测失败，本次按副本集处理（fail-loud，不缓存该结论，下次重探）：${err.message}`
    );
    return true;
  }
  return cachedSupport;
};

/**
 * 在事务中执行多步写（副本集），或降级顺序执行（standalone）
 * @param {(session: object|null) => Promise<T>} fn 业务写入，须向各操作透传 session
 * @param {object} [options] 透传给 startTransaction 的选项（如 readConcern/writeConcern）
 * @returns {Promise<T>} fn 的返回值
 */
async function withTransaction(fn, options = {}) {
  if (!(await detectTransactionSupport())) {
    if (!degradeWarned) {
      degradeWarned = true;
      logger.warn(
        'MongoDB standalone 拓扑：withTransaction 降级为顺序写，多集合一致性依赖应用层写入顺序（生产请部署副本集）'
      );
    }
    return fn(null);
  }

  const session = await mongoose.startSession();
  try {
    session.startTransaction(options);
    const result = await fn(session);
    await session.commitTransaction();
    return result;
  } catch (err) {
    try {
      await session.abortTransaction();
    } catch (_) {
      /* 事务可能已随错误终止，abort 失败不掩盖原始错误 */
    }
    throw err;
  } finally {
    // endSession() 是 async，而且它会**显式 rethrow**：node_modules/mongodb/lib/sessions.js:121-129
    // 的 catch 里除 MongoOperationTimeoutError 外全部 squash，唯独这一种 `throw error`。
    // 原先这里裸调用 ⇒ 没人持有的拒绝 ⇒ src/index.js:486 的 unhandledRejection 处理器
    // 在**所有环境**都 process.exit(1)：一次事务清理超时打死整个进程（不是日志噪音）。
    // 上游同一条链的写法就是"接住"：mongoose/lib/connection.js:743
    // `session.endSession().catch(() => {})`、mongodb/lib/cursor/abstract_cursor.js:579
    // `.then(undefined, squashError)`。这里与同文件 catch 里的 abort 同一口径
    // （await + 就地吞）：清理失败既不掩盖业务结果也不掩盖原始错误，
    // 顺带保证会话在 withTransaction 返回前已归还连接池。
    // 资源不靠这个 catch：驱动自己的 finally（sessions.js:132-144）先释放再传播拒绝。
    try {
      await session.endSession();
    } catch (_) {
      /* 会话已结束，清理超时不影响业务结果（见上） */
    }
  }
}

/** 仅供测试：重置降级告警标志与探测缓存 */
function _resetForTests() {
  degradeWarned = false;
  cachedSupport = null;
  topology = 'unknown';
}

/**
 * 启动期拓扑体检：把「事务是否可用」从请求期隐式降级变成启动日志里的显式事实。
 *
 * 为什么不能只靠 withTransaction 里的那次告警：它要等到第一次多集合写（如删除设备）
 * 才触发，且是 warn 级——生产上 standalone 意味着一致性退化为「按顺序写、失败留残骸」，
 * 这是部署形态缺陷，应该在进程起来的那一刻就可见，而不是等出事时翻日志。
 *
 * 探测结果同时写进 cachedSupport，使启动后的 withTransaction 复用同一次 hello；
 * 探测失败不缓存（沿用 detectTransactionSupport 的 fail-loud + 可自愈策略）。
 *
 * @returns {Promise<'replica-set'|'standalone'|'unknown'>}
 */
async function reportTransactionTopology() {
  try {
    const hello = await mongoose.connection.client.db('admin').command({ hello: 1 });
    const supported = Boolean(hello.setName) || hello.msg === 'isdbgrid';
    cachedSupport = supported;
    topology = supported ? 'replica-set' : 'standalone';

    if (supported) {
      logger.info('MongoDB 拓扑支持事务（副本集/mongos）：多集合写入走事务');
    } else {
      // 生产部署选错形态会直接损失跨集合原子性，故用 error 级；同进程不再重复告警
      degradeWarned = true;
      logger.error(
        'MongoDB standalone 拓扑：事务不可用，多集合写入降级为顺序写，失败可能残留跨集合不一致；生产请部署副本集'
      );
    }
    return topology;
  } catch (err) {
    topology = 'unknown';
    logger.warn(`启动期事务拓扑探测失败（不影响启动，/readyz 标记 unknown）：${err.message}`);
    return topology;
  }
}

/** 最近一次拓扑探测结果：'replica-set' | 'standalone' | 'unknown' */
function getTransactionTopology() {
  return topology;
}

/**
 * P-1：生产语义下 standalone 拓扑的就绪闸（2026-10-26）
 *
 * 就地更正一条此前的判断：`app.js` 的 `transactionMarker` 原注释写着
 * 「standalone 只降级不摘流量……把 /readyz 判成 unready 会让 LB 把整个实例下线，
 * 损失远大于『跨集合写非原子』本身」，据此只对外标 `degraded`、不参与就绪判定。
 *
 * 那条判断只在「多集合写是少数路径、失败可感知」时成立，它漏掉了真正的失败形态：
 * 顺序写在中途失败会**残留跨集合不一致**（幽灵告警、悬空巡检引用），而这类残骸
 * 没有任何自动修复路径——只能人工比对修复，且往往在数天后才被发现。
 * 生产选错拓扑是**部署缺陷**，不该由业务数据承担；`docker-compose.yml` 默认就是
 * 单节点副本集，正确部署不会命中这条闸。故改为：
 *   - 生产语义（`requiresProductionSemantics()`，含"未识别环境按生产办"）+ standalone
 *     ⇒ `/readyz` 503，让编排器/LB 摘流量；
 *   - 不阻断启动：进程照常起来，运维在启动日志与探针上同时看到确切原因，
 *     修好拓扑（或改部署形态）后探针自动转绿，无需重启代码路径。
 *   - 开发/测试/预发仍只降级：本地 `mongodb-memory-server` 就是单节点，
 *     摘流量毫无意义，而 `requiresProductionSemantics()` 对 dev/test/ci 返回 false。
 *
 * `requiresProductionSemantics` 走**惰性 require**：`config/validate` 的加载链
 * 会拉到 `models/AuditLog` → `services/auditBuffer` → `utils/auditChain`，
 * 其中任一环节将来若反向引用本模块，顶层 require 就会变成加载期环。
 *
 * @returns {{reason: string, detail: string}|null} null 表示不阻断就绪
 */
function transactionReadinessBlocker() {
  if (topology !== 'standalone') return null;
  let productionSemantics = true;
  try {
    productionSemantics = require('../config/validate').requiresProductionSemantics();
  } catch (_) {
    // 判定不可用 ⇒ 按生产办（与 config 层「未识别环境按生产办」同一保守方向）
    productionSemantics = true;
  }
  if (!productionSemantics) return null;
  return {
    reason: 'transactions_degraded',
    detail:
      'MongoDB 为 standalone 拓扑（hello 无 setName 且非 mongos）：事务不可用，' +
      '多集合写入降级为顺序写，失败会残留跨集合不一致；生产请部署副本集（单节点副本集即可）',
  };
}

/**
 * 仅供测试：直接设定拓扑探测结果。
 *
 * 拓扑由 `reportTransactionTopology()` 在启动时写入模块级变量，测试无法从外部
 * 触达；而 `/readyz` 的就绪闸必须能在**不起真实副本集**的前提下被证伪，
 * 否则这条闸只能靠"上生产看"来验证。与 `_resetForTests` 同一惯例。
 *
 * @param {'replica-set'|'standalone'|'unknown'} value
 */
function _setTopologyForTest(value) {
  topology = value;
  cachedSupport = value === 'unknown' ? null : value === 'replica-set';
}

module.exports = {
  withTransaction,
  reportTransactionTopology,
  getTransactionTopology,
  transactionReadinessBlocker,
  _resetForTests,
  _setTopologyForTest,
};
