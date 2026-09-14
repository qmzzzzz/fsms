/**
 * MongoDB 事务封装（第二轮审计 F-6，修复 B-1 的基础设施）
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

/** hello 探测当前拓扑是否支持事务；探测失败按支持处理（fail-loud） */
const detectTransactionSupport = async () => {
  if (cachedSupport !== null) return cachedSupport;
  try {
    const hello = await mongoose.connection.client.db('admin').command({ hello: 1 });
    cachedSupport = Boolean(hello.setName) || hello.msg === 'isdbgrid';
  } catch (err) {
    // 未连库（client 缺失）或探测网络失败：按支持处理，真实错误自然暴露
    logger.warn(`事务能力探测失败，按副本集处理（fail-loud）：${err.message}`);
    cachedSupport = true;
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
    session.endSession();
  }
}

/** 仅供测试：重置降级告警标志与探测缓存 */
function _resetForTests() {
  degradeWarned = false;
  cachedSupport = null;
}

module.exports = { withTransaction, _resetForTests };
