/**
 * 系统初始化数据服务 · 门面：initializeSystem 与导出面（与旧文件逐字同序）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const logger = require('../../utils/logger');
const { initPermissions, initRoles } = require('./seeding');
const { createDefaultAdmin, reconcileSuperAdmin } = require('./adminAccount');
const {
  reconcileUserIndexes,
  reconcileTokenBlacklistIndexes,
  reconcileAuditTtlIndex,
} = require('./indexes');
const { initSystemConfig } = require('./systemConfig');
const { defaultPermissions } = require('./permissions');
const { defaultRoles } = require('./roles');

const initializeSystem = async () => {
  try {
    await initPermissions();
    await initRoles();
    // users 索引对账（username + email 两件事）须在任何写入 users 之前：
    // ① createDefaultAdmin 依赖 findByUsername 的 collation 判重，索引缺失时该查询
    //    会退化为全表扫描；② A3 的 emailKey_1 切换若拖到建号之后，本进程内新建的
    //    管理员行会与"旧索引仍在"的判定打架（见 switchEmailIndexToKey 的四步）。
    await reconcileUserIndexes();
    await createDefaultAdmin();
    // 超管对账须在 createDefaultAdmin 之后：首次启动时 admin 账户此刻才存在
    await reconcileSuperAdmin();
    // 索引对账：清掉旧 schema 残留的唯一索引，否则 refresh 轮换会被误判为重放
    await reconcileTokenBlacklistIndexes();
    // 留存 TTL 常驻对账：改档后迁移不会重放，这里是唯一能把声明落到物理索引的地方
    await reconcileAuditTtlIndex();
    await initSystemConfig();
    logger.info('=== 系统初始化完成 ===');
  } catch (error) {
    logger.error(`系统初始化失败：${error.message}`);
    throw error;
  }
};

module.exports = {
  initializeSystem,
  initPermissions,
  initRoles,
  createDefaultAdmin,
  reconcileSuperAdmin,
  reconcileUserIndexes,
  reconcileTokenBlacklistIndexes,
  reconcileAuditTtlIndex,
  initSystemConfig,
  defaultPermissions,
  defaultRoles,
};
