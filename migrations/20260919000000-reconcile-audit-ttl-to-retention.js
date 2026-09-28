/**
 * 把 auditlogs 的 TTL 重新对齐到留存策略声明值（修复"已迁移库收不到纠正"的可达性问题）
 *
 * 为什么需要这条迁移，而不是只改 20260831000000 那个文件：
 *   migrate-mongo-config.js 里 `useFileHash: false`，而 status.js 的判定是
 *   `item.fileName === findTest.fileName`（不带 fileHash 时）——
 *   也就是说**迁移标识只有文件名**。任何已经执行过 20260831000000 的库，
 *   `_migrations` 里已有该 fileName，即便源码被改过，`migrate:up` 也永远把它视为
 *   "已应用"而跳过。那次改动（硬编码 15552000 → 读 constants/retention.js）
 *   对全新库有效，对**已经跑过旧版本的库完全无效**。
 *
 * 这不是理论问题：
 *   配了 `AUDIT_RETENTION_DAYS=365` 的环境一旦执行过旧版迁移，
 *   collMod 已把 TTL 写成 180 天，早于声明的 6 个月就开始物理删除审计记录；
 *   而应用侧 models/AuditLog.js 的 createIndexes 遇到同名不同选项会抛
 *   IndexOptionsConflict 而不会改选项，
 * 所以这个偏差只能由迁移修。⇒ 不追加这条，20260831000000 改读常量的修复在生产上是空的。
 *
 * 现状更正（本文件"src/ 内没有任何 collMod 自愈逻辑"那半句已不成立）：启动期常驻对账
 * `services/initData.js` 的 `reconcileAuditTtlIndex()` 与本迁移同尺（只把已存在的
 * timestamp_-1 对齐到声明值，不创建）。差别在可达性：迁移只在 `migrate:up` 那一跑生效，
 * 且标识是文件名（改档不会重放），常驻对账每次启动都跑 ⇒ 以后调留存档位不必再逐次追加迁移。
 *
 * 幂等：选项已一致则跳过；索引不存在时**不动**（创建是 20260831000000 与模型声明的职责，
 * 本迁移只负责"把已存在的值对齐到声明值"，避免同一件事出现两个所有者）。
 *
 * down()：刻意不回滚。把 TTL 改回"上一个值"等于重新引入可能更短的留存期，
 * 而且被 TTL 物理删除的审计记录不可能靠回滚恢复——回滚在这里是单向有害操作。
 * 但 migrate-mongo 的 down 动作会无条件调用 `migration.down()`
 * （lib/actions/down.js），缺省会抛错并卡住整个回滚演练，所以这里提供显式空实现。
 */

const COLLECTION = 'auditlogs';
// 与模型侧同一份声明（constants/retention.js 随 AUDIT_RETENTION_DAYS 变化），
// 迁移不得自己挑一个"看起来合理"的天数。
const { RETENTION_SECONDS } = require('../src/constants/retention');

const INDEX_NAME = 'timestamp_-1';

const getIndex = async (db, name) => {
  let list;
  try {
    list = await db.collection(COLLECTION).indexes();
  } catch (err) {
    // 集合还不存在（全新库首次 migrate）＝该索引必然不存在，走下面「不创建」分支。
    // 这条不是理论问题：deploy 的 migrate-up 排在容器切换之前，而 auditlogs
    // 要等应用启动期的模型初始化才建，所以**第一次部署必然**撞到这里；
    // 驱动在这种情况是抛 NamespaceNotFound（不是返回 []），
    // 未捕获会让整条 `migrate-mongo up` 失败退出、部署停在半途。
    //
    // 只放过这一种错误码：宽口径 catch 会把权限不足/网络抖动/超时一律读成
    // 「索引不存在」→ 本迁移静默跳过 TTL 对齐却打印成功（同一形状的假绿
    // 已在 scripts/fix-token-blacklist-index.js 判过一次），故其余原样抛出。
    if (err?.codeName === 'NamespaceNotFound' || err?.code === 26 || err?.code === 48) return null;
    throw err;
  }
  return list.find((i) => i.name === name) || null;
};

module.exports = {
  async up(db) {
    const idx = await getIndex(db, INDEX_NAME);

    if (!idx) {
      console.log(`${INDEX_NAME} 不存在，本迁移不创建（由模型声明与 20260831000000 负责）`);
      return;
    }
    if (idx.expireAfterSeconds === RETENTION_SECONDS) {
      console.log(`${INDEX_NAME} TTL 已等于留存声明值 ${RETENTION_SECONDS}s，跳过`);
      return;
    }

    // collMod 原地改 TTL，不需要删重建（删重建会让集合短暂失去索引）
    await db.command({
      collMod: COLLECTION,
      index: { keyPattern: { timestamp: -1 }, expireAfterSeconds: RETENTION_SECONDS },
    });
    console.log(
      `${INDEX_NAME} TTL 由 ${idx.expireAfterSeconds ?? '（未设置）'}s 对齐为留存声明值 ${RETENTION_SECONDS}s`
    );
  },

  async down() {
    console.log('本迁移不回滚：把留存期改回旧值可能更短，且已被 TTL 删除的审计记录无法恢复');
  },
};
