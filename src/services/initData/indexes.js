/**
 * 系统初始化数据服务 · 启动期集合索引对账（tokenblacklists / users / auditlogs TTL）
 * 2026-10-19 批 3c：自 src/services/initData.js 拆出（纯搬家，语义不变）。
 */

const mongoose = require('mongoose');
const logger = require('../../utils/logger');
const { RETENTION_SECONDS, RETENTION_DAYS } = require('../../constants/retention');

/**
 * 清理 tokenblacklists 集合的遗留唯一索引
 *
 * 背景：早期 schema 用明文 `token` 字段存黑名单，后改为 `tokenHash`（SHA-256）。
 * 字段改名了，但 MongoDB 里的 `token_1` 唯一索引不会随 schema 变更自动删除。
 * 于是新写入的文档 token 字段全为 undefined → 索引键均为 null →
 * **第二条起插入必然 E11000**。
 *
 * 后果（实测）：consumeToken 把这个 E11000 当作「refresh token 重放」，
 * 每次刷新都触发 invalidateUserTokens 递增 tokenVersion，用户会话被永久吊销，
 * 且因为同时写了 passwordChangedAt，前端收到「密码已修改，请重新登录」的
 * 误导性提示。表现为「注册用户的 refresh_token 永久失效」。
 *
 * 这里在启动期做幂等清理：只删 `token` 单键索引，不动 tokenHash/expiresAt/userId。
 * @returns {Promise<void>}
 */
const reconcileTokenBlacklistIndexes = async () => {
  try {
    const coll = mongoose.connection.collection('tokenblacklists');
    const indexes = await coll.indexes();

    // 精确匹配「仅含 token 单键」的索引；避免误删复合索引
    const legacy = indexes.filter((idx) => {
      const keys = Object.keys(idx.key || {});
      return keys.length === 1 && keys[0] === 'token';
    });

    if (legacy.length === 0) return;

    for (const idx of legacy) {
      await coll.dropIndex(idx.name);
      logger.warn(
        `已删除 tokenblacklists 的遗留索引 ${idx.name}（旧 schema 的明文 token 字段）：` +
          '该索引会让所有新文档因 token=null 撞唯一键，导致 refresh 轮换被误判为重放'
      );
    }
  } catch (e) {
    // 集合不存在（全新部署）属正常情况，其余异常只告警不阻断启动
    if (e.codeName === 'NamespaceNotFound' || /ns does not exist/i.test(e.message || '')) return;
    logger.warn(`tokenblacklists 索引对账跳过：${e.message}`);
  }
};

/**
 * 对账 users 集合的 username 索引
 *
 * schema 从「字段级 unique」改为「显式 collation 唯一索引 username_ci」后，
 * MongoDB 里既有的 `username_1`（默认 collation，大小写敏感）不会自动消失。
 * 两个索引并存时 username_1 仍然放行 Admin/admin 共存，修复等于没生效。
 *
 * 关键顺序问题：不能先删旧索引再建新索引——若库中已存在大小写冲突的账号，
 * 新的唯一索引会创建失败，而旧索引已被删掉，结果是**两个约束都没有**。
 * 因此流程为：① 先检测冲突组；② 有冲突则保留旧索引并告警，等人工处置；
 * ③ 无冲突才删除 username_1（新索引由 mongoose autoIndex 建立）。
 *
 * @returns {Promise<void>}
 */
const dropLegacyUsernameIndex = async (coll, indexes) => {
  const legacy = indexes.find((idx) => idx.name === 'username_1');
  if (!legacy) return;

  // 大小写归一化后分组，找出视觉等同却并存的账号
  const conflicts = await coll
    .aggregate([
      {
        $group: {
          _id: { $toLower: '$username' },
          count: { $sum: 1 },
          names: { $addToSet: '$username' },
        },
      },
      { $match: { count: { $gt: 1 } } },
    ])
    .toArray();

  if (conflicts.length > 0) {
    const detail = conflicts.map((c) => c.names.join('/')).join('；');
    logger.error(
      '检测到大小写冲突的用户名，无法启用大小写不敏感唯一索引：' +
        `${detail}。旧索引 username_1 已保留（约束不会中断），` +
        '请人工合并或重命名冲突账号后重启服务完成索引升级'
    );
    return;
  }

  await coll.dropIndex('username_1');
  logger.warn(
    '已删除 users 的遗留索引 username_1（大小写敏感）：' +
      '该索引允许 Admin/admin 并存，构成操作者身份仿冒面；' +
      '大小写不敏感的 username_ci 唯一索引由 schema 定义接管'
  );
};

/**
 * A3（2026-10-16）：把 users 的唯一约束从**明文列 email** 搬到**检索键列 emailKey**。
 *
 * 为什么必须搬：email 已 at-rest 加密（随机 IV），明文列上不存在"相等"这回事，
 * `email_1` 唯一索引对密文形同虚设 ⇒ 唯一性约束出现真空期。而 emailKey 是
 * HMAC（确定性），唯一索引在它上面才真的成立。
 *
 * **四步顺序固定，任一步不满足即保留旧索引 + 告警**（fail-loud，照抄 username_1 的形态）：
 *   ① 无缺失/空 emailKey 的行；② 无重复 emailKey；③ emailKey_1 确实已存在；④ 才删 email_1。
 *
 * 每一步都在防一个具体的坏结果（逐条实测，见 A3 方案 §2/§3）：
 *   · ① 唯一索引把「字段缺失」视作 null，多条缺失即
 *     `E11000 dup key: { emailKey: null }`，索引直接建不起来；`default: ''` 让空串行
 *     同样冲突（实测两行 `emailKey: ''` 也建不起来）。
 *   · ② 旧索引只保证明文列唯一，而回填是把明文映射成 HMAC——若历史上有绕过 schema
 *     的裸写造出重复邮箱，回填后就是重复键，新索引照样建不起来。
 *   · ③ 新索引由 mongoose autoIndex 依 schema 建立，**不保证**在本次启动的对账之前
 *     已经完成。没确认就先删旧的，等于把唯一性约束清零一段时间。
 *   · ④ 顺序不能反：先删旧再建新，若存在冲突则**两个约束都没有**（username_1 的教训）。
 *
 * @returns {Promise<void>}
 */
const switchEmailIndexToKey = async (coll, indexes) => {
  const legacy = indexes.find((idx) => idx.name === 'email_1');
  if (!legacy) return; // 已是目标形态（或本库从未建过明文唯一索引）

  // ① `{ emailKey: null }` 在 MongoDB 里同时匹配「字段缺失」与「显式 null」，
  //    再并上空串——三种形态在唯一索引眼里都是同一个键，都会让索引建不起来。
  const unbackfilled = await coll.countDocuments({
    $or: [{ emailKey: null }, { emailKey: '' }],
  });
  if (unbackfilled > 0) {
    logger.error(
      `users 集合有 ${unbackfilled} 行的 emailKey 未回填（缺失/空串），` +
        '无法启用 emailKey_1 唯一索引：请先执行 ' +
        '`ALLOWED_SOURCE_DB=<库名> node scripts/migrate-pii-encryption.js --keys-only --apply --yes` ' +
        '回填全表，再重启服务完成索引切换。' +
        '旧索引 email_1 已保留（唯一性约束不会中断）。'
    );
    return;
  }

  // ② 回填后仍重复 ⇒ 历史上有绕过 schema 的裸写造出了重复邮箱
  const dups = await coll
    .aggregate([
      { $group: { _id: '$emailKey', count: { $sum: 1 }, ids: { $addToSet: '$_id' } } },
      { $match: { count: { $gt: 1 } } },
      { $limit: 5 },
    ])
    .toArray();
  if (dups.length > 0) {
    const detail = dups.map((d) => `${d.count} 行（_id: ${d.ids.join(', ')}）`).join('；');
    logger.error(
      `检测到重复邮箱（emailKey 相同，至少 ${dups.length} 组）：${detail}。` +
        '无法启用 emailKey_1 唯一索引——请人工合并或改掉重复账号的邮箱后重启服务。' +
        '旧索引 email_1 已保留（唯一性约束不会中断）。'
    );
    return;
  }

  // ③ 新索引必须真的存在。emailKey_1 由 schema 声明 + mongoose autoIndex 建立，
  //    不保证在本次对账之前完成；未确认就删旧的 = 制造唯一性真空期。
  const fresh = (await coll.indexes()).find((idx) => idx.name === 'emailKey_1');
  if (!fresh) {
    logger.error(
      'emailKey_1 唯一索引尚未建立（mongoose autoIndex 未完成或创建失败），' +
        '本次不删除旧索引 email_1——先删旧的会让明文列的唯一性约束出现真空期。' +
        '请确认启动日志无索引创建失败后重启服务完成切换。'
    );
    return;
  }

  await coll.dropIndex('email_1');
  logger.warn(
    '已删除 users 的遗留索引 email_1（明文列唯一）：email 列已 at-rest 加密，' +
      '该索引对密文形同虚设（随机 IV 下不存在"相等"）；' +
      '唯一性约束现由 emailKey_1（HMAC 检索键）承担，约束真空期结束'
  );
};

const reconcileUserIndexes = async () => {
  try {
    const coll = mongoose.connection.collection('users');
    const indexes = await coll.indexes();
    // 两件事都要做，故不能在任一分支里 return——原实现是 `if (!legacy) return;`，
    // 那样 username_1 不存在时邮箱这一半会被整体跳过。
    await dropLegacyUsernameIndex(coll, indexes);
    await switchEmailIndexToKey(coll, indexes);
  } catch (e) {
    if (e.codeName === 'NamespaceNotFound' || /ns does not exist/i.test(e.message || '')) return;
    logger.warn(`users 索引对账跳过：${e.message}`);
  }
};

/**
 * 对账 auditlogs 的 TTL 索引到留存声明值
 *
 * 留存期改档后，光改代码到不了已迁移的库：`migrate-mongo-config.js:88` 的
 * `useFileHash: false` 让迁移标识只有文件名，`20260831000000` 与
 * `20260919000000`（它本身就是为补前者的可达性而追加的一次性迁移）在任何跑过
 * 它们的库上都永远算"已应用"；模型侧 `createIndexes` 遇同名不同选项只抛
 * IndexOptionsConflict 而不会改选项。于是 `AUDIT_RETENTION_DAYS` 从 180 改到 365
 * 之后，物理 TTL 仍按 180 天删记录——constants/retention.js 把这类偏差定性为
 * 「对外声明留存 N 天、实际留得更少」，在合规语境下比配置错误本身更严重。
 * 每次改档再补一条一次性迁移不可持续，故按仓内既有形态（reconcileUserIndexes /
 * reconcileTokenBlacklistIndexes）把它收成常驻不变量。
 *
 * 顺带覆盖一个回滚后遗症：`20260831000000.down()` 会把 timestamp_-1 重建为
 * **无 TTL** 索引（:89），若只回滚迁移不回滚代码，启动即声明/物理不一致——
 * 本对账会把它补回来。
 *
 * 只改已存在的索引，不创建：创建是模型声明与 20260831000000 的职责，
 * 同一件事不能有两个所有者（与 20260919000000 的幂等口径一致）。
 *
 * @returns {Promise<void>}
 */
const reconcileAuditTtlIndex = async () => {
  try {
    const indexes = await mongoose.connection.collection('auditlogs').indexes();
    const idx = indexes.find((i) => i.name === 'timestamp_-1');
    if (!idx) return;
    if (idx.expireAfterSeconds === RETENTION_SECONDS) return;

    // collMod 原地改 TTL，不需要删重建（删重建会让集合短暂失去该索引）
    await mongoose.connection.db.command({
      collMod: 'auditlogs',
      index: { keyPattern: { timestamp: -1 }, expireAfterSeconds: RETENTION_SECONDS },
    });
    logger.warn(
      `审计留存 TTL 由 ${idx.expireAfterSeconds ?? '（未设置）'}s 对齐为声明值 ` +
        `${RETENTION_SECONDS}s（${RETENTION_DAYS} 天）：改档只靠迁移到不了已迁移库` +
        '（迁移标识是文件名），物理删除窗口以声明值为准'
    );
  } catch (e) {
    // 集合尚不存在＝索引必然不存在，交给模型声明与迁移（实测驱动抛的是
    // NamespaceNotFound/26，不是返回空列表）。只放过这一种：宽口径 catch 会把
    // 权限不足读成"没有这个索引"→ 对账静默不生效却打印成功，即假绿。
    if (e.codeName === 'NamespaceNotFound' || e.code === 26) return;
    logger.warn(`auditlogs TTL 对账跳过：${e.message}`);
  }
};

module.exports = { reconcileUserIndexes, reconcileTokenBlacklistIndexes, reconcileAuditTtlIndex };
