/**
 * 审计部门成员缓存的上界（2026-10-03 审计线 R11-C #4）
 *
 * 缺陷形状：`deptMembersCache` 只有 TTL 没有上限，条目数是"用户表里出现过的
 * department 取值数"，只增不减（读到过期项走覆盖而非删除），值是整个部门的
 * 用户 id 列表。而模块头注释写着它与 reportDashboardService 的 dashboardCache
 * **同一口径**——那份缓存有 MAX_ENTRIES + 写前清扫 + 定时清扫。注释即事实：
 * 说法与实现不符就是缺陷，哪怕增长很慢。
 *
 * 判据怎么做到"不新增导出也能测"：缓存本体不导出（避免为测试扩大对外面），
 * 但淘汰是**可观测**的——被淘汰的部门下次读取会重新打 `User.distinct`。
 * 于是三条腿：
 *   ① 前提自证：写 N 个部门 ⇒ distinct 恰好 N 次（真的在按部门打库，不是常量空转）；
 *   ② 反向对照：TTL 内重复读同一部门 ⇒ distinct 0 次（缓存确实生效，
 *      否则 ③ 的"又打了一次"毫无信息量）；
 *   ③ 上界本身：写满上限之后再回头读最早那条 ⇒ 必须重新打库（说明它被淘汰了）。
 * 摘掉 enforce 调用 ⇒ ③ 立刻变红；把缓存整体改成不缓存 ⇒ ② 变红。
 */

const mongoose = require('mongoose');

jest.mock('../../middleware/rbac', () => ({
  getDataScope: jest.fn(),
  // auditScopeFilter 只用到 getDataScope；其余导出的存在会让 require 触发真实
  // rbac 依赖链（redis/审计模型），这里刻意不引。
}));

describe('auditScopeFilter 部门成员缓存的上界', () => {
  const CACHE_MAX = 500;
  let rbac;
  let User;
  let applyAuditDataScope;
  let distinct;

  const oneId = new mongoose.Types.ObjectId();

  beforeAll(() => {
    rbac = require('../../middleware/rbac');
    User = require('../../models/User');
    // 缓存条目按"部门名"分键，写满 501 个部门即可跨过上限
    applyAuditDataScope = require('../../services/auditScopeFilter').applyAuditDataScope;
    distinct = jest.spyOn(User, 'distinct').mockResolvedValue([oneId]);
  });

  afterAll(() => {
    distinct.mockRestore();
  });

  const queryFor = async (department) => {
    rbac.getDataScope.mockResolvedValue({ type: 'department', department });
    return applyAuditDataScope({}, 'operator-x');
  };

  test('前提自证：每个新部门各打一次 distinct（缓存没在空转，计数才有意义）', async () => {
    distinct.mockClear();
    for (let i = 0; i < 20; i += 1) await queryFor(`cap-a-${i}`);
    expect(distinct).toHaveBeenCalledTimes(20);
  });

  test('反向对照：TTL 内重复读同一部门不再打库（否则下一条的"重新打库"没有信息量）', async () => {
    distinct.mockClear();
    await queryFor('cap-a-0');
    await queryFor('cap-a-0');
    expect(distinct).not.toHaveBeenCalled();
  });

  test('上界本身：写满 CACHE_MAX 个部门后，最早的部门已被淘汰并重新打库', async () => {
    distinct.mockClear();
    for (let i = 0; i < CACHE_MAX; i += 1) await queryFor(`cap-b-${i}`);
    // 全部为新键 ⇒ 每次都 miss（这条同时钉住"填充满上限"这个前提真的发生了）
    expect(distinct).toHaveBeenCalledTimes(CACHE_MAX);

    // 最近写入的键仍在缓存（反向对照，防止"整个缓存被清空"被误当成上限生效）
    distinct.mockClear();
    await queryFor(`cap-b-${CACHE_MAX - 1}`);
    expect(distinct).not.toHaveBeenCalled();

    // 最早写入的键（cap-a-0）此刻必须已被淘汰 ⇒ 重新打库
    distinct.mockClear();
    await queryFor('cap-a-0');
    expect(distinct).toHaveBeenCalledTimes(1);
  });

  test('淘汰后仍能正常出结果（上界不是靠拒绝写入实现的）', async () => {
    const { query, dataScope } = await queryFor('cap-a-0');
    expect(dataScope.type).toBe('department');
    expect(query.userId).toEqual({ $in: [oneId] });
  });
});
