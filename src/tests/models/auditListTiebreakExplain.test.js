/**
 * F2 回归：审计列表的「等值筛选 + 时间倒序」索引必须能**供序**（explain 级锁定）
 *
 * 缺陷（第十一轮 F2 实测，work/_harness/_r11-probe-explain2.js，N=2000）：
 *   生产列表形态是 sort `{ timestamp: -1, _id: -1 }`（游标续页的平局裁决，见
 *   services/auditQueryService.js 的 fetchAuditCursorPage/fetchAuditOffsetPage），
 *   而模型只声明了二键 `{ <filter>: 1, timestamp: -1 }`。排序键序（timestamp,_id）与
 *   索引键序（filter,timestamp）不同向 ⇒ 索引只能供 filter 这一段的序，
 *   时间与 _id 两段必须**阻塞排序**。实测 category 筛选：
 *     plan=FETCH filter > IXSCAN(timestamp_-1__id_-1) | n=667 keys=2000 docs=2000
 *   —— 索引键扫到全部 2000 条才回 667 行，而声明的 category 索引完全没被选中。
 *   反证（把 `_id:-1` 补到索引尾部）：plan=IXSCAN(category_1_timestamp_-1__id_-1)，
 *   keys=667 docs=667，SORT 消失（同一实验里 6 条族 + category+action 全部如此）。
 *
 * 为什么必须用 explain 而不是断言 schema 声明：声明只说明「有这条索引」，
 * 而这里要锁的是「这条查询**选中**了它、且没有 SORT」——声明改错（漏 `_id:-1`）
 * 时 schema 依旧完好，只有执行计划会退化。同仓先例见
 * tests/services/deviceCascadeIndexLock.test.js 的头注释。
 *
 * 规模说明：本套件只造极小数据。explain 的计划选择不看数据量级，
 * 性能数字本身归 work/ 下的实测报告，不在此断言（避免把计时噪声变成红灯）。
 */

'use strict';

const mongoose = require('mongoose');

/** 与 utils/auditQuery.js assembleQuery 的筛选维度一一对应（每个维度都要有自己的索引臂） */
const CASES = [
  { label: 'category', filter: { category: 'auth' } },
  { label: 'category+action', filter: { category: 'auth', action: 'login' } },
  { label: 'action', filter: { action: 'login' } },
  { label: 'riskLevel', filter: { riskLevel: 'high' } },
  { label: 'success', filter: { success: true } },
  { label: 'ip', filter: { ip: '10.0.0.1' } },
  { label: 'userId', filter: null }, // userId 需要真实 ObjectId，在用例内填充
];

describe('F2 审计列表筛选索引必须供序（无 SORT）', () => {
  let AuditLog;
  const tag = `f2tiebreak${Date.now().toString(36)}`;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
    ({ AuditLog } = require('../../models'));
    // 索引声明 → 实际集合：CI 冷启动时集合不存在，不同步就等于在空索引集上 explain（结论归零）
    await AuditLog.syncIndexes();
    await AuditLog.collection.insertMany(
      Array.from({ length: 40 }, (_, i) => ({
        username: `${tag}-${i}`,
        category: ['auth', 'security', 'system'][i % 3],
        action: i % 2 === 0 ? 'login' : 'logout',
        riskLevel: ['low', 'medium', 'high'][i % 3],
        success: i % 2 === 0,
        ip: `10.0.0.${i % 4}`,
        userId: new mongoose.Types.ObjectId(
          'aabbccddeeff00112233' + String(4000 + (i % 5)).slice(-4)
        ),
        timestamp: new Date(Date.now() - i * 1000),
      }))
    );
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await AuditLog.collection
        .deleteMany({ username: { $gte: tag, $lt: `${tag}\uFFFF` } })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  /** 计划里所有 stage 名（递归，SBE 形态的 queryPlan 也走同一条） */
  const stagesOf = (node, out = []) => {
    if (!node || typeof node !== 'object') return out;
    if (typeof node.stage === 'string') out.push(node.stage);
    for (const v of Object.values(node)) stagesOf(v, out);
    return out;
  };

  /** 计划里被选中的索引名（可能多条：SORT_MERGE 两臂） */
  const indexNamesOf = (node, out = []) => {
    if (!node || typeof node !== 'object') return out;
    if (typeof node.indexName === 'string') out.push(node.indexName);
    for (const v of Object.values(node)) indexNamesOf(v, out);
    return out;
  };

  const explainCase = async (filter) => {
    const res = await AuditLog.find(filter)
      .sort({ timestamp: -1, _id: -1 })
      .limit(20)
      .lean()
      .explain('queryPlanner');
    return res.queryPlanner.winningPlan;
  };

  test('前提自证：模型声明的筛选索引都带 _id:-1 平局键（否则下面的计划断言无从谈起）', () => {
    const sigs = AuditLog.schema.indexes().map(([key]) =>
      Object.entries(key)
        .map(([k, v]) => `${k}:${v}`)
        .join('|')
    );
    for (const expected of [
      'userId:1|timestamp:-1|_id:-1',
      'category:1|timestamp:-1|_id:-1',
      'action:1|timestamp:-1|_id:-1',
      'riskLevel:1|timestamp:-1|_id:-1',
      'success:1|timestamp:-1|_id:-1',
      'ip:1|timestamp:-1|_id:-1',
      'category:1|action:1|timestamp:-1|_id:-1',
    ]) {
      expect(sigs).toContain(expected);
    }
  });

  test.each(CASES)(
    '$label 筛选 + {timestamp:-1,_id:-1} 排序 ⇒ 命中带 _id 的索引且无 SORT',
    async ({ filter }) => {
      const realFilter = filter || {
        userId: new mongoose.Types.ObjectId('aabbccddeeff001122334000'),
      };
      const plan = await explainCase(realFilter);
      const stages = stagesOf(plan);
      const names = indexNamesOf(plan);
      // ① 不许出现阻塞排序：SORT 出现即意味着等值块整块拉进内存（大集合撞 100MiB 上限）
      expect(stages).not.toContain('SORT');
      // ② 必须命中带平局键的那条索引；命中 timestamp_-1__id_-1 说明筛选索引根本没被选中
      //    （那正是修复前的形态：keys=全表，n=命中数）
      expect(names.length).toBeGreaterThan(0);
      expect(names.every((n) => n.endsWith('__id_-1'))).toBe(true);
      expect(names).not.toContain('timestamp_-1__id_-1');
    }
  );
});
