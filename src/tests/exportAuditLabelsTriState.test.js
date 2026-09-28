/**
 * 审计导出的「等级 / 操作结果 / 耗时」三列：缺位不得被翻译成结论，且必须与列表 level 筛选互为反向
 *
 * 列表侧 `buildLevelCondition` 用 Mongo **等值** `{success: true|false}` 筛档，
 * 导出侧 `EXPORT_ROW_TRANSFORMS.audit` 是它的 doc→label 镜像（F-149 立的口径：
 * 两侧同一份派生集合）。原镜像写成 `!item.success ? '错误' : ...` 与
 * `item.success ? '成功' : '失败'`，于是「字段缺位」这一第三种状态被两条分支各自
 * 认领成了一个**肯定性结论**。而缺位不是理论形态：`AuditLog.success` 是
 * `{type: Boolean}` 无 default、非 required（`models/AuditLog.js:114`），
 * 至少五处直写点根本不带该字段——
 * `login_unusual_time`（authService）、`suspicious_report`（securityController）、
 * 以及 securityAlert 的三处告警审计。一次凌晨 23 点的**成功**登录，
 * 在合规导出的 xlsx 里是「等级=错误 + 操作结果=失败」，
 * 而列表侧 `?level=error` 与 `?success=false` 都筛不出它：同一份数据两处自相矛盾。
 *
 * `duration` 同族：`item.duration ? ... : '-'` 把合法的 `0`（同一毫秒内返回，
 * 缓存命中时是常态）写成「未记录时长」；而 CSV 导出走的是原样 `csvEscape`，
 * 同一个字段两分钟内的两份合规材料一个给 `0ms` 一个给 `-`。
 * 本仓已有判例认定 0 合法：`securityController.js` 的 `duration: alert.duration ?? 0`。
 *
 * 四格：
 *   ① 档位对拍：对 success×riskLevel 的全形状矩阵，导出 label 命中集必须与
 *      `AuditLog.find(buildLevelCondition(level))` 的命中集**逐档相等**（这一格今天为红）；
 *   ② 缺位诚实：导出判为 `-` 的文档，三档筛选一个都不命中（承认盲区而不是编一个档）；
 *   ③ 高危独立触发：success=true 但 riskLevel 达高危仍为「错误」（$or 的第二分支，别改丢）；
 *   ④ 纯内存三态：success 的 true/false/缺位，与 duration 的 0/正数/缺位。
 */
const mongoose = require('mongoose');

const stamp = `zzbtl${Date.now().toString(36)}`.replace(/[^a-z0-9_]/g, '');
const CAT = 'security';

/** 与列表侧同一份档位表：改一边就会在这里露出来 */
const LEVEL_LABEL = { error: '错误', warning: '警告', info: '信息' };

describe('审计导出档位 vs 列表 level 筛选：同一文档两侧结论必须一致', () => {
  let AuditLog;
  let EXPORT_ROW_TRANSFORMS;
  let buildLevelCondition;

  const SUCCESS_STATES = [true, false, 'missing'];
  const RISK_STATES = ['low', 'medium', 'high', 'missing'];

  /** 每条形状一个独立 action：本库按 worker 共享，只能在自己的子集里对拍 */
  const actionFor = (s, r) => `${stamp}_${String(s)}_${r}`;
  const ids = {};

  const seeded = [];
  for (const s of SUCCESS_STATES) {
    for (const r of RISK_STATES) {
      seeded.push({ success: s, risk: r, action: actionFor(s, r) });
    }
  }

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    AuditLog = require('../models/AuditLog');
    ({ EXPORT_ROW_TRANSFORMS } = require('../services/reportExportService'));
    ({ buildLevelCondition } = require('../utils/auditQuery'));

    for (const doc of seeded) {
      const created = await AuditLog.create({
        action: doc.action,
        category: CAT,
        username: `${stamp}_u`,
        method: 'POST',
        path: '/api/zz-level-parity',
        ip: '203.0.113.11',
        timestamp: new Date(),
        ...(doc.success === 'missing' ? {} : { success: doc.success }),
        ...(doc.risk === 'missing' ? {} : { riskLevel: doc.risk }),
      });
      ids[`${doc.success}|${doc.risk}`] = String(created._id);
    }
  });

  afterAll(async () => {
    await AuditLog.deleteMany({ action: new RegExp(`^${stamp}_`) }).catch(() => {});
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /** 库里真的按该档条件筛出来的 id 集合 */
  const queryIds = async (level) => {
    const cond = buildLevelCondition(level);
    const docs = await AuditLog.find({
      action: new RegExp(`^${stamp}_`),
      ...cond,
    }).lean();
    return docs.map((d) => String(d._id)).sort();
  };

  /** 导出侧给该档 label 的 id 集合（逐条过真实行转换，不另写一份判据） */
  const labelIds = async (level) => {
    const docs = await AuditLog.find({ action: new RegExp(`^${stamp}_`) }).lean();
    return docs
      .filter((d) => EXPORT_ROW_TRANSFORMS.audit(d).level === LEVEL_LABEL[level])
      .map((d) => String(d._id))
      .sort();
  };

  for (const level of Object.keys(LEVEL_LABEL)) {
    test(`档位对拍 ${level}（${LEVEL_LABEL[level]}）：筛出的集合 = 导出标注的集合`, async () => {
      const queried = await queryIds(level);
      const exported = await labelIds(level);
      expect({
        level,
        onlyInQuery: queried.filter((id) => !exported.includes(id)),
        onlyInExport: exported.filter((id) => !queried.includes(id)),
      }).toEqual({ level, onlyInQuery: [], onlyInExport: [] });
    });
  }

  test('缺位诚实：导出判为 - 的文档，三档筛选一个都不命中', async () => {
    const docs = await AuditLog.find({ action: new RegExp(`^${stamp}_`) }).lean();
    const dashed = docs
      .filter((d) => EXPORT_ROW_TRANSFORMS.audit(d).level === '-')
      .map((d) => String(d._id));
    // 形状矩阵里必须真的存在缺位档，否则本条是空对空
    expect(dashed.length).toBeGreaterThan(0);
    for (const level of Object.keys(LEVEL_LABEL)) {
      const q = await queryIds(level);
      expect(q.filter((id) => dashed.includes(id))).toEqual([]);
    }
  });

  test('高危独立触发：success=true 但 riskLevel 达高危仍是错误（$or 第二分支不得改丢）', async () => {
    const doc = await AuditLog.findById(ids['true|high']).lean();
    expect(EXPORT_ROW_TRANSFORMS.audit(doc).level).toBe('错误');
    const doc2 = await AuditLog.findById(ids['false|low']).lean();
    expect(EXPORT_ROW_TRANSFORMS.audit(doc2).level).toBe('错误');
    expect(EXPORT_ROW_TRANSFORMS.audit(doc2).success).toBe('失败');
  });

  test('纯内存三态：success 缺位不是失败，duration 的 0 不是未记录', () => {
    const t = EXPORT_ROW_TRANSFORMS.audit;
    expect(t({})).toMatchObject({ success: '-', level: '-', duration: '-' });
    expect(t({ success: true, riskLevel: 'low' })).toMatchObject({
      success: '成功',
      level: '信息',
    });
    expect(t({ success: true, riskLevel: 'medium' })).toMatchObject({
      success: '成功',
      level: '警告',
    });
    expect(t({ success: false, riskLevel: 'low' })).toMatchObject({
      success: '失败',
      level: '错误',
    });
    expect(t({ duration: 0, success: true, riskLevel: 'low' }).duration).toBe('0ms');
    expect(t({ duration: 12, success: true, riskLevel: 'low' }).duration).toBe('12ms');
  });
});
