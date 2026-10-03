/**
 * 审计查询的"参数组合恒空"判据（level × success × riskLevel）。
 *
 * 起因：`?level=warning&success=false` 会组装出 `{success:false} ∩ {success:true, riskLevel:'medium'}`
 * = 空集，对外却是 200 + 空列表 + 零提示——审计人员以为"这段时间没有 warning"，
 * 实际是他自己的两个筛选条件互相抵消。本文件对同一形状早有裁定（utils/auditQuery.js:30-35：
 * 误导性空结果 ⇒ 收口为抛错，调用方给 400），这里把那条裁定补到 level 这条腿上。
 *
 * 门禁为什么长这样：
 *  - 对拍表是**手写**的三档语义（下面的 levelHitsDoc），不是把实现里的求值器再跑一遍——
 *    同一个来源自证 = 恒真；两份独立表述不一致才会红。
 *  - 两个方向都判：恒空的必须拒（漏拒 = 静默空结果），可用的一个都不许拒（误拒 = 把能用的窗口打死）。
 *  - 求值器遇到没建模的操作符必须"保守放行"，这条单独钉（它决定了实现会不会随条件形态变化而过度拒绝）。
 */
const {
  AUDIT_RISK_LEVELS,
  AUDIT_DISPLAY_LEVELS,
  AUDIT_ERROR_RISK_LEVELS,
  AUDIT_WARNING_OR_HIGHER_RISK_LEVELS,
} = require('../../constants/audit');
const {
  buildAuditQuery,
  assertFiltersMutuallySatisfiable,
  isProvablyEmptyCondition,
  auditFilterDomain,
} = require('../../utils/auditQuery');

/** 三档展示口径的命中语义：按 constants 的口径手抄一份，与实现无关（对拍的另一侧） */
const levelHitsDoc = (level, doc) => {
  if (level === 'error')
    return doc.success === false || AUDIT_ERROR_RISK_LEVELS.includes(doc.riskLevel);
  if (level === 'warning') return doc.success === true && doc.riskLevel === 'medium';
  if (level === 'info')
    return doc.success === true && !AUDIT_WARNING_OR_HIGHER_RISK_LEVELS.includes(doc.riskLevel);
  throw new Error(`对拍表没覆盖的 level：${level}`);
};

/** 显式过滤 + level 条件在真实数据域里是否可能存在一条同时命中的记录 */
const handSatisfiable = (level, success, riskLevel) =>
  auditFilterDomain().some(
    (doc) =>
      (success === undefined || doc.success === success) &&
      (riskLevel === undefined || doc.riskLevel === riskLevel) &&
      levelHitsDoc(level, doc)
  );

const throwsOn = (f) => {
  try {
    assertFiltersMutuallySatisfiable(f);
    return false;
  } catch (e) {
    if (!/恒空/.test(e.message)) throw e; // 只接受这条判据抛的错，别把别的 400 当成通过
    return true;
  }
};

// 'true'/'false' 是 query 形态；undefined = 该过滤项没传
const SUCCESS_FORMS = [undefined, 'true', 'false'];
const RISK_FORMS = [undefined, ...AUDIT_RISK_LEVELS];

/**
 * 「求值器该保守放行」的形状表：每条 = [条件, 期望, 为什么是这个期望]。
 *
 * 为什么长成表而不是七行字面 `expect(...)`：判据集中在一张表上时，把某一行的期望改错会让用例
 * 转红，删掉一行会被下面的行数地板抓到，删掉整个循环会让 `UNMODELED_SHAPES` 变成未使用变量
 * （eslint no-unused-vars 红）并且 `judged` 对不上行数。逐行写死 expect 的话，"删掉一行"
 * 只是一次静默的判据减质。
 */
const UNMODELED_SHAPES = [
  [{ success: { $regex: '^x$' } }, false, '$regex 不在建模范围内，不能断言"全不命中"'],
  [
    { timestamp: { $gte: new Date(0) } },
    false,
    '域外字段不在 (success × riskLevel) 域里，不能拿它推空',
  ],
  [{ $and: { success: true } }, false, '$and 形态残缺（不是数组）也不能拿来推"恒空"'],
  [
    { success: false, $and: [{ success: true }] },
    true,
    '$and 与同级显式过滤是并列合取项，漏掉任一侧都会把"该拒的"判成可用',
  ],
  [{ success: true, riskLevel: 'medium' }, false, '真的可满足'],
  [{ $and: [{ success: true }, { success: false }] }, true, '真的恒空'],
  [{}, false, '空条件 = 全命中'],
];

describe('level × success × riskLevel 组合可满足性', () => {
  test('三档 × 全部 riskLevel × success 三态逐项对拍：恒空一律拒，可用一律放行', () => {
    expect(AUDIT_DISPLAY_LEVELS).toEqual(['info', 'warning', 'error']);
    const mismatch = [];
    let probed = 0;
    for (const level of AUDIT_DISPLAY_LEVELS) {
      for (const success of SUCCESS_FORMS) {
        for (const riskLevel of RISK_FORMS) {
          probed += 1;
          const expected = handSatisfiable(
            level,
            success === undefined ? undefined : success === 'true',
            riskLevel
          );
          if (throwsOn({ level, success, riskLevel }) !== !expected) {
            mismatch.push(
              `level=${level} success=${success ?? '∅'} riskLevel=${riskLevel ?? '∅'}：` +
                `按 constants 口径${expected ? '可用却被拒' : '恒空却放行'}`
            );
          }
        }
      }
    }
    expect(mismatch).toEqual([]);
    // 三个轴的长度与"确实逐点判过"必须一起钉住。只钉 mismatch 的话，把某个轴改短
    // （或把某层循环换成写死的单元素）会让对拍静默少判一片形状而仍然全绿——
    // 这是变异台账第 28 轮实测出来的盲区，不是推测。
    expect(SUCCESS_FORMS).toEqual([undefined, 'true', 'false']);
    expect(RISK_FORMS).toEqual([undefined, ...AUDIT_RISK_LEVELS]);
    expect(new Set(AUDIT_RISK_LEVELS).size).toBe(AUDIT_RISK_LEVELS.length);
    expect(probed).toBe(AUDIT_DISPLAY_LEVELS.length * SUCCESS_FORMS.length * RISK_FORMS.length);
  });

  test('具体失实形态逐条钉住（不是只靠上面的循环）', () => {
    for (const [level, success, riskLevel] of [
      ['warning', 'false', undefined],
      ['warning', undefined, 'high'],
      ['info', 'false', undefined],
      ['info', undefined, 'critical'],
      ['error', 'true', 'low'],
    ]) {
      expect(throwsOn({ level, success, riskLevel })).toBe(true);
    }
    for (const [level, success, riskLevel] of [
      ['error', 'false', undefined],
      ['error', 'true', 'high'],
      ['warning', 'true', 'medium'],
      ['info', 'true', 'low'],
    ]) {
      expect(throwsOn({ level, success, riskLevel })).toBe(false);
    }
  });

  test('判据只由 level 触发：没有 level 时 success/riskLevel 任意组合都放行', () => {
    expect(throwsOn({ success: 'false', riskLevel: 'low' })).toBe(false);
    expect(throwsOn({ level: undefined, success: 'true', riskLevel: 'critical' })).toBe(false);
    // 未知 level 留给上游枚举校验（validateEnum），这里不许抢错
    expect(throwsOn({ level: 'zzz', success: 'false' })).toBe(false);
    expect(() => buildAuditQuery({ query: { level: 'zzz', success: 'false' } })).toThrow(/level/);
  });

  test('不抢原有那条 400：success 取值形状非法时仍是原消息', () => {
    expect(() => assertFiltersMutuallySatisfiable({ level: 'warning', success: 'yes' })).toThrow(
      /^参数 success 必须是 true 或 false$/
    );
    expect(() => assertFiltersMutuallySatisfiable({ level: 'warning', success: '' })).not.toThrow();
    // throwsOn 自己的守卫也有牙：非"恒空"的错必须原样抛出去。否则上面那张对拍表退化成
    // "只要抛错就算拒了"，实现里换成任何一条别的 400 都能让它保持全绿。
    expect(() => throwsOn({ level: 'warning', success: 'yes' })).toThrow(
      /^参数 success 必须是 true 或 false$/
    );
    expect(throwsOn({ level: 'error', success: 'true' })).toBe(false);
  });

  test('求值器对没建模的形态保守放行（宁可少拒，不许把可用窗口判成空集）', () => {
    expect(UNMODELED_SHAPES.length).toBeGreaterThanOrEqual(7);
    const wrong = [];
    let judged = 0;
    for (const [cond, expected, why] of UNMODELED_SHAPES) {
      judged += 1;
      if (isProvablyEmptyCondition(cond) !== expected) {
        wrong.push(`${why}：期望 ${expected}，实判 ${isProvablyEmptyCondition(cond)}`);
      }
    }
    expect(wrong).toEqual([]);
    // 行数地板管"删行"，judged 地板管"循环被掏空/偷偷加了过滤"——少一条都能静默减员
    expect(judged).toBe(UNMODELED_SHAPES.length);
  });

  test('取值域本身不许塌缩：塌了"恒空"就永远算不出来', () => {
    const domain = auditFilterDomain();
    expect(domain.length).toBe(AUDIT_RISK_LEVELS.length * 2);
    expect(new Set(domain.map((d) => d.riskLevel)).size).toBe(AUDIT_RISK_LEVELS.length);
    expect(new Set(domain.map((d) => d.success))).toEqual(new Set([true, false]));
  });

  test('接线：整条链（buildAuditQuery）当场拒绝恒空组合，可用组合照旧组装', () => {
    expect(() => buildAuditQuery({ query: { level: 'warning', success: 'false' } })).toThrow(
      /恒空/
    );
    const ok = buildAuditQuery({ query: { level: 'warning', success: 'true' } }).query;
    expect(ok.success).toBe(true);
    expect(ok.$and).toEqual([{ success: true, riskLevel: 'medium' }]);
  });
});
