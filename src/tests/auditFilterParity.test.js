/**
 * 审计筛选参数：查询侧严格化+ 查询/导出两侧枚举同源
 *
 * 起因（实测，改前）：`buildAuditQuery` 里
 *   query.success = success === 'true' || success === true
 * 这一行把「任何不等于 'true'/true 的入参」静默翻译成 `success: false`。
 * 实测被吞的值：'1'、'0'、'yes'、'no'、'TRUE'、'True'、' true'、
 * 数组（`?success=true&success=false`，extended query parser 造得出）、
 * 以及 `?success[$ne]=x` 造出的对象。后两者今天不构成注入
 * （布尔收敛把操作符对象吃掉了，这条也已钉住），但都构成
 * **误导性的窄结果集**：筛选条件写错 ⇒ 只返回失败记录 ⇒ HTTP 200、无提示。
 * 审计人员会以为自己按某条件筛过，实际看到的是另一个集合。
 *
 * 判例不是我个人偏好，是本仓既有裁定：
 * - 前端 `AuditLogView.buildFilterParams` 特意排除空串，注释原话是
 *   "否则空串会被后端解析为 false，导致『清空筛选=只看失败』的错误结果"——
 *   空串只是这条静默路径的一个入口，其余值走的是同一条路；
 * - 导出侧 `validateAuditExportEnums` 的 P3-13 注释：level 此前缺失校验，
 *   "非法值不命中派生分支被静默忽略，用户选『仅错误』却导出全量"——
 *   同一个"写错的筛选参数必须响"的裁定，level 修了、success 没修。
 *
 * 本文件的 riskLevel 清单原是本地字面量，与 constants/audit.js 的
 * AUDIT_RISK_LEVELS（导出侧引用的那份）同值但各写一份。两侧枚举清单
 * 不同源＝E-05 那类"两份实现漂移"的复发条件，这里用循环把它钉成契约。
 */

const { buildAuditQuery, buildLevelCondition } = require('../utils/auditQuery');
const { AUDIT_RISK_LEVELS, AUDIT_DISPLAY_LEVELS } = require('../constants/audit');
const { buildExportQuery, validateAuditExportEnums } = require('../services/reportExportService');

/** 调 buildAuditQuery，把抛错一起回传，便于同时断言"抛了"与"没产出错误查询" */
const tryBuild = (query) => {
  try {
    return { ok: true, built: buildAuditQuery({ query }).query };
  } catch (err) {
    return { ok: false, message: err.message };
  }
};

describe('success 筛选参数不再被静默翻译成 false', () => {
  // 合法值：逐字放行，语义不变
  it.each([
    ['true', true],
    ['false', false],
    [true, true],
    [false, false],
  ])('合法值 %p ⇒ query.success === %p', (raw, expected) => {
    const { ok, built } = tryBuild({ success: raw });
    expect(ok).toBe(true);
    expect(built.success).toBe(expected);
  });

  // 未传 / 空串：必须仍是"未筛选"。空串这条是前端 clearable 的既有契约，
  // 严格化不许把它顺带变成 400（那会让"清空筛选"按钮报错）
  it.each([
    ['未传', undefined],
    ['空串', ''],
  ])('%s ⇒ 不下发 success 条件（不报错、不筛选）', (_name, raw) => {
    const { ok, built } = tryBuild(raw === undefined ? {} : { success: raw });
    expect(ok).toBe(true);
    expect('success' in built).toBe(false);
  });

  // 歧义值：一律 400，不得产出一个"看着正常但语义不同"的查询
  // （修复前的失败形态正是"悄悄产出 success:false 并返回 200"，故断言点就是 ok===false）
  it.each([
    ['数字串 1', '1'],
    ['数字串 0', '0'],
    ['yes', 'yes'],
    ['no', 'no'],
    ['大写 TRUE', 'TRUE'],
    ['首字母大写 True', 'True'],
    ['带前导空格', ' true'],
    ['数组（同名参数重复）', ['true', 'false']],
    ['操作符对象（extended parser）', { $ne: 'x' }],
    ['空对象', {}],
  ])('%s ⇒ 400 而不是静默按 false 筛选', (_name, raw) => {
    const { ok, built, message } = tryBuild({ success: raw });
    expect(ok).toBe(false);
    expect(message).toContain('success');
    expect(built).toBeUndefined();
  });

  it('正对照：同一条件其余参数照常生效（400 只由 success 引起）', () => {
    const clean = tryBuild({ riskLevel: 'high', success: 'true' });
    expect(clean.ok).toBe(true);
    expect(clean.built).toEqual({ riskLevel: 'high', success: true });
    const dirty = tryBuild({ riskLevel: 'high', success: '1' });
    expect(dirty.ok).toBe(false);
  });
});

describe('查询侧与导出侧的枚举清单同源', () => {
  it('constants 的每个 riskLevel 都被查询侧接受（退回本地字面量即转红）', () => {
    expect(AUDIT_RISK_LEVELS.length).toBeGreaterThan(0);
    for (const level of AUDIT_RISK_LEVELS) {
      const { ok, built } = tryBuild({ riskLevel: level });
      expect(ok).toBe(true);
      expect(built.riskLevel).toBe(level);
    }
  });

  it('清单外的值两侧同口径拒绝（不允许"查询 400、导出放行"）', () => {
    const bogus = AUDIT_RISK_LEVELS.includes('urgent') ? 'zzz' : 'urgent';
    expect(tryBuild({ riskLevel: bogus }).ok).toBe(false);
    expect(() => validateAuditExportEnums({ riskLevel: bogus })).toThrow();
  });

  it('level 派生条件两侧一致（同一入参产出同一 $and 结构）', () => {
    for (const level of AUDIT_DISPLAY_LEVELS) {
      const q = tryBuild({ level }).built.$and[0];
      const e = buildExportQuery('audit', { level, dateFilter: {} });
      // 查询侧与导出侧的 level 派生分支必须同形，否则"导出即所见"不成立
      expect(e.$and[0]).toEqual(q);
    }
  });

  // 上面这条原先把清单**再抄第三份**写死在测试里（`['info','warning','error']`），
  // 于是它只能证明"三份抄得一样"，证明不了两侧同源：任何一侧单独增删一档，
  // 循环仍只跑这三档 ⇒ 全绿。下面两条把它换成行为比对，才是可证伪的漂移门禁。
  it('level 清单同源：两侧对同一候选集的"接受/拒绝"必须逐项相等', () => {
    // 候选集刻意**超出**当前清单：只有超出部分参与比对，"某侧偷偷多一档"才会转红。
    // 导出一侧的闸门是 validateAuditExportEnums（由 reportController 调用）——
    // buildExportQuery 自己不抛错，它对清单外的 level 是**静默不加 $and**，
    // 拿它比"抛不抛"会得到假的相等，所以这里比的是真正的闸门函数。
    const candidates = [...AUDIT_DISPLAY_LEVELS, 'debug', 'urgent', 'INFO', 'Info', 'all', 'none'];
    for (const level of candidates) {
      const querySide = tryBuild({ level }).ok;
      let exportSide = true;
      try {
        validateAuditExportEnums({ level });
      } catch {
        exportSide = false;
      }
      expect({ level, acceptedByExport: exportSide }).toEqual({
        level,
        acceptedByExport: querySide,
      });
    }
  });

  it('清单里每一档都必须有自己的派生分支（新增枚举不加分支即转红）', () => {
    // buildLevelCondition 的兜底分支就是 info 的形状，所以"未知值"与"info"同形。
    // 若给 AUDIT_DISPLAY_LEVELS 加第 4 档而忘了在 buildLevelCondition 加分支，
    // 该档会静默退化成"信息"筛选（200 + 又一个误导性结果集）——这条就是钉这个。
    const shapes = AUDIT_DISPLAY_LEVELS.map((level) => JSON.stringify(buildLevelCondition(level)));
    expect(new Set(shapes).size).toBe(AUDIT_DISPLAY_LEVELS.length);
  });

  // ── 上面那条只管「每档形状不同」，管不到档**内部点名的 riskLevel 清单**：
  // buildLevelCondition 里 ['high','critical'] / 'medium' / $nin 三份字面量是函数体里
  // 手抄的，与 constants/audit.js 的 AUDIT_RISK_LEVELS 没有任何连线。三种漂移都静默：
  //   1) 抄错一个字母（'critikal'）⇒ 该条件永不命中，critical 记录从"错误"筛选里凭空消失；
  //   2) 给 AUDIT_RISK_LEVELS 加第 5 档却忘了同步 ⇒ 新档被 info 的 $nin 兜住，
  //      一条比 high 更危险的经历被归进"信息"，而这正是本文件头记录过的
  //      "写错的筛选参数静默给出另一个结果集"同一裁定；
  //   3) 某一档的纳入清单与 info 的 $nin 不再互补 ⇒ 同一条记录两档都能筛出（重复计数），
  //      或哪档都筛不出（死角）。
  // 下面三条把「抄得一样」换成按维度逐项比对，才是可证伪的漂移门禁。

  /**
   * 从 buildLevelCondition 的返回值里取出「这一档显式点名了哪些 riskLevel，纳入还是排除」。
   * 只认三种形态：标量相等 / {$in:[...]} / {$nin:[...]}；$or/$and 递归下钻，
   * success 等非 riskLevel 维度跳过（本判据只管风险等级这一维）。
   * 认不出的形态记进 bad：判据失效时宁可红，绝不退化成「这一档没点名任何值」的假绿。
   */
  const riskTerms = (cond) => {
    const acc = { include: [], exclude: [], bad: [] };
    const walk = (c) => {
      for (const [key, val] of Object.entries(c)) {
        if (key === '$or' || key === '$and') {
          val.forEach(walk);
          continue;
        }
        if (key !== 'riskLevel') continue;
        if (Array.isArray(val && val.$in)) acc.include.push(...val.$in);
        else if (Array.isArray(val && val.$nin)) acc.exclude.push(...val.$nin);
        else if (typeof val === 'string') acc.include.push(val);
        else acc.bad.push(`${key}=${JSON.stringify(val)}`);
      }
    };
    walk(cond);
    return acc;
  };

  const termsByLevel = () =>
    Object.fromEntries(
      AUDIT_DISPLAY_LEVELS.map((level) => [level, riskTerms(buildLevelCondition(level))])
    );

  it('派生形态可解析：每档都必须用已知形态点名至少一个 riskLevel', () => {
    for (const [level, acc] of Object.entries(termsByLevel())) {
      expect({ level, bad: acc.bad }).toEqual({ level, bad: [] });
      expect(acc.include.length + acc.exclude.length).toBeGreaterThan(0);
    }
  });

  it('点名的取值必须都是 AUDIT_RISK_LEVELS 的成员（抄错的名字永不命中）', () => {
    const named = new Set(
      Object.values(termsByLevel()).flatMap((acc) => [...acc.include, ...acc.exclude])
    );
    expect([...named].filter((v) => !AUDIT_RISK_LEVELS.includes(v))).toEqual([]);
    // 反空心：named 为空时上一条的 filter 也恒为空集，必须确认清单真的非空
    expect(named.size).toBeGreaterThan(0);
  });

  it('分档互斥：默认档的排除清单必须正好等于其余各档纳入清单的并集', () => {
    const accs = termsByLevel();
    const usingNin = AUDIT_DISPLAY_LEVELS.filter((l) => accs[l].exclude.length > 0);
    // 本判据的前提是"恰有一档用排除式（$nin）定义"。若实现改成别种组织方式，
    // 这里必须红并要求同步重写判据，而不是静默退化成恒真。
    expect(usingNin).toHaveLength(1);
    const ninLevel = usingNin[0];
    const others = AUDIT_DISPLAY_LEVELS.filter((l) => l !== ninLevel).flatMap(
      (l) => accs[l].include
    );
    expect([...new Set(accs[ninLevel].exclude)].sort()).toEqual([...new Set(others)].sort());
  });

  it('覆盖性：至多一档可以不被显式点名（由默认档兜住），新增档位必须显式归类', () => {
    const named = new Set(
      Object.values(termsByLevel()).flatMap((acc) => [...acc.include, ...acc.exclude])
    );
    const implicit = AUDIT_RISK_LEVELS.filter((l) => !named.has(l));
    // 当前只有 'low' 落在默认口径里。给常量加一档而不同步 buildLevelCondition，
    // implicit 就变成两个 ⇒ 新档与 low 同屏，"信息"筛选里混进一个从未归类过的等级。
    expect(implicit).toEqual(['low']);
  });
});

/**
 * 导出侧 success 的同类缺陷：`reportExportService.buildExportQuery('audit')`
 * 原来也是 `auditQuery.success = success === 'true' || success === true`。
 * 该文件当时是并行会话的在途（M 态）文件，故按本仓既有惯例
 * （initDataLifecycle / credentialRedactionSinks）先用 test.failing 记账；
 * 2026-09-19 落地后 `.failing` 已摘除，现在是常规回归门禁。
 * 两侧的逐值真值表另有 `zzqA_exportSuccessParity` 钉住（那份比的是行为相等，
 * 将来若把判据抽成一个公共函数，它仍然有效）。
 */
describe('导出侧 success 同口径（已修）', () => {
  test('success=1 在导出侧同样不得静默按 false 筛选', () => {
    expect(() => buildExportQuery('audit', { success: '1', dateFilter: {} })).toThrow(/success/);
  });
});
