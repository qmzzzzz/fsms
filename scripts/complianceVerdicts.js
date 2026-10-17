#!/usr/bin/env node
/**
 * 合规检查器的**判据**（纯函数，无 recordCheck 依赖）—— A2 / A8，2026-10-16
 *
 * 为什么单独成文件：
 *   ① `scripts/compliance-check.js` 触到 `max-lines` 体积棘轮预算（300 行代码，
 *      eslint.config.js 里 skipBlankLines + skipComments 都开着，所以只有代码行算数）。
 *      把"怎么判"搬出来、"登记到哪"留下，正好把预算还给门禁本体。
 *   ② 而 `check*` 函数的**声明**必须留在 compliance-check.js：`complianceGate.test.js`
 *      的 C 用例按源码视图对账「登记表 = 源码里声明的全部 check* 函数」，
 *      搬走声明会让那条对账失去意义。
 *   ③ 判据与副作用分离本就是本仓对门禁的一贯要求（见 scripts/backupIntegrityPolicy.js
 *      文件头的同一段论证）：判据要能被用例直接驱动，而不是"跑一次脚本看输出"。
 *
 * 两个判据的**共同纪律**（写在这里一次，两处都适用）：
 *   - 通过条件只有"配置意图与实际生效一致"这一条；
 *   - **未启用/未声明不算不合规**——业务口径未定时不建 TTL、不承诺 RPO 是**正确**行为
 *     （技术单方面定数字等于静默销毁业务台账 / 把没人评估过的 SLA 印进测评材料），
 *     但"未启用"必须被**显式说出来**，不能让这条以一句"就绪"盖过去；
 *   - 一旦有人配了环境变量却被钳制/非法，立刻转红（那正是配置意图与实际不符）。
 */

/**
 * 业务数据保留期（A2）：User / FireDevice / FireAlarm / Inspection 是否声明并启用了
 * 保留期，以及"对外声明留 N 天、实际只留更少/更多"这类静默修正。
 *
 * 【F-07 修正（2026-10-17）】原判据是 `passed: adjusted.length === 0`——只要没有
 * "被钳制或非法调整"，**未启用本身不会让 allPassed 变 false**。于是
 * 「业务数据永久保留」与「保留策略已执行」在自动化消费方眼里是同一个结论，
 * 而 compliance-check 的 allPassed 正是发布流程读的那个字段。
 *
 * 现在的判据分两档，都要成立：
 *   ① 每个集合都已声明（declaredDays 非 null）且已启用（环境变量给了生效值）；
 *   ② 没有集合出现"配置意图与生效值不一致"（被钳制 / 超范围 / 超过声明天数）。
 * 未启用时 passed=false，detail 明确写"未启用 ⇒ 数据永久保留"，不再用"就绪"盖过去。
 *
 * @returns {{name: string, passed: boolean, detail: string}}
 */
function businessRetentionVerdict() {
  const {
    BUSINESS_RETENTION_POLICY,
    resolveBusinessRetention,
    describeAllBusinessRetention,
  } = require('../src/constants/businessRetention');

  const all = BUSINESS_RETENTION_POLICY.map((p) => resolveBusinessRetention(p.modelName));
  const enabled = all.filter((r) => r.enabled);
  const adjusted = all.filter((r) => r.wasAdjusted);
  const undeclared = all.filter((r) => r.declaredDays === null);
  const notEnabled = all.filter((r) => !r.enabled);
  // 声明是对外口径，实际保留不得长于它（长于声明 = "我们只留 180 天"在数据面上不成立）
  const longerThanDeclared = all.filter(
    (r) => r.enabled && r.declaredDays !== null && r.effectiveDays > r.declaredDays
  );

  const problems = [];
  if (undeclared.length > 0) {
    problems.push(
      `未声明口径：${undeclared.map((r) => r.modelName).join('/')}（declaredDays=null）`
    );
  }
  if (adjusted.length > 0) {
    problems.push(
      `配置意图与生效值不一致（被钳制或非法）：${adjusted
        .map((r) => `${r.modelName}(${r.rawDays}→${r.effectiveDays})`)
        .join('/')}`
    );
  }
  if (longerThanDeclared.length > 0) {
    problems.push(
      `生效值超过业务声明：${longerThanDeclared
        .map((r) => `${r.modelName}(${r.effectiveDays}>${r.declaredDays})`)
        .join('/')}`
    );
  }

  // passed 回答「代码/配置有没有自相矛盾」；notReady 回答「治理能力有没有真的开起来」。
  // 两者刻意分开：仓库态（CI）没有生产库，也没有生产环境的保留期开关——在那里把
  // 「未启用」判成红，门禁会永远红，红的原因却与代码无关，最后必然被人绕过。
  // 而部署门禁（COMPLIANCE_STRICT=1）读 notReady，未启用即阻断。
  const detail =
    problems.length === 0
      ? notEnabled.length === 0
        ? describeAllBusinessRetention().join('；')
        : `**未启用**（${notEnabled.map((r) => r.modelName).join('/')} 无 TTL，数据永久保留）：` +
          describeAllBusinessRetention().join('；')
      : `${problems.join('；')}。已启用 ${enabled.length}/${all.length} 个集合；` +
        '业务口径与处置方式见 src/constants/businessRetention.js';

  return {
    name: '业务数据保留期',
    passed: problems.length === 0,
    detail,
    notReady: problems.length > 0 || notEnabled.length > 0,
  };
}

/**
 * 备份 / 恢复目标（A8）：RPO / RTO 是否声明，以及声明值是否**优于备份频率下限**
 * （备份每天一次却声明 RPO=1h，是不可能兑现的承诺——比配置错误更严重，
 * 因为它在事故复盘时才会暴露，而那时已经有人按那个数字做过决策）。
 *
 * @returns {{name: string, passed: boolean, detail: string}}
 */
function backupObjectiveVerdict() {
  const {
    resolveBackupObjective,
    evaluateRpoAlignment,
    describeAllBackupObjectives,
    BACKUP_SCHEDULE,
  } = require('../src/constants/backupObjectives');

  const rpo = resolveBackupObjective('rpo');
  const rto = resolveBackupObjective('rto');
  const alignment = evaluateRpoAlignment({
    declaredRpoHours: rpo.set ? rpo.effectiveHours : null,
    intervalHours: BACKUP_SCHEDULE.intervalHours,
  });

  const unset = [rpo, rto].filter((o) => !o.set);
  const adjusted = [rpo, rto].filter((o) => o.wasAdjusted);
  const described = describeAllBackupObjectives().join('；');

  const detail =
    unset.length > 0
      ? `${described}；备份频率为每 ${BACKUP_SCHEDULE.intervalHours}h 一次` +
        `（${BACKUP_SCHEDULE.cron}，${BACKUP_SCHEDULE.source}）` +
        '⇒ 当前可兑现的 RPO 下限即该间隔；口径待业务方确认，' +
        '见 src/constants/backupObjectives.js 与 deployment/rollback-drill.md 第 5 节'
      : `${described}；${alignment.message}`;

  return {
    name: '备份/恢复目标（RPO/RTO）',
    passed: alignment.ok && adjusted.length === 0,
    detail,
    // 未声明 RPO/RTO 属于「治理能力未就绪」，不是「代码不合规」——同业务保留期的两档语义
    notReady: unset.length > 0 || !alignment.ok || adjusted.length > 0,
  };
}

module.exports = { businessRetentionVerdict, backupObjectiveVerdict };
