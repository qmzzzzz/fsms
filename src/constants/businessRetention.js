/**
 * 业务数据保留期声明（A2，2026-10-16）
 *
 * 缺口（deliverables/安全需求加固清单-2026-10-16.md A2）：需求「数据保护 → 全生命周期」
 * 六段里，**销毁段完全空白**——
 *   - 有保留期的：AuditLog / IPBlacklist / TokenBlacklist / UserSession（TTL 索引）；
 *   - 没有保留期的：User / FireDevice / FireAlarm / Inspection（`expireAfterSeconds` 零命中）。
 * 于是「业务数据留多久」这件事在代码里根本没有一处可查的声明。
 *
 * ⚠ 本模块**只声明、不启用**，这是刻意的：
 * 「报警/巡检记录留 N 年、设备台账随资产寿命」是**业务与合规口径**，不是技术参数。
 * 技术单方面定一个数字并建 TTL 索引，等于用一次 `npm start` 静默删掉业务方以为
 * 还在的历史台账（TTL 删除不可逆、且不会有任何提示）。故 `declaredDays` 全部为
 * `null`（= 未定），在业务方给出书面口径之前**不得**启用。
 *
 * 纪律与 constants/retention.js 同源（该文件头记录过一次「对外声明 N 天、实际只留更少」
 * 的事故）：解析必须严格（`Number` 而不是 `parseInt`）、空串归入「未配置」、
 * 生效值与原始值不等时 `wasAdjusted` 为 true 并由 compliance-check 告警。
 * 两套声明共用同一对合规区间常量（MIN/MAX 自 constants/retention.js 引入），
 * 不另抄一份——审计与业务数据的合规下限没有理由不同，且分叉会让"哪个区间才是真的"
 * 变成一道需要读两处才能回答的题。
 *
 * 启用流程（三步，缺一不可）：
 *   ① 业务方给出书面保留期口径（按集合）；
 *   ② 把该集合的 `declaredDays` 改为具体天数（本文件，随代码评审留痕）；
 *   ③ 在对应模型的 schema 上按 `resolveBusinessRetention(...).effectiveDays` 建 TTL 索引，
 *      并用 `assertBusinessRetentionEnforceable` 在**建索引前**判一次（fail-closed：
 *      口径没定就不许建，避免"忘了改 declaredDays 却建了索引"）。
 */

const { MIN_RETENTION_DAYS, MAX_RETENTION_DAYS } = require('./retention');

/** camelCase → SCREAMING_SNAKE（`FireAlarm` → `FIRE_ALARM`），用于拼环境变量名 */
const toScreamingSnake = (name) => name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();

/**
 * 受管业务集合的保留期声明（**单一声明**）。
 *
 * `declaredDays: null` = 业务口径未定 ⇒ 不得启用 TTL。
 * `basis` 记录的是"为什么这个集合需要保留期"，供业务方评审时对照（不是技术判断）。
 */
const BUSINESS_RETENTION_POLICY = Object.freeze(
  [
    [
      'FireAlarm',
      '消防报警记录是事故追溯与消防合规台账的一等证据，也是本系统唯一的"事件时间线"；' +
        '保留期由消防法规/行业台账要求决定，不由技术定。',
    ],
    ['Inspection', '巡检记录是履职证据（"什么时候谁查了哪里"），与报警记录同属合规台账。'],
    [
      'FireDevice',
      '设备台账随资产寿命：报废后仍需留存（报废原因/更换链），' +
        '故其保留期与"资产寿命 + 追责期"挂钩，通常显著长于事件类记录。',
    ],
    [
      'User',
      '用户账号本身不宜按天数自动删除（删掉会让审计链上的操作者变成悬空引用）；' +
        '本表列在这里是为了让"业务数据"清单完整——它的处置方式是**匿名化**' +
        '（见 services/userService.js 的 anonymizeById），不是 TTL。',
    ],
  ].map(([modelName, basis]) =>
    Object.freeze({
      modelName,
      envKey: `BUSINESS_RETENTION_DAYS_${toScreamingSnake(modelName)}`,
      declaredDays: null,
      basis,
    })
  )
);

/** 按模型名取声明（未登记即抛：静默返回 undefined 会让调用方拿着空对象继续走） */
const getBusinessRetentionPolicy = (modelName) => {
  const policy = BUSINESS_RETENTION_POLICY.find((p) => p.modelName === modelName);
  if (!policy) {
    throw new Error(
      `未登记保留期策略的集合：${modelName}。` +
        '新增业务集合时必须先在 constants/businessRetention.js 登记（否则"要不要留、留多久"永远没人问）'
    );
  }
  return policy;
};

/**
 * 解析某集合的保留期生效值。
 *
 * 与 constants/retention.js 逐条同口径：
 *   - 解析用 `Number` 而不是 `parseInt`（`90x`/`1e3` 这类写法不会被静默吃掉尾部）；
 *   - 空串（`.env` 里删掉值就是这个）显式归入"未配置"，不落到 0；
 *   - 生效值钳制到 [MIN, MAX]，原始值与生效值不等 ⇒ `wasAdjusted`。
 *
 * @param {string} modelName 模型名（如 'FireAlarm'）
 * @returns {{modelName: string, envKey: string, declaredDays: number|null,
 *   rawDays: number, isConfigured: boolean, effectiveDays: number|null,
 *   enabled: boolean, wasAdjusted: boolean}}
 */
const resolveBusinessRetention = (modelName) => {
  const policy = getBusinessRetentionPolicy(modelName);
  const rawEnv = process.env[policy.envKey];
  const rawDays = typeof rawEnv === 'string' && rawEnv.trim() === '' ? NaN : Number(rawEnv);
  const isConfigured = Number.isFinite(rawDays);
  const effectiveDays = isConfigured
    ? Math.min(Math.max(rawDays, MIN_RETENTION_DAYS), MAX_RETENTION_DAYS)
    : null;
  return {
    modelName,
    envKey: policy.envKey,
    declaredDays: policy.declaredDays,
    rawDays,
    isConfigured,
    effectiveDays,
    // enabled 的判据是"有生效值"，而不是"声明了"——声明只是评审留痕，
    // 真正的开关是环境变量，这样"改口径"与"改部署"各走各的通道，可分别回退。
    enabled: effectiveDays !== null,
    wasAdjusted: isConfigured ? rawDays !== effectiveDays : rawEnv !== undefined,
  };
};

/**
 * 建 TTL 索引前的 fail-closed 判据。
 *
 * 为什么要有它：将来某人给 FireAlarm 加 TTL 索引时，最容易发生的不是"算错天数"，
 * 而是**跳过业务口径直接写一个数字**。此函数把"口径没定"从"没人记得"变成"当场抛错"。
 *
 * @param {string} modelName 模型名
 * @returns {number} 生效保留天数
 * @throws {Error} 未配置保留期时抛出
 */
const assertBusinessRetentionEnforceable = (modelName) => {
  const r = resolveBusinessRetention(modelName);
  if (!r.enabled) {
    throw new Error(
      `拒绝为 ${modelName} 建保留期（TTL）索引：${r.envKey} 未配置。` +
        '业务数据保留期属业务/合规口径，须先由业务方给出书面天数并写入 ' +
        'constants/businessRetention.js 的 declaredDays，再设置环境变量。' +
        '（TTL 删除不可逆且无提示，技术单方面定数字等于静默销毁业务台账。）'
    );
  }
  return r.effectiveDays;
};

/** 单个集合的可读说明（供启动日志 / 合规检查） */
const describeBusinessRetention = (modelName) => {
  const r = resolveBusinessRetention(modelName);
  const declared = r.declaredDays === null ? '未声明（待业务口径）' : `${r.declaredDays} 天`;
  if (!r.enabled) {
    // 三种"没启用"必须分开说：环境变量没配（或配了空值）/ 配了但解析不出数字。
    // 混成一句"未配置"会让运维把"我明明写了 90x"读成"我没写过"——
    // 而 `90x` 恰恰是 parseInt 会静默吃掉尾部、只有严格 Number 才拦得住的形态。
    const rawEnv = process.env[r.envKey];
    const reason =
      rawEnv === undefined || rawEnv.trim() === ''
        ? `${r.envKey} 未配置`
        : `${r.envKey}=${JSON.stringify(rawEnv)} 无法解析为数值（已忽略，不启用 TTL）`;
    return `${modelName}：未启用（声明值 ${declared}，${reason}）` + '——当前无 TTL，数据永久保留';
  }
  if (r.wasAdjusted) {
    return (
      `${modelName}：${r.envKey}=${r.rawDays} 超出允许区间 ` +
      `[${MIN_RETENTION_DAYS}, ${MAX_RETENTION_DAYS}]，实际生效 ${r.effectiveDays} 天`
    );
  }
  return `${modelName}：${r.envKey}=${r.effectiveDays} 天（在允许区间内，原样生效）`;
};

/** 全集合说明（多行），供合规检查一次性列出 */
const describeAllBusinessRetention = () =>
  BUSINESS_RETENTION_POLICY.map((p) => describeBusinessRetention(p.modelName));

module.exports = {
  BUSINESS_RETENTION_POLICY,
  getBusinessRetentionPolicy,
  resolveBusinessRetention,
  assertBusinessRetentionEnforceable,
  describeBusinessRetention,
  describeAllBusinessRetention,
};
