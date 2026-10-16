/**
 * 备份 / 恢复目标（RPO / RTO）声明（A8，2026-10-16）
 *
 * 缺口（deliverables/安全需求加固清单-2026-10-16.md A8）：备份与恢复这条链上
 * 「多久备份一次」是写死的（cron），但「**允许丢多久数据**（RPO）」和
 * 「**多久必须恢复**（RTO）」在仓库里没有任何一处声明。于是：
 *   - 没人能从代码回答"我们的 RPO 是多少"；
 *   - 备份频率一旦被人改（比如从每日改成每周），没有任何东西会因此变红——
 *     而 RPO 承诺已经悄悄从 24h 退化成 168h；
 *   - 恢复演练记录里只有"耗时"这一个数字，没有可对照的目标值，于是"快不快"全凭感觉。
 *
 * ⚠ 本模块**只声明、不启用**，与 constants/businessRetention.js 同一纪律：
 * 「允许丢多久数据、多久必须恢复」是**业务与合规口径**（等保/消防行业有各自的
 * 可用性要求），不是技术参数。技术单方面写一个数字并对外当承诺，等于把
 * 一个没人评估过的 SLA 印进测评材料。故 `declaredHours` 全部为 `null`（= 未定），
 * 由环境变量在部署侧给值，业务方给出书面口径后才写进 `declaredHours`。
 *
 * 但**技术事实**可以先钉住，而且必须钉住——否则"对齐"这句话没有落点：
 * 备份频率是每日全量（`deployment/backup-encryption.md:40` 的 `0 2 * * *`，
 * 外加每次发布前由 `scripts/deploy.js` 触发一次），所以
 * **RPO 的技术下限就是 24 小时**：02:00 备份完成后立刻故障，最坏丢失一整天写入。
 * 声明一个**优于** 24h 的 RPO（例如 1 小时）在现有备份频率下是不可能兑现的承诺——
 * `evaluateRpoAlignment` 就是用来当场拦住这种"口头 SLA"的。
 *
 * 纪律与 constants/retention.js 同源：解析用 `Number` 而非 `parseInt`、
 * 空串归入"未配置"、生效值与原始值不等时 `wasAdjusted` 为 true（由 compliance-check 告警）。
 */

/** 目标值的合法区间（小时）。下限 1h：比 1 小时还短的恢复目标不是靠备份实现的。 */
const MIN_OBJECTIVE_HOURS = 1;
/** 上限 720h（30 天）：超过它已经不叫"恢复目标"，而叫"永远不恢复"。 */
const MAX_OBJECTIVE_HOURS = 720;

/**
 * 备份频率（**技术事实**，不是目标值）。
 *
 * 来源是文档里那条 cron，不是本文件发明的：
 *   - `deployment/backup-encryption.md:39-43`：`deploy.js` 每次发布前自动备份；
 *     `0 2 * * *` cron 每日全量。
 *   - `deployment/rollback-drill.md:17`：「发布前必须先备份」是铁律。
 * 改这条 cron 的人必须同时改这里——`evaluateRpoAlignment` 与巡检脚本都读它，
 * 于是"备份频率与 RPO 承诺是否还对齐"变成一次可执行的判定，而不是一句口号。
 */
const BACKUP_SCHEDULE = Object.freeze({
  cron: '0 2 * * *',
  /** 最坏情况下的备份间隔：两次定时备份之间的最大时长 */
  intervalHours: 24,
  /** 除定时之外，发布前还会额外备份一次（缩短实际间隔，但不改变最坏情况上界） */
  alsoOnDeploy: true,
  source: 'deployment/backup-encryption.md:39-43',
});

/**
 * 受管的恢复目标声明（**单一声明**）。
 *
 * `declaredHours: null` = 业务口径未定 ⇒ 不得对外承诺。
 * `basis` 记录"这个目标为什么由业务定"，供业务方评审时对照（不是技术判断）。
 */
const BACKUP_OBJECTIVES = Object.freeze(
  [
    [
      'rpo',
      'BACKUP_RPO_HOURS',
      'RPO（Recovery Point Objective）：故障发生时**允许丢失多长时间内的数据**。' +
        '它决定备份频率，取决于业务能承受丢掉多少条报警/巡检记录——是业务口径，不是技术参数。',
    ],
    [
      'rto',
      'BACKUP_RTO_HOURS',
      'RTO（Recovery Time Objective）：从故障发生到**系统恢复可用**允许花多长时间。' +
        '它决定演练合格线，取决于消防监管对系统中断的容忍度（等保/行业要求），是合规口径。',
    ],
  ].map(([key, envKey, basis]) =>
    Object.freeze({
      key,
      envKey,
      declaredHours: null,
      basis,
    })
  )
);

/** 按 key 取声明（未登记即抛：静默返回 undefined 会让调用方拿着空对象继续走） */
const getBackupObjective = (key) => {
  const objective = BACKUP_OBJECTIVES.find((o) => o.key === key);
  if (!objective) {
    throw new Error(
      `未登记的备份目标：${key}。新增目标（如 MTTR）时必须先在 constants/backupObjectives.js 登记`
    );
  }
  return objective;
};

/**
 * 解析某个恢复目标的生效值。
 *
 * 与 constants/retention.js 逐条同口径：
 *   - 解析用 `Number` 而不是 `parseInt`（`24x`/`1e3` 这类写法不会被静默吃掉尾部）；
 *   - 空串（`.env` 里删掉值就是这个）显式归入"未配置"，不落到 0；
 *   - 生效值钳制到 [MIN, MAX]，原始值与生效值不等 ⇒ `wasAdjusted`。
 *
 * @param {'rpo'|'rto'} key
 * @returns {{key: string, envKey: string, declaredHours: number|null,
 *   rawHours: number, isConfigured: boolean, effectiveHours: number|null,
 *   set: boolean, wasAdjusted: boolean}}
 */
const resolveBackupObjective = (key) => {
  const objective = getBackupObjective(key);
  const rawEnv = process.env[objective.envKey];
  const rawHours = typeof rawEnv === 'string' && rawEnv.trim() === '' ? NaN : Number(rawEnv);
  const isConfigured = Number.isFinite(rawHours);
  const effectiveHours = isConfigured
    ? Math.min(Math.max(rawHours, MIN_OBJECTIVE_HOURS), MAX_OBJECTIVE_HOURS)
    : null;
  return {
    key,
    envKey: objective.envKey,
    declaredHours: objective.declaredHours,
    rawHours,
    isConfigured,
    effectiveHours,
    // set 的判据是"有生效值"，而不是"声明了"——声明只是评审留痕，
    // 真正的开关是环境变量，这样"改口径"与"改部署"各走各的通道，可分别回退。
    set: effectiveHours !== null,
    wasAdjusted: isConfigured ? rawHours !== effectiveHours : rawEnv !== undefined,
  };
};

/**
 * RPO 与备份频率的对齐判定（A8 动作 2 的核心）。
 *
 * 判据只有一条：**声明的 RPO 不得优于备份频率允许的下限**。
 * 备份每 24h 一次 ⇒ 最坏情况必丢 24h ⇒ 声明 RPO < 24h 是一个不可能兑现的承诺。
 * 这不是"配置错误"，而是"对外承诺与内部能力不符"——比配置错误更严重，
 * 因为它在事故复盘时才会暴露，且暴露时已经有人按那个数字做过决策。
 *
 * @param {{declaredRpoHours: number|null, intervalHours?: number}} input
 * @returns {{ok: boolean, code: string|null, message: string, floorHours: number}}
 */
const evaluateRpoAlignment = ({ declaredRpoHours = null, intervalHours = null } = {}) => {
  const floorHours = Number.isFinite(intervalHours) ? intervalHours : BACKUP_SCHEDULE.intervalHours;

  if (declaredRpoHours === null) {
    return {
      ok: true,
      code: null,
      floorHours,
      message:
        `RPO 未声明（待业务口径）。备份频率为每 ${floorHours}h 一次（${BACKUP_SCHEDULE.cron}），` +
        '故当前可兑现的 RPO 下限即该间隔。',
    };
  }

  if (declaredRpoHours < floorHours) {
    return {
      ok: false,
      code: 'rpo_better_than_frequency',
      floorHours,
      message:
        `声明的 RPO ${declaredRpoHours}h **优于**备份频率下限 ${floorHours}h` +
        `（${BACKUP_SCHEDULE.source}）：现有备份频率不可能兑现该承诺，` +
        '要么加密备份频率，要么改口径——不能只改文档。',
    };
  }

  return {
    ok: true,
    code: null,
    floorHours,
    message: `声明的 RPO ${declaredRpoHours}h 不优于备份频率下限 ${floorHours}h，可兑现。`,
  };
};

/**
 * 对外的可读说明（供启动日志 / 合规检查 / 巡检报告）。
 * 三种"没设值"必须分开说：没配（或配了空值）/ 配了但解析不出数字 / 配了但被钳制。
 */
const describeBackupObjective = (key) => {
  const o = resolveBackupObjective(key);
  const declared = o.declaredHours === null ? '未声明（待业务口径）' : `${o.declaredHours} 小时`;
  const label = key.toUpperCase();

  if (!o.set) {
    const rawEnv = process.env[o.envKey];
    const reason =
      rawEnv === undefined || rawEnv.trim() === ''
        ? `${o.envKey} 未配置`
        : `${o.envKey}=${JSON.stringify(rawEnv)} 无法解析为数值（已忽略）`;
    return `${label}：未设定（声明值 ${declared}，${reason}）`;
  }
  if (o.wasAdjusted) {
    return (
      `${label}：${o.envKey}=${o.rawHours} 超出允许区间 ` +
      `[${MIN_OBJECTIVE_HOURS}, ${MAX_OBJECTIVE_HOURS}]，实际生效 ${o.effectiveHours} 小时`
    );
  }
  return `${label}：${o.envKey}=${o.effectiveHours} 小时（在允许区间内，原样生效）`;
};

/** 全目标说明（多行），供合规检查一次性列出 */
const describeAllBackupObjectives = () =>
  BACKUP_OBJECTIVES.map((o) => describeBackupObjective(o.key));

module.exports = {
  MIN_OBJECTIVE_HOURS,
  MAX_OBJECTIVE_HOURS,
  BACKUP_SCHEDULE,
  BACKUP_OBJECTIVES,
  getBackupObjective,
  resolveBackupObjective,
  evaluateRpoAlignment,
  describeBackupObjective,
  describeAllBackupObjectives,
};
