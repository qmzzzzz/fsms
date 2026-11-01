'use strict';

/** 临时权限授予（C-08）与特权操作双人复核（C-09）的取值与阈值 —— 单一事实来源。状态机单向：pending → active | rejected；active → revoked | expired；到期判定只认 expiresAt（读侧过滤），定时任务停摆时授权不会因此延长。 */

const PRIVILEGE_GRANT_STATUSES = ['pending', 'active', 'rejected', 'revoked', 'expired'];

const MIN_GRANT_HOURS = 1;
const MAX_GRANT_HOURS = 168; // 单次授予有效期上限（小时）= 7 天：超上限按上限裁剪，不报错也不静默放行

const MAX_GRANT_CODES = 20; // 单次授予条数上限：授予是例外通道，不是批量授权入口

/** 高敏模块前缀：命中即需双人复核（两人不得同为申请人，且互不相同）。`pii` 于 2026-10-31（审计二-1）移入：通配 `pii:*` 覆盖 `pii:export`（未脱敏 PII 导出），按低敏走即单人签批、与 `system:read` 双人口径不自洽；
 * 粒度是**模块**：不为单条码开动作级例外，例外一开口，下一个 `pii:*` 动作码自动落回单人档。 */
const HIGH_RISK_MODULES = ['user', 'role', 'permission', 'security', 'system', 'privilege', 'pii'];

// 目录（services/initData）登记过的模块前缀 = 高敏 ∪ 低敏业务模块；A2 起高敏判定 fail-closed：模块取不到（`*:*` 的 `*`、空模块）或不在本清单（管理员自建模块）一律按高敏，不得降级成单人签批。
const KNOWN_MODULES = [...HIGH_RISK_MODULES, 'device', 'alarm', 'inspection', 'report']; // 新增模块须同批登记到本清单（privilegeGrantFlow 的目录对账用例会红）

const REQUIRED_APPROVALS_HIGH_RISK = 2;
const REQUIRED_APPROVALS_NORMAL = 1;

const GRANT_LIST_FIELDS = [
  '_id',
  'userId',
  'username',
  'permissionCodes',
  'reason',
  'requestedBy',
  'requestedByName',
  'requestedAt',
  'approvals',
  'requiredApprovals',
  'highRisk',
  'durationHours',
  'status',
  'grantedAt',
  'expiresAt',
  'decisionReason',
  'revokeReason',
  'revokedAt',
  'revokedByName',
]; // 列表/复核清单对外字段白名单：.select() 显式投影，模型加字段不会自动下发，要下发必须改这一行并同步契约用例；decidedByName/decidedAt/expiredAt 不进白名单（lead 裁决）：前端对三键零命中，时间线读的是 requestedAt/approvals[].at/grantedAt/revokedAt/expiresAt，「谁在何时决定」由 approvals[] 承载，真需要展示时必须同步加契约用例

/** 定期复核：生效超过该天数仍未复核 ⇒ 计入超期（季度口径） */
const REVIEW_OVERDUE_DAYS = 90;

const EXPIRING_SOON_HOURS = 24; // 即将到期告警窗口（小时）

const moduleOf = (code) => String(code || '').split(':')[0];

const isHighRiskCode = (code) => {
  const mod = moduleOf(code); // 空模块与 `*:*` 的 `*` 都到不了任何已知模块 ⇒ 落到右侧按高敏
  return HIGH_RISK_MODULES.includes(mod) || !KNOWN_MODULES.includes(mod);
};

/** 按拟授予的权限码推导复核要求：判据只看模块前缀，不看角色层级（授予面本身会不会碰到管理面）；未登记模块一律按高敏，绝不因取不到模块而降级成单人签批。 */
const approvalPolicyOf = (codes) => {
  const highRisk = (Array.isArray(codes) ? codes : []).some(isHighRiskCode);
  return {
    highRisk,
    requiredApprovals: highRisk ? REQUIRED_APPROVALS_HIGH_RISK : REQUIRED_APPROVALS_NORMAL,
  };
};

module.exports = {
  PRIVILEGE_GRANT_STATUSES,
  MIN_GRANT_HOURS,
  MAX_GRANT_HOURS,
  MAX_GRANT_CODES,
  HIGH_RISK_MODULES,
  KNOWN_MODULES,
  REQUIRED_APPROVALS_HIGH_RISK,
  REQUIRED_APPROVALS_NORMAL,
  GRANT_LIST_FIELDS,
  REVIEW_OVERDUE_DAYS,
  EXPIRING_SOON_HOURS,
  isHighRiskCode,
  approvalPolicyOf,
};
