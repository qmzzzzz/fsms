/**
 * 认证控制器共享兜底：未知 outcome 的 fail-closed 处理
 * （2026-10-19 自 `controllers/authController.js` 原样迁出，供 credentials / profile 两段共用）
 */

const logger = require('../../utils/logger');
const ApiResponse = require('../../utils/apiResponse');

/**
 * fail-closed：控制器 switch 未覆盖的 outcome 一律按「服务端契约违背」处理，
 * 绝不落到成功分支。
 *
 * 依据 `deliverables/AGENT工作总账与待办-2026-09-21.md` §14.6 全仓 outcome switch 普查（2026-09-20 全仓普查）：authController 5 处 outcome switch
 * 此前都用 `default: break;` 直落成功分支。它们今天**已穷举** authService 的
 * outcome 集合（5/5、7/7、12/12、9/9、6/6），故本分支当前不可达——它守的是
 * 「将来新增 outcome 而此处忘映射」这种情况。同类缺陷在 authController 已真实发生过一次：
 * 见 changePassword 的 CONFIRM_MISMATCH 注释（缺该 case 时曾把「口令没改」
 * 回成「密码修改成功」）。
 */
const rejectUnknownOutcome = (res, scope, outcome) => {
  logger.error(`[${scope}] 返回未知 outcome，已按失败处理`, { outcome });
  return ApiResponse.codeError(res, 'INTERNAL_ERROR');
};

module.exports = { rejectUnknownOutcome };
