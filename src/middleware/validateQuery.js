/**
 * 校验结果消费中间件（P3-17）
 *
 * 问题：仓库里反复出现「路由挂了 express-validator 链，控制器却不读
 * validationResult」的组合——校验规则形同装饰，非法值继续流向查询条件。
 * 已实测的两例：securityController.getIPList（type 非法则静默全量返回）、
 * permissionController.batchCreatePermissions（max:500 与 `*:*` 拦截全部失效）。
 *
 * 逐个控制器补 `validationResult(req)` 只能治标：新增路由时同样会忘。
 * 因此提供一个可直接挂在校验链之后的中间件——校验声明与消费在同一处，
 * 路由读起来就是「校验 → 消费 → 控制器」，漏挂一眼可见。
 *
 * 与控制器内既有的 validationResult 消费并存：两者都通过时无额外开销
 * （validationResult 只是读 req 上已挂的结果数组）。
 */

const { validationResult } = require('express-validator');
const ApiResponse = require('../utils/apiResponse');

/**
 * 消费校验结果：有错即 400 返回，否则放行
 * @returns {import('express').RequestHandler}
 */
const consumeValidation = () => (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return ApiResponse.error(res, '数据验证失败', 400, errors.array());
  }
  return next();
};

module.exports = { consumeValidation };
