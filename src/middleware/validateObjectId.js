/**
 * ObjectId 参数校验中间件
 *
 * 用途（低危-:id 参数统一 isMongoId 校验）：
 * 路由 :id 参数若非法，Mongoose 查询会抛 CastError 被全局错误处理兜成 500，
 * 既暴露内部信息又污染审计/告警。本中间件在参数解析阶段统一拦截，返回 400 明确提示。
 *
 * 【P2-25 关键修正】原用法 `app.param('id', handler)` 是死代码。
 * Express 4 的参数回调只对**定义它的那个 router 自身**的路由生效，不会向
 * 子 Router 传播；而本项目全部业务路由都挂在 express.Router() 子路由上
 * （app.use('/api/users', userRoutes)），因此该校验一次都不会执行。
 * 实测（express 4.22.2）：
 *   子 Router 路由触发 app.param 次数 = 0
 *   app 直挂路由触发 app.param 次数 = 1
 *   子 Router 自注册 param 触发次数 = 1
 * 修复方式是逐个子 Router 注册（applyObjectIdParams），而非依赖 app 级注册。
 *
 * 注意：仅适用于该参数恒为 ObjectId 的资源路由（users/roles/permissions/
 * devices/alarms/inspections/security 等）。本项目所有 :id 路由均符合该约定。
 */

const mongoose = require('mongoose');
const ApiResponse = require('../utils/apiResponse');

/** 需要统一校验的路径参数名（securityRoutes 使用 :userId） */
const OBJECT_ID_PARAMS = ['id', 'userId'];

/**
 * Express param handler：签名 (req, res, next, value, name)
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 * @param {string} value 参数值
 * @param {string} name 参数名（通常为 'id'）
 */
const validateObjectIdParam = (req, res, next, value, name) => {
  // mongoose.Types.ObjectId.isValid 对 24 位 hex 与 12 字节字符串均判合法，
  // 这里用于拦截明显非法值（短串/含特殊字符），避免 CastError→500
  if (!mongoose.Types.ObjectId.isValid(value)) {
    return ApiResponse.codeError(res, 'PARAM_MUST_BE_VALID_OBJECT_ID', { message: `参数 ${name || 'id'} 必须是合法的对象 ID`, params: { name: name || 'id' } });
  }
  next();
};

/**
 * 为一组子 Router 批量注册 ObjectId 参数校验（P2-25）
 *
 * 必须在各 Router 内部注册才会生效。逐条 param() 而非依赖 app.param()，
 * 使校验成为「路由挂载即生效」的默认行为——新增资源路由时无需记得手写
 * param('id').isMongoId()，漏写也不会退化成 CastError→500。
 *
 * 与路由内既有的 express-validator `param('id').isMongoId()` 并存：
 * 后者提供统一的业务错误文案（"无效的设备ID"），本层是兜底防线，
 * 覆盖忘记挂校验链的路由。两者都通过时无额外开销（纯正则判断）。
 *
 * 幂等：createApp() 在测试中会被多次调用，而 Router 是 require 缓存的**同一个**
 * 实例；router.param() 每次调用都会追加一个回调，重复注册会让同一参数被校验
 * N 次（N = createApp 调用次数）。用 WeakSet 记录已注册的 Router，只注册一次。
 *
 * @param {...import('express').Router} routers 需要注册的子路由
 */
const registered = new WeakSet();

const applyObjectIdParams = (...routers) => {
  for (const router of routers) {
    if (!router || typeof router.param !== 'function') continue;
    if (registered.has(router)) continue;
    registered.add(router);
    for (const name of OBJECT_ID_PARAMS) {
      router.param(name, validateObjectIdParam);
    }
  }
};

module.exports = { validateObjectIdParam, applyObjectIdParams, OBJECT_ID_PARAMS };
