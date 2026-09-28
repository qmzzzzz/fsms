/**
 * 共享校验规则构造器
 */

const { body } = require('express-validator');

/**
 * 字符串形状闸门：只在客户端显式提交了「非字符串」时拒绝该请求。
 *
 * 为什么需要它（实测结论，express-validator 7.3.2）：链上的校验器拿到的是
 * `String(value)` 之后的值，`{}` ⇒ `'[object Object]'`（16 字符）、`123` ⇒ `'123'`，
 * 于是 `.trim().isLength({ max: 100 })` 这类"看起来有约束"的链对对象全程放行。
 * 更糟的是 `.trim()` 这类 sanitizer 会把强转结果 `setData()` 写回 `req.body`，
 * 于是 `'[object Object]'` 原样落库——接口返回 200，脏数据永久留下。
 *
 * 两条 placement 约束：
 *   1. 必须声明在**带 sanitizer**（`.trim()` 等）的受保护链之前。同一字段的前序链
 *      跑完后 `req.body` 里已经是字符串，后置闸门只会看到 `'[object Object]'` 并放行（已实测）。
 *      边界要说清：只有 sanitizer 会 `setData()` 写回，纯 `.isLength()` / `.custom()` 链不写回，
 *      所以"后置"对那类链仍然有效（`images.*` 实测：闸门挪到长度链之后照样点名）。
 *      ⇒ 顺序不是正确性的来源，**有没有闸门才是**；前置只是不必逐链判断的稳妥写法。
 *   2. 不能改成"在原链里 `.trim()` 后面补一个 `.isString()`"——同理，
 *      那时值已被 sanitizer 转成字符串，永远校验通过。
 *
 * 为什么不就地改链（把 `.isString()` 插到 `.trim()` 前）：`.optional()` 的默认
 * 语义只跳过 `undefined`，链内的 `.isString()` 会把显式 `null` 判成类型错误。
 * "提交 `department: null` 清空部门"目前是合法写入（sanitizer 归一成 `''`），
 * 而存量文档里这些字段本就可能是 `null`，前端回填后原样 PUT 就会开始报 400。
 * 用独立闸门 ⇒ 既有链一字不改，`undefined`/`null`/`''` 的行为完全维持原状。
 *
 * @param {string} field 与受保护链同名的 body 字段路径（支持 `a.b`、`arr.*.b`）
 * @param {string} label 报错文案里的字段名，取该链既有 `.withMessage()` 用词
 * @returns {import('express-validator').ValidationChain}
 */
function mustBeString(field, label) {
  return body(field)
    .if((value) => value !== undefined && value !== null)
    .isString()
    .withMessage(`${label}必须为字符串`);
}

/** 地理坐标的取值域：纬度 ±90、经度 ±180（WGS84 定义级边界，不是策略阈值） */
const COORD_BOUNDS = { lat: 90, lng: 180 };

/**
 * 坐标取值判定。
 *
 * 用 `.custom()` 而不是 `.isFloat()`：① `.custom()` 拿到的是**原值**，
 * 而标准校验器拿到的是 `String(value)`（见 mustBeString 的文件头），
 * 对象/布尔会被强转成 `'20'`、`'[object Object]'` 这类可解析或不可解析的字符串，
 * 类型判断不可靠；② `isFloat` 不接受带符号的指数形式，`1e-7` 这种**合法**的
 * 近赤道/近本初子午线坐标会被误拒（JSON.stringify(0.0000001) 正是 `"1e-7"`）。
 * 这里按数字处理，天然覆盖该形态；同时接受数字字符串（与 Mongoose 的 cast 口径一致，
 * 不让任何今天能写进去的值因为本闸门而写不进去）。
 */
function inCoordinateRange(axis) {
  const bound = COORD_BOUNDS[axis];
  return (value) => {
    if (typeof value !== 'number' && typeof value !== 'string') return false;
    if (typeof value === 'string' && value.trim() === '') return false;
    const n = Number(value);
    return Number.isFinite(n) && n >= -bound && n <= bound;
  };
}

/**
 * `location.coordinates.{lat,lng}` 的形状与取值域（设备 create/update、报警 report 共用）
 *
 * 两个模型都定义了 `location.coordinates`（FireDevice.js:55、FireAlarm.js:47），
 * 类型是 `Number` 且**没有任何边界**；而三条路由的 location 链各自校验了
 * building/floor/room，一个字都没写 coordinates。后果分两格：
 *   · 非法类型（`lat: 'abc'`、`coordinates: 'abc'`）确实被拒，但拒它的是 Mongoose 的
 *     cast——cast 失败被收进 ValidationError，errorHandler 在非 development 下
 *     把 `fieldErrors` 整个抹掉（errorHandler.js:69-71），于是提交者只看到一句
 *     「校验失败」，点不出自己写错的是哪个字段；
 *   · `lat: 91` 这类**物理上不存在**的坐标原样落库，再被详情接口回吐给每个读者。
 * `.optional({ values: 'null' })`：存量文档里 lat/lng 可能是 null（Mongoose 允许），
 * 只跳过 undefined 会让前端"读出来再原样存回去"的编辑路径开始报 400。
 *
 * @param {string} prefix 父字段路径，本仓三处都是 `location`
 * @returns {Array<import('express-validator').ValidationChain>}
 */
function coordinatesRules(prefix) {
  return [
    body(`${prefix}.coordinates`)
      .optional({ values: 'null' })
      .isObject()
      .withMessage('坐标必须是对象'),
    body(`${prefix}.coordinates.lat`)
      .optional({ values: 'null' })
      .custom(inCoordinateRange('lat'))
      .withMessage('纬度必须是 -90 到 90 之间的数字'),
    body(`${prefix}.coordinates.lng`)
      .optional({ values: 'null' })
      .custom(inCoordinateRange('lng'))
      .withMessage('经度必须是 -180 到 180 之间的数字'),
  ];
}

/**
 * 校验错误的**出站形态**：只保留字段定位与文案，剔除原始输入。
 *
 * express-validator 的 `errors.array()` 默认 formatter 返回含 `value`（用户原始
 * 输入）的完整错误对象。本仓校验链大量覆盖口令字段（登录/注册/改密/MFA，
 * 如 authRoutes 的 passwordStrengthCheck、securityRoutes 的改密链），强度或必填
 * 校验失败时 `value` 就是**明文口令**——经 ApiResponse 进响应体后会被前端
 * errorReporter 采集上报、进代理访问日志与浏览器 DevTools，与 app.js
 * 「对 404 打码防上报采集」的纪律直接矛盾。
 *
 * 消费契约（2026-09-26 审计 Top1 整改）：仓内测试与前端只读 `path` / `msg`
 * （前端不消费 fieldErrors，见 web-admin 全量 grep）；保留 `location`/`type`
 * 供排查定位，`value` 一律不出站。所有 `fieldErrors: errors.array()` 调用点
 * 必须经本函数出站——新增校验消费点时同样走这里，不要直接 `.array()`。
 *
 * @param {import('express-validator').Result} result validationResult(req) 的结果
 * @returns {Array<{type: string, location: string, path: string, msg: string}>}
 */
function safeFieldErrors(result) {
  return result.array().map((e) => ({
    type: e.type,
    location: e.location,
    path: e.path,
    msg: e.msg,
  }));
}

module.exports = { mustBeString, coordinatesRules, safeFieldErrors };
