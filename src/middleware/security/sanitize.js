/**
 * MongoDB 注入防护与 req.query 物化（自 `middleware/security.js` 拆出，2026-10-18）
 *
 * 内容：sanitizeMongo（NoSQL 操作符/原型污染键清理）与 materializeQuery
 * （query 只读物化——写 req.query 在 Express 5 会抛错，此处逐层拷贝成普通对象）。
 * 对外导出面由 security/index.js 原样再导出。
 */

const logger = require('../../utils/logger');
const ApiResponse = require('../../utils/apiResponse');

/**
 * 2. 数据清理 - MongoDB 注入防护
 * 清理请求中的 MongoDB 操作符，防止 NoSQL 注入
 *
 * ⚠ Express 5 前提（修正，2026-09-17；2026-09-30 收口）：req.query 是 getter
 * （node_modules/express/lib/request.js 的 defineGetter(req, 'query', ...)），
 * 每次访问都重新解析 URL 查询串。因此本中间件对 req.query 的**原地赋值无效**，
 * 且实测比"下次访问才丢"更彻底——同一 handler 同一 tick 内回读就已经是全新对象。
 *
 * 2026-09-30 起 query 侧改由 materializeQuery 收口：读一次 → 清洗 → 物化成自有
 * 数据属性 → **回读自证身份**。本中间件不再遍历 req.query（写了也是空操作，
 * 留着只会让人误以为 query 有两道防线）。
 *
 * req.body 与 req.params 是普通自有属性，原地清洗对它们确实生效。
 *
 * 注意：本中间件的单测用**手搓的 req 桩对象**，而桩上的 query 是普通属性——
 * 所以那组单测**结构上不可能**发现上面这条 Express 5 前提。
 * 「物化真的生效」由 src/tests/app/queryDefenseSingleSource.test.js 在**真实
 * express 实例**上钉住（真实 getter + 真实 supertest），不接受桩。
 */
// 递归深度上限：1mb 请求体可构造数千层嵌套，无上限的同步递归会被极端载荷
// 打爆调用栈（RangeError→500 资源骚扰）；超限分支直接整体丢弃该子树
const SANITIZE_MAX_DEPTH = 10;

// 除 `$` 前缀与 `.` 之外还要剔除的原型链入口：JSON.parse 可产生同名自有属性，
// 当前下游虽无对象合并消费点，显式剔除不依赖隐式前提
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** 该键是否必须删除（MongoDB 操作符/嵌套语法，或原型链入口） */
const isForbiddenKey = (key) => key.startsWith('$') || key.includes('.') || FORBIDDEN_KEYS.has(key);

/** 数组分支：逐元素递归；超深则整体丢弃该子树 */
const sanitizeArray = (obj, depth) => {
  if (depth >= SANITIZE_MAX_DEPTH) {
    obj.length = 0;
    return;
  }
  obj.forEach((item) => deepSanitizeKeys(item, depth + 1));
};

/** 普通对象分支：按键删除或递归；超深则整体丢弃该子树 */
const sanitizePlainObject = (obj, depth) => {
  if (depth >= SANITIZE_MAX_DEPTH) {
    for (const k of Object.keys(obj)) delete obj[k];
    return;
  }
  for (const key of Object.keys(obj)) {
    if (isForbiddenKey(key)) {
      logger.warn(`MongoDB 注入尝试被拦截：键 "${key}"`);
      delete obj[key];
    } else {
      deepSanitizeKeys(obj[key], depth + 1);
    }
  }
};

const deepSanitizeKeys = (obj, depth = 0) => {
  if (!obj || typeof obj !== 'object') return;
  // 数组需逐元素递归清洗：数组本身不携带 $ 键，但其元素对象可能携带，
  // 直接跳过数组会让数组内对象的 $ 操作符成为漏网之鱼
  if (Array.isArray(obj)) {
    sanitizeArray(obj, depth);
    return;
  }
  // 跳过 Date、Buffer 等特殊对象
  if (obj instanceof Date || Buffer.isBuffer(obj)) return;
  sanitizePlainObject(obj, depth);
};

const sanitizeMongo = (req, res, next) => {
  // **刻意不含 req.query**：Express 5 下 req.query 是原型上的 getter
  // （express/lib/request.js: defineGetter(req, 'query', ...)），每次访问都重新解析
  // URL 查询串，因此对它的原地清洗是**彻底无效的**——实测（Express 5.2.1 + supertest）
  // `delete req.query.search` 之后**同一 handler 同一 tick** 内 `Object.keys(req.query)`
  // 仍然读得到 `search`。
  //
  // 此处此前把 req.query 一起遍历（写作"对 body/params/query 都生效"），读代码的人
  // 会以为 query 有两道防线，实际其中一道从未存在过。已移交给 materializeQuery：
  // 它把解析结果物化成**自有数据属性**，清洗与"物化真的生效"由运行时自证。
  //
  // 必须显式包一层箭头函数：forEach 的实参是 (元素, 下标, 数组)，
  // 直接传函数引用会把**下标**当成 deepSanitizeKeys 的 depth 入参——
  // body 从 0 起算（正确），params 从 1 起算，于是 params 的可用嵌套预算凭空少 1 层：
  // 第 9 层子树就被整体清空，而注释承诺的是「SANITIZE_MAX_DEPTH 层内不误伤」。
  // 方向上仍偏保守（超限是删除而非放行），所以不是注入缺口，是数据损失 + 契约不符。
  [req.body, req.params].forEach((part) => deepSanitizeKeys(part));
  next();
};

/**
 * 2.5 req.query 物化 —— Express 5 下 query 侧唯一的收口点
 *
 * 解决的问题：`req.query` 是原型上的 getter，每次访问都从 `req.url` 重新解析。
 * 于是任何"清洗后再消费"的写法都不成立——清洗写在某次访问返回的临时对象上，
 * 下一个消费者拿到的是全新解析结果。Express 4 上（getter 内部有缓存）这是成立的，
 * v5 把缓存去掉后，全仓既有的 sanitizeMongo + hpp 的 query 分支**同时变成空操作**，
 * 而它们仍留在挂载链上，看起来像两道防线。
 *
 * 做法：读一次（触发唯一一次解析）→ 原地清洗（复用 deepSanitizeKeys，与 body/params
 * 同一份实现，不另造第二套规则）→ 用 defineProperty 把这个对象**物化**成 req 的自有
 * 数据属性，遮蔽原型 getter。此后所有消费者读到的是同一份、已清洗的快照。
 *
 * 为什么必须自证（这是本中间件与「注释里说它有效」的根本区别）：
 * 物化成不生效只有两种可能——defineProperty 抛错（req 被冻结），或将来 Express 改了
 * 实现让自有属性不再遮蔽原型 getter。两者都不会有任何报错，只会让防线**静默归零**，
 * 而这正是本仓吃过一次亏的形态（防线失效是被 e2e 白屏偶然发现，不是被发现）。
 * 所以每次物化后立即回读比对身份，不等即**拒绝本次请求**并 error 级留痕——
 * 「服务不可用」远好过「带着未清洗的 query 把请求处理下去」。
 *
 * 附带收益：解析次数从「每个消费者一次」（sanitizeMongo / hpp / queryScalarGuard /
 * queryLengthLimit / 各控制器各一次）降到全请求一次，query 键多时省掉的是实打实的
 * URL 重复解析与 GC 压力。
 *
 * 挂载位置（src/app.js）：必须在 queryScalarGuard 与 queryLengthLimit **之前**
 * （它们要读清洗后的形态），且在 auditLog 之前（审计落盘的 query 快照应当是清洗后的）。
 */
const materializeQuery = () => {
  return (req, res, next) => {
    let parsed;
    try {
      // 触发原型 getter，产出本次请求唯一一次解析结果
      parsed = req.query;
    } catch (parseErr) {
      // getter 内部抛错（query parser 配置错误等）：此时没有任何可清洗的形态，
      // 继续下去等于把未处理异常留给控制器伪装成业务 500。
      logger.error(`req.query 解析失败，拒绝本次请求：${parseErr.message}`, {
        reqId: req.id,
      });
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
    }

    if (!parsed || typeof parsed !== 'object') {
      // query parser 被配成 false（Express 语义：解析禁用）时 getter 返回
      // Object.create(null)，仍需物化——否则下面所有消费者各自触发一次解析。
      parsed = {};
    }

    // 原地清洗：与 req.body / req.params 复用同一份 deepSanitizeKeys，
    // 保证三处的键判定规则（$ 前缀、含 .、__proto__/constructor/prototype）不会分叉
    deepSanitizeKeys(parsed);

    try {
      Object.defineProperty(req, 'query', {
        value: parsed,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } catch (defineErr) {
      logger.error(
        `req.query 物化失败（defineProperty 抛错），拒绝本次请求：${defineErr.message}`,
        {
          reqId: req.id,
        }
      );
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
    }

    // 自证：回读必须拿到**同一个对象**。不相等意味着物化没生效——
    // 继续服务等于宣称"已清洗"而实际未清洗，是本仓最忌讳的那类谎报。
    if (req.query !== parsed) {
      logger.error(
        'req.query 物化未生效（回读身份不一致）：req.query 仍为原型 getter 或被框架重新定义。' +
          'query 注入防线此刻为零，拒绝本次请求而非放行',
        { reqId: req.id }
      );
      return ApiResponse.codeError(res, 'INTERNAL_ERROR');
    }

    return next();
  };
};
module.exports = {
  sanitizeMongo,
  materializeQuery,
};
