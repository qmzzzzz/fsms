'use strict';

/**
 * 测试 JWT 签发单一入口（2026-11-17 审计主题 H：6 处本地 jwt.sign 小函数单源化）。
 *
 * 合并口径（逐一核对过 6 处既有实现的并集，字段集合就是这三项）：
 *   - 载荷：userId = String(user._id)、username、tokenVersion。
 *     6 处均未用到 sub/role/permissions 等其它字段；需要时用 overrides 携带。
 *   - tokenVersion 统一 `?? 0` 语义：显式传 overrides.tokenVersion 时用 override，
 *     否则取 user.tokenVersion ?? 0。与被测侧 src/middleware/auth.js 的
 *     expectedTokenVersion = freshUser.tokenVersion ?? 0 同口径（令牌缺该字段一律拒绝）。
 *     旧实现的三种写法（`|| 0` / 硬编码 0 / 直取）在 User.tokenVersion default: 0
 *     （src/models/User.js:234）之下对既有用例全部等价于 `?? 0`；`|| 0` 会把 0 以外
 *     的 falsy 值也归零，但 Number 字段不存在该形态。
 *   - 密钥：process.env.JWT_SECRET；算法不指定（jsonwebtoken 默认 HS256），
 *     expiresIn '24h' 是 6 处既有实现的统一取值，高于 testTokenTtlFloor 闸的 6h 地板。
 *
 * @param {object} user 含 _id / username / tokenVersion 的用户文档（或同形对象）
 * @param {object} [overrides] 覆盖任意载荷字段（如 tokenVersion、username）
 * @returns {string} Bearer 令牌
 */

const jwt = require('jsonwebtoken');

/** 测试令牌寿命：与 6 处既有实现的 '24h' 一致（≥ testTokenTtlFloor 的 6h 地板） */
const TEST_TOKEN_EXPIRES_IN = '24h';

const signTestToken = (user, overrides = {}) =>
  jwt.sign(
    {
      userId: String(user._id),
      username: user.username,
      tokenVersion: user.tokenVersion ?? 0,
      ...overrides,
    },
    process.env.JWT_SECRET,
    { expiresIn: TEST_TOKEN_EXPIRES_IN }
  );

module.exports = { signTestToken };
