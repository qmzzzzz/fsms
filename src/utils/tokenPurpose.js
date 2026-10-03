/**
 * 「令牌用途」的唯一判据：refresh 令牌不得被当作 access 令牌使用
 *
 * access 与 refresh 由两把不同密钥签名，正常配置下 refresh 在验签阶段就失败。
 * 但 config 的"两把密钥不得相同"只在生产语义下强制（`validateConfig()` 对
 * development/staging 直接 return），于是运维把 JWT_SECRET 与 JWT_REFRESH_SECRET
 * 配成同一个值时二者完全等价：refresh 有效期 7 天且自带 userId/tokenVersion/sid，
 * 拿来当 Bearer 直连 API、或拿去通过 WebSocket 认证，
 * "access 短有效期 + 频繁换发"这条收缩访问窗口的机制整体失效。
 *
 * 判据只在 `type` 存在且不等于 'access' 时判违规：历史 access 令牌没有该字段，
 * 不因这次加固而集体失效。此前这条规则散在三处（HTTP 中间件、令牌有效性探测、
 * WS 认证），后两处漏抄 —— 收敛到这里，任何新增的验签入口都必须引用同一份。
 *
 * 「任何新增入口」这句以前只是注释，现在有判据：
 * `src/tests/security/tokenPurposeEntryInventory.test.js` **枚举** src/ 下所有
 * `jwt.verify(…, config.jwt.secret)` 调用（不是点名已知文件），未引用本判据的
 * 必须出现在豁免表里，而豁免表的两条豁免各绑一条行为用例——豁免的根据没了就红，
 * 不看文件名。实测全仓 5 处入口：3 处引用判据，2 处豁免（登出入口的预检、登出吊销）。
 *
 * @param {object} decoded jwt.verify 的产物
 * @returns {boolean} true = 用途不符（拒绝）
 */
const violatesAccessTokenPurpose = (decoded) =>
  Boolean(decoded) &&
  typeof decoded === 'object' &&
  decoded.type !== undefined &&
  decoded.type !== 'access';

module.exports = { violatesAccessTokenPurpose };
