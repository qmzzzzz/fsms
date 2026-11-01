/**
 * 邮箱比对的规范形态（单一事实来源）
 *
 * `User.email` 在 schema 上是 `lowercase: true` ⇒ 落库永远小写，且该 setter 同时作用于
 * **查询条件**；但 `email !== user.email` 这类普通 JS 比对吃内存里的原样串、没有 setter：
 * 用户提交"自己邮箱的大写形态"时比对不等 ⇒ 进入查重 ⇒ 被判成"已被他人占用"（400 EMAIL_TAKEN）。
 *
 * 所以这里显式取一次 `toLowerCase()`：比对不再依赖内存形态与 schema 形态是否一致，
 * 查重也不再隐式依赖 Mongoose 的 query-setter 行为（该行为历史上变动过）。
 * 刻意不做 `normalizeEmail` 那类额外改写（去点/去标签），以免"规范形态"与"落库形态"再次分叉。
 */
const normalizeEmailKey = (email) => (typeof email === 'string' ? email.toLowerCase() : email);

module.exports = { normalizeEmailKey };
