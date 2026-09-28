/**
 * 邮箱比对的规范形态（单一事实来源）
 *
 * `User.email` 在 schema 上是 `lowercase: true` ⇒ 落库永远是小写。本轮实测出的两件事：
 *  ① Mongoose 会把该 setter **同时作用于查询条件**：`User.findOne({ email: 'A@B.C' })`
 *    实际查的是 `a@b.c` ⇒ "大写形态绕过查重、撞唯一索引变成通用 400" 这个猜测**不成立**
 *    （用变异体实测过：查重两侧都用原样串时，EMAIL_TAKEN 依然正确命中）。
 *  ② 但 `email !== user.email` 这类**普通 JS 比对**吃的是内存里的原样串，没有任何 setter：
 *    用户提交"自己邮箱的大写形态"时，比对不等 ⇒ 进入查重 ⇒ ①里那条 setter 反而把它
 *    规范化成命中的记录 ⇒ 于是自己的邮箱被判成"已被他人占用"（400 EMAIL_TAKEN）。
 *    这才是真实缺陷，且它在修复前必然复现。
 *
 * 所以这里显式取一次 `toLowerCase()`：比对不再依赖内存形态与 schema 形态是否一致，
 * 查重也不再隐式依赖 Mongoose 的 query-setter 行为（该行为历史上变动过）。
 * 刻意不做 `normalizeEmail` 那类额外改写（去点/去标签），以免"规范形态"与"落库形态"再次分叉。
 */
const normalizeEmailKey = (email) => (typeof email === 'string' ? email.toLowerCase() : email);

module.exports = { normalizeEmailKey };
