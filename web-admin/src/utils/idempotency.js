/**
 * 前端幂等键（审计一-1）
 *
 * 后端已接受 `Idempotency-Key` 请求头，但**默认不强制**（本仓 8 个创建端点有 105 处
 * 既有调用，强制会一次性打断所有脚本与第三方接入）。所以"真实使用路径受保护"这件事
 * 必须由前端自己兑现：每一次业务提交都带一个键，重试时复用同一个键。
 *
 * 键的生命周期只有一次提交（含其重试）：页面上的"重试"复用同一个键，用户改完字段
 * 再提交则算新的一次。实现上就是调用方持有一个 `IdempotencyKey` 实例，把它交给
 * `withIdempotencyKey` 包住的请求；`retry()` 会复用，`renew()` 会换新的。
 *
 * 为什么不用 sessionStorage/localStorage 保存：键不是凭据，也不该在页面刷新后
 * 复活——刷新后用户看到的是一张空表单，那是一次**新的提交意图**，复用旧键只会让
 * 服务端把新内容当成"改载荷"而 409。键只活在内存里，与那次提交的 JS 生命周期同长。
 */

/** 生成一个键：优先 crypto.randomUUID（浏览器 >= Chrome 92 / Firefox 95） */
export function newIdempotencyKey() {
  const c = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined
  if (c && typeof c.randomUUID === 'function') return c.randomUUID()
  // 兜底：非安全上下文（http://内网 IP）下 crypto.randomUUID 不可用，
  // 用 getRandomValues 拼一个 32 位十六进制串（长度落在后端 8-64 的合法区间）
  if (c && typeof c.getRandomValues === 'function') {
    const bytes = new Uint8Array(16)
    c.getRandomValues(bytes)
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  }
  // 最后兜底（老运行时/测试环境）：时间戳 + 随机，不追求密码学强度——
  // 幂等键不是安全凭据，它只需要"同一次提交内稳定、不同提交间不撞"。
  return `${Date.now().toString(16)}${Math.random().toString(16).slice(2, 10)}`.padEnd(32, '0')
}

/**
 * 一次提交的幂等键持有者
 *
 * @example
 *   const idem = createSubmissionKey()
 *   await api.users.create(payload, idem.header())
 *   // 失败后用户点「重试」：仍用 idem.header()，服务端据此判定为同一次提交
 *   // 用户改了内容再提交：idem.renew() 后再发
 */
export function createSubmissionKey() {
  let key = newIdempotencyKey()
  return {
    header: () => ({ 'Idempotency-Key': key }),
    /** 换一个新键（内容变了 ⇒ 这是新的一次提交） */
    renew() {
      key = newIdempotencyKey()
      return key
    },
    /** 当前键值（排障/日志用；不要写进 localStorage） */
    value: () => key,
  }
}
