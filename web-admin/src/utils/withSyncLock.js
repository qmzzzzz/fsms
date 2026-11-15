/**
 * 同步重入锁（P2-29）
 *
 * `:disabled="submitting"` 依赖一次重渲染才生效：同一 tick 内的第二次点击到达时
 * 处理函数已经跑过了同步段、正停在第一个 await 上，按钮仍是可点状态 ——
 * 结果是双击弹两个确认框、发两次请求（LoginView/AlarmView 的行内注释均实测过）。
 *
 * 本工具把「首个 await 前同步判定并置位、finally 复位」收口成公共包装：
 * 包装函数被调用时先同步查锁，未锁则立即置位再进入原函数，原函数的 Promise
 * 落定（含抛错）后复位。第二次调用拿到的是已锁判定，直接返回已完成的 Promise。
 *
 * 用法：
 *   const submitForm = withSyncLock(async () => { ... await ... })
 *   const handleDelete = withSyncLock(async (row) => { ... })
 */
export function withSyncLock(fn) {
  let locked = false
  return function lockedFn(...args) {
    if (locked) return Promise.resolve(undefined)
    locked = true
    let result
    try {
      result = fn(...args)
    } catch (e) {
      locked = false
      throw e
    }
    const release = () => {
      locked = false
    }
    if (result && typeof result.then === 'function') return result.finally(release)
    locked = false
    return result
  }
}
