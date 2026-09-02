/**
 * 列表请求竞态守卫
 *
 * 场景:快速连续搜索/翻页时,先发出的慢请求可能后返回,把新结果
 * 覆盖成旧数据。每次发起请求取一张"门票",写回数据前校验门票
 * 仍是最新一次,过期响应直接丢弃。
 *
 * 用法:
 *   const guard = useLatestRequest()
 *   const loadData = async () => {
 *     const isCurrent = guard()
 *     loading.value = true
 *     const res = await api.users.getList(params)
 *     if (!isCurrent()) return   // 已有更新的请求,丢弃本次响应
 *     tableData.value = res.data.list
 *     loading.value = false
 *   }
 */
export function useLatestRequest() {
  let seq = 0
  return () => {
    const id = ++seq
    return () => id === seq
  }
}
