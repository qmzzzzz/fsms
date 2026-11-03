# 用户权限服务（userPermissionService）说明

本文件承接 `src/services/userPermissionService.js` 文件头的论证（注释密度棘轮按文件封顶，论证移此；行内不变量注释仍在原处）。

## 职责

用户权限查询 + 进程内 TTL 结果缓存。User 模型回归纯数据 schema（字段定义 + 密码哈希钩子 + 密码比对），权限聚合与缓存管理集中在此，便于独立演进（如替换 Redis）。

## 权限结果缓存（P-01）

背景：每个受保护请求原本都要执行「查用户 → populate roles → populate permissions」三层关联查询，100 QPS 下即产生 300+ 次/秒的数据库聚合负载。策略：进程内 TTL 缓存（30 秒；该用户有临时授予时按最近一条授予的到期时刻进一步收敛）+ 显式失效：

- 用户级失效：assignRoles 等变更某用户角色时，仅删除该用户条目
- 全局失效：角色权限被修改（assignPermissions）时清空整个缓存（permCache.clear()）

L-16 与后续修正：这里的 `permCacheGeneration` 有一段反复。L-16 时它「只被读取、从未递增」，因此是死变量，被删掉并把注释改成描述真实机制（全局失效走 clear()）——那一步判断本身没错，错在删完没留等价机制：getPermissions 是「先 await 查库、后 set 写回」，失效若落在这一趟往返中间，delete/clear 都作用在一个还不存在的条目上，随后 in-flight 的旧结果把条目种回去，主动失效被静默撤销到 TTL 到期（方向是「收回的权限仍能放行」）。现在代际被重新引入，且**两侧都接上了**：invalidatePermissionCacheLocal 递增、getPermissions 写回前比对（见该处注释）。与 middleware/auth.js 用户缓存的 queryStartedAt/invalidatedDuringQuery 是同一条不变量的第二次实现。

## 跨实例主动失效（L-4）

单进程内上述缓存自洽，但多副本部署时各进程各持一份缓存：实例 A 改了某用户角色/权限后，实例 B 的缓存最长仍会放行旧权限 30 秒。解法是借共享缓存门面的失效广播（sharedCache.publishInvalidate / onInvalidate，Redis pub/sub）：

- 本地失效（invalidatePermissionCache）发生时同步广播失效键给所有实例；
- 收到广播的实例做**本地**失效（不再二次广播，避免实例间互相触发成环）。

## 降级期 TTL 策略（P-3）

「没配 REDIS_URL」（静态单实例，A-2 的就绪闸会拦住疑似多实例部署）与「配了 REDIS_URL 但当前不可用」（本应多实例、失效广播此刻断绝）不是一回事：

- 前者本地失效就是全部真相，30 秒 TTL 只影响性能，维持原语义；
- 后者其它实例收不到失效广播，只能等自然过期，30 秒即最长越权窗口。
  因此在 `isRedisConfigured() && !isRedisEnabled()` 期间把写回 TTL 压到 2 秒（读路径也按同一口径判定，降级前写下的 30 秒条目会立即过期），把「收回的权限仍被放行」的跨实例窗口从 30 秒收敛到 ≤2 秒。代价是降级期间权限查询回表变频繁——安全系统优先选收敛而不是命中率。
