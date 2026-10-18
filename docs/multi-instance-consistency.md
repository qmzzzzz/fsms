# 多实例一致性清单（评价报告 #5）

> 背景：系统支持两种部署形态——单实例（内存态）与多实例（Redis 共享态，
> `REDIS_URL` 配置后生效，见 ADR-005）。本文档逐点列出**进程内状态**、
> 对应的 Redis 外置路径与多实例下的残余差异，作为扩容前的核对清单。
> 生产校验（`src/config/validate.js`）已强制生产环境配置 `REDIS_URL`。

## 一、已外置到 Redis 的共享状态

| 状态点                              | 文件                                          | Redis 路径                                        | 多实例语义                                                        |
| ----------------------------------- | --------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------- |
| 登录限流 / 通用限流等全部限流器计数 | `middleware/rateLimit.js`                     | rate-limit-redis（`rl:<prefix>:`）                | 跨实例共享配额；#6 修复后 RedisStore 的 init 在异步切换后显式补调 |
| 认证用户缓存失效广播                | `middleware/auth.js` + `services/sharedCache` | pub/sub 失效通道                                  | 任一实例改角色/降权，其余实例缓存即时失效                         |
| 用户权限聚合缓存失效                | `services/userPermissionService.js`           | 同上（L-4 命名空间隔离）                          | 同上                                                              |
| 审计链尾指针 + 分布式锁             | `utils/auditChain.js`                         | `CHAIN_TAIL_KEY`（CAS 写入）+ acquireLockBlocking | 链尾唯一、串链不分叉；单进程锁假设见 ADR-004                      |
| 登录口令 ECDH 一次性 nonce          | `utils/loginCipher.js`                        | setIfAbsent（防重放）                             | 信封不可跨实例重放                                                |
| 图形验证码（计数/存取/核销）        | `services/captchaService.js`                  | sharedCache get/set/del/incrWithTtl               | 任一实例签发、任一实例核销                                        |
| WebSocket 房间/广播路由             | `services/websocketService.js`                | @socket.io/redis-adapter                          | 跨实例事件可达                                                    |

## 二、进程内状态与多实例残余差异（扩容前必读）

| 状态点                  | 文件                                                | TTL/节奏              | 多实例下的行为                                                                    | 风险评估                                                                                                      |
| ----------------------- | --------------------------------------------------- | --------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 会话（session）读缓存   | `services/sessionService.js`（`SESSION_CACHE_TTL`） | 15s                   | 吊销/改密后，其他实例最长 15s 内仍可能凭旧缓存放行                                | **已知且有界**：吊销链路本身写库即时生效，窗口仅读缓存延迟；令牌黑名单 fail-closed 兜底（命中黑名单一律拒绝） |
| IP 黑名单降级快照       | `models/IPBlacklist.js`（`SNAPSHOT_TTL_MS`）        | 10s                   | 仅在 **DB 故障**时作为降级数据源；DB 正常时不参与判定（防解封后仍被陈旧缓存拦截） | 低：正常路径以库为准                                                                                          |
| 安全告警频控计数        | `services/securityAlert.js`                         | 进程内 Map + 定时清理 | 各实例独立计数 → 同一告警可能最多按实例数重复投递                                 | 中低：重复告警优于丢告警；如需精确去重可外置到 sharedCache                                                    |
| 审计异常监控定时器      | `services/auditMonitor.js`                          | `monitorTimer`        | 每实例都会跑一轮扫描 → 重复扫描（读多写少，落库键幂等）                           | 低：结果幂等；后续可加 sharedCache 锁选主                                                                     |
| 审计缓冲 flush 定时器   | `services/auditBuffer.js`                           | `flushTimer`          | 每实例独立 flush 各自缓冲；哈希链串接由 Redis 链尾锁保证（见上）                  | 低：链完整性不受影响                                                                                          |
| Grafana/Prometheus 抓取 | `deployment/observability/`                         | 15s                   | 任一实例的 `/metrics` 均只含本进程计数                                            | 运维注意：多实例需按实例聚合（Prometheus 多 target）                                                          |

## 三、验收口径

1. 生产部署必须配置 `REDIS_URL`（compose 已注入 `redis://redis:6379`），否则启动被 `validateConfig` 拒绝。
2. 「会话吊销广播 ≤15s」为设计承诺：压测/演练时可用双实例 + 改密后立即用旧令牌打接口验证（期望在 TTL 内转为 401）。
3. 限流共享计数回归：`src/tests/middleware/rateLimitStore.test.js`（RedisStore init 补调语义）。
4. 真实 Redis 的端到端集成测试（吊销广播 / 告警频控 / 链尾锁）需要在含 Redis 服务的 CI 环境跑——当前 CI 无 Redis service，属**待办**（报告 #5 的「真实 Redis 集成测试」项）。

## 四、K8s 多副本：部署期必须声明副本数（F-12，2026-10-17）

`constants/runtime.js` 的启动期拓扑校验有**三档**结论：

| 档位       | 触发条件                                                         | 日志级别 | 含义                       |
| ---------- | ---------------------------------------------------------------- | -------- | -------------------------- |
| `suspected` | PM2 / cluster / `WEB_CONCURRENCY` / `INSTANCE_COUNT` / `REPLICAS` / `RUNTIME_INSTANCE_COUNT` > 1，或 StatefulSet 序号 > 0 | error | **确证**多进程，列出失效清单 |
| `unproven`  | 在集群内（`KUBERNETES_SERVICE_HOST` 存在）、无上述强信号、且未声明 `RUNTIME_INSTANCE_COUNT=1` | warn | **无法自证单副本**，列出「若有多副本则会降级」的清单 |
| 无          | 其余情况                                                         | debug | 单进程假设成立             |

`unproven` 这一档的存在原因：**K8s Deployment 的 `replicas: 3` 不会注入任何环境变量**，
Pod 名（`<name>-<rsHash>-<5位随机>`）也不带 StatefulSet 那样的序号，所以进程在纯
K8s 多副本下**无从得知**自己不是唯一实例。修前这里只置 `k8sPodLike` 提示、日志级别
是 debug，等于静默放行；而审计哈希链分叉、限流配额放大恰恰最先发生在该拓扑。

**部署侧义务**：把真实副本数写进 `RUNTIME_INSTANCE_COUNT`。

- 不能靠 Downward API：它只能暴露 Pod 自身字段，**给不出 replicas**。
- 推荐由渲染阶段写入（helm `{{ .Values.replicaCount }}` / kustomize replacement），
  或 initContainer 用 ServiceAccount 读 `/apis/apps/v1/.../deployments/<name>` 的 `spec.replicas`。
- `RUNTIME_INSTANCE_COUNT=1` 表示"已声明单副本"，`unproven` 提示随之消失；
  写成 1 却实际扩容 = 自欺，`suspected` 也不会再报。

> 为什么不复用 `INSTANCE_COUNT`：`.env.example` 里 `INSTANCE_COUNT=1` 是随模板
> 复制进 ConfigMap 的**默认值**。拿它当"已声明单副本"的证明，会让所有按模板部署的
> 集群自动闭嘴——`src/tests/constants/deploymentReplicaProof.test.js` 钉住了这条。

## 五、容量模型（F-13：连接上限是**每进程**的）

`services/websocketService.js` 的 `MAX_CONNECTIONS = 1000` 数的是
`io.sockets.sockets.size`，即**单个 Socket.IO 进程**的在线连接数。
多副本时每个实例都能各自达到 1000，**整体没有统一上限**：

```
可承载连接总数 ≈ 实例数 × MAX_CONNECTIONS
```

- 反向代理 / Ingress 侧的总连接配额必须按这个乘积设置（Nginx `worker_connections`、
  云 LB 的 `MaxConnections`），否则单实例上限对连接风暴不起作用。
- `getStats()` 返回的 `maxConnections` 是**单进程**值，监控面板聚合时不要把它当总量。
- 若要真正的全局配额，需在网关层限流或引入共享计数（Redis `INCR` + TTL）；
  当前未实现，属已知缺口而非配置项。

