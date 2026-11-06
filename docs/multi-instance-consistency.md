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

> 本表与 `src/constants/runtime.js` 的 `SINGLE_PROCESS_DEPENDENCIES` 台账**逐项对齐**
> （25 项台账中未外置的 16 项全数在此；外置项见 §一，含 statsCache / sessionService /
> ipPoolBan 票据三项早期版本未列的外置行）。台账与文档的逐项对账由
> `singleProcessInventoryCompleteness` / `runtimeInventoryClaims` 门禁钉住——新增
> 进程内状态不登记台账即启动体检红，台账与本文档失同步属评审义务。

| 状态点                   | 文件                                         | TTL/节奏                 | 多实例下的行为                                                                    | 风险评估                                                                                  |
| ------------------------ | -------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| 审计缓冲 flush 定时器    | `services/auditBuffer.js`                    | `flushTimer`             | 每实例独立 flush 各自缓冲 + 本地 WAL；哈希链串接由 Redis 链尾锁保证（见 §一）     | 低：链完整性不受影响；多实例各写各的 WAL，账目互不混                                      |
| 安全告警频控计数         | `services/alertDispatch.js`                  | 进程内 Map + 定时清理    | 各实例独立计数 → 同一告警可能最多按实例数重复投递                                 | 中低：重复告警优于丢告警；如需精确去重可外置到 sharedCache                                |
| 限流升级触发计数         | `services/rateLimitEscalation.js`            | 令牌桶 Map（压力升序）   | 各实例只统计自己分到的 429，实际封禁阈值 = 配置阈值 × 实例数                      | **低（by design，少封不误封）**：429 拦截由限流器共享存储跨实例保证；文件头有既定取舍说明 |
| IP 归属地结果缓存        | `services/ipLocationService.js`              | FIFO 上限 2048           | 各进程独立缓存派生结果                                                            | 低：纯派生缓存无失效语义，仅性能                                                          |
| 时区 formatter 缓存      | `constants/timezone.js`                      | 上限 32                  | 各进程独立                                                                        | 低：纯派生缓存                                                                            |
| readyz 判定计数          | `utils/metricsRuntime.js`                    | `readyzChecks Map`       | 各进程独立计数                                                                    | 低：/metrics 的 readyz 观测值按进程呈现，聚合层按实例看                                   |
| IP 封禁动作缓存          | `middleware/security/ipBlacklist.js`         | `ipBlockCache Map`       | A 实例刚封禁的 IP 在 B 实例仍放行，直到 B 自己的 TTL 到期                         | **中**：封禁生效存在实例间时间窗；与下行名单快照叠加注意                                  |
| IP 黑名单名单快照        | `models/IPBlacklist.js`（`SNAPSHOT_TTL_MS`） | 10s                      | 仅在 **DB 故障**时作为降级数据源；DB 正常时不参与判定（防解封后仍被陈旧缓存拦截） | 低：正常路径以库为准                                                                      |
| 部门成员缓存（数据范围） | `services/auditScopeFilter.js`               | `deptMembersCache Map`   | 改部门成员后其余进程延迟生效                                                      | 中低：数据范围过滤按各进程缓存判定                                                        |
| 系统配置缓存             | `models/SystemConfig.js`                     | TTL 30s                  | 改配置后各进程最长 30s 仍按旧值判定（如关闭公开注册后仍可注册）                   | 中低：配置面收敛慢，安全开关类改动需知晓 30s 窗口                                         |
| 会话吊销进程内通知总线   | `services/sessionRevocationEvents.js`        | listeners Set            | A 实例的吊销不会即时通知 B 实例的 WebSocket 连接                                  | 低：由周期清扫按库复查兜底（30s 收敛）                                                    |
| 仪表盘缓存               | `services/reportDashboardService.js`         | 30s TTL                  | 各进程独立，滞后一个 TTL                                                          | 低：**刻意不接失效广播**（取舍见该文件头），配 REDIS_URL 也不会跨实例一致                 |
| 审计异常告警去重表       | `services/auditMonitor.js`                   | `notifiedDayByDimension` | 各进程各自去重，同一事件按实例数重复告警                                          | 中低：重复告警优于丢告警（原描述"重复扫描落库键幂等"是旧语义，机制已是告警去重表）        |
| 哨兵名当日告警去重       | `services/canaryWatch.js`                    | `notifiedDayByCanary`    | 各进程各自去重、各自对账；同一哨兵命中按实例数重复告警                            | 中低：同上                                                                                |
| 诱饵账户当日告警去重     | `services/honeypotWatch.js`                  | `notifiedDayByHoneypot`  | 各进程各自去重、各自物化；同一诱饵名命中按实例数重复告警                          | 中低：同上                                                                                |
| 取证触发标记表           | `services/forensicTrigger.js`                | marksByIp Map + LRU      | 各进程各自标记各自淘汰；同一 IP 只在实际命中它的实例上被取证                      | **中**：抽查面随实例数缩小，多实例下取证覆盖完整率下降                                    |
| Grafana/Prometheus 抓取  | `deployment/observability/`                  | 15s                      | 任一实例的 `/metrics` 均只含本进程计数                                            | 运维注意：多实例需按实例聚合（Prometheus 多 target）                                      |

## 三、验收口径

1. 生产部署必须配置 `REDIS_URL`（compose 已注入 `redis://redis:6379`），否则启动被 `validateConfig` 拒绝。
2. 「会话吊销广播 ≤15s」为设计承诺：压测/演练时可用双实例 + 改密后立即用旧令牌打接口验证（期望在 TTL 内转为 401）。
3. 限流共享计数回归：`src/tests/middleware/rateLimitStore.test.js`（RedisStore init 补调语义）。
4. 真实 Redis 的端到端集成测试（吊销广播 / 告警频控 / 链尾锁）需要在含 Redis 服务的 CI 环境跑——当前 CI 无 Redis service，属**待办**（报告 #5 的「真实 Redis 集成测试」项）。

## 四、K8s 多副本：部署期必须声明副本数（F-12，2026-10-17）

`constants/runtime.js` 的启动期拓扑校验有**三档**结论：

| 档位        | 触发条件                                                                                                                  | 日志级别 | 含义                                                 |
| ----------- | ------------------------------------------------------------------------------------------------------------------------- | -------- | ---------------------------------------------------- |
| `suspected` | PM2 / cluster / `WEB_CONCURRENCY` / `INSTANCE_COUNT` / `REPLICAS` / `RUNTIME_INSTANCE_COUNT` > 1，或 StatefulSet 序号 > 0 | error    | **确证**多进程，列出失效清单                         |
| `unproven`  | 在集群内（`KUBERNETES_SERVICE_HOST` 存在）、无上述强信号、且未声明 `RUNTIME_INSTANCE_COUNT=1`                             | warn     | **无法自证单副本**，列出「若有多副本则会降级」的清单 |
| 无          | 其余情况                                                                                                                  | debug    | 单进程假设成立                                       |

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

`services/websocketService/shared.js` 的 `MAX_CONNECTIONS_PER_PROCESS = 1000` 数的是
`io.sockets.sockets.size`，即**单个 Socket.IO 进程**的在线连接数。
多副本时每个实例都能各自达到 1000，**整体没有统一上限**：

```
可承载连接总数 ≈ 实例数 × MAX_CONNECTIONS_PER_PROCESS
```

- 反向代理 / Ingress 侧的总连接配额必须按这个乘积设置（Nginx `worker_connections`、
  云 LB 的 `MaxConnections`），否则单实例上限对连接风暴不起作用。
- `getStats()` 返回的 `maxConnections` 是**单进程**值，监控面板聚合时不要把它当总量。
- 若要真正的全局配额，需在网关层限流或引入共享计数（Redis `INCR` + TTL）；
  当前未实现，属已知缺口而非配置项。
