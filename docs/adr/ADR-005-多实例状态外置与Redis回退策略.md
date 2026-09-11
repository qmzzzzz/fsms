# ADR-005：多实例状态外置（sharedCache 门面 + Redis 可选回退）

- **状态**：已接受
- **日期**：2026-08-30
- **涉及**：`src/services/sharedCache.js`、`src/middleware/rateLimit.js`、`src/services/captchaService.js`、`src/utils/loginCipher.js`、`src/middleware/auth.js`、`src/services/websocketService.js`、`src/utils/auditChain.js`；优化清单 R-3 / M-1 / L-4 / A-1 / O-15

## 背景

系统内多类关键状态原为进程内内存态：限流计数、登录验证码、重放防护 nonce、用户/权限缓存、IP 封禁缓存、Socket.IO 房间、审计链尾锁。单进程部署时无碍；一旦多副本（水平扩容、蓝绿并存），各实例状态互不可见，后果不是「性能变差」而是**语义失效**：限流配额按副本数翻倍、验证码在 A 实例签发却在 B 实例校验失败、权限回收不跨实例生效、审计链分叉。

## 决策

引入统一共享缓存门面 `sharedCache`，全部共享态经它读写：

- **双后端**：配置 `REDIS_URL` 时走 Redis（跨实例一致）；未配置或连接失败时**自动回退**进程内内存实现并告警。两种后端对外同一套异步 API，调用方不感知部署形态。
- **环境边界**：`NODE_ENV=production` 无条件要求 `REDIS_URL`，缺失时启动即失败；开发与测试仍允许内存回退，保证本地和 CI 不引入外部组件依赖。
- **切换点**：限流器（`rate-limit-redis` store）、验证码（`incrWithTtl` + KV）、nonce 一次性消费（原子占位）、用户/权限与 IP 封禁缓存、Socket.IO `@socket.io/redis-adapter`、审计链尾的 CAS 读写。
- **L-4 失效广播**：写后失效经 pub/sub 通道广播（`publishInvalidate`/`onInvalidate`），各实例订阅后清本地影子缓存；内存模式下为 no-op。
- **A-1 链锁**：`withChainLock` 在 Redis 模式叠加跨实例分布式锁（`SET NX PX` + token 校验释放，`acquireLockBlocking`），内存模式保留进程内 Promise 锁（见 ADR-004）。
- **O-15 雪崩/穿透**：`jitterTtl` 为 TTL 附加 ±10% 随机抖动；`EMPTY_SENTINEL` 空值哨兵支持缓存「查无结果」防穿透。

## 理由

- **生产强制、开发回退**：生产限流、黑名单广播、nonce 去重与审计链锁的跨实例一致性是安全语义，不能静默降级；同时本地与测试保留内存后端以降低开发摩擦。
- **门面收口**：共享态入口收敛到一个模块，后续换存储（如 KeyDB/云托管）只改门面；也便于统一施加抖动、哨兵、失效广播等横切策略。

## 备选方案

- **直接依赖 Redis（无回退）**：语义最干净，但把开发/测试/单机部署绑死在外部组件上，被否。
- **数据库承载共享态**（Mongo 集合做限流/验证码）：少一个组件，但高频小键写入放大数据库压力，且缺少原生 TTL/发布订阅能力，被否。
- **粘性会话（负载均衡按用户固定实例）**：治标——限流与封禁仍会被多实例稀释，且粘性本身带来负载不均与故障切换复杂度，被否。

## 后果与局限

- 开发/单机未配 `REDIS_URL` 时可继续内存回退；生产必须显式接入 Redis 并演练失效广播与连接故障切换。
- Redis 连接抖动期间门面降级为内存态：可用性优先于跨实例一致性，期间限流/验证码按实例局部生效——这是有意取舍，需在运维监控中关注降级告警。
- `resign/迁移`类脚本与 Redis 无耦合（密钥材料仍按 ADR-003 管理）。
