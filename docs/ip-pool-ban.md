# IP 池 CIDR 封禁（ipPoolBan）说明

本文件承接 `src/services/ipPoolBan.js` 内联注释的论证（注释密度棘轮按文件封顶，论证移此，代码内只留一行指针与最短行内不变量）。

## 永远人工

网段封禁不做自动化，`IP_POOL_BAN_ALLOW_AUTO` 已移除（留着「默认关但能开」等于给未来留一个可以误开的开关，而误开的代价是封掉一栋楼的消防上报）。自动封禁的正确形态是单 IP 递进式（见 `rateLimitEscalationBan.escalateIp`：1h→4h→24h→7d），误伤半径只有一个人且可逆。

## 票据外置 sharedCache（B2，2026-11-03）

待确认票据不再驻留进程内 Map，改存 sharedCache（键 `ip_pool_ban:ticket:<token>`，TTL=CONFIRM_TTL_MS），消费用 getDel 原子取删——并发双击确认只有一方拿得到票，多实例部署下 A 实例出的票 B 实例可确认（这正是外置的目的：旧进程内 Map 在多副本下各持一份，同一张票可被确认两次）。

- **单实例回退语义**：未配 REDIS_URL 时 sharedCache 的内存后端就是全部真相，行为与旧 Map 版一致；Redis 已配置但不可用时**整体 fail-closed**——出票被拒（setIfAbsent 按重复处理返回 false ⇒ 拒绝出票）、确认取不到票（unknown_token）。绝不退回进程内存发一张「只有本实例认识」的票：多实例下另一实例会判 unknown_token，等价于静默丢票还自以为发过。
- **「敲错不消耗」（ADR-018 ③）**：确认判据失败时票据**原样写回**（set 带 PX 剩余 TTL，剩余 TTL 随票存进票对象）；写回若没落到共享层（返回 false），立即 dropLocalCopy 抹掉本地副本——那张票就此作废（getDel 已消费），操作者重新申请即可。绝不留一份会被内存回退读回来的陈旧真值，否则一次性消费在 Redis 抖动期被架空（并发双花窗口重新打开）。
- 进程内不再持有票据清单：旧 PENDING_MAX/sweep/trim 一并移除，票据上界改由 sharedCache 的容量收口（内存模式）与 Redis TTL（共享模式）承担。

## landed=false 时抹本地副本

共享层没收到（Redis 已配置但抖动）时，set 的内存回退副本必须立刻抹掉——getDel 的内存回退会把它当共享层真值读回来，「getDel 已消费」就变成假的，一次性消费在故障期被架空。票据就此丢失：操作者重新申请即可（可用性损失，安全方向无损）。

## 审计归因与可靠落库（B1/B3，2026-11-03）

确认落库的审计条目按 ipListController 同族口径补齐操作者与请求上下文（userId/username/method/path/auditClientAddress/userAgent/sessionId/fingerprint）；写入走 `auditOutbox.recordDurably`：DB 失败而审计 WAL 可用时事件入 WAL 待重放、不阻断响应；WAL 未启用时重抛（由调用方转 500，与 ipListController 同语义：宁可靠 500 暴露缺口，不假装记账成功——封禁已生效，此刻响应成功而零留痕是最坏组合）。lastErrors 数组（上限 5）替代旧单字段 lastError——后写覆盖先写会让连环失败只剩最后一条。审计条目的**构造**在 `ipPoolBanAudit.js`（纯函数，拆出为体积/复杂度双棘轮让路）。

## 其余行内判据（原文）

- 本地诊断面容量：审计写失败是「封禁已生效但追溯性受损」的缺口证据，连环失败时每一条都要留。
- 拒绝出口只此一处：计数与返回同行（两处分记会让 live_traffic 记 2 次）。
- 拒绝原因必须点名：运维要知道是「被白名单挡住」还是「是全网段」。
- 票据清点语义（`__resetForTest`）：sharedCache 门面没有 clear（Redis 无按前缀删除，内存后端不暴露枚举面）。测试隔离不依赖清票：token 是 16 字节随机数，用例间不复用；真实环境里每张票自带 TTL=CONFIRM_TTL_MS，reset 后未消费的票在 10 分钟内自然过期，不构成泄漏。
