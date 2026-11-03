# 未脱敏 PII 导出每日配额（piiExportQuota）说明

本文件承接 `src/services/piiExportQuota.js` 内联注释的论证（注释密度棘轮按文件封顶，论证移此，代码内只留指针与最短行内不变量）。

## 计数源（按部署形态二选一）

- **Redis**（REDIS_URL 已配置）＝主源。键 `pii_export_quota:<userId>:<YYYYMMDD(UTC+8)>`，INCR 后**首次**置 24h TTL（EXPIRE NX 语义：仅当键尚无 TTL 时设；`sharedCache.incrWithTtl` 的 Lua 还会在 TTL 意外丢失时兜底重建）。Redis 模式跨实例一致——这是它的唯一存在理由：多实例部署下审计库副本有复制延迟，「刚导过」在另一实例上读不到。
- **Redis 未配置**＝退回审计计数路径（数 `view_sensitive_data`/`export_realname` 留痕，滚动 24h 窗口）。单实例口径：多实例下各实例各算各的——零依赖回退是部署选择，语义差异如实，不得读成「两种模式等价」。

## 消费即扣减（consumePiiExportQuota）

配额在**写出之前**扣（INCR），写出失败也不退。比现状严（现状只在成功留痕后计数，失败重试可无限刷），方向安全。审计留痕仍在写出成功之后写（`watermark.traceId` 对账凭证不动）——扣减面与留痕面口径不同是刻意的：留痕回答「导出了什么」，计数回答「占了多少额度」。

## fail-closed

读失败一律上抛：Redis 已配置但未就绪/命令失败时抛 `PII_EXPORT_QUOTA_UNAVAILABLE`（调用方按 5xx 处理），绝不在「不知道今天已经导了几次」的时候放行。计数不可信的统一出口同此。

## TOCTOU 口径

`requirePiiExportQuota` 检查在二次验证**之前**（注定被拒的请求不烧凭据），检查通过到实际写出之间可被并发请求插队；E2 把扣减点前移到写出之前，插队窗口收窄为「检查→consume」一次往返，越界的并发者在 consume 处被拒（消费即扣减把检查与占用并成一步）。

## Redis 档当前计数

`- null = 未配置 Redis（调用方走审计计数路径）；已配置未就绪/命令失败 ⇒ 上抛。`

## 消费即扣减（写出之前调用）

`- INCR 并在首次置 24h TTL；null = 未配置 Redis（调用方保持现状：计数由写成功后的留痕承载）。`
