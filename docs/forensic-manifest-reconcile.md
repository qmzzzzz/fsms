# 取证清单↔库对账（forensicManifestReconcile）说明

本文件承接 `src/services/forensicManifestReconcile.js` 内联注释的论证（注释密度棘轮按文件封顶，论证移此，代码内只留指针）。

## 为什么需要对账

`verifyManifest` 只证明「清单自身没被动过」（链连续、哈希可复算、尾未被截），**不证明**清单里声明的记录还在库里——而「记录存在过」才是取证清单的核心承诺：攻击者不必改清单，直接 DELETE 几条 ForensicCapture 就够。

## 三种形态的判据口径（不能混成一个布尔）

- `record_missing`：清单声明 N 条、当天库里只有 M<N 条 ⇒ **篡改级**，红。
- `unmanifested`：库里有、清单没记 ⇒ 只警告。清单写入失败有计数可查，不等于篡改；但数量异常膨胀意味着有人往库里塞记录。
- `no_manifest`：当天清单根本不存在 ⇒ 无从对账，红。不能因为「没有证据」就判绿。

## 能力边界（如实说）

只能定位「少了 N 条」，**不能点名是哪几条**：清单每批只存逐条哈希的折叠值 `hashesDigest`，反推不出具体缺哪一个。要能点名就得在清单行里存全部 `recordHash`（单日约 4 万条 ⇒ 文件膨胀数十倍）。取舍：宁可省空间 + 报准确差额，也不假装能点名。

只读：绝不写库、不改清单（对账动作本身不得成为证据链的一环）。

## 对账窗口（F6）

窗口 = min(ForensicCapture TTL, manifest 保留期)：

- TTL 由 `constants/businessRetention.js` 的 `BUSINESS_RETENTION_DAYS_FORENSIC_CAPTURE` 开关决定（enabled=环境变量有生效值）。TTL 启用时库内数据只活 effectiveDays 天，更早的日期**无从对账**——拿它判 `record_missing` 是结构性假红。
- manifest 保留期默认 60 天（`forensicManifestPrune.DEFAULT_KEEP_DAYS`，env 可下调），更早的清单被归档走 ⇒ `no_manifest` 也是结构性假红。
- 窗口外的日期**显式 skip 计数**（结果里的 `skippedBeyondTtl`），绝不静默——「没查」必须与「查了且一致」可区分。窗口内 `no_manifest` 仍按红处理（窗口内清单不存在不是保留期问题，是留痕缺口）。
- TTL 未启用时窗口放宽到 manifest 保留期（60d）。若未来保留期上调，窗口随 `min(keep, ttl)` 动态取值，不需要改这里。

`effectiveReconcileWindowDays()` 生效对账窗口（天）= min(TTL 天数, manifest 保留天数)；TTL 未启用时 TTL 一侧视为 ∞，窗口落到 manifest 保留期（默认 60）。

`resolveKeepDays()`：manifest 保留期（天），与 `forensicManifestPrune` 同一 env、同一解析口径（该函数未导出，镜像实现并注明——两处若分叉，窗口会对着一份已归档的清单判红）。

`dateKey` 字符串比较即日历比较（YYYY-MM-DD 恒定宽）。

## reconcileManifest 的参数与返回

- `model` 可注入（用例传桩，生产用真模型）；`windowDays`/`now` 可注入（测试确定性用，缺省分别取 `resolveReconcileWindowDays()` 与当前时刻）。
- 返回 `{ok, checked, declared, shortfall, unmanifested, skippedBeyondTtl, problems}`。
- `ok` 的语义是「本次核到的范围内未发现篡改」——没核到的日子由 `skippedBeyondTtl` 计数与 info 日志承载，调用方不得把它读成「该日已核」。

## 取数口径

按**业务日**整天取库：seq 是 'RUN-序号' 字符串，字典序在 r-10/r-2 上会错，拿它做 $gte/$lte 区间会漏记录（B-2）。用 createdAt 落在业务日窗口内才可靠。

## 周期接线（F6）

`start()`/`stop()` 对齐 `auditChainMonitor` 的启动/停止模式（index.js 同款）：定时器 unref、启动幂等、优雅关闭停止。每轮只核窗口内**一个**业务日（游标轮转）：单日对账要拉当天全部 recordHash（可达数万条），一轮扫全窗口会把这件事放大 30 倍；轮转窗口让每个日期每 windowDays 轮被核一次。今天（day 0）不核——当天的清单还在持续追加，中途对账只会量到半程状态。

- 轮转游标：0=昨天、1=前天……在窗口内循环。
- `resolveIntervalMs()`：周期对账间隔（env `FORENSIC_RECONCILE_INTERVAL_MS`，毫秒），钳制到 [5min, 24h]；上界理由同 `auditChainMonitor`：超 2^31-1 的 setInterval 被 Node 静默压成 1ms。
- 单轮失败只记健康计数与 error 日志，绝不让定时器停摆。
- 窗口内的 no_manifest / record_missing 是红信号：留痕必须可见（计数 + warn）。
- `start()` 重复调用安全（幂等）。
- `getHealth()` 供运维/测试读取对账健康面（isRunning 只说定时器挂着）。
- `__resetForTest()` 重置周期面状态（不清窗口解析——它由 env 决定）。
