# 生产主机时钟同步基线（P1-5）

> 对应审计缺口 P1-5：生产环境没有 NTP 同步的客观证据，JWT 的 `nbf/exp`、
> TOTP 的 30 秒窗口、审计时间戳与跨机日志对齐都锚在**宿主时钟**上。
> 容器共享宿主内核时钟，在容器里装 NTP 客户端不解决这个问题。

## 1. 基线要求

| 项目     | 要求                                                                                   |
| -------- | -------------------------------------------------------------------------------------- |
| 同步源   | 至少 2 个内网/公网 NTP 源，禁止只配 `localhost`                                        |
| 同步状态 | `timedatectl` 的 `NTPSynchronized=yes`，或 `chronyc tracking` 的 `Leap status: Normal` |
| 偏移阈值 | 默认 ≤ 1000ms；发布单可用 `CLOCK_MAX_OFFSET_MS` 收紧（1..60000）                       |
| 判不了时 | 退出码 2，按**不通过**处理（不能让"没有输出"冒充"已同步"）                             |
| 检查位置 | 部署机/生产宿主，在 `scripts/deploy.js` 之前                                           |

## 2. 部署前检查

```bash
# 在真正运行容器的宿主机执行（不是 app 容器内）
node scripts/check-clock-sync.js
# 输出一行 JSON；退出码 0=通过，1=未同步/偏移超限，2=无法判定
CLOCK_MAX_OFFSET_MS=500 node scripts/check-clock-sync.js
```

`deploy.yml` 的两条路径（self-hosted runner 与 SSH 目标机）都会在正式发布前执行
该脚本；`dry_run` 只出计划，不执行检查。手工发布必须自己先跑一次并把输出贴进发布单。

## 3. systemd-timesyncd（Ubuntu/Debian 默认）

```bash
sudo timedatectl set-ntp true
timedatectl timesync-status
# 期望：Server: ... / Offset: ... / Packet count > 0
```

若使用 chrony，参考 `deployment/systemd/chrony.conf.example`，启用前替换
`ntp1.example.net` / `ntp2.example.net` 为实际 NTP 源。

## 4. 审计留证

发布单/变更单附以下两项：

1. `node scripts/check-clock-sync.js` 的 JSON 输出（含 `ok`、`source`、`offsetMs`）；
2. `timedatectl timesync-status` 或 `chronyc tracking` 的原始输出截图。

只写"已配置 NTP"不算证据；必须能出示**检查当时**的同步状态与偏移。
