# 审计探针（P1-30）

审计报告（2026-09-16 全面代码审计报告，**该报告已删除**）附录 A 中的
端到端实证脚本，原为仓库根目录的 `.audit-*` 文件（含本机绝对路径与源码片段，
已在 `.gitignore` 中忽略）。其中唯一**尚无等价跟踪测试**的 P0-2 复现脚本
（WebSocket 会话吊销 / IP 白名单双绕过）移入本目录保留，作为修复完成前的
可复现证据。

## ws-session-bypass.cjs

复现 P0-2：同一 JWT 在 HTTP 侧因某条规则被拒（`DEVICE_SESSION_REVOKED` /
`AUTH_IP_RANGE_DENIED`），却在 WebSocket 侧认证成功——`authenticateSocket`
曾经既不校验 `sid`（设备会话状态）也不校验 `allowedIPs`。

用法（需先在仓库根 `npm install`）：

```bash
node scripts/audit-probes/ws-session-bypass.cjs; echo "exit=$?"
```

### 两个单违规场景

**2026-10-24 起**探针跑两个场景，每个场景只带**一条**违规：

| 场景              | 违规                    | HTTP 期望                      | WS 期望理由                  |
| ----------------- | ----------------------- | ------------------------------ | ---------------------------- |
| `session_revoked` | 会话已吊销，IP 不限制   | `401 / DEVICE_SESSION_REVOKED` | 设备会话已失效               |
| `ip_not_allowed`  | 会话正常，IP 不在白名单 | `403 / AUTH_IP_RANGE_DENIED`   | 当前网络不在允许的 IP 范围内 |

**为什么必须拆开**：原实现只用一个令牌，同时带两条违规，判据是"收到任何
`auth-error` 就算拒绝"。它只能证明**至少一条**控制在生效——把 `sid` 校验删掉、
只留 IP 校验，探针照样 `exit 0` 报"P0-2 修复在位"。对一个有两条独立控制项的
漏洞，"至少一条"不是有效证据。实测（2026-10-24）：只摘 IP 校验时旧判据给 ✅，
新判据给 `ip_not_allowed bypass exit=1`。

### 退出码即结论

| 退出码 | 含义                                                                                                                                    |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `0`    | 两个场景都已拒，且**拒绝理由各自匹配**本场景期望的那条控制                                                                              |
| `1`    | 至少一个场景确认绕过（socket 绑上了该场景用户的 userId）                                                                                |
| `2`    | 不可判定：没绑上 userId 但没看到 `auth-error`；或 `auth-error` 的理由对不上；或 HTTP 前置对照没按预期被拒。三者都不构成"修复生效"的证据 |

`auth-error` 帧里没有错误码（`{ message }` 是唯一通道），故归因靠文案。文案
改动会让探针落到 `2` 而不是 `0`——这正是要的：探针说不出"是哪条控制拒的"时，
它就没有资格宣布那条控制在位。

### 判据的回归

`decideVerdict` 的真值表由 `src/tests/wsProbeVerdict.test.js`（9 例）钉住：
三态与退出码两两不同、绕过优先于帧内容、"没绑上但没回帧"必须判不可判定、
**理由不匹配必须判不可判定**、两个场景的理由互不通用、未声明期望理由必须判
不可判定、下游帧非字符串不得抛错。

探针自身带 `require.main` 守卫，所以那个套件可以只 require 它取判据而不触发建库。

### 复核记录

- **2026-09-17**：P0-2 修复已落地（`_assertHandshakeSessionUsable` /
  `_assertHandshakeIpAllowed` 在 `authenticateSocket` 内于密码修改校验之后调用）。
- **2026-09-19**：真跑实测 `verdict=rejected exit=0`。
- **2026-10-24**：拆成两个单违规场景 + 理由归因。真跑实测两场景各自拿到
  `42["auth-error",{"message":"该设备会话已失效，请重新登录"}]` 与
  `42["auth-error",{"message":"当前网络不在允许的 IP 范围内"}]`，`exit=0`。

对应的自动化回归见 `src/tests/services/websocketAuthScope.test.js`（8 用例：
allowedIPs 命中/不命中/为空/非法、sid 已吊销/不存在/active/缺省）。
本脚本保留为可脱离 Jest 的人工复核工具（走真实 socket.io 握手路径，
覆盖 Jest 单测不经过的 engine.io 轮询层）。

其余 `.audit-*` 探针（数据范围、XFF、脱敏深度等）的结论均已转化为
`src/tests/` 下的真实断言（见 `src/tests/security/adversarialProbeRegression.test.js`
及各专项测试），无需在本目录重复保留。
