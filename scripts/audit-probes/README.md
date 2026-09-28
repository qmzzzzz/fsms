# 审计探针（P1-30）

审计报告（2026-09-16 全面代码审计报告，**该报告已删除**）附录 A 中的
端到端实证脚本，原为仓库根目录的 `.audit-*` 文件（含本机绝对路径与源码片段，
已在 `.gitignore` 中忽略）。其中唯一**尚无等价跟踪测试**的 P0-2 复现脚本
（WebSocket 会话吊销 / IP 白名单双绕过）移入本目录保留，作为修复完成前的
可复现证据。

## ws-session-bypass.cjs

复现 P0-2：同一 JWT 在 HTTP 侧被 403（`AUTH_IP_RANGE_DENIED`），
却在 WebSocket 侧认证成功——`authenticateSocket` 不校验 `sid`
（设备会话状态）与 `allowedIPs`。

用法（需先在仓库根 `npm install`）：

```bash
node scripts/audit-probes/ws-session-bypass.cjs; echo "exit=$?"
```

**退出码即结论**（2026-09-19 起，此前无论结论如何都 exit 0）：

| 退出码 | 含义                                                                                                                                  |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `0`    | 已拒，**且拿到 `auth-error` 帧作为正向证据**                                                                                          |
| `1`    | 确认绕过（socket 绑上了 userId）                                                                                                      |
| `2`    | 不可判定：没绑上用户、也没有 auth-error 回帧——多半是握手层变了使请求根本没走到 `authenticateSocket`；探针自身的失效不能当成"漏洞已修" |

`decideVerdict` 的真值表由 `src/tests/zzqoder_wsProbeVerdict.test.js`（6 例）钉住；
探针自身带 `require.main` 守卫，所以那个套件可以只 require 它取判据而不触发建库。

**2026-09-17 复核：P0-2 修复已落地**；2026-09-19 真跑实测 `verdict=rejected exit=0`，
下行帧为 `42["auth-error",{"message":"当前网络不在允许的 IP 范围内"}]`。
对应的自动化回归见 `src/tests/services/websocketAuthScope.test.js`（8 用例：
allowedIPs 命中/不命中/为空/非法、sid 已吊销/不存在/active/缺省）。
本脚本保留为可脱离 Jest 的人工复核工具（走真实 socket.io 握手路径，
覆盖 Jest 单测不经过的 engine.io 轮询层）。

其余 `.audit-*` 探针（数据范围、XFF、脱敏深度等）的结论均已转化为
`src/tests/` 下的真实断言（见 `src/tests/security/adversarialProbeRegression.test.js`
及各专项测试），无需在本目录重复保留。
