# ADR-021：L4 边界 PROXY protocol 接入与信任边界

> 状态：已接受 ｜ 日期：2026-11-04
> 相关：`src/utils/proxyProtocol.js`（解析器 + 前置服务器）、
> `src/config/proxyProtocol.js`（开关解析）、`src/index.js`（接线）、
> `src/config/validate.js`（生产硬闸）、`src/constants/failOpenSites.js`
> （`proxy_protocol_header_rejected` 台账条目）、
> `deployment/observability/alert-rules.yml`（`ProxyProtocolHeaderRejected` 专条）、
> `deployment/nginx.conf.example`（LB→nginx 变体拓扑注释段）
> 前置：F-01 信任边界判据（`src/utils/ipUtils.js` 的 `isPeerTrustedProxy`）、
> ADR-009（网络分段）

## 背景

本仓的客户端 IP 信任模型一直假设「TLS/代理在宿主 nginx 终结，后端只从 nginx 收
X-Forwarded-For」：`TRUST_PROXY_HOPS` + `TRUSTED_PROXY_CIDRS`（F-01）裁决 XFF 可信性，
`socket.remoteAddress` 是全链路共同的「不可伪造地面真相」。这在现有 compose 拓扑
（app 只绑 127.0.0.1、宿主 nginx 反代）下是自洽的。

当部署形态改为 **L4 负载均衡（云 NLB、HAProxy、F5）直连后端 3000 端口**时，模型出现
结构性缺口：L4 层不做 HTTP，无从写 X-Forwarded-For，后端 socket 对端**恒为 LB 地址**。
后果不是「IP 少了精度」而是安全语义整体塌陷——限流桶全站共享一个（一人试错锁死所有
经 LB 的用户）、自动封禁打在 LB 上（等于对全部用户断网）、审计 IP 全部失真、
metricsAuth 的「回环=本机」假设与 canaryWatch 的归因链一并失效。

PROXY protocol（HAProxy 官方 spec doc/proxy-protocol.txt）是这个场景的标准解：LB 在
转发首字节前先发一行 v1 文本头或一段 v2 二进制头，声明真实连接四元组。问题只剩
「后端在哪一层、以什么信任边界消费它」。

## 决定

### ① 连接层前置服务器还原，重写 socket，下游零改动

启用（`PROXY_PROTOCOL=on`）时，`src/index.js` 用 `net.Server` 前置监听真实端口，
在**任何 HTTP/TLS 解析之前**消费 PROXY 头，把还原出的四元组直接重写到
`socket.remoteAddress/remotePort/localAddress/localPort`（proxywrap 形态：解析完成后
`innerServer.emit('connection', socket)` 转交）。

选「重写 socket」而不是「新加读头中间件」的理由：重写发生在请求产生之前，下游全部
消费方**零改动**地保持自洽——`req.ip`（trust proxy 开与不开两种形态）、
`classifyIpAttribution`（两侧同值 ⇒ 判 DIRECT，惩罚落真实客户端）、metricsAuth（裸
socket 对端）、WS 握手（`handshake.address` 读同一 socket）、审计
`clientInfo.socketPeer`。若只改 req.ip 不改 socket（或反之），上面几处会各拿一种地址，
等于把 F-01 的教训（判据分置 → 收紧漏一处）在新维度重演。

选「前置 net.Server」而不是在内层 server 上挂 connection 监听的理由：内层是
`http/https.createServer` 的产物，对 https（tls.Server）内部监听器会在同一事件里创建
TLSSocket 并开始握手，用户侧再插手就是与内部实现抢时序；前置层把 accept 权握在
自己手里，HTTP 与 TLS 两条路径形态一致。代价是监听/错误兜底/停 accept 的宿主换成
前置层（接线约定见 `src/index.js` 对应注释），内层保持是 `httpServer`——WS 挂载与
`closeIdleConnections/closeAllConnections` 语义不变（两层连接表登记的是同一批 socket）。

### ② 信任锚复用 TRUSTED_PROXY_CIDRS，一张名单一个语义

谁有权发 PROXY 头，与「谁写的 XFF 可信」**完全同级**——PROXY 头一旦被接受就等价于
重写地面真相。故刻意复用同一份名单与同一把判据（`isPeerTrustedProxy`，含未配置时
仅回环的兼容档），不设独立的 `PROXY_PROTOCOL_CIDRS`：

- 一张名单、一个语义：「可信边缘对端」。运维不需要理解两份名单在 XFF 信任与
  PROXY 头信任上的交叉优先级；
- 名单的解析/校验/fail-closed（空项、非法项、全域网段、混排整单作废）在
  `config/trustedProxies.js` 已经过对抗测试，本功能不重抄一遍。

生产硬闸（`config/validate.js`）：`PROXY_PROTOCOL=on` 时 `TRUSTED_PROXY_CIDRS`
必须已配置，否则拒绝启动。未配名单时运行期判据只信回环——还原功能实际一个对端
都不会放行，形同虚设却让运维误以为 L4 还原已生效；宁可拒启逼出显式配置。
staging 宽松清单同步登记跳过项。

### ③ 三态语义：透传 / 还原 / 拒绝

1. **首段无 PROXY 签名** ⇒ 原样透传（PROXY 头是可选的：只有 LB 才发）。这条不可
   去掉：容器网 Prometheus 直抓 `app:3000` 与 docker healthcheck 都不发 PROXY 头，
   监听器级「必须发头」会直接杀掉现有监控与健康检查面；
2. **有签名且对端可信** ⇒ 解析成功则重写后转交；解析失败（畸形头）⇒ 断开；
3. **有签名且对端不可信** ⇒ 断开 + 安全计数。不是「忽略头继续解析 HTTP」——
   头凭据未通过名单校验时，把任意四元组塞进下一个解析器等于开走私口子。

头阶段另有 10s 超时（从 accept 到透传判定或头解析完成的硬上限），防「连接了但不发
完整头」的慢速占用。超时**不进安全计数**：其成因大多是探活与端口扫描，逐条告警会把
`security_alerts_total` 刷成扫描器账本；签名可识别但被名单拒绝的才计数
（`proxy_protocol_header_rejected`，high，台账信号段登记 + `ProxyProtocolHeaderRejected`
专条告警，for: 0m——伪造尝试天然可以是低频单发）。

### ④ 默认 off；取值域只有 off/on

`PROXY_PROTOCOL` 未配置 = off：不创建前置服务器，监听路径与未引入本功能前逐字节
一致。取值域刻意不收 `true/false/1/0` 别名——在 `.env` 文档、compose 默认值、README
登记表之外多一种「对的写法」，登记面就要多一处同步，且没有任何运维收益。

### ⑤ 形态支持范围（v1 + v2，AF_UNIX 刻意不支持）

v1 文本头（行上限 108 字节含 CRLF，`UNKNOWN` 保留真实对端）与 v2 二进制头
（12 字节签名，ver/cmd/fam 严格白名单，TLV 整段跳过不解析，`LOCAL` 保留真实对端）
都支持——真实 LB（AWS NLB、HAProxy）两者都在用，且同一部署里可能混用。
**AF_UNIX 刻意判 invalid**：其「地址」是文件路径文本，重写进 remoteAddress 毫无意义，
反而给伪造留了非 IP 文本的口子。IPv4-mapped 形态（`::ffff:a.b.c.d`）统一经
`normalizeIP` 收敛为纯 IPv4，与全仓地址口径同源。

### ⑥ 刻意不支持的组合：PROXY_PROTOCOL=on + ENABLE_HTTPS=true（启动硬闸）

进程自启 HTTPS 时，PROXY 头还原与 TLS 握手在 Node 里**不可共存**，这是平台硬限制
而非本实现可绕过：TLSSocket 在**句柄层**读底层 socket（三条探针实测钉死——流级
`unshift` 还回的字节、无论经 `innerServer.emit('connection')` 转交还是手工
`new TLSSocket(rawSocket)` 升级，TLS 都看不见），而 PROXY 头还原必须先于 TLS 消费
首段字节。消费掉的头字节落在流缓冲里回不到句柄层，典型 TCP 分段下（LB 的头与
ClientHello 同段到达）表现是「连接被接受、TLS 握手永久悬挂」——最难排查的静默
故障形态。与其给一条半可用路径，不如启动面直接拒绝（validate.js 生产硬闸 +
index.js 非生产兜底守卫，两处同文案）。

生产可用的两种形态都不受影响：LB 终结 TLS（明文 + PROXY 头直达后端，本功能
全量支持）；LB 透传 TLS 到宿主 nginx（`listen proxy_protocol` + `real_ip_header`
消费，后端保持 `PROXY_PROTOCOL=off`，判据完全不变）。

## 踩过的坑（都被实测钉住，不是推测）

- **v1 行尾 `\r` 进了最后一个字段**：`slice` 边界差一位，端口校验报出误导性的
  「端口非数字」——测试钉住四元组全量还原后自行现身；
- **IPv6 按字节展开成 16 组**：全展开文本必须是 8 组 uint16，逐字节拼出的
  16 组文本 `parseIP` 直接判 null——v2 INET6 用例钉住；
- **块注释里写 `remote*/local*`**：`*/` 把块注释提前终止，babel 直接语法报错；
  注释里凡提这两个通配名一律写 `remote* 与 local*`；
- **测试挂具的分段监听**：keep-alive 用例若给两笔响应各挂一个 data 监听器，
  响应 1 会留进被丢弃的缓冲——单一累积器贯穿整条连接（该坑属于测试，不属于实现）；
- **TLSSocket 的句柄级读取（决定 ⑥ 的根因）**：三条探针逐步钉死——
  (a) 读首段后 `unshift` 再 `httpsServer.emit('connection', socket)`，握手悬挂；
  (b) 不消费任何字节直接转交，握手正常（字节在 OS 缓冲，句柄级读得到）；
  (c) 手工 `new TLSSocket(rawSocket, {isServer:true})` 升级已 unshift 的连接，
  同样悬挂。结论：TLSSocket 只从句柄/OS 缓冲读，永远看不见流缓冲，
  与流模式（flowing/paused）无关。

## 后果与局限

- **局限 1：名单内对端被完全信任。** LB（或名单内任何主机）声明的四元组就是后端
  眼中的地面真相——这与「名单内对端写的 XFF 可信」同级，是信任锚的固有代价。
  残余风险与 F-01 相同：名单配多大，信任面就多大；全域网段仍被 trustedProxies 拒绝。
- **局限 2：PROXY 头与 XFF 并存时以 PROXY 为准。** 还原后 socket 对端 = 真实客户端，
  XFF 左端若与其不一致，归因仍判 DIRECT（两侧同值）——LB 必须保证两者一致，这是
  LB 配置责任，应用侧不做二次仲裁（也没有可靠依据做仲裁）。
- **局限 3：metricsAuth 的「回环=抓取方」假设在 LB 拓扑下自然失效**——经 LB 的
  抓取方还原为真实 IP 后不再是回环，必须带 METRICS_TOKEN。这与 2026-11-03 的
  metricsAuth 收窄（i760 #21）方向一致，不是回归。
- **局限 4：头阶段 10s 超时替换了「accept 到首字节」的 85s 窗口**（仅 on 时）。
  真实 LB 在首字节包里带头，健康检查连了不发/发了就关，均不受影响；直连慢客户端
  （telnet 挂着不发）会被提前断开——这是刻意的资源保护。
- 运维面：`.env.example`、`docker-compose.yml`（默认 off）、README 环境变量表与
  上线清单、`deployment/edge-protection.md`、`deployment/nginx.conf.example`
  （LB→nginx 变体拓扑参考）已同步登记；测试覆盖解析器逐格判据、真实 socket 集成
  （还原/透传/拒绝/超时/keep-alive/IPv6）与生产启动闸。
