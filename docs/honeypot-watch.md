# 蜜罐监视（honeypotWatch）说明

本文件承接 `src/services/honeypotWatch.js` 部分内联注释的论证（注释密度棘轮按文件封顶，论证移此，代码内只留最短行内不变量）。

## WS 侧取地址：与封禁闸同一把尺（F1）

与 WS 封禁闸同用一把安全裁决尺（websocketService/handshake 的 resolveHandshakeIPForSecurityDecision）——裸 handshake.address 是「请求方可写的那一侧」，反向代理/伪造握手头能让留痕落到任意地址。惰性 require：handshake.js 顶部反向依赖本模块（isHoneypotSocket），加载期互引会成环。

## 诱饵会话呈现层

自本文件拆出（体积棘轮）：纯呈现工厂、不持状态，经同名再导出保持 authService 与测试的引用面不变（见 honeypotLurePresentation.js 文件头）。

## 留痕的来源归因口径

对齐 recordHoneypotLogin：封禁/留痕依据是哪一类来源（trusted_proxy「可用但不可区分」/ public_peer_header 已改打对端）必须可事后追查，DIRECT 是默认事实不必刷存在。

## 告警档位为什么拆成两个调用点

档位必须是**静态可解析**的：outboundAlertContract D1 用静态扫描核对每个调用点的档位实参是否 ∈ ALERT_LEVELS，三元实参没有唯一取值，被判成「既不是键也不是字面量」。因此拆成两个调用点由 writeAttempt 选路：档位语义一字未变，可判定性保住。
